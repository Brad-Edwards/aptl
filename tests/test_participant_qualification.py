"""Behavioral tests for participant-profile conformance evaluation (APP-2)."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import shutil

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from aptl.cli.lab import app as lab_app
from aptl.core.runstore import LocalRunStore
from aptl.validation.participant_profile import (
    ParticipantProfileError,
    load_participant_profile,
)
from aptl.validation.participant_qualification import (
    ParticipantQualificationError,
    ParticipantQualificationReport,
    VerifiedParticipantQualification,
    evaluate_participant_qualification,
    load_participant_qualification_report,
    participant_qualification_attestation_payload,
    persist_participant_qualification,
    verify_participant_qualification_attestation,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = (
    PROJECT_ROOT / "participant-profiles" / "guided-purple-v1" / "profile.json"
)
_QUALIFICATION_PRIVATE_KEY = Ed25519PrivateKey.generate()
_QUALIFICATION_PUBLIC_KEY_PEM = _QUALIFICATION_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
_QUALIFICATION_PUBLIC_KEY_ID = (
    "sha256:"
    + hashlib.sha256(
        _QUALIFICATION_PRIVATE_KEY.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
)


def _profile():
    return load_participant_profile(PROJECT_ROOT, PROFILE_PATH)


def _passing_report_payload() -> dict:
    profile = _profile()
    matrix = profile.expected_matrix
    return {
        "schema_version": "aptl.participant-qualification/v1",
        "profile_id": profile.manifest.profile_id,
        "profile_version": profile.manifest.version,
        "profile_sha256": profile.manifest_sha256,
        "asset_lock_digest": (
            "sha256:" + profile.manifest.release_evidence.asset_lock_sha256
        ),
        "run_record_ref": "runs/profile-proof/run-record.json",
        "run_record_sha256": "0" * 64,
        "snapshot_ref": "runs/profile-proof/snapshot.json",
        "snapshot_sha256": "0" * 64,
        "hardware": {
            "architecture": "x86_64",
            "vcpus": 8,
            "memory_bytes": 17179869184,
            "disk_bytes": 107374182400,
            "hypervisor": "kvm",
            "engine": "docker",
        },
        "surface": {
            "selected_profiles": list(matrix.selected_profiles),
            "expected_services": list(matrix.expected_services),
            "actual_services": list(matrix.expected_services),
            "expected_networks": list(matrix.expected_networks),
            "actual_networks": list(matrix.expected_networks),
            "actual_workbench_profiles": list(
                profile.manifest.capabilities.workbench_profiles
            ),
            "actual_mcp_servers": list(profile.mcp_server_ids),
            "actual_browser_capabilities": list(profile.browser_refs),
        },
        "checks": [
            {
                "check_id": check.check_id,
                "status": "passed",
                "summary": "semantic operation passed",
            }
            for check in profile.readiness.checks
        ],
        "offline": {
            "egress_denied": True,
            "download_attempts": 0,
            "image_pulls": 0,
            "image_builds": 0,
            "package_resolutions": 0,
        },
        "measurements": {
            "peak_cpu_percent": 60.0,
            "peak_memory_bytes": 8589934592,
            "staged_profile_assets_bytes": 32212254720,
            "unique_image_compressed_bytes": 10737418240,
            "unique_image_expanded_bytes": 26843545600,
            "peak_runtime_disk_bytes": 16106127360,
            "cold_start_seconds": 600.0,
            "warm_start_seconds": 180.0,
            "clean_reset_seconds": 420.0,
        },
        "sample_count": 3,
        "aggregation": "worst-conforming-sample",
        "attestation": {
            "algorithm": "ed25519",
            "key_id": _QUALIFICATION_PUBLIC_KEY_ID,
            "signature": "AA==",
        },
    }


def _canonical_json_bytes(document: dict[str, object]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _canonical_evidence(
    payload: dict,
) -> tuple[dict[str, object], dict[str, object]]:
    snapshot: dict[str, object] = {
        "containers": [
            {"name": service, "status": "Up"}
            for service in payload["surface"]["actual_services"]
        ],
        "networks": [
            {"name": network} for network in payload["surface"]["actual_networks"]
        ],
    }
    run_record: dict[str, object] = {
        "schema_version": "aptl.run-record/v1",
        "run_id": "profile-proof",
        "outcome": "success",
        "backend_evidence": {
            "selected_profiles": payload["surface"]["selected_profiles"],
            "range_snapshot": snapshot,
        },
    }
    return run_record, snapshot


def _attested_evidence(payload: dict) -> VerifiedParticipantQualification:
    run_record, snapshot = _canonical_evidence(payload)
    payload["run_record_sha256"] = hashlib.sha256(
        _canonical_json_bytes(run_record)
    ).hexdigest()
    payload["snapshot_sha256"] = hashlib.sha256(
        _canonical_json_bytes(snapshot)
    ).hexdigest()
    unsigned = ParticipantQualificationReport.model_validate(payload)
    payload["attestation"]["signature"] = base64.b64encode(
        _QUALIFICATION_PRIVATE_KEY.sign(
            participant_qualification_attestation_payload(unsigned)
        )
    ).decode("ascii")
    report = ParticipantQualificationReport.model_validate(payload)
    verify_participant_qualification_attestation(
        report,
        _QUALIFICATION_PUBLIC_KEY_PEM,
    )
    return VerifiedParticipantQualification(report, run_record, snapshot)


def _evaluate(payload: dict):
    return evaluate_participant_qualification(
        _profile(),
        _attested_evidence(payload),
    )


def _write_attested_bundle(
    project: Path,
    payload: dict,
) -> tuple[Path, Path, VerifiedParticipantQualification]:
    evidence = _attested_evidence(payload)
    report_path = project / "evidence" / "report.json"
    public_key_path = project / "evidence" / "qualification-public-key.pem"
    run_record_path = project / evidence.report.run_record_ref
    snapshot_path = project / evidence.report.snapshot_ref
    for path in (report_path, run_record_path, snapshot_path):
        path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        evidence.report.model_dump_json(),
        encoding="utf-8",
    )
    run_record_path.write_bytes(_canonical_json_bytes(evidence.run_record))
    snapshot_path.write_bytes(_canonical_json_bytes(evidence.snapshot))
    public_key_path.write_bytes(_QUALIFICATION_PUBLIC_KEY_PEM)
    return report_path, public_key_path, evidence


def _materialized_profile_project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    shutil.copytree(
        PROJECT_ROOT / "participant-profiles",
        project / "participant-profiles",
    )
    (project / "scenarios").mkdir()
    shutil.copy2(
        PROJECT_ROOT / "scenarios" / "catalog.json",
        project / "scenarios" / "catalog.json",
    )
    shutil.copy2(
        PROJECT_ROOT / "scenarios" / "techvault-attacker-target.sdl.yaml",
        project / "scenarios" / "techvault-attacker-target.sdl.yaml",
    )
    shutil.copy2(PROJECT_ROOT / "docker-compose.yml", project / "docker-compose.yml")
    workbench_profile = Path("src/aptl/workbench/profiles.py")
    (project / workbench_profile).parent.mkdir(parents=True)
    shutil.copy2(PROJECT_ROOT / workbench_profile, project / workbench_profile)
    for package in ("mcp-red", "mcp-indexer", "mcp-wazuh"):
        for filename in (
            "package-lock.json",
            "docker-lab-config.json",
            "build/index.js",
        ):
            source = PROJECT_ROOT / "mcp" / package / filename
            target = project / "mcp" / package / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    return project


def test_complete_report_passes_every_conformance_layer() -> None:
    evaluation = _evaluate(_passing_report_payload())

    assert evaluation.passed
    assert {check.name for check in evaluation.checks} == {
        "profile_identity",
        "minimum_hardware",
        "runtime_surface",
        "semantic_readiness",
        "disabled_capability_absence",
        "staged_offline_start",
        "resource_budgets",
    }


def test_profile_identity_or_asset_lock_drift_fails() -> None:
    payload = _passing_report_payload()
    payload["profile_sha256"] = "0" * 64
    payload["asset_lock_digest"] = "sha256:" + "1" * 64

    evaluation = _evaluate(payload)

    check = next(c for c in evaluation.checks if c.name == "profile_identity")
    assert not check.passed
    assert check.diagnostics == ("profile identity or digest does not match",)


def test_missing_or_unexpected_runtime_service_fails() -> None:
    payload = _passing_report_payload()
    payload["surface"]["actual_services"].pop()
    payload["surface"]["actual_services"].append("thehive")

    evaluation = _evaluate(payload)

    check = next(c for c in evaluation.checks if c.name == "runtime_surface")
    assert not check.passed
    assert any("expected service" in item for item in check.diagnostics)
    assert any(
        "unexpected steady-state container" in item for item in check.diagnostics
    )


@pytest.mark.parametrize(
    ("field", "value", "diagnostic"),
    [
        (
            "selected_profiles",
            ["kali", "victim", "wazuh"],
            "reported selected profiles do not match the admitted profile surface",
        ),
        (
            "expected_networks",
            ["security"],
            "reported expected networks do not match the derived profile surface",
        ),
    ],
)
def test_reported_profile_or_network_surface_must_match_derivation(
    field: str,
    value: list[str],
    diagnostic: str,
) -> None:
    payload = _passing_report_payload()
    payload["surface"][field] = value

    evaluation = _evaluate(payload)

    check = next(c for c in evaluation.checks if c.name == "runtime_surface")
    assert not check.passed
    assert diagnostic in check.diagnostics


def test_failed_required_semantic_operation_fails() -> None:
    payload = _passing_report_payload()
    payload["checks"][0]["status"] = "failed"
    payload["checks"][0]["summary"] = "backend operation did not pass"

    evaluation = _evaluate(payload)

    check = next(c for c in evaluation.checks if c.name == "semantic_readiness")
    assert not check.passed
    assert check.diagnostics == ("required readiness checks did not pass",)


def test_unexpected_semantic_check_fails() -> None:
    payload = _passing_report_payload()
    payload["checks"].append(
        {
            "check_id": "unexpected.check",
            "status": "passed",
            "summary": "not part of the bound readiness suite",
        }
    )

    evaluation = _evaluate(payload)

    check = next(c for c in evaluation.checks if c.name == "semantic_readiness")
    assert not check.passed
    assert check.diagnostics == (
        "qualification checks do not exactly match the readiness suite",
    )


def test_disabled_participant_surface_must_be_absent() -> None:
    payload = _passing_report_payload()
    payload["surface"]["actual_mcp_servers"].append("aptl-casemgmt")
    payload["surface"]["actual_browser_capabilities"].append("thehive")
    payload["surface"]["actual_workbench_profiles"].append("blue")

    evaluation = _evaluate(payload)

    check = next(
        c for c in evaluation.checks if c.name == "disabled_capability_absence"
    )
    assert not check.passed
    assert check.diagnostics == (
        "participant workbench, MCP, or browser surface does not match the allow-list",
    )


def test_missing_allowed_participant_surface_fails() -> None:
    payload = _passing_report_payload()
    payload["surface"]["actual_mcp_servers"].remove("aptl-wazuh")
    payload["surface"]["actual_browser_capabilities"] = []

    evaluation = _evaluate(payload)

    check = next(
        c for c in evaluation.checks if c.name == "disabled_capability_absence"
    )
    assert not check.passed
    assert check.diagnostics == (
        "participant workbench, MCP, or browser surface does not match the allow-list",
    )


def test_reported_expected_matrix_must_match_profile_derivation() -> None:
    payload = _passing_report_payload()
    payload["surface"]["expected_services"].append("thehive")

    evaluation = _evaluate(payload)

    check = next(c for c in evaluation.checks if c.name == "runtime_surface")
    assert not check.passed
    assert any("reported expected services" in item for item in check.diagnostics)


def test_post_stage_network_dependency_fails() -> None:
    payload = _passing_report_payload()
    payload["offline"]["image_pulls"] = 1

    evaluation = _evaluate(payload)

    check = next(c for c in evaluation.checks if c.name == "staged_offline_start")
    assert not check.passed
    assert check.diagnostics == (
        "staged startup attempted a download, pull, build, or package resolution",
    )


def test_hardware_or_budget_breach_fails() -> None:
    payload = _passing_report_payload()
    payload["hardware"]["memory_bytes"] = 8 * 1024**3
    payload["measurements"]["cold_start_seconds"] = 901.0

    evaluation = _evaluate(payload)

    hardware = next(c for c in evaluation.checks if c.name == "minimum_hardware")
    budgets = next(c for c in evaluation.checks if c.name == "resource_budgets")
    assert not hardware.passed
    assert not budgets.passed
    assert budgets.diagnostics == ("measured resource or lifecycle budget exceeded",)


def test_persistence_uses_runstore_redaction(tmp_path: Path) -> None:
    profile = _profile()
    payload = _passing_report_payload()
    payload["checks"][0]["summary"] = "password=should-not-persist"
    evidence = _attested_evidence(payload)
    evaluation = evaluate_participant_qualification(profile, evidence)
    store = LocalRunStore(tmp_path / "runs")
    store.create_run("profile-proof")

    path = persist_participant_qualification(
        store,
        "profile-proof",
        evidence,
        evaluation,
    )

    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert "should-not-persist" not in path.read_text(encoding="utf-8")
    assert persisted["evaluation"]["conforming"] is True
    assert {item["outcome"] for item in persisted["evaluation"]["checks"]} == {"pass"}


def test_cli_qualifies_and_persists_a_contained_report(tmp_path: Path) -> None:
    project = _materialized_profile_project(tmp_path)
    report, public_key, _ = _write_attested_bundle(
        project,
        _passing_report_payload(),
    )

    result = CliRunner().invoke(
        lab_app,
        [
            "qualify-profile",
            "--project-dir",
            str(project),
            "--report",
            str(report),
            "--public-key",
            str(public_key),
            "--run-id",
            "profile-proof",
        ],
    )

    assert result.exit_code == 0, result.output
    summary = json.loads(result.stdout)
    assert summary["conforming"] is True
    assert (
        project
        / "runs"
        / "profile-proof"
        / "participant-profile"
        / "qualification.json"
    ).is_file()


def test_cli_fails_on_nonconforming_report(tmp_path: Path) -> None:
    project = _materialized_profile_project(tmp_path)
    payload = _passing_report_payload()
    payload["offline"]["download_attempts"] = 1
    report, public_key, _ = _write_attested_bundle(project, payload)

    result = CliRunner().invoke(
        lab_app,
        [
            "qualify-profile",
            "--project-dir",
            str(project),
            "--report",
            str(report),
            "--public-key",
            str(public_key),
            "--run-id",
            "profile-proof",
        ],
    )

    assert result.exit_code == 1
    assert json.loads(result.stdout)["conforming"] is False


def test_report_rejects_unsafe_canonical_evidence_reference(
    tmp_path: Path,
) -> None:
    payload = _passing_report_payload()
    payload["snapshot_ref"] = "../outside.json"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(
        ParticipantQualificationError,
        match="invalid participant qualification report",
    ):
        load_participant_qualification_report(
            tmp_path,
            report,
            tmp_path / "qualification-public-key.pem",
        )


def test_report_tampering_invalidates_attestation(tmp_path: Path) -> None:
    project = _materialized_profile_project(tmp_path)
    report_path, public_key_path, evidence = _write_attested_bundle(
        project,
        _passing_report_payload(),
    )
    tampered = evidence.report.model_dump(mode="json")
    tampered["offline"]["download_attempts"] = 1
    report_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(
        ParticipantQualificationError,
        match="attestation is invalid",
    ):
        load_participant_qualification_report(
            project,
            report_path,
            public_key_path,
        )


@pytest.mark.parametrize("artifact", ["run_record", "snapshot"])
def test_canonical_evidence_digest_drift_is_rejected(
    tmp_path: Path,
    artifact: str,
) -> None:
    project = _materialized_profile_project(tmp_path)
    report_path, public_key_path, evidence = _write_attested_bundle(
        project,
        _passing_report_payload(),
    )
    reference = getattr(evidence.report, f"{artifact}_ref")
    (project / reference).write_text("{}", encoding="utf-8")

    with pytest.raises(
        ParticipantQualificationError,
        match=f"{artifact.replace('_', ' ')} digest mismatch",
    ):
        load_participant_qualification_report(
            project,
            report_path,
            public_key_path,
        )


def test_run_record_and_snapshot_must_be_correlated(tmp_path: Path) -> None:
    project = _materialized_profile_project(tmp_path)
    payload = _passing_report_payload()
    report_path, public_key_path, evidence = _write_attested_bundle(project, payload)
    altered_run_record = json.loads(json.dumps(evidence.run_record))
    altered_run_record["backend_evidence"]["range_snapshot"] = {
        "containers": [],
        "networks": [],
    }
    run_record_bytes = _canonical_json_bytes(altered_run_record)
    (project / evidence.report.run_record_ref).write_bytes(run_record_bytes)
    payload["run_record_sha256"] = hashlib.sha256(run_record_bytes).hexdigest()
    payload["attestation"]["signature"] = "AA=="
    unsigned = ParticipantQualificationReport.model_validate(payload)
    payload["attestation"]["signature"] = base64.b64encode(
        _QUALIFICATION_PRIVATE_KEY.sign(
            participant_qualification_attestation_payload(unsigned)
        )
    ).decode("ascii")
    report_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(
        ParticipantQualificationError,
        match="evidence is not correlated",
    ):
        load_participant_qualification_report(
            project,
            report_path,
            public_key_path,
        )


def test_reported_surface_must_match_authenticated_snapshot() -> None:
    payload = _passing_report_payload()
    evidence = _attested_evidence(payload)
    mismatched_snapshot = {
        **evidence.snapshot,
        "containers": evidence.snapshot["containers"][:-1],
    }
    evidence = VerifiedParticipantQualification(
        evidence.report,
        evidence.run_record,
        mismatched_snapshot,
    )

    evaluation = evaluate_participant_qualification(_profile(), evidence)

    check = next(c for c in evaluation.checks if c.name == "runtime_surface")
    assert not check.passed
    assert (
        "reported actual services do not match the authenticated snapshot"
        in check.diagnostics
    )


def test_mcp_artifact_bytes_must_match_asset_lock(tmp_path: Path) -> None:
    project = _materialized_profile_project(tmp_path)
    artifact = project / "mcp" / "mcp-red" / "build" / "index.js"
    artifact.write_bytes(artifact.read_bytes() + b"\n// drift")

    with pytest.raises(
        ParticipantProfileError,
        match="profile reference digest mismatch",
    ):
        load_participant_profile(
            project,
            project / "participant-profiles" / "guided-purple-v1" / "profile.json",
        )
