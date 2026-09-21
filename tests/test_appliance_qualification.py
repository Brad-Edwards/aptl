"""Candidate qualification derivation and independent drill aggregation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aptl.appliance.models import MachineDrill
from aptl.appliance.qualification import (
    BrowserProbeReceipt,
    FailedCandidateReceipt,
    NativeClientProbeReceipt,
    QualificationMeasurementReceipt,
    aggregate_machine_drills,
    build_participant_qualification,
    record_machine_drill,
)
from aptl.appliance.seat.access import GuestRuntimeEvidence
from aptl.validation.participant_profile_models import (
    AssetLockEntry,
    ParticipantAssetLock,
    ParticipantProfileManifest,
    ParticipantReadinessSuite,
)
from aptl.validation.participant_qualification_evidence import (
    QualificationCheckEvidence,
    QualificationMeasurements,
)

_A = "a" * 64
_B = "b" * 64
_C = "c" * 64
_D = "d" * 64


def _runtime(*, qualification: bool = False) -> GuestRuntimeEvidence:
    snapshot = {
        "containers": [{"name": "aptl-kali", "status": "Up 1 minute"}],
        "networks": [{"name": "seat_participant"}],
    }
    return GuestRuntimeEvidence(
        schema_version="aptl.guest-runtime-evidence/v1",
        run_id="run-1",
        run_record={
            "schema_version": "aptl.run-record/v1",
            "outcome": "success",
            "backend_evidence": {
                "range_snapshot": snapshot,
                "selected_profiles": ["techvault-full"],
            },
        },
        snapshot=snapshot,
        qualification_checks=(
            (
                QualificationCheckEvidence(
                    check_id="runtime.live",
                    status="passed",
                    summary="runtime check passed",
                ),
            )
            if qualification
            else ()
        ),
    )


def _measurements() -> QualificationMeasurements:
    return QualificationMeasurements(
        peak_cpu_percent=10,
        peak_memory_bytes=1024,
        staged_profile_assets_bytes=2048,
        unique_image_compressed_bytes=1024,
        unique_image_expanded_bytes=2048,
        peak_runtime_disk_bytes=4096,
        cold_start_seconds=30,
        warm_start_seconds=10,
        clean_reset_seconds=5,
    )


def _probe(client: str, seat_id: str = "seat-1") -> NativeClientProbeReceipt:
    return NativeClientProbeReceipt(
        schema_version="aptl.native-client-probe/v1",
        candidate_id="aptl-1.0.0-candidate-x86_64",
        candidate_manifest_digest="sha256:" + _A,
        golden_image_digest="sha256:" + _B,
        seat_id=seat_id,
        generation=1,
        client=client,
        server_name="kali",
        tool_name="kali_info",
        client_version="1.0",
        active_response_digest="sha256:"
        + hashlib.sha256(f"{seat_id}:{client}".encode()).hexdigest(),
        live_call_passed=True,
        stale_call_rejected=True,
    )


def _write_json(path: Path, model: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(model.model_dump_json())  # type: ignore[attr-defined]


def _candidate_manifest() -> SimpleNamespace:
    artifacts = (
        SimpleNamespace(kind="participant-profile", path="profile.json"),
        SimpleNamespace(kind="participant-readiness", path="readiness.json"),
        SimpleNamespace(kind="participant-asset-lock", path="asset-lock.json"),
        SimpleNamespace(
            kind="golden-disk", path="aptl-golden.qcow2", sha256="sha256:" + _B
        ),
    )
    return SimpleNamespace(
        candidate_id="aptl-1.0.0-candidate-x86_64",
        payload_digest="sha256:" + _C,
        artifacts=artifacts,
        guest=SimpleNamespace(architecture="x86_64"),
    )


def _write_profile_documents(candidate: Path) -> ParticipantReadinessSuite:
    profile = ParticipantProfileManifest.model_validate(
        {
            "schema_version": "aptl.participant-profile/v1",
            "profile_id": "techvault-full",
            "version": 1,
            "narrative": {"path": "narrative.json", "sha256": _A},
            "scenario": {
                "catalog_id": "techvault",
                "path": "scenario.yaml",
                "sha256": _A,
            },
            "config": {"path": "aptl.json", "sha256": _A},
            "readiness": {"path": "readiness.json", "sha256": _A},
            "capabilities": {"workbench_profiles": ["red", "blue"]},
            "release_evidence": {
                "asset_lock_schema": "aptl.participant-asset-lock/v2",
                "qualification_report_schema": "aptl.participant-qualification/v1",
                "asset_lock_ref": "evidence/asset-lock.json",
                "asset_lock_sha256": _A,
                "qualification_report_ref": "evidence/qualification.json",
            },
            "budgets": {
                "minimum_hardware": {
                    "architecture": "x86_64",
                    "vcpus": 8,
                    "memory_bytes": 1024,
                    "disk_bytes": 1024,
                },
                "maximums": {
                    **_measurements().model_dump(),
                    "peak_cpu_percent": 95,
                },
            },
        }
    )
    check_rows = [
        ("host.claude", "client-transport", "claude"),
        ("host.codex", "client-transport", "codex"),
        ("full.runtime", "runtime-surface", "techvault"),
        ("full.capture", "evidence", "techvault"),
        ("full.offline", "offline-assets", "techvault"),
        ("full.resources", "resource-budget", "techvault"),
    ]
    readiness = ParticipantReadinessSuite.model_validate(
        {
            "schema_version": "aptl.participant-readiness/v1",
            "suite_id": "techvault-full",
            "version": 1,
            "checks": [
                {
                    "check_id": check_id,
                    "capability_id": check_id,
                    "kind": kind,
                    "subject_id": subject,
                    "operation_id": "verify-" + check_id,
                    "timeout_seconds": 60,
                }
                for check_id, kind, subject in check_rows
            ],
        }
    )
    lock = ParticipantAssetLock(
        schema_version="aptl.participant-asset-lock/v2",
        profile_id="techvault-full",
        profile_version=1,
        assets=(
            AssetLockEntry(
                asset_id="input-1",
                kind="input-file",
                source="fixture",
                sha256=_A,
            ),
        ),
    )
    (candidate / "profile.json").write_text(profile.model_dump_json())
    (candidate / "readiness.json").write_text(readiness.model_dump_json())
    (candidate / "asset-lock.json").write_text(lock.model_dump_json())
    return readiness


def test_build_participant_qualification_signs_real_derived_evidence(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    readiness = _write_profile_documents(candidate)
    runtime_path = tmp_path / "runtime.json"
    browser_path = tmp_path / "browser.json"
    measurement_path = tmp_path / "measurements.json"
    _write_json(runtime_path, _runtime())
    _write_json(
        browser_path,
        BrowserProbeReceipt(schema_version="aptl.browser-probe/v1", checks=()),
    )
    _write_json(
        measurement_path,
        QualificationMeasurementReceipt(
            schema_version="aptl.qualification-measurements/v1",
            measurements=_measurements(),
        ),
    )
    receipt_paths = []
    for client in ("claude", "codex"):
        path = tmp_path / f"{client}.json"
        _write_json(path, _probe(client))
        receipt_paths.append(path)
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "qualification-private.pem"
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    output = tmp_path / "evidence"
    with (
        patch(
            "aptl.appliance.qualification.verify_candidate_directory",
            return_value=(_candidate_manifest(), SimpleNamespace()),
        ),
        patch(
            "aptl.appliance.qualification._host_capacity",
            return_value=(16, 64 * 1024**3, 500 * 1024**3),
        ),
    ):
        report = build_participant_qualification(
            candidate_dir=candidate,
            candidate_public_key=tmp_path / "candidate.pem",
            runtime_evidence=runtime_path,
            browser_probe=browser_path,
            client_receipts=tuple(receipt_paths),
            measurements=measurement_path,
            qualification_private_key=private_path,
            output_dir=output,
        )

    assert tuple(item.check_id for item in report.checks) == tuple(
        item.check_id for item in readiness.checks
    )
    assert report.attestation.signature != "pending"
    assert (output / "participant-qualification.json").is_file()
    assert (output / "qualification-public.pem").is_file()


def test_record_and_aggregate_independent_machine_drills(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    golden = candidate / "aptl-golden.qcow2"
    golden.write_bytes(b"golden")
    golden.chmod(0o444)
    roots = (tmp_path / "seat-a", tmp_path / "seat-b")
    records = []
    receipt_paths = []
    all_receipts = []
    for index, root in enumerate(roots, start=1):
        generation = 3 if index == 1 else 2
        root.mkdir()
        records.append(
            SimpleNamespace(
                seat_id=f"seat-{index}",
                instance_id=f"{index:032x}",
                generation=generation,
                selected_release_id="aptl-1.0.0-candidate-x86_64",
                trust_mode="qualification-only",
                lifecycle_state="staged",
                overlay_path="overlay.qcow2",
            )
        )
        invalidated = root / "access" / "generation-1" / "invalidated"
        invalidated.parent.mkdir(parents=True)
        invalidated.write_text("seat-reset\n")
        _write_json(
            invalidated.parent / "runtime-evidence.json",
            _runtime(qualification=True),
        )
        for client in ("claude", "codex"):
            receipt = _probe(client, f"seat-{index}")
            path = tmp_path / f"seat-{index}-{client}.json"
            _write_json(path, receipt)
            receipt_paths.append(path)
            all_receipts.append(receipt)
    failed_path = tmp_path / "failed.json"
    _write_json(
        failed_path,
        FailedCandidateReceipt(
            schema_version="aptl.failed-candidate-proof/v1",
            candidate_id="aptl-1.0.0-candidate-x86_64",
            candidate_manifest_digest="sha256:" + _A,
            rejected=True,
            active_response_digests=tuple(
                item.active_response_digest for item in all_receipts
            ),
        ),
    )
    inspection = SimpleNamespace(manifest_digest="sha256:" + _A)
    with (
        patch(
            "aptl.appliance.qualification.verify_candidate_directory",
            return_value=(_candidate_manifest(), inspection),
        ),
        patch("aptl.appliance.qualification.load_seat_record", side_effect=records),
        patch("aptl.appliance.qualification.platform.machine", return_value="x86_64"),
        patch(
            "aptl.appliance.qualification._host_capacity",
            return_value=(16, 64 * 1024**3, 500 * 1024**3),
        ),
        patch("aptl.appliance.qualification._machine_id", return_value="sha256:" + _C),
    ):
        first = record_machine_drill(
            candidate_dir=candidate,
            candidate_public_key=tmp_path / "candidate.pem",
            seat_roots=roots,
            probe_receipts=tuple(receipt_paths),
            failed_candidate_receipt=failed_path,
            output=tmp_path / "machine-a.json",
        )

    second = first.model_copy(update={"machine_id": "sha256:" + _D, "seat_count": 1})
    (tmp_path / "machine-b.json").write_text(second.model_dump_json())
    with patch(
        "aptl.appliance.qualification.verify_candidate_directory",
        return_value=(_candidate_manifest(), inspection),
    ):
        aggregate = aggregate_machine_drills(
            candidate_dir=candidate,
            candidate_public_key=tmp_path / "candidate.pem",
            reports=(tmp_path / "machine-a.json", tmp_path / "machine-b.json"),
            output=tmp_path / "drill.json",
        )

    assert first.passed is True
    assert len(aggregate.machines) == 2
    assert aggregate.distinct_overlay_identities_passed is True
