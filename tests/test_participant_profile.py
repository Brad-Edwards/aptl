"""Contract tests for the versioned bounded participant profile (APP-2)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aptl.validation.participant_profile import (
    ParticipantProfileError,
    load_participant_profile,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = (
    PROJECT_ROOT / "participant-profiles" / "guided-purple-v1" / "profile.json"
)


def _write_modified_manifest(
    tmp_path: Path,
    mutate,
    *,
    copy_narrative: bool = False,
) -> Path:
    manifest = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    mutate(manifest)
    path = tmp_path / "participant-profiles" / "guided-purple-v1" / "profile.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(manifest), encoding="utf-8")
    if copy_narrative:
        source = PROFILE_PATH.with_name("narrative.json")
        path.with_name("narrative.json").write_bytes(source.read_bytes())
    return path


def test_guided_profile_resolves_existing_content_derived_surface() -> None:
    profile = load_participant_profile(PROJECT_ROOT, PROFILE_PATH)

    assert profile.manifest.profile_id == "guided-purple"
    assert profile.manifest.version == 1
    assert profile.manifest.scenario.catalog_id == "techvault-attacker-target"
    assert profile.manifest.capabilities.workbench_profiles == (
        "red",
        "guided-blue",
    )
    assert set(profile.mcp_server_ids) == {
        "aptl-red",
        "aptl-indexer",
        "aptl-wazuh",
    }
    assert set(profile.browser_refs) == {
        "aptl-guide",
        "kali-desktop",
        "soc-wazuh",
    }
    assert (
        profile.manifest.release_evidence.asset_lock_ref
        == "participant-profiles/guided-purple-v1/asset-lock.json"
    )
    assert (
        profile.manifest.release_evidence.qualification_report_ref
        == "release/qualification/guided-purple-v1.json"
    )
    assert profile.manifest.budgets.minimum_hardware.vcpus == 8
    assert profile.manifest.budgets.minimum_hardware.memory_bytes == 16 * 1024**3
    assert set(profile.expected_matrix.selected_profiles) == {
        "kali",
        "victim",
        "wazuh",
        "otel",
    }
    assert "wazuh.manager" in profile.expected_matrix.expected_services
    assert "kali" in profile.expected_matrix.expected_services
    assert "victim" in profile.expected_matrix.expected_services
    assert "suricata" not in profile.expected_matrix.expected_services
    assert "misp" not in profile.expected_matrix.expected_services
    assert "thehive" not in profile.expected_matrix.expected_services
    assert "shuffle-backend" not in profile.expected_matrix.expected_services
    locked_ids = {asset.asset_id for asset in profile.asset_lock.assets}
    assert {
        "aces-scenario",
        "compose-model",
        "mcp-red-build",
        "mcp-indexer-build",
        "mcp-wazuh-build",
        "image-kali",
        "image-victim",
        "image-wazuh-manager",
        "image-wazuh-indexer",
        "image-wazuh-dashboard",
        "image-otel-collector",
        "image-tempo",
        "image-grafana",
    } <= locked_ids
    assert {
        service
        for asset in profile.asset_lock.assets
        if asset.kind == "oci-image"
        for service in asset.services
    } == set(profile.expected_matrix.expected_services)


def test_manifest_rejects_unknown_fields(tmp_path: Path) -> None:
    path = _write_modified_manifest(
        tmp_path,
        lambda manifest: manifest.update(event_name="black-hat"),
    )

    with pytest.raises(ParticipantProfileError, match="invalid participant profile"):
        load_participant_profile(tmp_path, path)


def test_manifest_rejects_digest_drift(tmp_path: Path) -> None:
    def mutate(manifest: dict) -> None:
        manifest["narrative"]["sha256"] = "0" * 64

    path = _write_modified_manifest(tmp_path, mutate, copy_narrative=True)

    with pytest.raises(ParticipantProfileError, match="digest mismatch"):
        load_participant_profile(tmp_path, path)


def test_manifest_rejects_reference_traversal(tmp_path: Path) -> None:
    def mutate(manifest: dict) -> None:
        manifest["narrative"]["path"] = "../outside.json"

    path = _write_modified_manifest(tmp_path, mutate)

    with pytest.raises(ParticipantProfileError, match="unsafe profile reference"):
        load_participant_profile(tmp_path, path)


def test_required_narrative_operations_have_readiness_checks() -> None:
    profile = load_participant_profile(PROJECT_ROOT, PROFILE_PATH)

    required_capabilities = {
        operation.capability_id
        for operation in profile.narrative.operations
        if operation.classification == "required"
    }
    checked_capabilities = {check.capability_id for check in profile.readiness.checks}
    assert required_capabilities <= checked_capabilities
    assert {
        "red.kali-command",
        "red.ssh-authentication-attack",
        "blue.indexer-investigation",
        "blue.wazuh-investigation",
        "browser.aptl-guide",
        "browser.kali-desktop",
        "browser.soc-wazuh",
    } <= required_capabilities
    assert {
        check.subject_id
        for check in profile.readiness.checks
        if check.kind == "browser-operation"
    } == set(profile.browser_refs)


def test_participant_profiles_are_packaged_lab_assets() -> None:
    from aptl._asset_manifest import ASSET_ROOTS

    assert "participant-profiles" in ASSET_ROOTS
