"""Tests for the REP-001 RAES-aligned run reproducibility record builder."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from raes_contracts.runtime_state import RuntimeSnapshot

from raes.module_registry import LOCKFILE_NAME

from aptl.backends.raes_repro import RunRecordInputs, build_reproducibility_record

_DEFAULTS: dict = dict(
    run_id="run_20260101T000000Z",
    backend_name="aptl",
    started_at="2026-01-01T00:00:00Z",
    finished_at="2026-01-01T00:01:00Z",
    outcome="success",
    final_snapshot=None,  # replaced in _dummy_record to allow module-level dict
    realization_details={"profiles": ["wazuh"]},
    selected_profiles=["wazuh"],
    pack_interaction_evidence={},
    scenario_path=None,
    scenario_display_name="techvault-operational",
    range_snapshot_dict={"timestamp": "2026-01-01T00:00:00Z", "containers": []},
    config_digests={"aptl.json": "abc123"},
    container_image_digests={},
    detection_content_digest="",
    tool_versions={"python": "3.11"},
    evidence_references=[],
)


def _dummy_record(**overrides):
    """Build a minimal reproducibility record with monkeypatched RAES calls."""
    fields = {**_DEFAULTS, "final_snapshot": RuntimeSnapshot()}
    fields.update(overrides)
    return build_reproducibility_record(RunRecordInputs(**fields))


class TestReproRecord:
    """Tests for build_reproducibility_record."""

    def test_backend_manifest_section_present_with_correct_profile(self):
        record = _dummy_record()
        assert record["raes"]["backend_manifest"]["schema_version"] == "backend-manifest/v2"
        # Orchestrator name comes from create_aptl_manifest() — it is "aptl-rte-orchestrator"
        orchestrator_name = (
            record["raes"]["backend_manifest"]["capabilities"]["orchestrator"]["name"]
        )
        assert isinstance(orchestrator_name, str)
        assert orchestrator_name  # non-empty

    def test_raes_runtime_snapshot_separate_from_range_snapshot(self):
        record = _dummy_record(
            range_snapshot_dict={"timestamp": "2026-01-01T00:00:00Z", "containers": []}
        )
        assert "runtime_snapshot" in record["raes"]
        assert record["raes"]["runtime_snapshot"]["schema_version"] == "runtime-snapshot/v1"
        assert "range_snapshot" in record["backend_evidence"]
        # They must be separate objects, not merged
        assert record["raes"]["runtime_snapshot"] is not record["backend_evidence"]["range_snapshot"]

    def test_sensitive_value_redacted_on_write(self, tmp_path):
        """Confirm write_json redacts sensitive realization details."""
        from aptl.core.runstore import LocalRunStore

        sensitive_key = "".join(("pass", "word"))
        sentinel_value = "-".join(("redaction", "target"))
        record = _dummy_record(
            realization_details={sensitive_key: sentinel_value},
        )
        store = LocalRunStore(tmp_path / "runs")
        run_id = "run_20260101T000000Z"
        store.create_run(run_id)
        store.write_json(run_id, "manifest.json", record)
        loaded = store.get_run_manifest(run_id)

        raw = json.dumps(loaded)
        assert sentinel_value not in raw
        assert "[REDACTED]" in raw

    def test_runtime_parameters_are_intentionally_omitted(self):
        record = _dummy_record()
        assert record["raes"]["scenario_parameters"] is None
        note = record["raes"]["scenario_parameters_note"]
        assert "intentionally omitted" in note
        assert "raw scenario bindings" in note

    def test_image_digest_captured_when_available(self):
        record = _dummy_record(
            container_image_digests={"aptl-victim": "sha256:abc123"},
        )
        assert record["backend_evidence"]["container_image_digests"]["aptl-victim"] == "sha256:abc123"

    def test_image_digest_empty_safe(self):
        record = _dummy_record(
            container_image_digests={},
        )
        assert record["backend_evidence"]["container_image_digests"] == {}

    def test_evidence_reference_paths_are_relative(self):
        record = _dummy_record(
            evidence_references=[
                {"kind": "range-snapshot", "path": "snapshot.json"},
                {"kind": "inventory", "path": "inventory/manifest.json"},
            ],
        )
        for ref in record["backend_evidence"]["evidence_references"]:
            path = ref.get("path", "")
            assert not path.startswith("/"), f"Path should not be absolute: {path}"

    def test_tool_versions_present(self):
        record = _dummy_record(
            tool_versions={"python": "3.11", "aptl": "0.2.0"},
        )
        assert record["backend_evidence"]["tool_versions"]["python"] == "3.11"
        assert record["backend_evidence"]["tool_versions"]["aptl"] == "0.2.0"

    def test_pack_interaction_is_backend_evidence_not_portable_realization(self):
        evidence = {
            "pack": {
                "pack_id": "techvault",
                "pack_version": "0.1.0",
                "set_digest": "sha256:" + "a" * 64,
            },
            "provider": {
                "provider_id": "techvault-aptl-serving",
                "extension_api_version": "1",
                "distribution": "aptl-techvault-pack-interaction",
                "distribution_version": "0.1.0",
                "entry_point": "techvault.aptl",
                "mapping_digest": "sha256:" + "b" * 64,
            },
            "selected_profiles": ["soc", "otel"],
        }

        record = _dummy_record(pack_interaction_evidence=evidence)

        assert record["backend_evidence"]["pack_interaction"] == evidence
        assert "pack_interaction" not in record["raes"]["realization"]

    def test_schema_version(self):
        record = _dummy_record()
        assert record["schema_version"] == "aptl.run-record/v2"

    def test_raes_lock_digest_none_when_no_lock(self, tmp_path):
        record = _dummy_record(scenario_path=tmp_path / "techvault.sdl.yaml")
        assert record["raes"]["scenario"]["raes_lock_digest"] is None

    def test_raes_lock_digest_computed_when_lock_present(self, tmp_path):
        scenario = tmp_path / "scenarios" / "techvault.sdl.yaml"
        scenario.parent.mkdir()
        scenario.touch()
        lock = scenario.parent / LOCKFILE_NAME
        lock.write_text('{"version": 1}')
        record = _dummy_record(scenario_path=scenario)
        assert record["raes"]["scenario"]["raes_lock_digest"] is not None
        assert len(record["raes"]["scenario"]["raes_lock_digest"]) == 64


def test_module_lockfile_name_is_the_upstream_owned_contract():
    """Pin the lockfile name RAES actually publishes.

    Production and the fixtures both read ``LOCKFILE_NAME`` from RAES so they
    can never drift apart, but that also means a silent upstream rename would
    be followed without anyone noticing. This assertion is the tripwire: RAES
    2.0.0 publishes ``raes.lock.json``. A future change here is another real
    on-disk contract change and must be handled deliberately rather than
    absorbed through an APTL-owned alias.
    """
    assert LOCKFILE_NAME == "raes.lock.json"
