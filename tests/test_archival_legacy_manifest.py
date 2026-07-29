"""Version-dispatching run-manifest read adapter (EXP-009 / ADR-050 criterion E).

New terminal attempts write only the RAES ``experiment-run/v1`` record; existing
``aptl.run-record/v1|v2`` archives and the older flat shape stay readable through
this one adapter. No second permanent run model is emitted for a new attempt.
"""

from __future__ import annotations

import json

from tests.archival_fixtures import completed_context
from aptl.core.archival.coordinator import finalize_terminal_attempt
from aptl.core.archival.layout import RUN_MANIFEST_RELPATH
from aptl.core.archival.legacy_manifest import (
    is_raes_run_record,
    summarize_manifest,
)
from aptl.core.runstore import LocalRunStore


class TestRaesRecord:
    def test_sealed_raes_manifest_summarizes(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        context = completed_context()
        finalize_terminal_attempt(context, store=store)
        manifest = json.loads(
            (store.get_run_path(context.attempt_id) / RUN_MANIFEST_RELPATH).read_text()
        )
        assert is_raes_run_record(manifest)
        summary = summarize_manifest(manifest)
        assert summary.is_raes is True
        assert summary.run_id == context.attempt_id
        assert summary.scenario_id == "scenario-techvault"
        assert summary.status == "completed"
        assert summary.outcome == "succeeded"
        assert summary.duration_seconds == 30 * 60  # 00:10:00 -> 00:40:00


class TestLegacyReproducibilityRecord:
    def test_v2_record_summarizes_from_raes_section(self):
        manifest = {
            "schema_version": "aptl.run-record/v2",
            "run_id": "run-2026",
            "started_at": "2026-05-26T00:00:00Z",
            "finished_at": "2026-05-26T00:30:00Z",
            "outcome": "success",
            "raes": {"scenario": {"display_name": "TechVault"}},
        }
        assert not is_raes_run_record(manifest)
        summary = summarize_manifest(manifest)
        assert summary.is_raes is False
        assert summary.scenario_name == "TechVault"
        assert summary.outcome == "success"

    def test_v1_record_reads_aces_section(self):
        manifest = {
            "schema_version": "aptl.run-record/v1",
            "run_id": "run-old",
            "outcome": "success",
            "aces": {"scenario": {"display_name": "LegacyLab"}},
        }
        summary = summarize_manifest(manifest)
        assert summary.scenario_name == "LegacyLab"


class TestFlatRunManifest:
    def test_flat_shape_reads_top_level_fields(self):
        manifest = {
            "run_id": "test-run",
            "scenario_id": "sc1",
            "scenario_name": "Test Scenario",
            "started_at": "2026-05-26T00:00:00Z",
            "duration_seconds": 42.0,
            "flags_captured": 3,
        }
        summary = summarize_manifest(manifest)
        assert summary.is_raes is False
        assert summary.scenario_id == "sc1"
        assert summary.scenario_name == "Test Scenario"
        assert summary.duration_seconds == 42.0
        assert summary.flags_captured == 3
