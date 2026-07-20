"""Tests for ``aptl.core.correlation.persistence`` (OBS-002 Stage 2, issue #447).

Uses a real ``LocalRunStore`` against a ``tmp_path`` archive (not a fake).
Covers: ``build_and_persist_correlation`` reads ``manifest.json`` and
``orchestration/*/{result.json,history.jsonl}`` through the store's path
API, persists ``<run_id>/correlation.json`` under the run directory (never
``create_json_once``'s sibling namespace — the confirmed exporter gotcha),
round-trips the persisted content back to an equal projection, redacts a
secret-shaped value carried in a raw input, and that
``aptl.core.exporter.export_local``'s tar actually contains
``correlation.json`` end to end. Also covers the ADR-047 fail-closed
diagnostic shape for a missing/corrupt archive.
"""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest

from aptl.core.correlation.clock import FixedClockProvider
from aptl.core.correlation.models import CorrelationProjection
from aptl.core.correlation.persistence import (
    build_and_persist_correlation,
    persist_run_correlation_best_effort,
)
from aptl.core.experiment.errors import AdmissionRejection
from aptl.core.exporter import export_local
from aptl.core.runstore import LocalRunStore

_PARTICIPANT_ADDRESS = "participant.behavior.techvault.kali-victim-ssh-probe"


def _behavior_event(*, event_type: str, timestamp: str, episode_id: str, action_instance_id: str, **overrides):
    base = {
        "event_type": event_type,
        "timestamp": timestamp,
        "participant_address": _PARTICIPANT_ADDRESS,
        "episode_id": episode_id,
        "action_instance_id": action_instance_id,
        "action_contract_address": "participant.action-contract.aptl.kali-victim-ssh-probe",
        "observation_boundary_address": None,
        "observation_status": None,
        "actor_provenance": "codex-cli",
        "lifecycle_phase": None,
        "phase_realization": None,
        "admission_disposition": None,
        "operation_ref": None,
        "operation_state": None,
        "state_transition_kind": None,
        "post_state_digest": None,
        "joint_action_set_id": None,
        "realized_order": None,
        "interaction_ref": None,
        "interaction_class": "shared_state_change",
        "shared_state_refs": ["container:aptl-kali"],
        "details": {},
    }
    base.update(overrides)
    return base


def _write_run_archive(
    store: LocalRunStore,
    run_id: str,
    *,
    evidence_references: list[dict[str, object]] | None = None,
    write_orchestration: bool = True,
) -> None:
    store.create_run(run_id)
    episode_id = "episode-persist-1"
    action_id = "participant.behavior.techvault.kali-victim-ssh-probe.persist1"
    attempted = _behavior_event(
        event_type="action_attempted",
        timestamp="2026-01-01T00:00:00Z",
        episode_id=episode_id,
        action_instance_id=action_id,
    )
    observed = _behavior_event(
        event_type="observation_emitted",
        timestamp="2026-01-01T00:00:05Z",
        episode_id=episode_id,
        action_instance_id=action_id,
    )
    runtime_snapshot = {
        "participant_episode_results": {
            _PARTICIPANT_ADDRESS: {"episode_id": episode_id, "status": "running"}
        },
        "participant_episode_history": {},
        "participant_behavior_history": {_PARTICIPANT_ADDRESS: [attempted, observed]},
        "evaluation_results": {
            "evaluation.objective.techvault.foothold": {
                "outcome": "succeeded",
                "started_at": "2026-01-01T00:00:01Z",
                "updated_at": "2026-01-01T00:00:06Z",
            }
        },
    }
    manifest = {
        "schema_version": "aptl.run-record/v1",
        "run_id": run_id,
        "aces": {"runtime_snapshot": runtime_snapshot, "realization": {}},
        "backend_evidence": {"evidence_references": evidence_references or []},
    }
    store.write_json(run_id, "manifest.json", manifest)

    if write_orchestration:
        result = {
            "state_schema_version": "aces-workflow-state/v1",
            "workflow_status": "succeeded",
            "run_id": "workflow-internal-deadbeefdeadbeefdeadbeefdeadbeef",
            "started_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:02Z",
            "terminal_reason": "completed",
            "compensation_status": "not_required",
            "compensation_started_at": None,
            "compensation_updated_at": None,
            "compensation_failures": [],
            "steps": {},
        }
        store.write_json(run_id, "orchestration/runtime_apply_orchestration/result.json", result)
        history_events = [
            {
                "event_type": "workflow_started",
                "timestamp": "2026-01-01T00:00:00Z",
                "step_name": None,
                "branch_name": None,
                "join_step": None,
                "outcome": None,
                "details": {},
            },
            {
                "event_type": "workflow_completed",
                "timestamp": "2026-01-01T00:00:02Z",
                "step_name": None,
                "branch_name": None,
                "join_step": None,
                "outcome": None,
                "details": {"reason": "completed"},
            },
        ]
        for event in history_events:
            store.append_jsonl(run_id, "orchestration/runtime_apply_orchestration/history.jsonl", [event])


def _clock_provider() -> FixedClockProvider:
    return FixedClockProvider(measurement_time="2026-01-01T00:10:00Z")


# ---------------------------------------------------------------------------
# build_and_persist_correlation — happy path.
# ---------------------------------------------------------------------------


class TestBuildAndPersistCorrelation:
    def test_persists_correlation_json_under_the_run_directory(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        run_id = "run-persist-1"
        _write_run_archive(store, run_id)

        build_and_persist_correlation(run_id=run_id, run_store=store, clock_provider=_clock_provider())

        correlation_path = tmp_path / "runs" / run_id / "correlation.json"
        assert correlation_path.is_file()

    def test_does_not_use_create_json_once_sibling_namespace(self, tmp_path):
        """The confirmed exporter gotcha: `create_json_once` writes to
        `<base_dir>/<namespace>/...`, a SIBLING of the run tree, not under
        it. Assert nothing new landed outside `<base_dir>/<run_id>/`."""
        store = LocalRunStore(tmp_path / "runs")
        run_id = "run-persist-2"
        _write_run_archive(store, run_id)
        base_dir = tmp_path / "runs"
        before = {p.relative_to(base_dir) for p in base_dir.rglob("*") if p.is_file()}

        build_and_persist_correlation(run_id=run_id, run_store=store, clock_provider=_clock_provider())

        after = {p.relative_to(base_dir) for p in base_dir.rglob("*") if p.is_file()}
        new_files = after - before
        assert new_files == {Path(run_id) / "correlation.json"}

    def test_returned_projection_matches_the_persisted_file(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        run_id = "run-persist-3"
        _write_run_archive(store, run_id)

        projection = build_and_persist_correlation(
            run_id=run_id, run_store=store, clock_provider=_clock_provider()
        )

        correlation_path = tmp_path / "runs" / run_id / "correlation.json"
        persisted = json.loads(correlation_path.read_text(encoding="utf-8"))
        assert persisted == projection.to_canonical_dict()

    def test_persisted_content_round_trips_to_an_equal_projection(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        run_id = "run-persist-4"
        _write_run_archive(store, run_id)

        projection = build_and_persist_correlation(
            run_id=run_id, run_store=store, clock_provider=_clock_provider()
        )

        correlation_path = tmp_path / "runs" / run_id / "correlation.json"
        persisted = json.loads(correlation_path.read_text(encoding="utf-8"))
        reloaded = CorrelationProjection.from_canonical_dict(persisted)

        assert reloaded.projection_digest == projection.projection_digest
        assert reloaded.canonical_bytes == projection.canonical_bytes
        assert set(reloaded.nodes) == set(projection.nodes)
        assert set(reloaded.edges) == set(projection.edges)

    def test_finds_the_expected_association_methods_from_a_real_archive(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        run_id = "run-persist-5"
        _write_run_archive(store, run_id)

        projection = build_and_persist_correlation(
            run_id=run_id, run_store=store, clock_provider=_clock_provider()
        )
        methods = {e.association_method.value for e in projection.edges}
        assert "explicit_identifier" in methods
        assert "declared_rule" in methods
        assert "time_window_candidate" in methods


# ---------------------------------------------------------------------------
# Redaction.
# ---------------------------------------------------------------------------


class TestRedaction:
    def test_secret_shaped_value_in_an_external_evidence_reference_is_absent_from_the_persisted_file(
        self, tmp_path
    ):
        store = LocalRunStore(tmp_path / "runs")
        run_id = "run-persist-secret-1"
        _write_run_archive(
            store,
            run_id,
            evidence_references=[
                {"kind": "pcap", "note": "password=hunter2-super-secret-value"}
            ],
        )

        build_and_persist_correlation(run_id=run_id, run_store=store, clock_provider=_clock_provider())

        correlation_path = tmp_path / "runs" / run_id / "correlation.json"
        raw_text = correlation_path.read_text(encoding="utf-8")
        assert "hunter2-super-secret-value" not in raw_text
        assert "password=" not in raw_text


# ---------------------------------------------------------------------------
# Export sweep.
# ---------------------------------------------------------------------------


class TestExportIncludesCorrelation:
    def test_exported_tar_contains_correlation_json(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        run_id = "run-persist-export-1"
        _write_run_archive(store, run_id)
        build_and_persist_correlation(run_id=run_id, run_store=store, clock_provider=_clock_provider())

        output_dir = tmp_path / "exports"
        archive_path = export_local(store, run_id, output_dir)

        with tarfile.open(archive_path, "r:gz") as tar:
            names = tar.getnames()
        assert f"{run_id}/correlation.json" in names


# ---------------------------------------------------------------------------
# Fail-closed diagnostics.
# ---------------------------------------------------------------------------


class TestFailClosedDiagnostics:
    def test_missing_manifest_raises_admission_rejection(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        run_id = "run-persist-missing-1"
        store.create_run(run_id)  # no manifest.json written

        with pytest.raises(AdmissionRejection) as exc_info:
            build_and_persist_correlation(run_id=run_id, run_store=store, clock_provider=_clock_provider())
        assert len(exc_info.value.diagnostics) == 1
        assert exc_info.value.diagnostics[0].domain == "obs-002-correlation"

    def test_malformed_orchestration_history_raises_admission_rejection(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        run_id = "run-persist-malformed-1"
        _write_run_archive(store, run_id, write_orchestration=False)
        run_dir = tmp_path / "runs" / run_id
        (run_dir / "orchestration" / "runtime_apply_orchestration").mkdir(parents=True)
        (run_dir / "orchestration" / "runtime_apply_orchestration" / "history.jsonl").write_text(
            "{not valid json\n"
        )

        with pytest.raises(AdmissionRejection):
            build_and_persist_correlation(run_id=run_id, run_store=store, clock_provider=_clock_provider())

    def test_diagnostic_message_never_leaks_a_secret_shaped_value(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        run_id = "run-persist-missing-2"
        store.create_run(run_id)

        with pytest.raises(AdmissionRejection) as exc_info:
            build_and_persist_correlation(run_id=run_id, run_store=store, clock_provider=_clock_provider())
        for diag in exc_info.value.diagnostics:
            assert "password=" not in diag.message


# ---------------------------------------------------------------------------
# Fuzz (property-based) — persistence-layer determinism.
# ---------------------------------------------------------------------------

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402


@pytest.mark.fuzz
class TestFuzzPersistenceDeterminism:
    @given(run_suffix=st.integers(min_value=0, max_value=10_000))
    @settings(max_examples=15, deadline=None)
    def test_repeated_persist_of_the_same_archive_is_byte_identical(self, tmp_path_factory, run_suffix):
        tmp_path = tmp_path_factory.mktemp(f"persist-fuzz-{run_suffix}")
        store = LocalRunStore(tmp_path / "runs")
        run_id = f"run-fuzz-{run_suffix}"
        _write_run_archive(store, run_id)

        first = build_and_persist_correlation(run_id=run_id, run_store=store, clock_provider=_clock_provider())
        second = build_and_persist_correlation(run_id=run_id, run_store=store, clock_provider=_clock_provider())

        assert first.canonical_bytes == second.canonical_bytes


class TestPersistRunCorrelationBestEffort:
    """The run-finalization wiring (lab.py `_write_run_record`): build+persist
    is best-effort — it emits ``<run_id>/correlation.json`` on success and
    NEVER raises (returns None) when the archive is missing/unreadable, so an
    audit-projection failure can never fail the run itself (OBS-002:
    correlation is layered over the already-sealed run record)."""

    def test_success_emits_correlation_json_and_returns_projection(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        run_id = "run-besteffort-ok"
        _write_run_archive(store, run_id)
        projection = persist_run_correlation_best_effort(
            run_id=run_id, run_store=store, clock_provider=_clock_provider()
        )
        assert isinstance(projection, CorrelationProjection)
        assert (store.get_run_path(run_id) / "correlation.json").is_file()

    def test_missing_manifest_returns_none_and_does_not_raise(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        run_id = "run-besteffort-nomanifest"
        store.create_run(run_id)  # no manifest.json written
        # build_and_persist_correlation would raise AdmissionRejection here;
        # the best-effort wrapper must swallow it and return None instead.
        result = persist_run_correlation_best_effort(
            run_id=run_id, run_store=store, clock_provider=_clock_provider()
        )
        assert result is None
        assert not (store.get_run_path(run_id) / "correlation.json").exists()

    def test_defaults_to_system_clock_when_none_supplied(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        run_id = "run-besteffort-defaultclock"
        _write_run_archive(store, run_id)
        projection = persist_run_correlation_best_effort(run_id=run_id, run_store=store)
        assert isinstance(projection, CorrelationProjection)
        assert (store.get_run_path(run_id) / "correlation.json").is_file()
