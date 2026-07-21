"""Tests for the evidence-acquisition coordinator (EXP-010 / issue #752).

Exercises the lifecycle + terminal-semantics contract with fake collectors and
a real ``LocalRunStore``: distinct dispositions for success / startup-failure /
finalization-failure / truncation / accepted-degradation, reverse-order stop,
content-addressed persistence, ACES evidence records, and the never-empty-on-
error rule.
"""

from __future__ import annotations

import pytest

from aptl.core.correlation.clock import FixedClockProvider
from aptl.core.evidence.coordinator import acquire_evidence
from aptl.core.evidence.outcomes import AcquisitionDisposition, CollectorStatus
from aptl.core.evidence.protocol import CollectorOutcome
from aptl.core.experiment.capture_registry import CaptureBinding, CaptureLimits, CaptureVisibility
from aptl.core.runstore import LocalRunStore

_CLOCK = FixedClockProvider(measurement_time="2026-07-20T00:00:00Z")


def _binding(*, requirement_id="req-a", registration_id="aptl.collector.a", max_bytes=4096, **overrides) -> CaptureBinding:
    """Build a representative pinned binding for the coordinator tests."""
    fields: dict[str, object] = {
        "capture_spec_id": "cap-1",
        "requirement_id": requirement_id,
        "window_refs": ("run-window",),
        "registration_id": registration_id,
        "implementation_version": "1.0.0",
        "contract_version": "experiment-capture-spec/v1",
        "effective_config_digest": "sha256:" + "cd" * 32,
        "channel_ref_id": "chan",
        "channel_ref_version": "1.0.0",
        "channel_kind": "evaluation-history",
        "capture_kind": "trace",
        "capture_scope": "network",
        "expected_media_types": ("application/json",),
        "required_artifact_roles": ("observation",),
        "sensitivity": "internal",
        "redaction_required": False,
        "integrity_requirements": ("sha256-digest",),
        "retention_policy": "retain",
        "loss_disclosure_required": True,
        "visibility_class": CaptureVisibility.EVALUATOR_ONLY,
        "limits": CaptureLimits(max_bytes=max_bytes, max_artifact_count=10, max_duration_s=60),
    }
    fields.update(overrides)
    return CaptureBinding(**fields)


def _ok_outcome(payload: bytes = b'{"event": 1}', *, count: int = 1) -> CollectorOutcome:
    """A successful JSON capture outcome."""
    return CollectorOutcome(
        status=CollectorStatus.OK,
        started_at="2026-07-20T00:00:00Z",
        finished_at="2026-07-20T00:00:05Z",
        chunks=[payload],
        media_type="application/json",
        event_count=count,
    )


class _FakeCollector:
    """A fake collector recording start/stop order, with configurable behavior."""

    def __init__(self, registration_id, *, outcome=None, start_raises=False, stop_raises=False, log=None):
        self._registration_id = registration_id
        self._outcome = outcome if outcome is not None else _ok_outcome()
        self._start_raises = start_raises
        self._stop_raises = stop_raises
        self._log = log if log is not None else []

    @property
    def registration_id(self) -> str:
        return self._registration_id

    def start(self, context):
        self._log.append(("start", self._registration_id))
        if self._start_raises:
            raise RuntimeError("boom-start")
        return object()

    def stop(self, handle):
        self._log.append(("stop", self._registration_id))
        if self._stop_raises:
            raise RuntimeError("boom-stop")
        return self._outcome


def _acquire(tmp_path, bindings, collectors, **kwargs):
    """Run acquire_evidence against a real run store."""
    store = LocalRunStore(tmp_path / "runs")
    return acquire_evidence(
        bindings=bindings,
        collectors=collectors,
        run_store=store,
        run_id="run-1",
        planned_trial_id="trial-1",
        attempt_id="attempt-1",
        clock=_CLOCK,
        **kwargs,
    )


class TestSuccessPath:
    def test_all_ok_is_sealed_ready_with_records_and_refs(self, tmp_path):
        binding = _binding()
        result = _acquire(tmp_path, [binding], {"aptl.collector.a": _FakeCollector("aptl.collector.a")})

        assert result.disposition is AcquisitionDisposition.SEALED_READY
        assert len(result.records) == 1
        assert len(result.refs) == 1
        assert result.refs[0].requirement_id == "req-a"
        assert result.records[0].evidence_kind == "trace"

    def test_evidence_bytes_are_persisted_content_addressed(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        binding = _binding()
        result = acquire_evidence(
            bindings=[binding],
            collectors={"aptl.collector.a": _FakeCollector("aptl.collector.a")},
            run_store=store,
            run_id="run-1",
            planned_trial_id="trial-1",
            attempt_id="attempt-1",
            clock=_CLOCK,
        )
        ref = result.refs[0]
        stored = (store.get_run_path("run-1") / ref.content_uri).read_bytes()
        assert stored == b'{"event": 1}'

    def test_empty_ok_is_a_success_not_a_failure(self, tmp_path):
        binding = _binding()
        outcome = CollectorOutcome(
            status=CollectorStatus.EMPTY_OK,
            started_at="2026-07-20T00:00:00Z",
            finished_at="2026-07-20T00:00:05Z",
            chunks=[b"[]"],
            media_type="application/json",
        )
        result = _acquire(tmp_path, [binding], {"aptl.collector.a": _FakeCollector("aptl.collector.a", outcome=outcome)})
        assert result.disposition is AcquisitionDisposition.SEALED_READY


class TestTerminalSemantics:
    def test_startup_failure_is_inconclusive(self, tmp_path):
        binding = _binding()
        result = _acquire(
            tmp_path, [binding], {"aptl.collector.a": _FakeCollector("aptl.collector.a", start_raises=True)}
        )
        assert result.disposition is AcquisitionDisposition.INCONCLUSIVE
        assert result.reports[0].status is CollectorStatus.STARTUP_FAILURE

    def test_finalization_failure_invalidates_a_required_capture(self, tmp_path):
        binding = _binding()
        result = _acquire(
            tmp_path, [binding], {"aptl.collector.a": _FakeCollector("aptl.collector.a", stop_raises=True)}
        )
        assert result.disposition is AcquisitionDisposition.INVALIDATED
        assert result.reports[0].status is CollectorStatus.FINALIZATION_FAILURE
        assert result.diagnostics

    def test_missing_collector_is_inconclusive(self, tmp_path):
        binding = _binding()
        result = _acquire(tmp_path, [binding], {})
        assert result.disposition is AcquisitionDisposition.INCONCLUSIVE
        assert result.reports[0].status is CollectorStatus.SOURCE_UNAVAILABLE

    def test_over_quota_truncation_invalidates_a_required_capture(self, tmp_path):
        binding = _binding(max_bytes=4)  # smaller than the payload
        result = _acquire(tmp_path, [binding], {"aptl.collector.a": _FakeCollector("aptl.collector.a")})
        assert result.reports[0].status is CollectorStatus.TRUNCATION
        assert result.disposition is AcquisitionDisposition.INVALIDATED

    def test_accepted_degradation_truncation_is_completed_partial(self, tmp_path):
        binding = _binding(max_bytes=4, accepted_limitation="partial-window", comparability_disclosure_ref="disc:1")
        result = _acquire(tmp_path, [binding], {"aptl.collector.a": _FakeCollector("aptl.collector.a")})
        assert result.reports[0].status is CollectorStatus.TRUNCATION
        assert result.disposition is AcquisitionDisposition.COMPLETED_PARTIAL
        # The evidence record still exists, with a mandatory loss disclosure.
        assert result.records[0].raw_content.loss_disclosure is not None


class TestReverseOrderStop:
    def test_collectors_stop_in_reverse_start_order(self, tmp_path):
        log: list = []
        b1 = _binding(requirement_id="req-a", registration_id="aptl.collector.a")
        b2 = _binding(requirement_id="req-b", registration_id="aptl.collector.b")
        collectors = {
            "aptl.collector.a": _FakeCollector("aptl.collector.a", log=log),
            "aptl.collector.b": _FakeCollector("aptl.collector.b", log=log),
        }
        _acquire(tmp_path, [b1, b2], collectors)

        starts = [rid for kind, rid in log if kind == "start"]
        stops = [rid for kind, rid in log if kind == "stop"]
        assert starts == ["aptl.collector.a", "aptl.collector.b"]
        assert stops == ["aptl.collector.b", "aptl.collector.a"]


class TestRegistrationMismatch:
    def test_a_collector_whose_id_mismatches_the_binding_is_rejected(self, tmp_path):
        binding = _binding(registration_id="aptl.collector.a")
        # Wired under the right key but reporting a different id.
        result = _acquire(tmp_path, [binding], {"aptl.collector.a": _FakeCollector("aptl.collector.WRONG")})
        assert result.disposition is AcquisitionDisposition.INCONCLUSIVE
        assert any("registration-mismatch" in d.code for d in result.diagnostics)


# ---------------------------------------------------------------------------
# Limit enforcement + loss downgrade (codex review findings)
# ---------------------------------------------------------------------------


class TestLimitEnforcement:
    def test_mid_run_dropped_events_downgrade_to_loss_and_invalidate(self, tmp_path):
        binding = _binding()
        outcome = CollectorOutcome(
            status=CollectorStatus.OK, started_at="2026-07-20T00:00:00Z", finished_at="2026-07-20T00:00:00Z",
            chunks=[b'{"e": 1}'], media_type="application/json", event_count=1, dropped_count=3,
        )
        result = _acquire(tmp_path, [binding], {"aptl.collector.a": _FakeCollector("aptl.collector.a", outcome=outcome)})
        # A positive dropped_count is never silently OK / seal-ready.
        assert result.reports[0].status is CollectorStatus.MID_RUN_LOSS
        assert result.disposition is AcquisitionDisposition.INVALIDATED

    def test_over_artifact_count_is_truncation(self, tmp_path):
        binding = _binding(limits=CaptureLimits(max_bytes=8192, max_artifact_count=1, max_duration_s=60))
        outcome = CollectorOutcome(
            status=CollectorStatus.OK, started_at="2026-07-20T00:00:00Z", finished_at="2026-07-20T00:00:00Z",
            chunks=[b'[{"e":1},{"e":2},{"e":3}]'], media_type="application/json", event_count=3,
        )
        result = _acquire(tmp_path, [binding], {"aptl.collector.a": _FakeCollector("aptl.collector.a", outcome=outcome)})
        assert result.reports[0].status is CollectorStatus.TRUNCATION
        assert result.disposition is AcquisitionDisposition.INVALIDATED

    def test_over_duration_is_timeout(self, tmp_path):
        binding = _binding(limits=CaptureLimits(max_bytes=8192, max_artifact_count=10, max_duration_s=1))
        # The outcome's own start/finish span 5s, exceeding the 1s admitted duration.
        outcome = CollectorOutcome(
            status=CollectorStatus.OK, started_at="2026-07-20T00:00:00Z", finished_at="2026-07-20T00:00:05Z",
            chunks=[b'{"e": 1}'], media_type="application/json", event_count=1,
        )
        result = _acquire(tmp_path, [binding], {"aptl.collector.a": _FakeCollector("aptl.collector.a", outcome=outcome)})
        assert result.reports[0].status is CollectorStatus.TIMEOUT
        assert result.disposition is AcquisitionDisposition.INVALIDATED


class TestBindingKeyIsCaptureSpecScoped:
    def test_two_specs_sharing_a_requirement_id_do_not_collide(self, tmp_path):
        b1 = _binding(capture_spec_id="cap-1", requirement_id="shared", registration_id="aptl.collector.a")
        b2 = _binding(capture_spec_id="cap-2", requirement_id="shared", registration_id="aptl.collector.b")
        collectors = {
            "aptl.collector.a": _FakeCollector("aptl.collector.a"),
            "aptl.collector.b": _FakeCollector("aptl.collector.b"),
        }
        result = _acquire(tmp_path, [b1, b2], collectors)
        assert result.disposition is AcquisitionDisposition.SEALED_READY
        # Both bindings produced their own record — no overwrite.
        assert len(result.records) == 2
        spec_ids = {ref.capture_spec_id for ref in result.refs}
        assert spec_ids == {"cap-1", "cap-2"}


# ---------------------------------------------------------------------------
# Trial-body lifecycle + media check (test-quality review: assert documented branches)
# ---------------------------------------------------------------------------


class TestTrialBodyLifecycle:
    def test_trial_body_runs_while_collectors_are_live(self, tmp_path):
        called = []
        binding = _binding()
        _acquire(
            tmp_path, [binding], {"aptl.collector.a": _FakeCollector("aptl.collector.a")},
            trial_body=lambda: called.append("ran"),
        )
        assert called == ["ran"]

    def test_trial_body_is_skipped_when_no_collector_starts(self, tmp_path):
        called = []
        binding = _binding()
        # No collector wired -> nothing starts -> the trial body is not run.
        _acquire(tmp_path, [binding], {}, trial_body=lambda: called.append("ran"))
        assert called == []

    def test_a_raising_trial_body_still_runs_cleanup_and_captures_evidence(self, tmp_path):
        def _boom():
            raise RuntimeError("trial failed")

        binding = _binding()
        result = _acquire(
            tmp_path, [binding], {"aptl.collector.a": _FakeCollector("aptl.collector.a")}, trial_body=_boom
        )
        # The raise is swallowed; the collector is still stopped and its evidence captured.
        assert len(result.records) == 1
        assert result.disposition is AcquisitionDisposition.SEALED_READY


class TestMediaTypeCheck:
    def test_unexpected_media_type_is_a_loss_and_invalidates(self, tmp_path):
        binding = _binding()  # expects application/json
        outcome = CollectorOutcome(
            status=CollectorStatus.OK, started_at="2026-07-20T00:00:00Z", finished_at="2026-07-20T00:00:00Z",
            chunks=[b"plain text"], media_type="text/plain", event_count=1,
        )
        result = _acquire(tmp_path, [binding], {"aptl.collector.a": _FakeCollector("aptl.collector.a", outcome=outcome)})
        assert result.reports[0].status is CollectorStatus.MID_RUN_LOSS
        assert any("media-type-mismatch" in d.code for d in result.diagnostics)
        assert result.disposition is AcquisitionDisposition.INVALIDATED
