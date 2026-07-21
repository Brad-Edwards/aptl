"""Security tests for evidence acquisition (EXP-010 / issue #752 PR 2).

Proves control-plane secrets are redacted out of the stored bytes, that
participant-hidden / evaluator-only evidence never enters the participant
projection, and that hostile filesystem inputs (symlinked components) fail
closed at the content-addressed persistence boundary.
"""

from __future__ import annotations

import json

import pytest

from aptl.core.correlation.clock import FixedClockProvider
from aptl.core.evidence._persist import EvidenceRef
from aptl.core.evidence.content_store import create_content_addressed
from aptl.core.evidence.coordinator import acquire_evidence
from aptl.core.evidence.outcomes import AcquisitionDisposition, CollectorStatus
from aptl.core.evidence.protocol import CollectorOutcome
from aptl.core.evidence.visibility import project_for_participant
from aptl.core.experiment.capture_registry import CaptureBinding, CaptureLimits, CaptureVisibility
from aptl.core.runstore import LocalRunStore
from aptl.utils.pathsafe import PathContainmentError

_CLOCK = FixedClockProvider(measurement_time="2026-07-20T00:00:00Z")
_SECRET = "sk-live-super-secret-token-abcdef1234567890"


def _binding(*, visibility=CaptureVisibility.PARTICIPANT_VISIBLE, **overrides) -> CaptureBinding:
    fields: dict = {
        "capture_spec_id": "cap-1", "requirement_id": "req-a", "window_refs": ("run-window",),
        "registration_id": "aptl.collector.a", "implementation_version": "1.0.0",
        "contract_version": "experiment-capture-spec/v1", "effective_config_digest": "sha256:" + "cd" * 32,
        "channel_ref_id": "chan", "channel_ref_version": "1.0.0", "channel_kind": "participant-observation",
        "capture_kind": "observation", "capture_scope": "participant", "expected_media_types": ("application/json",),
        "required_artifact_roles": ("observation",), "sensitivity": "internal", "redaction_required": True,
        "integrity_requirements": ("sha256-digest",), "retention_policy": "retain", "loss_disclosure_required": True,
        "visibility_class": visibility,
        "limits": CaptureLimits(max_bytes=8192, max_artifact_count=10, max_duration_s=60),
    }
    fields.update(overrides)
    return CaptureBinding(**fields)


class _FakeCollector:
    def __init__(self, registration_id, outcome):
        self._rid = registration_id
        self._outcome = outcome

    @property
    def registration_id(self):
        return self._rid

    def start(self, context):
        return object()

    def stop(self, handle):
        return self._outcome


def _json_outcome(records):
    return CollectorOutcome(
        status=CollectorStatus.OK, started_at="2026-07-20T00:00:00Z", finished_at="2026-07-20T00:00:05Z",
        chunks=[json.dumps(records).encode("utf-8")], media_type="application/json", event_count=len(records),
    )


class TestSecretRedaction:
    def test_control_plane_secret_is_redacted_from_stored_bytes(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        binding = _binding()
        outcome = _json_outcome([{"user": "admin", "api_key": _SECRET}])
        result = acquire_evidence(
            bindings=[binding], collectors={"aptl.collector.a": _FakeCollector("aptl.collector.a", outcome)},
            run_store=store, run_id="run-1", planned_trial_id="trial-1", attempt_id="a1", clock=_CLOCK,
        )
        stored = (store.get_run_path("run-1") / result.refs[0].content_uri).read_bytes()
        assert _SECRET.encode() not in stored
        assert result.records[0].redaction_state == "redacted"

    def test_redacted_record_carries_a_disclosure(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        binding = _binding()
        outcome = _json_outcome([{"token": _SECRET}])
        result = acquire_evidence(
            bindings=[binding], collectors={"aptl.collector.a": _FakeCollector("aptl.collector.a", outcome)},
            run_store=store, run_id="run-1", planned_trial_id="trial-1", attempt_id="a1", clock=_CLOCK,
        )
        assert result.records[0].raw_content.loss_disclosure is not None


class TestVisibilityProjection:
    def _ref(self, visibility_class):
        return EvidenceRef(
            evidence_record_id="e1", content_uri="evidence/x", content_digest="sha256:" + "ab" * 32,
            capture_spec_id="cap-1", requirement_id="req-a", registration_id="aptl.collector.a",
            visibility_class=visibility_class,
        )

    def test_evaluator_only_and_apparatus_only_are_dropped(self):
        refs = [
            self._ref("participant-visible"),
            self._ref("disclosed"),
            self._ref("evaluator-only"),
            self._ref("apparatus-only"),
        ]
        visible = project_for_participant(refs)
        classes = {r.visibility_class for r in visible}
        assert classes == {"participant-visible", "disclosed"}

    def test_evaluator_only_evidence_never_enters_the_participant_projection(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        binding = _binding(visibility=CaptureVisibility.EVALUATOR_ONLY)
        outcome = _json_outcome([{"detection": 1}])
        result = acquire_evidence(
            bindings=[binding], collectors={"aptl.collector.a": _FakeCollector("aptl.collector.a", outcome)},
            run_store=store, run_id="run-1", planned_trial_id="trial-1", attempt_id="a1", clock=_CLOCK,
        )
        assert result.disposition is AcquisitionDisposition.SEALED_READY
        assert project_for_participant(result.refs) == ()


class TestHostilePersistence:
    def test_symlinked_evidence_component_fails_closed(self, tmp_path):
        store = LocalRunStore(tmp_path / "runs")
        run_dir = store.create_run("run-1")
        # Plant a symlink where the evidence subtree would be created.
        outside = tmp_path / "outside"
        outside.mkdir()
        (run_dir / "evidence").symlink_to(outside, target_is_directory=True)

        with pytest.raises(PathContainmentError):
            create_content_addressed(store, "run-1", [b"x"], subdir="evidence/blobs", max_bytes=64)
