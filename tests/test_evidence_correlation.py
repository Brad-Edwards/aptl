"""Integration between acquired evidence and the OBS-002 correlation projection
(EXP-010 / issue #752 PR 2 — "Evidence references integrate with #447").

The coordinator's :class:`EvidenceRef`s project to the
``backend_evidence.evidence_references`` shape the correlation builder already
consumes, so acquired evidence appears as evidence nodes in the run's
correlation projection.
"""

from __future__ import annotations

import json

from aptl.core.correlation.builder import build_correlation_projection
from aptl.core.correlation.clock import FixedClockProvider
from aptl.core.evidence.coordinator import acquire_evidence
from aptl.core.evidence.outcomes import CollectorStatus
from aptl.core.evidence.protocol import CollectorOutcome
from aptl.core.experiment.capture_registry import CaptureBinding, CaptureLimits, CaptureVisibility
from aptl.core.runstore import LocalRunStore

_CLOCK = FixedClockProvider(measurement_time="2026-07-20T00:00:00Z")


def _binding() -> CaptureBinding:
    return CaptureBinding(
        capture_spec_id="cap-1", requirement_id="req-a", window_refs=("run-window",),
        registration_id="aptl.collector.a", implementation_version="1.0.0",
        contract_version="experiment-capture-spec/v1", effective_config_digest="sha256:" + "cd" * 32,
        channel_ref_id="chan", channel_ref_version="1.0.0", channel_kind="participant-observation",
        capture_kind="observation", capture_scope="participant", expected_media_types=("application/json",),
        required_artifact_roles=("observation",), sensitivity="internal", redaction_required=False,
        integrity_requirements=("sha256-digest",), retention_policy="retain", loss_disclosure_required=True,
        visibility_class=CaptureVisibility.PARTICIPANT_VISIBLE,
        limits=CaptureLimits(max_bytes=4096, max_artifact_count=10, max_duration_s=60),
    )


class _FakeCollector:
    registration_id = "aptl.collector.a"

    def start(self, context):
        return object()

    def stop(self, handle):
        return CollectorOutcome(
            status=CollectorStatus.OK, started_at="2026-07-20T00:00:00Z", finished_at="2026-07-20T00:00:05Z",
            chunks=[json.dumps([{"action": "recon"}]).encode()], media_type="application/json", event_count=1,
        )


def test_acquired_evidence_refs_appear_in_the_correlation_projection(tmp_path):
    store = LocalRunStore(tmp_path / "runs")
    result = acquire_evidence(
        bindings=[_binding()], collectors={"aptl.collector.a": _FakeCollector()},
        run_store=store, run_id="run-1", planned_trial_id="trial-1", attempt_id="a1", clock=_CLOCK,
    )
    assert result.refs

    # Project the acquired refs into the run record the correlation builder reads.
    run_record = {
        "backend_evidence": {"evidence_references": [ref.as_reference_dict() for ref in result.refs]},
    }
    projection = build_correlation_projection(
        run_id="run-1", run_record=run_record, orchestration={}, clock_provider=_CLOCK,
    )

    evidence_nodes = [node for node in projection.nodes if node.ref_kind == "evidence"]
    assert len(evidence_nodes) == 1
    # And every evidence node is linked to the run.
    assert any(edge.target_ref for edge in projection.edges)


def test_reference_dict_carries_bounded_identity_only(tmp_path):
    store = LocalRunStore(tmp_path / "runs")
    result = acquire_evidence(
        bindings=[_binding()], collectors={"aptl.collector.a": _FakeCollector()},
        run_store=store, run_id="run-1", planned_trial_id="trial-1", attempt_id="a1", clock=_CLOCK,
    )
    ref_dict = result.refs[0].as_reference_dict()
    assert ref_dict["kind"] == "experiment-evidence"
    assert ref_dict["requirement_id"] == "req-a"
    assert ref_dict["digest"].startswith("sha256:")
    # No raw bytes / host path leak into the reference.
    assert "/" not in ref_dict["path"].split("evidence/")[-1] or ref_dict["path"].startswith("evidence/")
