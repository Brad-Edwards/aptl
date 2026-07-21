"""Tests for ACES evidence-record construction (EXP-010 / issue #752 PR 2).

The emitted record is a public ``ExperimentEvidenceRecordModel`` (validated at
construction and round-trippable through the ACES model), its identity is
derived from stable inputs only (never ``captured_at`` / ingestion order), and
a truncated/redacted/withheld record always carries the mandatory loss
disclosure the ACES model requires.
"""

from __future__ import annotations

from aces_contracts.contracts import ExperimentEvidenceRecordModel

from aptl.core.evidence.protocol import CollectorOutcome
from aptl.core.evidence.outcomes import CollectorStatus
from aptl.core.evidence.records import build_evidence_record, derive_evidence_record_id
from aptl.core.evidence.content_store import ContentInsertion
from aptl.core.experiment.capture_registry import CaptureBinding, CaptureLimits, CaptureVisibility


def _binding(**overrides) -> CaptureBinding:
    fields: dict = {
        "capture_spec_id": "cap-1", "requirement_id": "network-trace", "window_refs": ("run-window",),
        "registration_id": "aptl.collector.a", "implementation_version": "1.0.0",
        "contract_version": "experiment-capture-spec/v1", "effective_config_digest": "sha256:" + "cd" * 32,
        "channel_ref_id": "chan", "channel_ref_version": "1.0.0", "channel_kind": "evaluation-history",
        "capture_kind": "trace", "capture_scope": "network", "expected_media_types": ("application/json",),
        "required_artifact_roles": ("observation",), "sensitivity": "internal", "redaction_required": False,
        "integrity_requirements": ("sha256-digest",), "retention_policy": "retain", "loss_disclosure_required": True,
        "visibility_class": CaptureVisibility.EVALUATOR_ONLY,
        "limits": CaptureLimits(max_bytes=1024, max_artifact_count=10, max_duration_s=60),
    }
    fields.update(overrides)
    return CaptureBinding(**fields)


def _content(digest_hex="ab" * 32, size=42) -> ContentInsertion:
    return ContentInsertion(relative_path=f"evidence/{digest_hex}", digest=f"sha256:{digest_hex}", size=size, truncated=False)


def _outcome() -> CollectorOutcome:
    return CollectorOutcome(status=CollectorStatus.OK, started_at="2026-07-20T00:00:00Z", finished_at="2026-07-20T00:00:05Z", event_count=3)


def _record(**overrides):
    kwargs = dict(
        binding=_binding(), run_id="run-1", planned_trial_id="trial-1", content=_content(), outcome=_outcome(),
        captured_at="2026-07-20T00:00:05Z", sensitivity="internal", redaction_state="none",
    )
    kwargs.update(overrides)
    return build_evidence_record(**kwargs)


class TestIdentity:
    def test_same_inputs_yield_the_same_id(self):
        a = derive_evidence_record_id(run_id="r", planned_trial_id="t", binding=_binding(), content_digest="sha256:" + "ab" * 32)
        b = derive_evidence_record_id(run_id="r", planned_trial_id="t", binding=_binding(), content_digest="sha256:" + "ab" * 32)
        assert a == b

    def test_id_excludes_captured_at(self):
        first = _record(captured_at="2026-07-20T00:00:05Z")
        second = _record(captured_at="2026-07-20T23:59:59Z")
        assert first.evidence_record_id == second.evidence_record_id

    def test_id_depends_on_retained_content(self):
        a = _record(content=_content("ab" * 32))
        b = _record(content=_content("ef" * 32))
        assert a.evidence_record_id != b.evidence_record_id


class TestConformance:
    def test_record_round_trips_through_the_aces_model(self):
        record = _record()
        # exclude_none: ACES reference models distinguish an absent optional
        # field from one explicitly present as null (a capture-spec ref must
        # not CARRY ref_digest/ref_path), so canonical serialization drops
        # None-valued optionals.
        reparsed = ExperimentEvidenceRecordModel.model_validate(record.model_dump(mode="json", exclude_none=True))
        assert reparsed.evidence_record_id == record.evidence_record_id
        assert reparsed.schema_version == "experiment-evidence-record/v1"

    def test_record_carries_run_and_channel_references(self):
        record = _record()
        assert record.run_ref.ref_kind == "run"
        assert record.source_refs[0].ref_kind == "measurement-channel"
        assert record.raw_content.content_checksum.algorithm == "sha256"


class TestLossDisclosure:
    def test_withheld_record_requires_a_disclosure(self):
        record = _record(redaction_state="withheld", loss_disclosure="withheld for evaluator-only visibility")
        assert record.raw_content.loss_disclosure is not None

    def test_lossless_participant_visible_record_has_none(self):
        record = _record(redaction_state="none", loss_disclosure=None)
        assert record.raw_content.loss_disclosure is None
