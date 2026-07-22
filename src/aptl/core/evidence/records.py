"""ACES evidence-record construction for evidence acquisition (EXP-010 / issue
#752 preflight "Evidence ownership and persistence").

Portable evidence is emitted ONLY through public ACES models
(:class:`ExperimentEvidenceRecordModel`,
:class:`ExperimentRawEvidenceContentModel`, :class:`ExperimentChecksumModel`,
:class:`ExperimentReferenceModel`) — never an APTL-local mirror. This module is
a pure builder: the coordinator has already streamed, quota'd, hashed, and
(where required) redacted the raw bytes into a content-addressed
:class:`~aptl.core.runstore.ContentInsertion`; here we only assemble the ACES
record around it.

Evidence-record identity derives from stable run / planned-trial / capture-spec
/ requirement / window / collector-config / retained-content identity via
RFC-8785 canonical JSON + SHA-256 — NEVER from ``captured_at``, filesystem
order, or ingestion order (preflight). The checksum in the record identifies
the bytes actually retained; when the source was truncated or lossy, a
mandatory ``loss_disclosure`` records it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import rfc8785
from aces_contracts.contracts import (
    ExperimentCaptureSpecReferenceModel,
    ExperimentChecksumModel,
    ExperimentEvidenceRecordModel,
    ExperimentRawEvidenceContentModel,
    ExperimentReferenceModel,
)

from aptl.core.evidence.content_store import ContentInsertion
from aptl.core.evidence.protocol import CollectorOutcome
from aptl.core.experiment.capture_registry import CaptureBinding

#: Versioned domain separator for evidence-record ID derivation (independent
#: of the trial-plan / seed domains so an algorithm revision never collides).
_EVIDENCE_ID_DOMAIN = "aptl.exp.evidence-record/v1"
_EVIDENCE_ID_PREFIX = "evidence-"
_RECORD_VERSION = "1.0.0"


@dataclass(frozen=True)
class RecordDisclosure:
    """The coordinator's decided sensitivity + redaction/loss disposition for a record.

    Bundled so :func:`build_evidence_record` stays within the parameter budget;
    every field reflects what the coordinator actually did to the bytes, never
    something inferred in the record builder.
    """

    sensitivity: str
    redaction_state: str
    loss_disclosure: str | None = None


def _bare_hex(prefixed_digest: str) -> str:
    """Return the bare hex of a ``sha256:<hex>`` prefixed digest for ACES checksum value."""
    return prefixed_digest.split(":", 1)[1]


def derive_evidence_record_id(
    *, run_id: str, planned_trial_id: str, binding: CaptureBinding, content_digest: str
) -> str:
    """Derive one evidence record's stable ID from identity inputs only.

    Excludes ``captured_at`` and any ingestion/filesystem order — two
    acquisitions of the same bytes for the same trial/requirement/window
    yield the same ID, and different retained content yields a different ID.
    """
    projection = {
        "domain": _EVIDENCE_ID_DOMAIN,
        "run_id": run_id,
        "planned_trial_id": planned_trial_id,
        "capture_spec_id": binding.capture_spec_id,
        "requirement_id": binding.requirement_id,
        "window_refs": sorted(binding.window_refs),
        "effective_config_digest": binding.effective_config_digest,
        "content_digest": content_digest,
    }
    return _EVIDENCE_ID_PREFIX + hashlib.sha256(rfc8785.dumps(projection)).hexdigest()


def _raw_content(
    content: ContentInsertion, *, event_count: int, loss_disclosure: str | None
) -> ExperimentRawEvidenceContentModel:
    """Build the raw-content block: content_uri + checksum of the RETAINED bytes + loss disclosure."""
    return ExperimentRawEvidenceContentModel(
        content_uri=content.relative_path,
        content_checksum=ExperimentChecksumModel(algorithm="sha256", value=_bare_hex(content.digest)),
        payload_summary=f"{event_count} event(s), {content.size} byte(s) retained",
        loss_disclosure=loss_disclosure,
    )


def build_evidence_record(
    *,
    binding: CaptureBinding,
    run_id: str,
    planned_trial_id: str,
    content: ContentInsertion,
    outcome: CollectorOutcome,
    captured_at: str,
    disclosure: RecordDisclosure,
) -> ExperimentEvidenceRecordModel:
    """Assemble one ACES :class:`ExperimentEvidenceRecordModel` for a captured binding.

    ``disclosure`` carries the coordinator's decided sensitivity + redaction/
    loss disposition (what it actually did to the bytes), never inferred here.
    The record references the run, the capture spec, and the source measurement
    channel the evidence satisfies; identity is derived deterministically from
    the binding + retained-content digest.
    """
    window_ref = binding.window_refs[0] if binding.window_refs else binding.requirement_id
    record_id = derive_evidence_record_id(
        run_id=run_id, planned_trial_id=planned_trial_id, binding=binding, content_digest=content.digest
    )
    return ExperimentEvidenceRecordModel(
        schema_version="experiment-evidence-record/v1",
        evidence_record_id=record_id,
        record_version=_RECORD_VERSION,
        capture_spec_ref=ExperimentCaptureSpecReferenceModel(
            ref_kind="capture-spec", ref_id=binding.capture_spec_id
        ),
        capture_requirement_ref=binding.requirement_id,
        run_ref=ExperimentReferenceModel(ref_kind="run", ref_id=run_id),
        source_refs=[
            ExperimentReferenceModel(
                ref_kind="measurement-channel",
                ref_id=binding.channel_ref_id,
                ref_version=binding.channel_ref_version,
            )
        ],
        evidence_kind=binding.capture_kind,
        captured_at=captured_at,
        capture_window_ref=window_ref,
        raw_content=_raw_content(
            content, event_count=outcome.event_count, loss_disclosure=disclosure.loss_disclosure
        ),
        sensitivity=disclosure.sensitivity,
        redaction_state=disclosure.redaction_state,
    )
