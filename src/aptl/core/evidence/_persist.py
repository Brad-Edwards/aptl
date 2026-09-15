"""Per-outcome persistence for the acquisition coordinator (EXP-010 / #752).

Split out of :mod:`aptl.core.evidence.coordinator` to keep that module within
the 500-line budget and its orchestration readable. This module owns the
coordinator-side work for ONE successfully-captured collector outcome: the
media-type check, structured redaction, content-addressed persistence (with
the byte quota + truncation), and RAES evidence-record + reference assembly.
A collector never does any of this itself (preflight "Narrow collector
boundary").
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime

from raes_contracts.contracts import ExperimentEvidenceRecordModel

from aptl.core.evidence import content_store
from aptl.core.evidence.content_store import ContentInsertion
from aptl.core.evidence.outcomes import CollectorStatus
from aptl.core.evidence.protocol import CollectorOutcome
from aptl.core.evidence.records import RecordDisclosure, build_evidence_record
from aptl.core.experiment.capture_registry import CaptureBinding, CaptureVisibility
from aptl.core.runstore import LocalRunStore
from aptl.utils.redaction import redact

#: Media types with a trusted, bounded redaction path before persistence.
_JSON_MEDIA_TYPES = frozenset(
    {"application/json", "application/x-ndjson", "application/jsonl"}
)
_REDACTABLE_MEDIA_TYPES = _JSON_MEDIA_TYPES | {"text/plain"}
_REDACTION_HANDLERS = {
    # APTL's shared recursive redactor is deliberately the stronger handler:
    # it removes credentials and sensitivity-labelled values.  Both authored
    # policies are named explicitly here so an unknown policy can never be
    # treated as either one by a truthy boolean conversion.
    "redact_secrets": redact,
    "redact_sensitive": redact,
}

#: Run-relative subdirectory for content-addressed raw evidence blobs.
_EVIDENCE_SUBDIR = "evidence/blobs"

#: Run-relative subdirectory for the explicit, create-once evidence-record ledger.
_LEDGER_SUBDIR = "evidence/records"


@dataclass(frozen=True)
class EvidenceRef:
    """A verified evidence reference for the run / #447 correlation projection.

    Carries only bounded identity — record/content identity, the capture
    spec/requirement it satisfies, the producing registration, and the
    visibility class — never raw bytes or a host path.
    """

    evidence_record_id: str
    content_uri: str
    content_digest: str
    capture_spec_id: str
    requirement_id: str
    registration_id: str
    visibility_class: str

    def as_reference_dict(self) -> dict[str, str]:
        """Project to the ``backend_evidence.evidence_references`` shape OBS-002 consumes."""
        return {
            "path": self.content_uri,
            "kind": "experiment-evidence",
            "evidence_record_id": self.evidence_record_id,
            "digest": self.content_digest,
            "requirement_id": self.requirement_id,
            "visibility_class": self.visibility_class,
        }


@dataclass(frozen=True)
class ProcessedOutcome:
    """The result of persisting one success outcome.

    ``effective_status`` may downgrade the collector's reported status — e.g.
    a source reported OK but the content-store truncated it to the byte quota,
    yielding :attr:`CollectorStatus.TRUNCATION`.
    """

    record: ExperimentEvidenceRecordModel
    ref: EvidenceRef
    effective_status: CollectorStatus


def _media_type_of(outcome: CollectorOutcome, binding: CaptureBinding) -> str:
    """Return the effective media type (collector-reported, else the binding's first expected)."""
    if outcome.media_type is not None:
        return outcome.media_type
    return (
        binding.expected_media_types[0]
        if binding.expected_media_types
        else "application/octet-stream"
    )


def media_type_supported(outcome: CollectorOutcome, binding: CaptureBinding) -> bool:
    """Return whether the outcome's media type is one the requirement expects."""
    if not binding.expected_media_types:
        return True
    return _media_type_of(outcome, binding) in binding.expected_media_types


def _redact_json_bytes(
    raw: bytes, handler: Callable[[object], object]
) -> tuple[bytes, bool]:
    """Redact one JSON value; malformed input must never pass through raw."""
    parsed = json.loads(raw)
    safe = handler(parsed)
    if safe == parsed:
        return raw, False
    return json.dumps(safe, separators=(",", ":")).encode("utf-8"), True


def _prepare_bytes(
    outcome: CollectorOutcome, media_type: str, binding: CaptureBinding
) -> tuple[Sequence[bytes], str]:
    """Return the (possibly redacted) chunks + the redaction_state for persistence.

    Bound input before joining or decoding it. Reject an oversized
    document rather than retaining a truncated, potentially secret-bearing
    fragment. Opaque capture cannot satisfy a required redaction policy.
    """
    if media_type not in _REDACTABLE_MEDIA_TYPES:
        if binding.redaction_required:
            raise ValueError("capture media type has no trusted redaction adapter")
        return outcome.chunks, "none"

    raw = _consume_bounded_chunks(outcome.chunks, binding.limits.max_bytes)
    handler = _redaction_handler(binding)
    redacted, changed = _prepare_redactable_bytes(raw, media_type, handler)
    if len(redacted) > binding.limits.max_bytes:
        raise BufferError("redacted capture exceeds its admitted byte budget")
    return [redacted], ("redacted" if changed else "none")


def _consume_bounded_chunks(chunks: Sequence[bytes], max_bytes: int) -> bytes:
    """Join a complete stream without reading beyond its admitted byte budget."""

    raw = bytearray()
    for chunk in chunks:
        if len(chunk) > max_bytes - len(raw):
            raise BufferError("capture exceeds its admitted byte budget")
        raw.extend(chunk)
    return bytes(raw)


def _redaction_handler(
    binding: CaptureBinding,
) -> Callable[[object], object] | None:
    """Resolve only the binding's explicitly admitted trusted handler."""

    handler = None
    if binding.redaction_required:
        handler = _REDACTION_HANDLERS.get(binding.redaction_policy or "")
        if handler is None:
            raise ValueError("capture redaction policy has no trusted handler")
    return handler


def _prepare_redactable_bytes(
    raw: bytes,
    media_type: str,
    handler: Callable[[object], object] | None,
) -> tuple[bytes, bool]:
    """Validate and optionally redact one complete structured/text payload."""

    if media_type == "application/json":
        if handler is not None:
            prepared = _redact_json_bytes(raw, handler)
        else:
            json.loads(raw)
            prepared = raw, False
    elif media_type == "text/plain":
        prepared = _prepare_text_bytes(raw, handler)
    else:
        prepared = _prepare_json_lines(raw, handler)
    return prepared


def _prepare_text_bytes(
    raw: bytes, handler: Callable[[object], object] | None
) -> tuple[bytes, bool]:
    """Decode complete UTF-8 text and apply its trusted redaction policy."""

    text = raw.decode("utf-8")
    safe = handler(text) if handler is not None else text
    if not isinstance(safe, str):
        raise TypeError("text redaction handler returned non-text")
    return safe.encode("utf-8"), safe != text


def _prepare_json_lines(
    raw: bytes, handler: Callable[[object], object] | None
) -> tuple[bytes, bool]:
    """Validate and optionally redact every non-empty NDJSON record."""

    lines: list[tuple[bytes, bool]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        if handler is None:
            json.loads(line)
            lines.append((line, False))
        else:
            lines.append(_redact_json_bytes(line, handler))
    changed = any(was_changed for _, was_changed in lines)
    redacted = b"\n".join(line for line, _ in lines) + (b"\n" if lines else b"")
    return redacted, changed


def persist_success_outcome(
    *,
    binding: CaptureBinding,
    outcome: CollectorOutcome,
    run_store: LocalRunStore,
    run_id: str,
    planned_trial_id: str,
    captured_at: str,
) -> ProcessedOutcome:
    """Persist one captured outcome content-addressably and build its RAES record.

    Enforces the binding's byte quota during streaming (truncation flips the
    effective status and adds a mandatory loss disclosure), redacts structured
    payloads, and derives a deterministic evidence-record identity.
    ``WITHHELD``-visibility evidence keeps its bytes but is recorded as
    ``redaction_state="withheld"`` so a participant projection can drop it.
    """
    media_type = _media_type_of(outcome, binding)
    chunks, structured_redaction_state = _prepare_bytes(outcome, media_type, binding)

    content = content_store.create_content_addressed(
        run_store,
        run_id,
        chunks,
        subdir=_EVIDENCE_SUBDIR,
        max_bytes=binding.limits.max_bytes,
    )

    effective_status = _effective_status(outcome, content=content, binding=binding)

    withheld = binding.visibility_class in (
        CaptureVisibility.EVALUATOR_ONLY,
        CaptureVisibility.APPARATUS_ONLY,
    )
    redaction_state = "withheld" if withheld else structured_redaction_state
    loss_disclosure = _loss_disclosure(
        outcome, effective_status=effective_status, redaction_state=redaction_state
    )

    record = build_evidence_record(
        binding=binding,
        run_id=run_id,
        planned_trial_id=planned_trial_id,
        content=content,
        outcome=outcome,
        captured_at=captured_at,
        disclosure=RecordDisclosure(
            sensitivity=_record_sensitivity(binding.sensitivity),
            redaction_state=redaction_state,
            loss_disclosure=loss_disclosure,
        ),
    )
    # Persist the record into the explicit, create-once run-scoped evidence
    # ledger (identity is content-derived, so re-persisting is idempotent).
    content_store.create_run_json_once(
        run_store,
        run_id,
        f"{_LEDGER_SUBDIR}/{record.evidence_record_id}.json",
        record.model_dump(mode="json", exclude_none=True),
    )
    ref = EvidenceRef(
        evidence_record_id=record.evidence_record_id,
        content_uri=content.relative_path,
        content_digest=content.digest,
        capture_spec_id=binding.capture_spec_id,
        requirement_id=binding.requirement_id,
        registration_id=binding.registration_id,
        visibility_class=binding.visibility_class.value,
    )
    return ProcessedOutcome(record=record, ref=ref, effective_status=effective_status)


#: Fixed disclosure text per non-``none`` redaction state (RAES requires a
#: disclosure whenever the record is redacted or withheld).
_REDACTION_DISCLOSURES = {
    "withheld": "content withheld from participant projection (evaluator-only/apparatus-only visibility)",
    "redacted": "payload redacted at the persistence boundary (ADR-029)",
}

#: Disclosure text per limit/loss status the coordinator enforces. ``{dropped}``
#: is filled from the outcome's dropped-event count.
_STATUS_DISCLOSURES = {
    CollectorStatus.TIMEOUT: "collector exceeded the admitted duration; capture is incomplete",
    CollectorStatus.TRUNCATION: "content truncated to the admitted quota; {dropped} event(s) dropped",
    CollectorStatus.MID_RUN_LOSS: "{dropped} event(s) dropped mid-run",
}

# Capture-demand sensitivity and evidence-record sensitivity are different
# governed vocabularies. ``plain`` means the retained payload is not marked
# sensitive; the portable evidence record expresses that as ``public``.
_RECORD_SENSITIVITY = {
    "plain": "public",
    "public": "public",
    "internal": "internal",
    "restricted": "restricted",
    "redacted": "redacted",
}


def _record_sensitivity(value: str) -> str:
    """Map an admitted capture sensitivity to the portable record vocabulary."""

    try:
        return _RECORD_SENSITIVITY[value]
    except KeyError as exc:
        raise ValueError("unsupported evidence-record sensitivity") from exc


def _elapsed_seconds(outcome: CollectorOutcome) -> float:
    """Return the collector's observed run duration in seconds (0.0 if unparseable)."""
    try:
        start = datetime.fromisoformat(outcome.started_at.replace("Z", "+00:00"))
        end = datetime.fromisoformat(outcome.finished_at.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return 0.0
    return max(0.0, (end - start).total_seconds())


def _effective_status(
    outcome: CollectorOutcome, *, content: ContentInsertion, binding: CaptureBinding
) -> CollectorStatus:
    """Downgrade a reported OK to a limit/loss status the coordinator enforces.

    The binding's admitted duration, artifact-count, and byte limits are ALL
    enforced here (not just the byte quota the content store applied): an
    over-duration run is a ``TIMEOUT``, an over-byte or over-count capture is a
    ``TRUNCATION``, and any mid-run drop is a ``MID_RUN_LOSS``. Each is a hard
    failure the disposition invalidates unless the policy accepted the
    degradation — a dropped-event capture is never silently OK / seal-ready.
    """
    limits = binding.limits
    if _elapsed_seconds(outcome) > limits.max_duration_s:
        return CollectorStatus.TIMEOUT
    if content.truncated or outcome.event_count > limits.max_artifact_count:
        return CollectorStatus.TRUNCATION
    return CollectorStatus.MID_RUN_LOSS if outcome.dropped_count > 0 else outcome.status


def _loss_disclosure(
    outcome: CollectorOutcome,
    *,
    effective_status: CollectorStatus,
    redaction_state: str,
) -> str | None:
    """Return a mandatory, bounded loss/redaction disclosure, or ``None`` when there is nothing to disclose.

    A limit/loss status (timeout, truncation, mid-run loss) always discloses;
    otherwise a redacted/withheld record discloses; a lossless, un-redacted,
    participant-visible record needs none.
    """
    status_text = _STATUS_DISCLOSURES.get(effective_status)
    if status_text is not None:
        return status_text.format(dropped=outcome.dropped_count)
    return _REDACTION_DISCLOSURES.get(redaction_state)
