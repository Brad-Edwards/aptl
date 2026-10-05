"""Read-back qualification of a retained full-run transcript."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from aptl.core.evidence.coordinator import AcquisitionResult
from aptl.core.evidence.outcomes import (
    AcquisitionDisposition,
    CollectorStatus,
    STATUS_DIAGNOSTIC_CODES,
    capture_diagnostic,
)
from aptl.core.evidence_bundle._io import SourceMissing, SourceRejected, read_source
from aptl.core.experiment.capture_registry import CaptureBinding
from aptl.core.runstore import LocalRunStore


def qualify_retained_transcript(
    result: AcquisitionResult,
    runtime_adapter: object,
    payload: object,
    binding: CaptureBinding,
    store_base: Path,
    run_id: str,
) -> AcquisitionResult:
    """Read back the retained blob and turn semantic failure into a typed outcome."""
    validator = getattr(runtime_adapter, "validate_retained_transcript", None)
    try:
        if not callable(validator) or len(result.records) != 1:
            raise ValueError("transcript validator unavailable")
        record = result.records[0]
        retained_digest, _, body = read_source(
            LocalRunStore(store_base).get_run_path(run_id),
            record.raw_content.content_uri,
            max_bytes=binding.limits.max_bytes,
        )
        if retained_digest != f"sha256:{record.raw_content.content_checksum.value}":
            raise ValueError("retained transcript checksum mismatch")
        sessions = payload["sessions"]  # type: ignore[index]
        validator(
            json.loads(body),
            expected_entries=len(payload["expected_session_ids"]),  # type: ignore[index]
            expected_frames=sum(len(item["frames"]) for item in sessions),
        )
    except (KeyError, TypeError, ValueError, SourceMissing, SourceRejected):
        return _invalid_retained_transcript_result(result)
    return result


def _invalid_retained_transcript_result(result: AcquisitionResult) -> AcquisitionResult:
    """Report a fixed redacted failure without exposing transcript content."""
    status = CollectorStatus.FINALIZATION_FAILURE
    code = STATUS_DIAGNOSTIC_CODES[status]
    return AcquisitionResult(
        disposition=AcquisitionDisposition.INVALIDATED,
        records=result.records,
        refs=result.refs,
        reports=tuple(
            replace(report, status=status, diagnostic_code=code)
            for report in result.reports
        ),
        diagnostics=result.diagnostics
        + (
            capture_diagnostic(
                code, "transcript", "retained transcript failed validation"
            ),
        ),
    )
