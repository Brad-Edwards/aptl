"""Reference-driven collection of a run's ready-to-seal closure entries.

Enumerates the closure by REFERENCE (the evidence ledger, each record's declared
blob, and the known backend-evidence roots), never by scanning the run
directory, and validates that every run-scoped artifact belongs to the requested
run. Every source is read through :mod:`aptl.utils.pathsafe` (no-follow,
one-open). Shared content-addressed blobs coalesce into one member; conflicting
artifacts sharing a bundle path are dropped and disclosed.
"""

from __future__ import annotations

import json
from pathlib import Path

from raes_contracts.contracts import ExperimentEvidenceRecordModel

from aptl.core.evidence_bundle import codes
from aptl.core.evidence_bundle._io import (
    SourceMissing,
    SourceRejected,
    hash_source,
    read_source,
)
from aptl.core.evidence_bundle.errors import BundleError
from aptl.core.evidence_bundle.limits import BundleLimits
from aptl.core.evidence_bundle.models import (
    ClosureEntry,
    ClosureLimitation,
    Disclosures,
)
from aptl.utils import pathsafe

_MEDIA_JSON = "application/json"
_MEDIA_OCTET = "application/octet-stream"
_EVIDENCE_LEDGER_DIR = "evidence/records"

# Known backend-evidence roots: (run-relative source, bundle path, role,
# contract id, whether absence is a recorded limitation).
_BACKEND_ROOTS: tuple[tuple[str, str, str, str | None, bool], ...] = (
    ("manifest.json", "backend/run-manifest.json", "run-manifest", None, True),
    (
        "provenance/run-provenance.json",
        "backend/run-provenance.json",
        "run-provenance",
        "aptl.run-provenance/v1",
        True,
    ),
    (
        "provenance/startup-provenance.json",
        "backend/startup-provenance.json",
        "startup-provenance",
        "aptl.run-provenance/v1",
        False,
    ),
    (
        "correlation.json",
        "backend/correlation.json",
        "correlation",
        "aptl-correlation/v1",
        True,
    ),
)


def _declared_run_id(body: bytes) -> str | None:
    """Return the top-level ``run_id`` of a backend JSON artifact, or None."""
    try:
        document = json.loads(body)
    except ValueError:
        return None
    return document.get("run_id") if isinstance(document, dict) else None


def collect_backend_evidence(
    run_dir: Path,
    run_id: str,
    entries: list[ClosureEntry],
    limitations: list[ClosureLimitation],
    limits: BundleLimits,
) -> None:
    """Add each known backend-evidence root that belongs to this run, disclosing gaps."""
    for relpath, bundle_path, role, contract_id, expected in _BACKEND_ROOTS:
        try:
            digest, size, body = read_source(
                run_dir, relpath, max_bytes=limits.max_member_bytes
            )
        except SourceMissing:
            if expected:
                limitations.append(
                    ClosureLimitation(codes.MISSING_SOURCE, f"{role} absent", relpath)
                )
            continue
        except SourceRejected as exc:
            limitations.append(
                ClosureLimitation(codes.REJECTED_SOURCE, exc.detail, relpath)
            )
            continue
        # Run-join: a run-scoped root that declares a different run is stale or
        # copied in, not part of THIS run's closure, so it is excluded and
        # disclosed rather than misrepresented as belonging to the export.
        if _declared_run_id(body) != run_id:
            limitations.append(
                ClosureLimitation(
                    codes.REJECTED_SOURCE,
                    f"{role} does not belong to this run",
                    relpath,
                )
            )
            continue
        entries.append(
            ClosureEntry(
                bundle_path=bundle_path,
                logical_role=role,
                classification="backend-evidence",
                contract_id=contract_id,
                source_ref=relpath,
                digest=digest,
                size=size,
                media_type=_MEDIA_JSON,
                source_run_relpath=relpath,
            )
        )


def collect_evidence(
    run_dir: Path,
    run_id: str,
    entries: list[ClosureEntry],
    limitations: list[ClosureLimitation],
    limits: BundleLimits,
) -> None:
    """Enumerate the evidence ledger and collect each record (and its blob)."""
    try:
        names = pathsafe.listdir_contained_nofollow(run_dir, _EVIDENCE_LEDGER_DIR)
    except pathsafe.PathContainmentError as exc:
        code = (
            codes.MISSING_SOURCE
            if exc.reason == pathsafe.REASON_NOT_FOUND
            else codes.REJECTED_SOURCE
        )
        limitations.append(
            ClosureLimitation(code, "evidence ledger unavailable", _EVIDENCE_LEDGER_DIR)
        )
        return

    record_names = [name for name in names if name.endswith(".json")]
    if not record_names:
        limitations.append(
            ClosureLimitation(
                codes.MISSING_SOURCE, "evidence ledger empty", _EVIDENCE_LEDGER_DIR
            )
        )
        return
    if len(record_names) > limits.max_entries:
        raise BundleError(
            codes.REJECTED_SOURCE, "evidence ledger exceeds the entry limit"
        )

    for name in record_names:
        _collect_one_record(run_dir, run_id, name, entries, limitations, limits)


def _read_and_validate_record(
    run_dir: Path, relpath: str, limits: BundleLimits
) -> tuple[
    tuple[str, int, ExperimentEvidenceRecordModel] | None, ClosureLimitation | None
]:
    """Read and RAES-validate one ledger record, or return a disclosing limitation."""
    error: ClosureLimitation | None = None
    try:
        digest, size, body = read_source(
            run_dir, relpath, max_bytes=limits.max_member_bytes
        )
        record = ExperimentEvidenceRecordModel.model_validate_json(body)
    except SourceMissing:
        error = ClosureLimitation(
            codes.MISSING_SOURCE, "evidence record absent", relpath
        )
    except SourceRejected as exc:
        error = ClosureLimitation(codes.REJECTED_SOURCE, exc.detail, relpath)
    except ValueError:
        error = ClosureLimitation(
            codes.INVALID_RECORD, "record failed RAES validation", relpath
        )
    if error is not None:
        return None, error
    return (digest, size, record), None


def _collect_one_record(
    run_dir: Path,
    run_id: str,
    name: str,
    entries: list[ClosureEntry],
    limitations: list[ClosureLimitation],
    limits: BundleLimits,
) -> None:
    """Read, run-join, and append one ledger record plus its referenced blob."""
    relpath = f"{_EVIDENCE_LEDGER_DIR}/{name}"
    parsed, limitation = _read_and_validate_record(run_dir, relpath, limits)
    if limitation is not None:
        limitations.append(limitation)
        return
    digest, size, record = parsed

    # Run-join: a record whose run_ref names a different run is not part of this
    # run's closure. Exclude and disclose rather than misattributing it.
    if record.run_ref.ref_id != run_id:
        limitations.append(
            ClosureLimitation(
                codes.REJECTED_SOURCE, "record does not belong to this run", relpath
            )
        )
        return

    disclosures = Disclosures(
        sensitivity=record.sensitivity,
        redaction_state=record.redaction_state,
        loss_disclosure=record.raw_content.loss_disclosure,
    )
    entries.append(
        ClosureEntry(
            bundle_path=f"{_EVIDENCE_LEDGER_DIR}/{record.evidence_record_id}.json",
            logical_role="evidence-record",
            classification="canonical",
            contract_id=record.schema_version,
            source_ref=record.evidence_record_id,
            digest=digest,
            size=size,
            media_type=_MEDIA_JSON,
            source_run_relpath=relpath,
            disclosures=disclosures,
            provenance_ref=(
                record.provenance_refs[0] if record.provenance_refs else None
            ),
        )
    )
    _collect_blob(run_dir, record, disclosures, entries, limitations, limits)


def _collect_blob(
    run_dir: Path,
    record: ExperimentEvidenceRecordModel,
    disclosures: Disclosures,
    entries: list[ClosureEntry],
    limitations: list[ClosureLimitation],
    limits: BundleLimits,
) -> None:
    """Verify and append the record's referenced blob, or disclose its absence."""
    blob_uri = record.raw_content.content_uri
    try:
        digest, size = hash_source(run_dir, blob_uri, max_bytes=limits.max_member_bytes)
    except SourceMissing:
        limitations.append(
            ClosureLimitation(codes.MISSING_SOURCE, "referenced blob absent", blob_uri)
        )
        return
    except SourceRejected as exc:
        limitations.append(
            ClosureLimitation(codes.REJECTED_SOURCE, exc.detail, blob_uri)
        )
        return

    declared = record.raw_content.content_checksum.value
    if declared and digest != f"sha256:{declared}":
        limitations.append(
            ClosureLimitation(
                codes.REJECTED_SOURCE,
                "blob digest disagrees with record checksum",
                blob_uri,
            )
        )
        return

    entries.append(
        ClosureEntry(
            bundle_path=f"evidence/blobs/{digest.split(':', 1)[1]}",
            logical_role="evidence-blob",
            classification="canonical",
            contract_id=None,
            source_ref=blob_uri,
            digest=digest,
            size=size,
            media_type=_MEDIA_OCTET,
            source_run_relpath=blob_uri,
            disclosures=disclosures,
        )
    )


def coalesce(
    entries: list[ClosureEntry],
) -> tuple[list[ClosureEntry], list[ClosureLimitation]]:
    """Coalesce content-addressed entries that share one normalized bundle path.

    Several records legitimately reference the same content-addressed blob (and a
    record may be reachable through more than one ledger file). Those resolve to
    one identical bundle entry, so they are merged into a single archive member.
    Two DIFFERENT artifacts claiming the same bundle path is a conflict: both are
    dropped and disclosed rather than emitting a duplicate that would fail the
    archive's uniqueness check.
    """
    kept: dict[str, ClosureEntry] = {}
    order: list[str] = []
    conflicted: set[str] = set()
    limitations: list[ClosureLimitation] = []
    for entry in entries:
        path = entry.bundle_path
        if path in conflicted:
            continue
        existing = kept.get(path)
        if existing is None:
            kept[path] = entry
            order.append(path)
        elif (
            existing.digest,
            existing.size,
            existing.logical_role,
            existing.contract_id,
        ) != (entry.digest, entry.size, entry.logical_role, entry.contract_id):
            conflicted.add(path)
            limitations.append(
                ClosureLimitation(
                    codes.REJECTED_SOURCE,
                    "conflicting artifacts share one bundle path",
                    path,
                )
            )
    result = [kept[path] for path in order if path not in conflicted]
    return result, limitations


__all__ = ["collect_backend_evidence", "collect_evidence", "coalesce"]
