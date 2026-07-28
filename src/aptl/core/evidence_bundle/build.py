"""Top-level orchestration for building a portable evidence bundle.

Ties the four separated concerns together: verified closure -> published RAES
schemas -> loss-accounted projections -> packaging envelope -> deterministic
archive -> local self-verification. Never mutates the source run; never treats a
readiness state as a verified seal; always exports partial/invalid runs with
their limitations intact.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from aptl.core.evidence_bundle import _io, codes
from aptl.core.evidence_bundle.archive import (
    ArchiveResult,
    BundleMember,
    write_bundle_archive,
)
from aptl.core.evidence_bundle.closure import (
    ClosureLimitation,
    ClosureSource,
    SealScope,
    SealVerifier,
    VerifiedClosure,
    build_closure,
)
from aptl.core.evidence_bundle.envelope import BundleEnvelopeV1, InventoryRow
from aptl.core.evidence_bundle.errors import BundleError
from aptl.core.evidence_bundle.inventory import (
    EnvelopeInputs,
    build_envelope,
    envelope_member,
    projection_row,
    row_from_closure_entry,
    row_from_schema,
)
from aptl.core.evidence_bundle.limits import DEFAULT_LIMITS, BundleLimits
from aptl.core.evidence_bundle.projections import run_projections
from aptl.core.evidence_bundle.projections.registry import ProjectionContext
from aptl.core.evidence_bundle.schemas import SchemaArtifact, collect_schemas
from aptl.core.evidence_bundle.verify import VerificationReport, verify_bundle
from aptl.utils import redaction

_BUNDLE_PROFILE = "aptl-evidence-bundle-profile/v1"
_MEDIA_SCHEMA = "application/schema+json"


def _scrub_rows(rows: list[InventoryRow]) -> tuple[list[InventoryRow], bool]:
    """Redact secret-shaped values in GENERATED free-text metadata only.

    Export is not the first redaction boundary (ADR-029): canonical record/blob
    bytes are never rewritten. But a free-text disclosure the builder copies into
    the envelope is new metadata, so a secret-shaped value there is redacted and
    disclosed rather than published.
    """
    scrubbed = False
    result: list[InventoryRow] = []
    for row in rows:
        disclosure = row.loss_disclosure
        if disclosure:
            redacted = redaction.redact(disclosure)
            if redacted != disclosure:
                row = row.model_copy(update={"loss_disclosure": redacted})
                scrubbed = True
        result.append(row)
    return result, scrubbed


@dataclass(frozen=True)
class BundleBuildResult:
    """The published bundle plus its identity and honest disclosures."""

    archive: ArchiveResult
    root_identity: str
    unsealed: bool
    limitations: tuple[ClosureLimitation, ...]


def _load_records(
    run_dir: Path, closure: VerifiedClosure, limits: BundleLimits
) -> tuple[list[dict[str, object]], dict[str, int | None]]:
    """Re-read the evidence records as canonical SOURCE dicts + retained sizes.

    Parsing to a plain dict (rather than the pydantic model) preserves each
    field's exact source presence for the projections. The records were already
    validated against the RAES model during closure assembly.
    """
    blob_sizes = {
        entry.source_ref: entry.size
        for entry in closure.entries
        if entry.logical_role == "evidence-blob"
    }
    records: list[dict[str, object]] = []
    retained: dict[str, int | None] = {}
    for entry in closure.entries:
        if entry.logical_role != "evidence-record":
            continue
        _, _, body = _io.read_source(
            run_dir, entry.source_run_relpath, max_bytes=limits.max_member_bytes
        )
        record = json.loads(body)
        records.append(record)
        content_uri = record.get("raw_content", {}).get("content_uri")
        retained[record["evidence_record_id"]] = blob_sizes.get(content_uri)
    return records, retained


@dataclass(frozen=True)
class BundleOptions:
    """Optional inputs controlling how an evidence bundle is built."""

    projections: Sequence[str] = ()
    seal_verifier: SealVerifier | None = None
    source: ClosureSource | None = None
    limits: BundleLimits = DEFAULT_LIMITS
    created_at: str | None = None
    self_verify: bool = True


def build_evidence_bundle(
    run_dir: Path,
    run_id: str,
    output_path: Path,
    *,
    options: BundleOptions = BundleOptions(),
) -> BundleBuildResult:
    """Build and publish a portable evidence bundle for ``run_id``."""
    limits = options.limits
    closure = build_closure(
        run_dir,
        run_id,
        seal_verifier=options.seal_verifier,
        source=options.source,
        limits=limits,
    )
    records, retained = _load_records(run_dir, closure, limits)

    proj_ctx = ProjectionContext(
        run_dir=run_dir, records=tuple(records), retained_sizes=retained, limits=limits
    )
    projection_run = (
        run_projections(options.projections, proj_ctx)
        if options.projections
        else run_projections([], proj_ctx)
    )

    contract_ids = {
        entry.contract_id
        for entry in closure.entries
        if entry.classification == "canonical" and entry.contract_id
    }
    schemas, unresolved = collect_schemas(contract_ids)

    limitations = list(closure.limitations) + list(projection_run.limitations)
    for contract_id in unresolved:
        limitations.append(
            ClosureLimitation(
                codes.MISSING_SOURCE, "published schema unavailable", contract_id
            )
        )

    rows = [row_from_closure_entry(entry) for entry in closure.entries]
    rows += [row_from_schema(schema) for schema in schemas]
    descriptor_by_path = {
        path: descriptor
        for descriptor in projection_run.descriptors
        for path in descriptor.bundle_paths
    }
    for member in projection_run.members:
        rows.append(projection_row(member, descriptor_by_path[member.bundle_path]))

    rows, scrubbed = _scrub_rows(rows)
    if scrubbed:
        limitations.append(
            ClosureLimitation(
                codes.METADATA_REDACTED,
                "secret-shaped bundle metadata was redacted",
                "envelope",
            )
        )

    validation_disclosures = [
        "canonical artifacts carry their published RAES JSON Schema for structural validation",
        "semantic/conformance validation is NOT performed by export",
    ]
    envelope = build_envelope(
        EnvelopeInputs(
            run_id=run_id,
            bundle_profile=_BUNDLE_PROFILE,
            limits_profile=limits.profile_id,
            seal=closure.seal,
            rows=rows,
            schemas=schemas,
            projections=projection_run.descriptors,
            limitations=limitations,
            validation_disclosures=validation_disclosures,
            created_at=options.created_at,
        )
    )

    members = _assemble_members(closure, schemas, projection_run.members, envelope)
    archive = write_bundle_archive(run_dir, output_path, members, limits=limits)
    if options.self_verify:
        report = verify_bundle(Path(archive.archive_path))
        if not report.ok:
            raise _verification_failed(report)

    return BundleBuildResult(
        archive=archive,
        root_identity=envelope.root_identity(),
        unsealed=closure.seal.scope is SealScope.UNSEALED,
        limitations=tuple(limitations),
    )


def _assemble_members(
    closure: VerifiedClosure,
    schemas: Sequence[SchemaArtifact],
    projection_members: Sequence[BundleMember],
    envelope: BundleEnvelopeV1,
) -> list[BundleMember]:
    """Collect closure, schema, projection, and envelope members into one list."""
    members: list[BundleMember] = [
        BundleMember(
            bundle_path=entry.bundle_path,
            digest=entry.digest,
            size=entry.size,
            media_type=entry.media_type,
            source_run_relpath=entry.source_run_relpath,
        )
        for entry in closure.entries
    ]
    members += [
        BundleMember(
            bundle_path=schema.bundle_path,
            digest=schema.digest,
            size=schema.size,
            media_type=_MEDIA_SCHEMA,
            content=schema.content,
        )
        for schema in schemas
    ]
    members += list(projection_members)
    members.append(envelope_member(envelope))
    return members


def _verification_failed(report: VerificationReport) -> BundleError:
    """Build the ``BundleError`` raised when a bundle fails local self-verification."""
    return BundleError(
        codes.REJECTED_SOURCE, f"self-verification failed: {'; '.join(report.issues)}"
    )


__all__ = ["BundleBuildResult", "BundleOptions", "build_evidence_bundle"]
