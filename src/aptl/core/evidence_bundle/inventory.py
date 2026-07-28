"""Build the bundle inventory, data dictionary, and packaging envelope.

The inventory is the only packaging-level source of truth: one row per included
regular file, referencing its canonical source by path/role/contract/digest.
The envelope member (``bundle.json``) is NEVER listed in its own inventory — a
checksum surface does not include or rewrite itself.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence

from aptl.core.evidence_bundle.archive import BundleMember
from aptl.core.evidence_bundle.closure import (
    ClosureEntry,
    ClosureLimitation,
    SealBinding,
)
from aptl.core.evidence_bundle.envelope import (
    BundleEnvelopeV1,
    DataDictionary,
    InventoryRow,
    LimitationDoc,
    ProjectionDescriptor,
    SchemaRef,
    SealDoc,
)
from aptl.core.evidence_bundle.schemas import SchemaArtifact

_MEDIA_SCHEMA = "application/schema+json"
_ENVELOPE_BUNDLE_PATH = "bundle.json"
_MEDIA_JSON = "application/json"


def row_from_closure_entry(entry: ClosureEntry) -> InventoryRow:
    disclosures = entry.disclosures
    return InventoryRow(
        bundle_path=entry.bundle_path,
        logical_role=entry.logical_role,
        classification=entry.classification,
        contract_id=entry.contract_id,
        source_ref=entry.source_ref,
        digest=entry.digest,
        size=entry.size,
        media_type=entry.media_type,
        sensitivity=disclosures.sensitivity,
        visibility=disclosures.visibility,
        redaction_state=disclosures.redaction_state,
        loss_disclosure=disclosures.loss_disclosure,
        transformation=disclosures.transformation,
        provenance_ref=entry.provenance_ref,
        clock_ref=entry.clock_ref,
    )


def row_from_schema(schema: SchemaArtifact) -> InventoryRow:
    return InventoryRow(
        bundle_path=schema.bundle_path,
        logical_role="raes-schema",
        classification="reference",
        contract_id=schema.contract_id,
        source_ref=schema.schema_id,
        digest=schema.digest,
        size=schema.size,
        media_type=_MEDIA_SCHEMA,
    )


def schema_ref(schema: SchemaArtifact) -> SchemaRef:
    return SchemaRef(
        contract_id=schema.contract_id,
        bundle_path=schema.bundle_path,
        schema_id=schema.schema_id,
        raes_version=schema.raes_version,
        digest=schema.digest,
        size=schema.size,
    )


def projection_row(
    member: BundleMember, descriptor: ProjectionDescriptor
) -> InventoryRow:
    return InventoryRow(
        bundle_path=member.bundle_path,
        logical_role="projection",
        classification="derived",
        contract_id=f"{descriptor.mapping_id}/{descriptor.mapping_version}",
        source_ref=descriptor.mapping_id,
        digest=member.digest,
        size=member.size,
        media_type=member.media_type,
        transformation=descriptor.target_format,
    )


def limitation_doc(limitation: ClosureLimitation) -> LimitationDoc:
    return LimitationDoc(
        code=limitation.code, detail=limitation.detail, subject=limitation.subject
    )


def seal_doc(seal: SealBinding) -> SealDoc:
    return SealDoc(
        scope=seal.scope.value,
        root_identity=seal.root_identity,
        verifier_id=seal.verifier_id,
    )


def build_envelope(
    *,
    run_id: str,
    bundle_profile: str,
    limits_profile: str,
    seal: SealBinding,
    rows: Iterable[InventoryRow],
    schemas: Sequence[SchemaArtifact],
    projections: Sequence[ProjectionDescriptor],
    limitations: Iterable[ClosureLimitation],
    validation_disclosures: Sequence[str],
    created_at: str | None = None,
) -> BundleEnvelopeV1:
    """Assemble the ``aptl-evidence-bundle/v1`` envelope from its parts."""
    inventory = sorted(rows, key=lambda row: row.bundle_path)
    return BundleEnvelopeV1(
        bundle_profile=bundle_profile,
        limits_profile=limits_profile,
        run_id=run_id,
        seal=seal_doc(seal),
        inventory=inventory,
        data_dictionary=DataDictionary(
            schemas=[schema_ref(schema) for schema in schemas],
            projections=list(projections),
        ),
        limitations=[limitation_doc(limitation) for limitation in limitations],
        validation_disclosures=list(validation_disclosures),
        created_at=created_at,
    )


def envelope_member(envelope: BundleEnvelopeV1) -> BundleMember:
    """Render the envelope as the ``bundle.json`` archive member."""
    content = envelope.to_canonical_bytes()
    return BundleMember(
        bundle_path=_ENVELOPE_BUNDLE_PATH,
        digest=f"sha256:{hashlib.sha256(content).hexdigest()}",
        size=len(content),
        media_type=_MEDIA_JSON,
        content=content,
    )


__all__ = [
    "row_from_closure_entry",
    "row_from_schema",
    "projection_row",
    "schema_ref",
    "limitation_doc",
    "seal_doc",
    "build_envelope",
    "envelope_member",
]
