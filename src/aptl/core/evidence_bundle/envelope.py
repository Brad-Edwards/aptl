"""The single versioned APTL packaging envelope for an evidence bundle.

``aptl-evidence-bundle/v1`` describes ONLY packaging metadata — inventory, data
dictionary, projections, seal identity, limitations. It never restates a field
owned by a RAES artifact; an inventory row *references* the canonical artifact
by path/role/contract/digest/source-ref (EXP-008 preflight "Preserve canonical
contracts; add only a packaging envelope").

The reproducible bundle identity is ``sha256`` over the RFC 8785 canonical
envelope EXCLUDING ``created_at`` — so an optional human-facing timestamp never
changes the identity, and a default (``created_at=None``) build is fully
reproducible byte-for-byte.
"""

from __future__ import annotations

import hashlib
from typing import Literal

import rfc8785
from pydantic import BaseModel, ConfigDict

SCHEMA_VERSION = "aptl-evidence-bundle/v1"


class _Frozen(BaseModel):
    """Base config for the frozen, extra-forbidding envelope models."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class SealDoc(_Frozen):
    """Seal identity recorded in the envelope: scope and optional root/verifier."""

    scope: str
    root_identity: str | None = None
    verifier_id: str | None = None


class InventoryRow(_Frozen):
    """One inventory row referencing an included artifact by path/role/digest."""

    bundle_path: str
    logical_role: str
    classification: str
    contract_id: str | None = None
    source_ref: str
    digest: str
    size: int
    media_type: str
    sensitivity: str | None = None
    visibility: str | None = None
    redaction_state: str | None = None
    loss_disclosure: str | None = None
    transformation: str | None = None
    provenance_ref: str | None = None
    clock_ref: str | None = None


class SchemaRef(_Frozen):
    """A published RAES JSON Schema included in the bundle's data dictionary."""

    contract_id: str
    bundle_path: str
    schema_id: str
    raes_version: str
    digest: str
    size: int


class ProjectionFieldMap(_Frozen):
    """One source-to-target field mapping within a projection descriptor."""

    source_contract: str | None
    source_field: str | None
    target_field: str
    physical_type: str
    null_treatment: str
    notes: str | None = None


class ProjectionDescriptor(_Frozen):
    """Describes one projection: its mapping, target format, and loss disclosures."""

    mapping_id: str
    mapping_version: str
    target_format: str
    target_schema_version: str
    source_contract_versions: list[str]
    bundle_paths: list[str]
    field_maps: list[ProjectionFieldMap]
    reference_preservation: str
    row_order: str
    loss_disclosures: list[str]


class DataDictionary(_Frozen):
    """The bundle's published schemas and projection descriptors."""

    schemas: list[SchemaRef]
    projections: list[ProjectionDescriptor]


class LimitationDoc(_Frozen):
    """One disclosed limitation: code, detail, and optional subject."""

    code: str
    detail: str
    subject: str | None = None


class BundleEnvelopeV1(_Frozen):
    """The ``aptl-evidence-bundle/v1`` packaging envelope."""

    schema_version: Literal["aptl-evidence-bundle/v1"] = SCHEMA_VERSION
    bundle_profile: str
    limits_profile: str
    run_id: str
    seal: SealDoc
    inventory: list[InventoryRow]
    data_dictionary: DataDictionary
    limitations: list[LimitationDoc]
    validation_disclosures: list[str]
    #: Optional, human-facing, EXCLUDED from the reproducible identity.
    created_at: str | None = None

    def identity_document(self) -> dict[str, object]:
        # The reproducible root identity is the CONTENT identity: inventory, data
        # dictionary, projections, limitations. It excludes ``created_at`` (human
        # metadata) AND ``seal`` — a #444 seal is a DETACHED attestation OVER this
        # root, so it must not be part of the document whose hash it binds
        # (otherwise ``seal.root_identity == root`` is an impossible fixed point).
        return self.model_dump(
            mode="json", exclude={"created_at", "seal"}, exclude_none=True
        )

    def identity_bytes(self) -> bytes:
        return rfc8785.dumps(self.identity_document())

    def root_identity(self) -> str:
        return f"sha256:{hashlib.sha256(self.identity_bytes()).hexdigest()}"

    def to_canonical_bytes(self) -> bytes:
        """Canonical bytes archived as ``bundle.json`` (includes ``created_at`` when set)."""
        return rfc8785.dumps(self.model_dump(mode="json", exclude_none=True))


__all__ = [
    "SCHEMA_VERSION",
    "SealDoc",
    "InventoryRow",
    "SchemaRef",
    "ProjectionFieldMap",
    "ProjectionDescriptor",
    "DataDictionary",
    "LimitationDoc",
    "BundleEnvelopeV1",
]
