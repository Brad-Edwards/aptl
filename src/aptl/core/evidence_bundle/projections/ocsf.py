"""OCSF-aligned projection: include the mcp-red OCSF derivative, don't rebuild it.

The run's ``mcp-side/ocsf.jsonl`` is an OCSF-aligned derivative whose classifier,
extractor, and field vocabulary are owned by ``mcp/mcp-red`` and
``docs/red-team-taxonomy.md``. EXP-008 includes it verbatim with an explicit
APTL mapping/taxonomy version and its source tool-call references — it does NOT
re-classify in Python and does NOT claim official OCSF conformance (no pinned
OCSF schema/validator ships in the bundle). When the run has no such file, the
projection records a ``projection-unavailable`` limitation.
"""

from __future__ import annotations

from aptl.core.evidence_bundle import _io, codes
from aptl.core.evidence_bundle.archive import BundleMember
from aptl.core.evidence_bundle.closure import ClosureLimitation
from aptl.core.evidence_bundle.envelope import ProjectionDescriptor, ProjectionFieldMap
from aptl.core.evidence_bundle.projections.registry import (
    ProjectionContext,
    ProjectionResult,
    register,
)

_SOURCE_RELPATH = "mcp-side/ocsf.jsonl"
_BUNDLE_PATH = "projections/ocsf/mcp-side-ocsf.jsonl"
_MEDIA = "application/x-ndjson"
_MAPPING_ID = "aptl.evidence-bundle.ocsf.mcp-red-aligned"
_MAPPING_VERSION = "1"
_TAXONOMY_VERSION = "aptl-red-team-taxonomy/v1"


def _descriptor() -> ProjectionDescriptor:
    """Describe the OCSF-aligned passthrough of mcp-red's derivative rows."""
    return ProjectionDescriptor(
        mapping_id=_MAPPING_ID,
        mapping_version=_MAPPING_VERSION,
        target_format="ocsf-aligned-jsonl",
        target_schema_version=_TAXONOMY_VERSION,
        source_contract_versions=["mcp-red-ocsf-jsonl"],
        bundle_paths=[_BUNDLE_PATH],
        field_maps=[
            ProjectionFieldMap(
                source_contract="mcp-red-ocsf-jsonl",
                source_field="(mcp-side/ocsf.jsonl rows)",
                target_field="(rows)",
                physical_type="ocsf-aligned-jsonl",
                null_treatment="source-preserved",
                notes="included verbatim from the mcp-red taxonomy owner; not re-classified",
            )
        ],
        reference_preservation="source-tool-call-references-retained",
        row_order="source-order-preserved",
        loss_disclosures=[
            "OCSF-aligned via the APTL/mcp-red taxonomy; NOT certified OCSF-conformant "
            "(no pinned OCSF schema/validator ships in the bundle)"
        ],
    )


class OcsfProjection:
    """OCSF-aligned projection: include mcp-red's derivative verbatim."""

    format = "ocsf"

    @staticmethod
    def project(ctx: ProjectionContext) -> ProjectionResult:
        try:
            digest, size, body = _io.read_source(
                ctx.run_dir, _SOURCE_RELPATH, max_bytes=ctx.limits.max_member_bytes
            )
        except _io.SourceMissing:
            return ProjectionResult(
                descriptor=None,
                members=(),
                limitations=(
                    ClosureLimitation(
                        codes.PROJECTION_UNAVAILABLE,
                        "no mcp-side/ocsf.jsonl present in the run closure",
                        "ocsf",
                    ),
                ),
            )
        except _io.SourceRejected as exc:
            return ProjectionResult(
                descriptor=None,
                members=(),
                limitations=(
                    ClosureLimitation(codes.REJECTED_SOURCE, exc.detail, "ocsf"),
                ),
            )
        member = BundleMember(
            bundle_path=_BUNDLE_PATH,
            digest=digest,
            size=size,
            media_type=_MEDIA,
            content=body,
        )
        return ProjectionResult(
            descriptor=_descriptor(), members=(member,), limitations=()
        )


register(OcsfProjection())

__all__ = ["OcsfProjection"]
