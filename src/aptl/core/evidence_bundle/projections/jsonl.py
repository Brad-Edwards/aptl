"""Lossless JSONL projection of the canonical evidence records.

Each row is the RFC 8785 canonical JSON of one evidence record — the whole
record, so missing/null/unavailable/withheld/redacted, string identifiers,
exact timestamps, and nested references are all preserved exactly. Rows are
ordered by ``evidence_record_id`` so the projection is deterministic.
"""

from __future__ import annotations

import hashlib

import rfc8785

from aptl.core.evidence_bundle import codes
from aptl.core.evidence_bundle.archive import BundleMember
from aptl.core.evidence_bundle.closure import ClosureLimitation
from aptl.core.evidence_bundle.envelope import ProjectionDescriptor, ProjectionFieldMap
from aptl.core.evidence_bundle.errors import BundleError
from aptl.core.evidence_bundle.projections.registry import (
    ProjectionContext,
    ProjectionResult,
    register,
)

_BUNDLE_PATH = "projections/jsonl/evidence-records.jsonl"
_MEDIA = "application/x-ndjson"
_MAPPING_ID = "aptl.evidence-bundle.jsonl.evidence-record"
_MAPPING_VERSION = "1"


def _descriptor() -> ProjectionDescriptor:
    return ProjectionDescriptor(
        mapping_id=_MAPPING_ID,
        mapping_version=_MAPPING_VERSION,
        target_format="jsonl",
        target_schema_version="experiment-evidence-record/v1",
        source_contract_versions=["experiment-evidence-record/v1"],
        bundle_paths=[_BUNDLE_PATH],
        field_maps=[
            ProjectionFieldMap(
                source_contract="experiment-evidence-record/v1",
                source_field="(whole record)",
                target_field="(row)",
                physical_type="canonical-json-object",
                null_treatment="preserved-exact",
                notes=(
                    "one RFC 8785 canonical JSON object per row, U+000A-delimited; "
                    "raw newlines inside values are JCS-escaped, so readers split on "
                    "U+000A only (never on other Unicode line boundaries)"
                ),
            )
        ],
        reference_preservation="nested-references-preserved-as-json",
        row_order="sorted-by-evidence-record-id",
        loss_disclosures=[],
    )


class JsonlProjection:
    format = "jsonl"

    def project(self, ctx: ProjectionContext) -> ProjectionResult:
        if not ctx.records:
            return ProjectionResult(
                descriptor=None,
                members=(),
                limitations=(
                    ClosureLimitation(
                        codes.PROJECTION_INELIGIBLE,
                        "no evidence records to project",
                        "jsonl",
                    ),
                ),
            )
        records = sorted(ctx.records, key=lambda record: record["evidence_record_id"])
        if len(records) > ctx.limits.max_jsonl_rows:
            raise BundleError(
                codes.REJECTED_SOURCE, "jsonl projection exceeds row limit"
            )
        rows: list[bytes] = []
        for record in records:
            # Canonicalize the SOURCE dict directly: an explicit ``null`` field
            # stays present as null, distinct from an absent field.
            row = rfc8785.dumps(record)
            if len(row) > ctx.limits.max_jsonl_row_bytes:
                raise BundleError(codes.REJECTED_SOURCE, "jsonl row exceeds byte limit")
            rows.append(row)
        body = b"\n".join(rows) + b"\n"
        member = BundleMember(
            bundle_path=_BUNDLE_PATH,
            digest=f"sha256:{hashlib.sha256(body).hexdigest()}",
            size=len(body),
            media_type=_MEDIA,
            content=body,
        )
        return ProjectionResult(
            descriptor=_descriptor(), members=(member,), limitations=()
        )


register(JsonlProjection())

__all__ = ["JsonlProjection"]
