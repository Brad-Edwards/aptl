"""In-process, loss-accounted Parquet projection of the evidence records.

Type fidelity is the whole point (EXP-008 preflight "Round-trip semantics are
load-bearing"):

- identifiers stay strings even when digit-shaped;
- timestamps keep their exact source instant/offset as strings, never a
  floating-point epoch;
- nested references become canonical-JSON strings, never delimiter-joined;
- integers use exact ``int64``; a value outside ``int64`` is encoded as an exact
  decimal string with a declared loss disclosure rather than an IEEE-754 float;
- missing/null retained sizes stay null.

pyarrow is an optional extra. When it is absent, the projection records a
``projection-unavailable`` limitation instead of failing the whole export.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

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

_BUNDLE_PATH = "projections/parquet/evidence-records.parquet"
_MEDIA = "application/vnd.apache.parquet"
_MAPPING_ID = "aptl.evidence-bundle.parquet.evidence-record"
_MAPPING_VERSION = "1"
_INT64_MAX = 2**63 - 1


def _canonical_json(value: object) -> str:
    """Return the RFC 8785 canonical JSON of ``value`` as an ASCII string."""
    return rfc8785.dumps(value).decode("ascii")


def _get(record: dict[str, object], *path: str) -> object | None:
    """Walk ``record`` along ``path``, returning the value or ``None`` if absent."""
    cur: object = record
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def _string_columns(records: list[dict[str, object]]) -> dict[str, list[str | None]]:
    """Build the string-typed Parquet columns from the evidence records."""
    return {
        "evidence_record_id": [r.get("evidence_record_id") for r in records],
        "record_version": [r.get("record_version") for r in records],
        "schema_version": [r.get("schema_version") for r in records],
        "run_ref": [_get(r, "run_ref", "ref_id") for r in records],
        "evidence_kind": [r.get("evidence_kind") for r in records],
        "captured_at": [r.get("captured_at") for r in records],
        "sensitivity": [r.get("sensitivity") for r in records],
        "redaction_state": [r.get("redaction_state") for r in records],
        "capture_requirement_ref": [r.get("capture_requirement_ref") for r in records],
        "content_uri": [_get(r, "raw_content", "content_uri") for r in records],
        "content_algorithm": [
            _get(r, "raw_content", "content_checksum", "algorithm") for r in records
        ],
        "content_checksum": [
            _get(r, "raw_content", "content_checksum", "value") for r in records
        ],
        "loss_disclosure": [_get(r, "raw_content", "loss_disclosure") for r in records],
        "source_refs": [_canonical_json(r.get("source_refs", [])) for r in records],
        "provenance_refs": [
            _canonical_json(r["provenance_refs"])
            if r.get("provenance_refs") is not None
            else None
            for r in records
        ],
    }


def _presence_columns(records: list[dict[str, object]]) -> dict[str, list[bool]]:
    """Build the companion presence booleans distinguishing absent from null."""
    # Companion booleans so absent and explicit-null stay distinguishable in the
    # flat table: `<field>_present` is True when the key exists in the source
    # (even if its value is null), False when the field is absent.
    return {
        "loss_disclosure_present": [
            "loss_disclosure" in (r.get("raw_content") or {}) for r in records
        ],
        "provenance_refs_present": ["provenance_refs" in r for r in records],
    }


def _retained_bytes_column(
    records: list[dict[str, object]], retained_sizes: Mapping[str, int | None]
) -> tuple[str, list[int | str | None], str | None]:
    """Return the retained-bytes column type, cells, and any loss disclosure."""
    values = [retained_sizes.get(r["evidence_record_id"]) for r in records]
    present = [v for v in values if v is not None]
    if all(0 <= v <= _INT64_MAX for v in present):
        return "int64", values, None
    # Any value outside int64: encode every cell as an exact decimal string so a
    # large integer is NEVER routed through a float. Disclose the transformation.
    string_cells = [None if v is None else str(v) for v in values]
    loss = "retained_content_bytes exceeds int64; encoded as exact decimal string"
    return "string", string_cells, loss


def _field_maps() -> list[ProjectionFieldMap]:
    """Return the field maps documenting the Parquet projection's type fidelity."""
    src = "experiment-evidence-record/v1"
    return [
        ProjectionFieldMap(
            source_contract=src,
            source_field="evidence_record_id",
            target_field="evidence_record_id",
            physical_type="string",
            null_treatment="non-null",
            notes="identifier kept as string even when digit-shaped",
        ),
        ProjectionFieldMap(
            source_contract=src,
            source_field="captured_at",
            target_field="captured_at",
            physical_type="string",
            null_treatment="non-null",
            notes="exact source instant/offset; never an epoch float",
        ),
        ProjectionFieldMap(
            source_contract=src,
            source_field="source_refs",
            target_field="source_refs",
            physical_type="string(canonical-json)",
            null_treatment="non-null",
            notes="nested references preserved as canonical JSON",
        ),
        ProjectionFieldMap(
            source_contract=src,
            source_field="raw_content.loss_disclosure",
            target_field="loss_disclosure",
            physical_type="string(nullable)",
            null_treatment="null-preserved",
            notes="companion loss_disclosure_present distinguishes absent from explicit null",
        ),
        ProjectionFieldMap(
            source_contract=src,
            source_field="raw_content.loss_disclosure (presence)",
            target_field="loss_disclosure_present",
            physical_type="bool",
            null_treatment="non-null",
            notes="True when the source field exists (even if null); False when absent",
        ),
        ProjectionFieldMap(
            source_contract=src,
            source_field="provenance_refs (presence)",
            target_field="provenance_refs_present",
            physical_type="bool",
            null_treatment="non-null",
            notes="True when the source field exists (even if null); False when absent",
        ),
        ProjectionFieldMap(
            source_contract=src,
            source_field="(retained bytes)",
            target_field="retained_content_bytes",
            physical_type="int64|string(exact-decimal)",
            null_treatment="null-preserved",
            notes="int64 exact; exact decimal string when outside int64",
        ),
    ]


def _descriptor(loss: list[str]) -> ProjectionDescriptor:
    """Describe the loss-accounted Parquet projection of the evidence records."""
    return ProjectionDescriptor(
        mapping_id=_MAPPING_ID,
        mapping_version=_MAPPING_VERSION,
        target_format="parquet",
        target_schema_version="aptl-evidence-bundle-parquet/v1",
        source_contract_versions=["experiment-evidence-record/v1"],
        bundle_paths=[_BUNDLE_PATH],
        field_maps=_field_maps(),
        reference_preservation="nested-references-as-canonical-json",
        row_order="sorted-by-evidence-record-id",
        loss_disclosures=loss,
    )


class ParquetProjection:
    """Loss-accounted Parquet projection of the evidence records."""

    format = "parquet"

    @staticmethod
    def project(ctx: ProjectionContext) -> ProjectionResult:
        try:
            import pyarrow as pa
            import pyarrow.parquet as pq
        except ImportError:
            return ProjectionResult(
                descriptor=None,
                members=(),
                limitations=(
                    ClosureLimitation(
                        codes.PROJECTION_UNAVAILABLE,
                        "pyarrow not installed; parquet projection omitted",
                        "parquet",
                    ),
                ),
            )
        if not ctx.records:
            return ProjectionResult(
                descriptor=None,
                members=(),
                limitations=(
                    ClosureLimitation(
                        codes.PROJECTION_INELIGIBLE,
                        "no evidence records to project",
                        "parquet",
                    ),
                ),
            )
        records = sorted(ctx.records, key=lambda record: record["evidence_record_id"])
        columns: dict[str, object] = dict(_string_columns(records))
        int_type, retained_cells, loss = _retained_bytes_column(
            records, ctx.retained_sizes
        )

        arrays = {
            name: pa.array(values, type=pa.string()) for name, values in columns.items()
        }
        for name, flags in _presence_columns(records).items():
            arrays[name] = pa.array(flags, type=pa.bool_())
        arrays["retained_content_bytes"] = pa.array(
            retained_cells, type=pa.int64() if int_type == "int64" else pa.string()
        )
        table = pa.table(arrays)
        sink = pa.BufferOutputStream()
        pq.write_table(table, sink, compression="none", write_statistics=False)
        body = sink.getvalue().to_pybytes()
        if len(body) > ctx.limits.max_member_bytes:
            raise BundleError(
                codes.REJECTED_SOURCE, "parquet projection exceeds member byte limit"
            )

        member = BundleMember(
            bundle_path=_BUNDLE_PATH,
            digest=f"sha256:{hashlib.sha256(body).hexdigest()}",
            size=len(body),
            media_type=_MEDIA,
            content=body,
        )
        loss_list = [loss] if loss else []
        return ProjectionResult(
            descriptor=_descriptor(loss_list), members=(member,), limitations=()
        )


register(ParquetProjection())

__all__ = ["ParquetProjection"]
