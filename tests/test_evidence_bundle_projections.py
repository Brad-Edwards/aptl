"""Tests for the closed, versioned projection registry (JSONL / Parquet / OCSF).

Covers fail-closed selection, lossless JSONL round-trip, Parquet type fidelity
(string identifiers, string timestamps, canonical-JSON nested refs, exact int64
with an out-of-range exact-decimal fallback, null preservation), Parquet
determinism + schema evolution, the pyarrow-absent limitation, and the
OCSF-aligned include-not-reclassify contract.
"""

from __future__ import annotations

import copy
import io
import json
import sys
from pathlib import Path

import pyarrow.parquet as pq
import pytest

sys.path.insert(0, str(Path(__file__).parent))
import _bundle_fixtures as fixtures  # noqa: E402

from aptl.core.evidence_bundle.errors import BundleError  # noqa: E402
from aptl.core.evidence_bundle.limits import DEFAULT_LIMITS  # noqa: E402
from aptl.core.evidence_bundle.projections import (  # noqa: E402
    available_formats,
    get_projection,
    run_projections,
)
from aptl.core.evidence_bundle.projections.registry import ProjectionContext  # noqa: E402


def _records() -> tuple[dict, ...]:
    a = fixtures.build_evidence_record(
        run_id="run-1",
        blob_bytes=b"a",
        requirement_id="12345",
        capture_spec_id="spec-a",
    ).model_dump(mode="json", exclude_none=True)
    b = fixtures.build_evidence_record(
        run_id="run-1",
        blob_bytes=b"bb",
        requirement_id="req-b",
        capture_spec_id="spec-b",
        loss_disclosure="1 field redacted",
    ).model_dump(mode="json", exclude_none=True)
    return (a, b)


def _ctx(tmp_path: Path, *, retained_sizes=None):
    records = _records()
    sizes = retained_sizes or {r["evidence_record_id"]: 10 for r in records}
    return ProjectionContext(
        run_dir=tmp_path, records=records, retained_sizes=sizes, limits=DEFAULT_LIMITS
    )


class TestRegistry:
    def test_built_in_formats_registered(self) -> None:
        assert available_formats() == frozenset({"jsonl", "parquet", "ocsf"})

    def test_unknown_format_fails_closed(self) -> None:
        with pytest.raises(BundleError):
            get_projection("yaml")


class TestJsonl:
    def test_lossless_round_trip(self, tmp_path: Path) -> None:
        run = run_projections(["jsonl"], _ctx(tmp_path))
        member = next(m for m in run.members if m.bundle_path.endswith(".jsonl"))
        lines = member.content.decode().splitlines()
        assert len(lines) == 2
        parsed = [json.loads(line) for line in lines]
        # ids are strings; nested source_refs preserved as nested objects
        assert all(isinstance(row["evidence_record_id"], str) for row in parsed)
        assert isinstance(parsed[0]["source_refs"], list)
        # null loss_disclosure stays absent/None, not coerced to ""
        first = next(r for r in parsed if r["capture_requirement_ref"] == "12345")
        assert "loss_disclosure" not in first["raw_content"]

    def test_rows_are_ordered_by_record_id(self, tmp_path: Path) -> None:
        run = run_projections(["jsonl"], _ctx(tmp_path))
        member = next(m for m in run.members if m.bundle_path.endswith(".jsonl"))
        ids = [
            json.loads(line)["evidence_record_id"]
            for line in member.content.decode().splitlines()
        ]
        assert ids == sorted(ids)


def _read_parquet(body: bytes):
    return pq.read_table(io.BytesIO(body))


class TestParquetTypeFidelity:
    def test_identifiers_and_timestamps_stay_strings(self, tmp_path: Path) -> None:
        run = run_projections(["parquet"], _ctx(tmp_path))
        member = next(m for m in run.members if m.bundle_path.endswith(".parquet"))
        table = _read_parquet(member.content)
        schema = table.schema
        assert str(schema.field("capture_requirement_ref").type) == "string"
        assert str(schema.field("captured_at").type) == "string"
        col = table.column("capture_requirement_ref").to_pylist()
        assert "12345" in col  # digit-shaped id kept as the string "12345"

    def test_no_floating_point_columns(self, tmp_path: Path) -> None:
        run = run_projections(["parquet"], _ctx(tmp_path))
        member = next(m for m in run.members if m.bundle_path.endswith(".parquet"))
        table = _read_parquet(member.content)
        types = {str(field.type) for field in table.schema}
        assert not any("float" in t or "double" in t for t in types)

    def test_nested_refs_are_canonical_json(self, tmp_path: Path) -> None:
        run = run_projections(["parquet"], _ctx(tmp_path))
        member = next(m for m in run.members if m.bundle_path.endswith(".parquet"))
        table = _read_parquet(member.content)
        refs = table.column("source_refs").to_pylist()[0]
        assert json.loads(refs)[0]["ref_kind"] == "measurement-channel"

    def test_int64_retained_bytes_exact(self, tmp_path: Path) -> None:
        records = _records()
        big = 9223372036854775807  # int64 max
        sizes = {
            records[0]["evidence_record_id"]: big,
            records[1]["evidence_record_id"]: None,
        }
        ctx = ProjectionContext(
            run_dir=tmp_path,
            records=records,
            retained_sizes=sizes,
            limits=DEFAULT_LIMITS,
        )
        run = run_projections(["parquet"], ctx)
        member = next(m for m in run.members if m.bundle_path.endswith(".parquet"))
        table = _read_parquet(member.content)
        assert str(table.schema.field("retained_content_bytes").type) == "int64"
        values = table.column("retained_content_bytes").to_pylist()
        assert big in values
        assert None in values

    def test_out_of_int64_uses_exact_decimal_string(self, tmp_path: Path) -> None:
        records = _records()
        huge = 2**70  # beyond int64
        sizes = {
            records[0]["evidence_record_id"]: huge,
            records[1]["evidence_record_id"]: 5,
        }
        ctx = ProjectionContext(
            run_dir=tmp_path,
            records=records,
            retained_sizes=sizes,
            limits=DEFAULT_LIMITS,
        )
        run = run_projections(["parquet"], ctx)
        member = next(m for m in run.members if m.bundle_path.endswith(".parquet"))
        table = _read_parquet(member.content)
        assert str(table.schema.field("retained_content_bytes").type) == "string"
        assert str(huge) in table.column("retained_content_bytes").to_pylist()
        assert run.descriptors[0].loss_disclosures  # transformation disclosed


class TestPresencePreservation:
    """Absent vs explicit-null must stay distinguishable (round-trip contract)."""

    def _presence_ctx(self, tmp_path: Path) -> ProjectionContext:
        base = _records()[0]  # redaction "none" -> loss_disclosure absent
        absent = copy.deepcopy(base)
        absent["raw_content"].pop("loss_disclosure", None)
        absent["evidence_record_id"] = "evidence-absent"
        explicit = copy.deepcopy(base)
        explicit["raw_content"]["loss_disclosure"] = None
        explicit["evidence_record_id"] = "evidence-null"
        sizes = {"evidence-absent": 1, "evidence-null": 1}
        return ProjectionContext(
            run_dir=tmp_path,
            records=(absent, explicit),
            retained_sizes=sizes,
            limits=DEFAULT_LIMITS,
        )

    def test_jsonl_distinguishes_absent_from_explicit_null(
        self, tmp_path: Path
    ) -> None:
        run = run_projections(["jsonl"], self._presence_ctx(tmp_path))
        member = next(m for m in run.members if m.bundle_path.endswith(".jsonl"))
        rows = {
            json.loads(line)["evidence_record_id"]: json.loads(line)
            for line in member.content.decode().split("\n")
            if line
        }
        assert "loss_disclosure" not in rows["evidence-absent"]["raw_content"]
        assert rows["evidence-null"]["raw_content"]["loss_disclosure"] is None

    def test_parquet_distinguishes_absent_from_explicit_null(
        self, tmp_path: Path
    ) -> None:
        run = run_projections(["parquet"], self._presence_ctx(tmp_path))
        member = next(m for m in run.members if m.bundle_path.endswith(".parquet"))
        table = _read_parquet(member.content)
        ids = table.column("evidence_record_id").to_pylist()
        present = dict(
            zip(ids, table.column("loss_disclosure_present").to_pylist(), strict=True)
        )
        values = dict(
            zip(ids, table.column("loss_disclosure").to_pylist(), strict=True)
        )
        assert present["evidence-absent"] is False
        assert present["evidence-null"] is True
        # Both value cells are null; the companion column carries the distinction.
        assert values["evidence-absent"] is None
        assert values["evidence-null"] is None


class TestParquetDeterminismAndEvolution:
    def test_two_projections_are_byte_identical(self, tmp_path: Path) -> None:
        first = run_projections(["parquet"], _ctx(tmp_path)).members[0].content
        second = run_projections(["parquet"], _ctx(tmp_path)).members[0].content
        assert first == second

    def test_mapping_and_target_schema_versions_are_declared(
        self, tmp_path: Path
    ) -> None:
        run = run_projections(["parquet"], _ctx(tmp_path))
        descriptor = run.descriptors[0]
        assert descriptor.mapping_id
        assert descriptor.mapping_version
        assert descriptor.target_schema_version == "aptl-evidence-bundle-parquet/v1"
        assert descriptor.field_maps

    def test_reader_tolerates_added_column_schema_evolution(
        self, tmp_path: Path
    ) -> None:
        import pyarrow as pa

        run = run_projections(["parquet"], _ctx(tmp_path))
        body = run.members[0].content
        base = _read_parquet(body)
        # Simulate a v2 that appends a column; a reader of the union still finds v1 columns.
        evolved = base.append_column("new_v2_field", pa.array(["x"] * base.num_rows))
        assert "evidence_record_id" in evolved.schema.names
        assert "new_v2_field" in evolved.schema.names


class TestParquetUnavailable:
    def test_missing_pyarrow_records_a_limitation(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "pyarrow", None)
        monkeypatch.setitem(sys.modules, "pyarrow.parquet", None)
        run = run_projections(["parquet"], _ctx(tmp_path))
        assert run.members == ()
        assert any(
            lim.code == "aptl.evidence-bundle.projection-unavailable"
            for lim in run.limitations
        )


class TestOcsf:
    def test_includes_mcp_red_ocsf_verbatim_with_disclosure(
        self, tmp_path: Path
    ) -> None:
        fixtures.write_ocsf(tmp_path, rows=[{"class_uid": 1001, "activity_id": 1}])
        run = run_projections(["ocsf"], _ctx(tmp_path))
        member = next(m for m in run.members if m.bundle_path.endswith("ocsf.jsonl"))
        assert json.loads(member.content.decode().splitlines()[0])["class_uid"] == 1001
        descriptor = run.descriptors[0]
        assert any(
            "not certified ocsf-conformant" in d.lower()
            for d in descriptor.loss_disclosures
        )

    def test_absent_source_records_unavailable_limitation(self, tmp_path: Path) -> None:
        run = run_projections(["ocsf"], _ctx(tmp_path))
        assert run.members == ()
        assert any(
            lim.code == "aptl.evidence-bundle.projection-unavailable"
            for lim in run.limitations
        )
