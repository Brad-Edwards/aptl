"""Property-based tests for evidence-bundle determinism and round-trip fidelity.

Run with ``pytest -m fuzz`` (skipped by the default run per pyproject).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest
import rfc8785
from hypothesis import given, settings
from hypothesis import strategies as st
from raes_contracts.contracts import ExperimentEvidenceRecordModel

sys.path.insert(0, str(Path(__file__).parent))
import _bundle_fixtures as fixtures  # noqa: E402

from aptl.core.evidence_bundle import build_evidence_bundle  # noqa: E402

pytestmark = pytest.mark.fuzz

_KINDS = [
    "artifact",
    "observation",
    "trace",
    "telemetry",
    "log",
    "packet-capture",
    "other",
]
_SENSITIVITY = ["public", "internal", "restricted", "redacted"]
_REDACTION = ["none", "redacted", "withheld"]

_record_specs = st.lists(
    st.fixed_dictionaries(
        {
            "blob": st.binary(min_size=0, max_size=96),
            "sensitivity": st.sampled_from(_SENSITIVITY),
            "redaction_state": st.sampled_from(_REDACTION),
            "loss": st.one_of(st.none(), st.text(min_size=1, max_size=40)),
            "kind": st.sampled_from(_KINDS),
        }
    ),
    min_size=1,
    max_size=4,
)


def _write_run(run_dir: Path, specs: list[dict]) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    fixtures.write_manifest(run_dir, run_id="run-1")
    for index, spec in enumerate(specs):
        loss = spec["loss"]
        # RAES invariant: redacted/withheld records must carry a loss disclosure.
        if spec["redaction_state"] in ("redacted", "withheld") and not loss:
            loss = "redacted at the persistence boundary"
        fixtures.write_evidence(
            run_dir,
            run_id="run-1",
            blob_bytes=spec["blob"] + index.to_bytes(2, "big"),
            requirement_id=f"req-{index}",
            capture_spec_id=f"spec-{index}",
            sensitivity=spec["sensitivity"],
            redaction_state=spec["redaction_state"],
            loss_disclosure=loss,
            evidence_kind=spec["kind"],
        )


@settings(deadline=None, max_examples=25)
@given(specs=_record_specs)
def test_export_is_byte_deterministic(specs: list[dict]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        run_dir = base / "run-1"
        _write_run(run_dir, specs)
        first = build_evidence_bundle(
            run_dir, "run-1", base / "o1" / "b.tar", projections=["jsonl", "parquet"]
        )
        second = build_evidence_bundle(
            run_dir, "run-1", base / "o2" / "b.tar", projections=["jsonl", "parquet"]
        )
        assert (
            Path(first.archive.archive_path).read_bytes()
            == Path(second.archive.archive_path).read_bytes()
        )
        assert first.root_identity == second.root_identity


@settings(deadline=None, max_examples=25)
@given(specs=_record_specs)
def test_jsonl_rows_round_trip_through_the_raes_model(specs: list[dict]) -> None:
    import tarfile

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        run_dir = base / "run-1"
        _write_run(run_dir, specs)
        out = base / "o" / "b.tar"
        build_evidence_bundle(run_dir, "run-1", out, projections=["jsonl"])
        with tarfile.open(out, "r:") as tar:
            body = tar.extractfile("projections/jsonl/evidence-records.jsonl").read()

        # JSONL is U+000A-delimited; JCS escapes raw newlines inside values but
        # NOT other Unicode line boundaries (U+0085/2028/2029), so a reader must
        # split on "\n" only — never str.splitlines().
        rows = [row for row in body.decode().split("\n") if row]
        assert len(rows) == len(specs)
        for row in rows:
            raw = row.encode()
            record = ExperimentEvidenceRecordModel.model_validate_json(raw)
            recanonical = rfc8785.dumps(
                record.model_dump(mode="json", exclude_none=True)
            )
            # canonical and idempotent: reserializing the parsed model yields the row
            assert recanonical == raw
