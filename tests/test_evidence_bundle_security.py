"""Security tests for evidence-bundle export.

Covers the EXP-008 acceptance criteria: path traversal, symlink escape, zip
bomb / resource exhaustion, formula injection, malicious Unicode/filenames, and
accidental secret fixtures. Export is packaging, not sanitation: hostile source
names/paths are rejected or reduced to bounded data, code-owned bundle paths are
used, and secret-shaped values in GENERATED metadata are redacted (canonical
bytes are never rewritten — redaction is upstream).
"""

from __future__ import annotations

import dataclasses
import os
import sys
import tarfile
from pathlib import Path

import rfc8785

sys.path.insert(0, str(Path(__file__).parent))
import _bundle_fixtures as fixtures  # noqa: E402

from aptl.core.evidence_bundle import BundleOptions  # noqa: E402
from aptl.core.evidence_bundle import build_evidence_bundle  # noqa: E402
from aptl.core.evidence_bundle.limits import DEFAULT_LIMITS  # noqa: E402
from aptl.core.evidence_bundle.projections import available_formats  # noqa: E402

# A value the ADR-029 redactor recognizes (bearer token), so the same redaction
# contract the run store enforces also covers new bundle metadata.
_SECRET_TOKEN = "eyJhbGciOiJIabcdef1234567890"
_SECRET = f"Bearer {_SECRET_TOKEN}"


def _write_record(run_dir: Path, record) -> None:
    (run_dir / "evidence" / "records").mkdir(parents=True, exist_ok=True)
    (run_dir / f"evidence/records/{record.evidence_record_id}.json").write_bytes(
        rfc8785.dumps(record.model_dump(mode="json", exclude_none=True))
    )


def _member_names(archive_path: Path) -> list[str]:
    with tarfile.open(archive_path, "r:") as tar:
        return tar.getnames()


def _envelope_bytes(archive_path: Path) -> bytes:
    with tarfile.open(archive_path, "r:") as tar:
        return tar.extractfile("bundle.json").read()


def _codes(result) -> set[str]:
    return {limitation.code for limitation in result.limitations}


class TestSymlinkAndTraversal:
    def test_symlinked_blob_is_rejected_and_target_never_included(
        self, tmp_path: Path
    ) -> None:
        run_dir = tmp_path / "run-1"
        fixtures.build_ready_to_seal_run(run_dir, run_id="run-1")
        secret_target = tmp_path / "outside-secret.txt"
        secret_target.write_bytes(b"OUTSIDE-SECRET-BYTES")
        # Replace a real blob with a symlink pointing outside the run tree.
        blob = next((run_dir / "evidence" / "blobs").iterdir())
        blob.unlink()
        blob.symlink_to(secret_target)

        out = tmp_path / "exports" / "b.tar"
        result = build_evidence_bundle(
            run_dir, "run-1", out, options=BundleOptions(projections=["jsonl"])
        )

        assert "aptl.evidence-bundle.rejected-source" in _codes(result)
        archive_bytes = out.read_bytes()
        assert b"OUTSIDE-SECRET-BYTES" not in archive_bytes

    def test_symlinked_records_dir_is_rejected(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "run-1"
        run_dir.mkdir()
        fixtures.write_manifest(run_dir, run_id="run-1")
        outside = tmp_path / "attacker"
        outside.mkdir()
        (run_dir / "evidence").mkdir()
        (run_dir / "evidence" / "records").symlink_to(outside)

        out = tmp_path / "exports" / "b.tar"
        result = build_evidence_bundle(run_dir, "run-1", out)

        assert "aptl.evidence-bundle.rejected-source" in _codes(result)

    def test_traversal_content_uri_is_rejected(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "run-1"
        run_dir.mkdir()
        fixtures.write_manifest(run_dir, run_id="run-1")
        record = fixtures.build_evidence_record(
            run_id="run-1", blob_bytes=b"x", content_uri="../../../../etc/passwd"
        )
        _write_record(run_dir, record)

        out = tmp_path / "exports" / "b.tar"
        result = build_evidence_bundle(run_dir, "run-1", out)

        assert "aptl.evidence-bundle.rejected-source" in _codes(result)
        assert b"root:" not in out.read_bytes()


class TestResourceExhaustion:
    def test_oversized_blob_is_excluded_not_fatal(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "run-1"
        fixtures.build_ready_to_seal_run(run_dir, run_id="run-1")
        # Enlarge the blob well past a tight member bound; schema/envelope stay small.
        blob = next((run_dir / "evidence" / "blobs").iterdir())
        blob.write_bytes(os.urandom(50_000))
        limits = dataclasses.replace(DEFAULT_LIMITS, max_member_bytes=20_000)

        out = tmp_path / "exports" / "b.tar"
        result = build_evidence_bundle(
            run_dir, "run-1", out, options=BundleOptions(limits=limits)
        )

        assert "aptl.evidence-bundle.rejected-source" in _codes(result)
        assert not any(
            name.startswith("evidence/blobs/") for name in _member_names(out)
        )


class TestFormulaInjection:
    def test_no_csv_projection_in_v1(self) -> None:
        assert "csv" not in available_formats()

    def test_formula_markers_are_preserved_verbatim_not_escaped(
        self, tmp_path: Path
    ) -> None:
        run_dir = tmp_path / "run-1"
        run_dir.mkdir()
        fixtures.write_manifest(run_dir, run_id="run-1")
        fixtures.write_evidence(
            run_dir, run_id="run-1", loss_disclosure="=SUM(A1)+cmd|calc"
        )

        out = tmp_path / "exports" / "b.tar"
        build_evidence_bundle(
            run_dir, "run-1", out, options=BundleOptions(projections=["jsonl"])
        )

        with tarfile.open(out, "r:") as tar:
            jsonl = (
                tar.extractfile("projections/jsonl/evidence-records.jsonl")
                .read()
                .decode()
            )
        # The formula marker is preserved as data, never prefixed with a "'" escape.
        assert "=SUM(A1)+cmd|calc" in jsonl
        assert "'=SUM(A1)" not in jsonl


class TestMaliciousFilenames:
    def test_hostile_unicode_blob_name_never_becomes_an_archive_path(
        self, tmp_path: Path
    ) -> None:
        run_dir = tmp_path / "run-1"
        run_dir.mkdir()
        fixtures.write_manifest(run_dir, run_id="run-1")
        # RTL-override + homoglyph name, built from escapes so the source stays ASCII.
        hostile = "evidence/blobs/" + "\u202eevil\u202c-dropme\u200b"
        (run_dir / "evidence" / "blobs").mkdir(parents=True)
        blob_bytes = b"raw observation"
        (run_dir / hostile).write_bytes(blob_bytes)
        record = fixtures.build_evidence_record(
            run_id="run-1", blob_bytes=blob_bytes, content_uri=hostile
        )
        _write_record(run_dir, record)

        out = tmp_path / "exports" / "b.tar"
        build_evidence_bundle(run_dir, "run-1", out)

        names = _member_names(out)
        assert all(name.isascii() for name in names)
        assert not any("evil" in name for name in names)
        # the blob is still included under a code-owned digest path
        assert any(name.startswith("evidence/blobs/") for name in names)


class TestAccidentalSecrets:
    def test_secret_shaped_metadata_is_redacted_in_the_envelope(
        self, tmp_path: Path
    ) -> None:
        run_dir = tmp_path / "run-1"
        run_dir.mkdir()
        fixtures.write_manifest(run_dir, run_id="run-1")
        fixtures.write_evidence(run_dir, run_id="run-1", loss_disclosure=_SECRET)

        out = tmp_path / "exports" / "b.tar"
        result = build_evidence_bundle(
            run_dir, "run-1", out, options=BundleOptions(projections=["jsonl"])
        )

        envelope = _envelope_bytes(out)
        assert _SECRET_TOKEN.encode() not in envelope
        assert b"[REDACTED]" in envelope
        assert "aptl.evidence-bundle.metadata-redacted" in _codes(result)
