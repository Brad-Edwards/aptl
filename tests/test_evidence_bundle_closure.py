"""Tests for the EXP-008 verified-closure builder.

The closure is assembled from the ready-to-seal artifacts by REFERENCE (the
evidence ledger + each record's blob ref + the known backend-evidence roots),
never by scanning the run directory. Until #444 lands, the seal is honestly
reported as unsealed with an explicit limitation.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import _bundle_fixtures as fixtures  # noqa: E402

from aptl.core.evidence_bundle.closure import (  # noqa: E402
    SealScope,
    build_closure,
)


def _roles(closure) -> list[str]:
    return [entry.logical_role for entry in closure.entries]


def _by_role(closure, role: str):
    return [entry for entry in closure.entries if entry.logical_role == role]


class TestReferenceDrivenClosure:
    def test_includes_every_ready_to_seal_artifact(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "run-1"
        fixtures.build_ready_to_seal_run(run_dir, run_id="run-1", evidence_count=2)

        closure = build_closure(run_dir, "run-1")

        roles = _roles(closure)
        assert roles.count("evidence-record") == 2
        assert roles.count("evidence-blob") == 2
        assert "run-manifest" in roles
        assert "run-provenance" in roles
        assert "correlation" in roles

    def test_entries_carry_digest_size_and_media_type(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "run-1"
        fixtures.build_ready_to_seal_run(run_dir, run_id="run-1")

        closure = build_closure(run_dir, "run-1")

        for entry in closure.entries:
            assert entry.digest.startswith("sha256:")
            assert entry.size >= 0
            assert entry.media_type
            assert entry.bundle_path
            assert entry.classification in {
                "canonical",
                "backend-evidence",
                "derived",
                "reference",
            }

    def test_evidence_record_and_blob_are_classified_canonical(
        self, tmp_path: Path
    ) -> None:
        run_dir = tmp_path / "run-1"
        fixtures.build_ready_to_seal_run(run_dir, run_id="run-1")

        closure = build_closure(run_dir, "run-1")

        assert all(
            e.classification == "canonical"
            for e in _by_role(closure, "evidence-record")
        )
        assert all(
            e.classification == "canonical" for e in _by_role(closure, "evidence-blob")
        )
        assert all(
            e.classification == "backend-evidence"
            for e in _by_role(closure, "correlation")
        )

    def test_does_not_scan_unreferenced_files(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "run-1"
        fixtures.build_ready_to_seal_run(run_dir, run_id="run-1")
        # Stray files an ambient rglob would sweep in — but nothing references them.
        (run_dir / "notes.txt").write_text("operator scratch", encoding="utf-8")
        (run_dir / "evidence" / "blobs" / "orphan").write_bytes(b"unreferenced")

        closure = build_closure(run_dir, "run-1")

        bundle_paths = {e.bundle_path for e in closure.entries}
        source_paths = {
            e.source_run_relpath for e in closure.entries if e.source_run_relpath
        }
        assert not any("notes.txt" in p for p in bundle_paths)
        assert not any(p.endswith("/orphan") for p in source_paths)


class TestSealSeam:
    def test_default_is_unsealed_with_a_limitation(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "run-1"
        fixtures.build_ready_to_seal_run(run_dir, run_id="run-1")

        closure = build_closure(run_dir, "run-1")

        assert closure.seal.scope is SealScope.UNSEALED
        assert closure.seal.root_identity is None
        assert any(
            lim.code == "aptl.evidence-bundle.seal-absent"
            for lim in closure.limitations
        )

    def test_ready_to_seal_state_is_not_treated_as_a_verified_seal(
        self, tmp_path: Path
    ) -> None:
        run_dir = tmp_path / "run-1"
        fixtures.build_ready_to_seal_run(run_dir, run_id="run-1")

        closure = build_closure(run_dir, "run-1")

        # provenance/run-provenance.json carries seal_state="ready-to-seal";
        # that MUST NOT flip the bundle to a verified seal.
        assert closure.seal.scope is SealScope.UNSEALED


class TestPartialAndInvalidRuns:
    def test_missing_referenced_blob_becomes_a_limitation_not_a_crash(
        self, tmp_path: Path
    ) -> None:
        run_dir = tmp_path / "run-1"
        written = fixtures.build_ready_to_seal_run(run_dir, run_id="run-1")
        # Delete the blob a record references — a partial/invalid run.
        (run_dir / written[0].blob_relpath).unlink()

        closure = build_closure(run_dir, "run-1")

        assert any(
            lim.code == "aptl.evidence-bundle.missing-source"
            for lim in closure.limitations
        )
        # The record itself is still exportable.
        assert _by_role(closure, "evidence-record")

    def test_missing_provenance_and_correlation_still_exportable(
        self, tmp_path: Path
    ) -> None:
        run_dir = tmp_path / "run-1"
        fixtures.build_ready_to_seal_run(run_dir, run_id="run-1")
        (run_dir / "provenance" / "run-provenance.json").unlink()
        (run_dir / "correlation.json").unlink()

        closure = build_closure(run_dir, "run-1")

        assert _by_role(closure, "evidence-record")
        codes = {lim.code for lim in closure.limitations}
        assert "aptl.evidence-bundle.missing-source" in codes

    def test_preserves_redaction_and_sensitivity_disclosures(
        self, tmp_path: Path
    ) -> None:
        run_dir = tmp_path / "run-1"
        run_dir.mkdir()
        fixtures.write_manifest(run_dir, run_id="run-1")
        fixtures.write_evidence(
            run_dir,
            run_id="run-1",
            redaction_state="redacted",
            loss_disclosure="1 field(s) redacted at the persistence boundary",
        )

        closure = build_closure(run_dir, "run-1")

        record_entry = _by_role(closure, "evidence-record")[0]
        assert record_entry.disclosures.redaction_state == "redacted"
        assert record_entry.disclosures.loss_disclosure


class TestRunJoin:
    def test_record_declaring_a_different_run_is_rejected(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "run-1"
        run_dir.mkdir()
        fixtures.write_manifest(run_dir, run_id="run-1")
        # A stale/copied record whose run_ref names a different run.
        fixtures.write_evidence(run_dir, run_id="other-run")

        closure = build_closure(run_dir, "run-1")

        assert not _by_role(closure, "evidence-record")
        assert any(
            lim.code == "aptl.evidence-bundle.rejected-source" and "run" in lim.detail
            for lim in closure.limitations
        )

    def test_backend_artifact_declaring_a_different_run_is_rejected(
        self, tmp_path: Path
    ) -> None:
        run_dir = tmp_path / "run-1"
        run_dir.mkdir()
        fixtures.write_manifest(run_dir, run_id="wrong-run")

        closure = build_closure(run_dir, "run-1")

        assert not _by_role(closure, "run-manifest")
        assert any(
            lim.code == "aptl.evidence-bundle.rejected-source"
            for lim in closure.limitations
        )


class TestSharedContentAddressedBlob:
    def test_shared_blob_is_coalesced_not_duplicated(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "run-1"
        run_dir.mkdir()
        fixtures.write_manifest(run_dir, run_id="run-1")
        shared = b'{"event": "shared observation"}\n'
        fixtures.write_evidence(
            run_dir,
            run_id="run-1",
            blob_bytes=shared,
            requirement_id="req-a",
            capture_spec_id="spec-a",
        )
        fixtures.write_evidence(
            run_dir,
            run_id="run-1",
            blob_bytes=shared,
            requirement_id="req-b",
            capture_spec_id="spec-b",
        )

        closure = build_closure(run_dir, "run-1")

        # Two records reference one content-addressed blob -> one blob member.
        assert len(_by_role(closure, "evidence-record")) == 2
        assert len(_by_role(closure, "evidence-blob")) == 1
        blob_paths = [e.bundle_path for e in _by_role(closure, "evidence-blob")]
        assert len(blob_paths) == len(set(blob_paths))


class TestEmptyRun:
    def test_run_with_no_evidence_ledger_is_exportable_with_a_limitation(
        self, tmp_path: Path
    ) -> None:
        run_dir = tmp_path / "run-1"
        run_dir.mkdir()
        fixtures.write_manifest(run_dir, run_id="run-1")

        closure = build_closure(run_dir, "run-1")

        assert _by_role(closure, "run-manifest")
        assert any(
            lim.code == "aptl.evidence-bundle.missing-source"
            for lim in closure.limitations
        )
