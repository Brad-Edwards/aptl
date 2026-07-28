"""Atomic seal commit, immutability, and crash recovery (EXP-009 / ADR-050).

The seal marker is the archive's one commit point: before it, the attempt is an
unsealed recovery candidate even with a complete manifest; after it, every
overwrite-capable writer refuses. Identical finalization is idempotent; a
differing record for the same attempt is a conflict; a sealed artifact that
cannot be read blocks the seal.
"""

from __future__ import annotations

import json

import pytest
from raes_contracts.contracts import ExperimentRunModel
from raes_contracts.satisfiability import canonical_contract_digest

from tests.archival_fixtures import completed_context
from aptl.core.archival.coordinator import finalize_terminal_attempt
from aptl.core.archival.discovery_index import DiscoveryIndex, IndexEntry
from aptl.core.archival.layout import RUN_MANIFEST_RELPATH, SEAL_MARKER_RELPATH
from aptl.core.archival.run_record import build_experiment_run_model
from aptl.core.archival.seal import SealedArtifactSpec
from aptl.core.archival.status import TerminalCause
from aptl.core.runstore import LocalRunStore, RunStoreConflictError, SealedRunError
from aptl.utils.pathsafe import PathContainmentError


def _store(tmp_path) -> LocalRunStore:
    return LocalRunStore(tmp_path / "runs")


class TestSealCommit:
    def test_seal_writes_manifest_and_marker_and_indexes(self, tmp_path):
        store = _store(tmp_path)
        context = completed_context()
        result = finalize_terminal_attempt(context, store=store)

        run_dir = store.get_run_path(context.attempt_id)
        assert (run_dir / RUN_MANIFEST_RELPATH).exists()
        assert (run_dir / SEAL_MARKER_RELPATH).exists()
        assert store.is_sealed(context.attempt_id)
        assert result.idempotent is False

        index = DiscoveryIndex(store.base_dir)
        assert [e.run_id for e in index.discover()] == [context.attempt_id]

    def test_manifest_is_the_public_raes_run_record(self, tmp_path):
        store = _store(tmp_path)
        context = completed_context()
        finalize_terminal_attempt(context, store=store)
        raw = (store.get_run_path(context.attempt_id) / RUN_MANIFEST_RELPATH).read_text()
        manifest = json.loads(raw)
        assert manifest["schema_version"] == "experiment-run/v1"
        # Round-trips through the installed contract model.
        ExperimentRunModel.model_validate(manifest)

    def test_marker_records_real_run_status_not_sealed(self, tmp_path):
        store = _store(tmp_path)
        context = completed_context()
        result = finalize_terminal_attempt(context, store=store)
        marker = store.read_seal_marker(context.attempt_id)
        assert marker["seal_state"] == "sealed"
        assert marker["run_status"] == "completed"  # the real outcome, not "sealed"
        assert marker["run_record_digest"] == result.run_record_digest
        assert marker["completeness"]["complete"] is True

    def test_inventory_covers_manifest_and_extra_sealed_artifacts(self, tmp_path):
        store = _store(tmp_path)
        # A provenance artifact written by its owner before the handoff.
        store.write_json(
            "run-techvault-001",
            "provenance/run-provenance.json",
            {"seal_state": "ready-to-seal"},
        )
        context = completed_context(
            sealed_artifacts=(
                SealedArtifactSpec(
                    "provenance/run-provenance.json", "application/json", "provenance"
                ),
            )
        )
        result = finalize_terminal_attempt(context, store=store)
        paths = {entry.path for entry in result.inventory}
        assert RUN_MANIFEST_RELPATH in paths
        assert "provenance/run-provenance.json" in paths
        # Every inventory entry carries a real checksum + size.
        for entry in result.inventory:
            assert entry.checksum_algorithm == "sha256"
            assert len(entry.checksum_value) == 64
            assert entry.size_bytes > 0


class TestIdempotencyAndConflict:
    def test_identical_reseal_is_idempotent(self, tmp_path):
        store = _store(tmp_path)
        context = completed_context()
        first = finalize_terminal_attempt(context, store=store)
        second = finalize_terminal_attempt(context, store=store)
        assert second.idempotent is True
        assert first.run_record_digest == second.run_record_digest

    def test_differing_reseal_is_a_conflict(self, tmp_path):
        store = _store(tmp_path)
        finalize_terminal_attempt(completed_context(), store=store)
        # Same attempt id, different terminal cause -> different record -> conflict.
        conflicting = completed_context(
            terminal_cause=TerminalCause.SCENARIO_FAILURE, evaluator_outcome=None
        )
        with pytest.raises(RunStoreConflictError):
            finalize_terminal_attempt(conflicting, store=store)


class TestImmutability:
    def test_overwrite_writes_rejected_after_seal(self, tmp_path):
        store = _store(tmp_path)
        context = completed_context()
        finalize_terminal_attempt(context, store=store)
        with pytest.raises(SealedRunError):
            store.write_json(context.attempt_id, "late.json", {"x": 1})
        with pytest.raises(SealedRunError):
            store.append_jsonl(context.attempt_id, "late.jsonl", [{"x": 1}])
        with pytest.raises(SealedRunError):
            store.write_file(context.attempt_id, "late.bin", b"x")

    def test_create_once_into_sealed_run_rejected(self, tmp_path):
        # A create-once write can no longer add a file to a sealed run (the
        # earlier bypass); only the marker-commit path may touch a sealed run.
        store = _store(tmp_path)
        context = completed_context()
        finalize_terminal_attempt(context, store=store)
        with pytest.raises(SealedRunError):
            store.create_run_json_once(context.attempt_id, "extra.json", {"x": 1})

    def test_generic_writer_still_cannot_forge_marker_after_seal(self, tmp_path):
        store = _store(tmp_path)
        context = completed_context()
        finalize_terminal_attempt(context, store=store)
        with pytest.raises(SealedRunError):
            store.create_run_json_once(context.attempt_id, SEAL_MARKER_RELPATH, {"forged": 1})


class TestInventoryVerification:
    def test_tampered_sealed_artifact_is_detected(self, tmp_path):
        from aptl.core.archival.discovery_index import DiscoveryIndex, IndexCorruptionError
        from aptl.core.archival.verify import SealVerificationError, verify_sealed_archive

        store = _store(tmp_path)
        store.write_json(
            "run-techvault-001", "provenance/run-provenance.json", {"seal_state": "ready-to-seal"}
        )
        context = completed_context(
            sealed_artifacts=(
                SealedArtifactSpec(
                    "provenance/run-provenance.json", "application/json", "provenance"
                ),
            )
        )
        finalize_terminal_attempt(context, store=store)
        # A clean sealed archive verifies.
        assert verify_sealed_archive(store.base_dir, context.attempt_id) is not None

        # An attacker tampers a sealed artifact directly on disk (bypassing the
        # store's sealed-state guard). Verification and discovery both catch it.
        (store.get_run_path(context.attempt_id) / "provenance" / "run-provenance.json").write_text(
            '{"tampered": true}'
        )
        with pytest.raises(SealVerificationError):
            verify_sealed_archive(store.base_dir, context.attempt_id)
        with pytest.raises(IndexCorruptionError):
            DiscoveryIndex(store.base_dir).discover()


class TestArtifactIdentityJoin:
    def _artifact_ref(self, sha256_hex: str, size: int):
        from raes_contracts.contracts import (
            ExperimentArtifactRefModel,
            ExperimentChecksumModel,
        )

        return ExperimentArtifactRefModel(
            artifact_id="evidence-blob-1",
            role="observation",
            media_type="application/json",
            uri="evidence/blobs/blob-1.json",
            checksum=ExperimentChecksumModel(algorithm="sha256", value=sha256_hex),
            size_bytes=size,
            created_at="2026-05-26T00:40:00Z",
            source="collector",
            sensitivity="internal",
        )

    def test_sealed_bytes_matching_claimed_identity_seal(self, tmp_path):
        import hashlib

        store = _store(tmp_path)
        blob = b'{"evidence": true}'
        store.write_file("run-techvault-001", "evidence/blobs/blob-1.json", blob)
        ref = self._artifact_ref(hashlib.sha256(blob).hexdigest(), len(blob))
        spec = SealedArtifactSpec.from_artifact_ref(
            run_relative_path="evidence/blobs/blob-1.json",
            artifact_ref=ref,
            role="evidence-blob",
        )
        context = completed_context(sealed_artifacts=(spec,))
        result = finalize_terminal_attempt(context, store=store)
        assert store.is_sealed(context.attempt_id)
        assert any(e.path == "evidence/blobs/blob-1.json" for e in result.inventory)

    def test_sealed_bytes_diverging_from_claimed_checksum_are_rejected(self, tmp_path):
        from aptl.core.archival.seal import SealIntegrityError

        store = _store(tmp_path)
        blob = b'{"evidence": true}'
        store.write_file("run-techvault-001", "evidence/blobs/blob-1.json", blob)
        # The RAES ref claims a different checksum than the bytes on disk.
        ref = self._artifact_ref("f" * 64, len(blob))
        spec = SealedArtifactSpec.from_artifact_ref(
            run_relative_path="evidence/blobs/blob-1.json",
            artifact_ref=ref,
            role="evidence-blob",
        )
        context = completed_context(sealed_artifacts=(spec,))
        with pytest.raises(SealIntegrityError):
            finalize_terminal_attempt(context, store=store)
        assert not store.is_sealed(context.attempt_id)

    def test_sealed_bytes_diverging_from_claimed_size_are_rejected(self, tmp_path):
        import hashlib

        from aptl.core.archival.seal import SealIntegrityError

        store = _store(tmp_path)
        blob = b'{"evidence": true}'
        store.write_file("run-techvault-001", "evidence/blobs/blob-1.json", blob)
        ref = self._artifact_ref(hashlib.sha256(blob).hexdigest(), len(blob) + 99)
        spec = SealedArtifactSpec.from_artifact_ref(
            run_relative_path="evidence/blobs/blob-1.json",
            artifact_ref=ref,
            role="evidence-blob",
        )
        with pytest.raises(SealIntegrityError):
            finalize_terminal_attempt(completed_context(sealed_artifacts=(spec,)), store=store)


class TestReservedMarkerPath:
    def test_generic_writers_cannot_target_the_seal_marker(self, tmp_path):
        store = _store(tmp_path)
        store.create_run("run-x")
        with pytest.raises(SealedRunError):
            store.write_json("run-x", SEAL_MARKER_RELPATH, {"forged": True})
        with pytest.raises(SealedRunError):
            store.write_file("run-x", SEAL_MARKER_RELPATH, b"forged")
        with pytest.raises(SealedRunError):
            store.append_jsonl("run-x", SEAL_MARKER_RELPATH, [{"forged": True}])


class TestCrashRecovery:
    def test_crash_before_marker_leaves_unsealed_recovery_candidate(self, tmp_path):
        store = _store(tmp_path)
        context = completed_context()
        run = build_experiment_run_model(context)
        digest = canonical_contract_digest(run)
        # Simulate a crash: manifest written and index prepared, marker never committed.
        store.create_run(context.attempt_id)
        store.create_run_json_once(
            context.attempt_id, RUN_MANIFEST_RELPATH, run.model_dump(mode="json")
        )
        index = DiscoveryIndex(store.base_dir)
        index.prepare(
            IndexEntry(
                run_id=context.attempt_id,
                run_version=run.run_version,
                manifest_digest=digest,
                seal_state="sealed",
                terminal_at=run.ended_at,
                location=RUN_MANIFEST_RELPATH,
            )
        )
        assert not store.is_sealed(context.attempt_id)
        assert index.discover() == []
        assert [c.run_id for c in index.recovery_candidates()] == [context.attempt_id]

    def test_missing_sealed_artifact_blocks_the_seal(self, tmp_path):
        store = _store(tmp_path)
        context = completed_context(
            sealed_artifacts=(
                SealedArtifactSpec("provenance/missing.json", "application/json", "provenance"),
            )
        )
        with pytest.raises(PathContainmentError):
            finalize_terminal_attempt(context, store=store)
        # A failed finalization never leaves a sealed run.
        assert not store.is_sealed(context.attempt_id)
