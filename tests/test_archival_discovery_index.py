"""Append-safe discovery index journal (EXP-009 / ADR-050).

The index is a derived recovery journal of bounded routing facts, published with
a prepared/committed protocol under a store-owned lock. Discovery never scans
arbitrary filesystem paths (acceptance criterion D): it replays validated
canonical entries and verifies each against the COMPLETE on-disk seal marker AND
its sealed manifest. A crash between the seal commit and the committed append is
reconciled from the one validated attempt path; a partial trailing append is
recovered; a corrupt mid-file line, a forged/incomplete marker, or a marker that
does not match its sealed manifest is surfaced, not silently trusted.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from aptl.core.archival.discovery_index import (
    DiscoveryIndex,
    IndexCorruptionError,
    IndexEntry,
)
from aptl.core.archival.layout import (
    INDEX_JOURNAL_RELPATH,
    RUN_MANIFEST_RELPATH,
    SEAL_MARKER_DIGEST_FIELD,
    SEAL_MARKER_RELPATH,
    SEAL_MARKER_SCHEMA_VERSION,
)

_OTHER_DIGEST = "sha256:" + "b" * 64


def _seal_run(base_dir, run_id: str, *, marker_digest: str | None = None) -> str:
    """Write a real manifest + a complete seal marker; return the manifest digest.

    ``marker_digest`` overrides the digest the marker claims (to exercise a
    marker that disagrees with its sealed manifest); by default the marker
    matches the manifest bytes.
    """
    run_dir = base_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    manifest_bytes = json.dumps(
        {"schema_version": "experiment-run/v1", "run_id": run_id}, sort_keys=True
    ).encode("utf-8")
    (run_dir / RUN_MANIFEST_RELPATH).write_bytes(manifest_bytes)
    digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    marker = {
        "schema_version": SEAL_MARKER_SCHEMA_VERSION,
        "run_id": run_id,
        "seal_state": "sealed",
        SEAL_MARKER_DIGEST_FIELD: marker_digest or digest,
        "inventory": [],
        "completeness": {"complete": True, "statement": "test", "limitations": []},
    }
    (run_dir / SEAL_MARKER_RELPATH).write_text(json.dumps(marker), encoding="utf-8")
    return digest


def _entry(run_id: str, digest: str) -> IndexEntry:
    return IndexEntry(
        run_id=run_id,
        run_version="1.0.0",
        manifest_digest=digest,
        seal_state="sealed",
        terminal_at="2026-07-28T00:00:00Z",
        location=RUN_MANIFEST_RELPATH,
    )


class TestPrepareCommitDiscovery:
    def test_committed_entry_with_matching_marker_is_discovered(self, tmp_path):
        index = DiscoveryIndex(tmp_path)
        digest = _seal_run(tmp_path, "attempt-0001")
        entry = _entry("attempt-0001", digest)
        index.prepare(entry)
        index.commit(entry)

        sealed = index.discover()
        assert [e.run_id for e in sealed] == ["attempt-0001"]
        assert sealed[0].manifest_digest == digest

    def test_discovery_does_not_scan_run_directories(self, tmp_path):
        """A sealed run absent from the journal is NOT discovered by scanning."""
        index = DiscoveryIndex(tmp_path)
        _seal_run(tmp_path, "orphan-run")  # sealed on disk, but no journal entry
        assert index.discover() == []

    def test_multiple_runs_are_discovered_in_journal_order(self, tmp_path):
        index = DiscoveryIndex(tmp_path)
        for i in (1, 2, 3):
            rid = f"attempt-{i:04d}"
            entry = _entry(rid, _seal_run(tmp_path, rid))
            index.prepare(entry)
            index.commit(entry)
        assert [e.run_id for e in index.discover()] == [
            "attempt-0001",
            "attempt-0002",
            "attempt-0003",
        ]


class TestCrashRecovery:
    def test_prepared_without_commit_but_with_marker_is_reconciled(self, tmp_path):
        """Crash between seal commit and committed append -> reconciled as sealed."""
        index = DiscoveryIndex(tmp_path)
        digest = _seal_run(tmp_path, "attempt-0001")
        entry = _entry("attempt-0001", digest)
        index.prepare(entry)
        # ...the committed journal append never happened, but the marker exists.

        assert [e.run_id for e in index.discover()] == ["attempt-0001"]
        assert index.recovery_candidates() == []

    def test_prepared_without_marker_is_a_recovery_candidate_not_sealed(self, tmp_path):
        """Crash before the seal marker -> unsealed recovery candidate."""
        index = DiscoveryIndex(tmp_path)
        entry = _entry("attempt-0001", "sha256:" + "a" * 64)
        index.prepare(entry)  # no marker/manifest written

        assert index.discover() == []
        assert [c.run_id for c in index.recovery_candidates()] == ["attempt-0001"]

    def test_partial_trailing_line_is_recovered(self, tmp_path):
        index = DiscoveryIndex(tmp_path)
        entry = _entry("attempt-0001", _seal_run(tmp_path, "attempt-0001"))
        index.prepare(entry)
        index.commit(entry)
        # Simulate a torn append: a partial, non-newline-terminated trailing line.
        journal = tmp_path / INDEX_JOURNAL_RELPATH
        with open(journal, "ab") as fh:
            fh.write(b'{"event":"committed","run_id":"attempt-99')

        assert [e.run_id for e in index.discover()] == ["attempt-0001"]


class TestCorruptionSurfaces:
    def test_corrupt_mid_file_line_raises(self, tmp_path):
        index = DiscoveryIndex(tmp_path)
        entry = _entry("attempt-0001", _seal_run(tmp_path, "attempt-0001"))
        index.prepare(entry)
        index.commit(entry)
        # Insert a corrupt, newline-terminated line in the MIDDLE (not trailing).
        journal = tmp_path / INDEX_JOURNAL_RELPATH
        existing = journal.read_bytes()
        journal.write_bytes(b"not-json-at-all\n" + existing)

        with pytest.raises(IndexCorruptionError):
            index.discover()

    def test_conflicting_committed_digests_raise(self, tmp_path):
        index = DiscoveryIndex(tmp_path)
        digest = _seal_run(tmp_path, "attempt-0001")
        index.commit(_entry("attempt-0001", digest))
        index.commit(_entry("attempt-0001", _OTHER_DIGEST))  # same run, different digest
        with pytest.raises(IndexCorruptionError):
            index.discover()

    def test_committed_entry_disagreeing_with_marker_raises(self, tmp_path):
        index = DiscoveryIndex(tmp_path)
        # Marker/manifest sealed at the real digest, but the entry claims another.
        _seal_run(tmp_path, "attempt-0001")
        index.commit(_entry("attempt-0001", _OTHER_DIGEST))
        with pytest.raises(IndexCorruptionError):
            index.discover()

    def test_marker_not_matching_sealed_manifest_raises(self, tmp_path):
        index = DiscoveryIndex(tmp_path)
        # The marker claims a digest that does not match the manifest bytes.
        real = _seal_run(tmp_path, "attempt-0001", marker_digest=_OTHER_DIGEST)
        index.commit(_entry("attempt-0001", real))
        with pytest.raises(IndexCorruptionError):
            index.discover()

    def test_incomplete_forged_marker_raises(self, tmp_path):
        index = DiscoveryIndex(tmp_path)
        digest = _seal_run(tmp_path, "attempt-0001")
        # Overwrite the marker with a forged minimal one carrying only the digest.
        (tmp_path / "attempt-0001" / SEAL_MARKER_RELPATH).write_text(
            json.dumps({SEAL_MARKER_DIGEST_FIELD: digest}), encoding="utf-8"
        )
        index.commit(_entry("attempt-0001", digest))
        with pytest.raises(IndexCorruptionError):
            index.discover()

    def test_duplicate_identical_events_are_idempotent(self, tmp_path):
        index = DiscoveryIndex(tmp_path)
        entry = _entry("attempt-0001", _seal_run(tmp_path, "attempt-0001"))
        index.commit(entry)
        index.commit(entry)  # identical replay
        assert [x.run_id for x in index.discover()] == ["attempt-0001"]


class TestValidation:
    def test_prepare_rejects_unsafe_run_id(self, tmp_path):
        index = DiscoveryIndex(tmp_path)
        entry = _entry("../escape", "sha256:" + "a" * 64)
        with pytest.raises(ValueError):
            index.prepare(entry)

    def test_prepare_rejects_non_prefixed_digest(self, tmp_path):
        index = DiscoveryIndex(tmp_path)
        entry = _entry("attempt-0001", "a" * 64)  # missing sha256: prefix
        with pytest.raises(ValueError):
            index.prepare(entry)

    def test_prepare_rejects_absolute_location(self, tmp_path):
        index = DiscoveryIndex(tmp_path)
        bad = IndexEntry(
            run_id="attempt-0001",
            run_version="1.0.0",
            manifest_digest="sha256:" + "a" * 64,
            seal_state="sealed",
            terminal_at="2026-07-28T00:00:00Z",
            location="/etc/passwd",
        )
        with pytest.raises(ValueError):
            index.prepare(bad)


class TestRebuild:
    def test_rebuild_from_sealed_runs_reconstructs_journal(self, tmp_path):
        index = DiscoveryIndex(tmp_path)
        entries = [
            _entry(f"attempt-{i:04d}", _seal_run(tmp_path, f"attempt-{i:04d}"))
            for i in (1, 2)
        ]
        index.rebuild(entries)
        assert sorted(e.run_id for e in index.discover()) == [
            "attempt-0001",
            "attempt-0002",
        ]
