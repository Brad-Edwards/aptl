"""Tests for the content-addressed + run-scoped create-once evidence
persistence functions (EXP-010 / issue #752 evidence acquisition).

``create_content_addressed`` streams raw evidence into a digest-named object
under the run dir with byte quotas enforced during streaming, no-follow /
create-exclusive publication, and post-write digest verification.
``create_run_json_once`` is the run-scoped create-once JSON writer (travels in
the exporter's per-run tar). Both extend the ``LocalRunStore`` boundary
narrowly rather than adding a second repository.
"""

from __future__ import annotations

import hashlib

import pytest

from aptl.core.evidence.content_store import create_content_addressed, create_run_json_once
from aptl.core.runstore import LocalRunStore, RunStoreConflictError, SecretInvariantError


def _store(tmp_path) -> LocalRunStore:
    """Return a LocalRunStore rooted at a fresh temp dir."""
    return LocalRunStore(tmp_path / "runs")


# ---------------------------------------------------------------------------
# create_content_addressed
# ---------------------------------------------------------------------------


class TestContentAddressed:
    def test_stores_under_digest_named_path_and_returns_metadata(self, tmp_path):
        store = _store(tmp_path)
        payload = b"raw evidence bytes"
        digest_hex = hashlib.sha256(payload).hexdigest()

        result = create_content_addressed(store, "run-1", [payload], subdir="evidence", max_bytes=1024)

        assert result.relative_path == f"evidence/{digest_hex}"
        assert result.digest == f"sha256:{digest_hex}"
        assert result.size == len(payload)
        assert result.truncated is False
        stored = (store.get_run_path("run-1") / result.relative_path).read_bytes()
        assert stored == payload

    def test_streams_multiple_chunks(self, tmp_path):
        store = _store(tmp_path)
        chunks = [b"aaa", b"bbb", b"ccc"]
        joined = b"".join(chunks)

        result = create_content_addressed(store, "run-1", chunks, subdir="evidence", max_bytes=1024)

        assert result.size == len(joined)
        assert result.digest == f"sha256:{hashlib.sha256(joined).hexdigest()}"

    def test_over_quota_source_is_truncated_not_buffered(self, tmp_path):
        store = _store(tmp_path)
        result = create_content_addressed(store, "run-1", [b"x" * 10, b"y" * 10], subdir="evidence", max_bytes=15)
        assert result.size == 15
        assert result.truncated is True

    def test_exact_fill_with_no_more_data_is_not_truncated(self, tmp_path):
        store = _store(tmp_path)
        result = create_content_addressed(store, "run-1", [b"x" * 8], subdir="evidence", max_bytes=8)
        assert result.size == 8
        assert result.truncated is False

    def test_exact_fill_with_more_data_is_truncated(self, tmp_path):
        store = _store(tmp_path)
        result = create_content_addressed(store, "run-1", [b"x" * 8, b"y"], subdir="evidence", max_bytes=8)
        assert result.size == 8
        assert result.truncated is True

    def test_identical_bytes_are_idempotent(self, tmp_path):
        store = _store(tmp_path)
        first = create_content_addressed(store, "run-1", [b"same"], subdir="evidence", max_bytes=64)
        second = create_content_addressed(store, "run-1", [b"same"], subdir="evidence", max_bytes=64)
        assert first == second

    def test_zero_max_bytes_is_rejected(self, tmp_path):
        store = _store(tmp_path)
        with pytest.raises(ValueError, match="max_bytes must be positive"):
            create_content_addressed(store, "run-1", [b"x"], subdir="evidence", max_bytes=0)

    def test_traversal_subdir_is_rejected(self, tmp_path):
        store = _store(tmp_path)
        with pytest.raises(ValueError):
            create_content_addressed(store, "run-1", [b"x"], subdir="../escape", max_bytes=64)


# ---------------------------------------------------------------------------
# create_run_json_once
# ---------------------------------------------------------------------------


class TestRunJsonOnce:
    def test_writes_under_the_run_dir(self, tmp_path):
        store = _store(tmp_path)
        target = create_run_json_once(store, "run-1", "evidence/records/rec-1.json", {"a": 1})
        assert target.is_relative_to(store.get_run_path("run-1"))
        assert target.exists()

    def test_identical_payload_is_idempotent(self, tmp_path):
        store = _store(tmp_path)
        first = create_run_json_once(store, "run-1", "evidence/r.json", {"a": 1, "b": 2})
        second = create_run_json_once(store, "run-1", "evidence/r.json", {"b": 2, "a": 1})
        assert first == second

    def test_different_payload_conflicts(self, tmp_path):
        store = _store(tmp_path)
        create_run_json_once(store, "run-1", "evidence/r.json", {"a": 1})
        with pytest.raises(RunStoreConflictError):
            create_run_json_once(store, "run-1", "evidence/r.json", {"a": 2})

    def test_secret_shaped_payload_is_rejected(self, tmp_path):
        store = _store(tmp_path)
        with pytest.raises(SecretInvariantError):
            create_run_json_once(store, "run-1", "evidence/r.json", {"api_key": "sk-live-secret-value-123456789"})
