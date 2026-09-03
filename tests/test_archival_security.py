"""Security properties of the terminal-attempt seal (EXP-009 / ADR-050).

The seal boundary must not become a leak or traversal vector: sealed-artifact
paths are contained, and every structured payload (run manifest, seal marker,
index entry) passes the shared secret-invariant so identity-bearing secret-shaped
content is rejected rather than silently persisted.
"""

from __future__ import annotations

import json

import pytest

from tests.archival_fixtures import completed_context
from aptl.core.archival.coordinator import finalize_terminal_attempt
from aptl.core.archival.layout import RUN_MANIFEST_RELPATH, SEAL_MARKER_RELPATH
from aptl.core.archival.seal import SealedArtifactSpec
from aptl.core.runstore import LocalRunStore, SecretInvariantError
from aptl.utils.pathsafe import PathContainmentError

# A secret-shaped value the shared redactor flags (a PEM private-key block).
_FAKE_SECRET = "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBg\n-----END PRIVATE KEY-----"


def _store(tmp_path) -> LocalRunStore:
    return LocalRunStore(tmp_path / "runs")


class TestContainment:
    def test_traversal_sealed_artifact_path_is_rejected(self, tmp_path):
        store = _store(tmp_path)
        context = completed_context(
            sealed_artifacts=(
                SealedArtifactSpec("../../etc/passwd", "text/plain", "evidence-blob"),
            )
        )
        with pytest.raises((ValueError, PathContainmentError)):
            finalize_terminal_attempt(context, store=store)
        assert not store.is_sealed(context.attempt_id)

    def test_absolute_sealed_artifact_path_is_rejected(self, tmp_path):
        store = _store(tmp_path)
        context = completed_context(
            sealed_artifacts=(
                SealedArtifactSpec("/etc/passwd", "text/plain", "evidence-blob"),
            )
        )
        with pytest.raises((ValueError, PathContainmentError)):
            finalize_terminal_attempt(context, store=store)


class TestSecretInvariant:
    def test_secret_shaped_completeness_statement_is_rejected(self, tmp_path):
        store = _store(tmp_path)
        context = completed_context()
        with pytest.raises(SecretInvariantError):
            finalize_terminal_attempt(
                context,
                store=store,
                completeness_statement=f"sealed with token {_FAKE_SECRET}",
            )

    def test_sealed_marker_and_manifest_carry_no_secret(self, tmp_path):
        store = _store(tmp_path)
        context = completed_context()
        finalize_terminal_attempt(context, store=store)
        run_dir = store.get_run_path(context.attempt_id)
        marker_text = (run_dir / SEAL_MARKER_RELPATH).read_text()
        manifest_text = (run_dir / RUN_MANIFEST_RELPATH).read_text()
        assert _FAKE_SECRET not in marker_text
        assert _FAKE_SECRET not in manifest_text
        # The marker is well-formed JSON with only routing/inventory facts.
        marker = json.loads(marker_text)
        assert set(marker) >= {"schema_version", "run_id", "inventory", "completeness"}
