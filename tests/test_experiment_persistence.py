"""Tests for ``LocalRunStore.create_json_once`` (ADR-047 "Persistence and
state model").

Create-once, canonical (RFC 8785), atomic persistence for a controller-owned
journal artifact (e.g. a future admitted experiment trial plan) — distinct
from the timestamp run-id run-archive tree (``write_json``/``_run_dir``).
Immutability requires more than calling ``write_json`` twice: this is a
narrow new create-once operation on the existing run-store protocol, not a
second experiment repository.
"""

import json

import pytest
import rfc8785

from aptl.core.runstore import (
    LocalRunStore,
    RunStoreConflictError,
    SecretInvariantError,
)
from aptl.utils.pathsafe import PathContainmentError


class TestCreateJsonOnceHappyPath:
    def test_writes_canonical_rfc8785_bytes(self, tmp_path):
        store = LocalRunStore(tmp_path / "store")
        payload = {"b": 2, "a": 1, "nested": {"z": [3, 2, 1], "y": True}}

        path = store.create_json_once("experiment-plans", "plan-abc", payload)

        expected = rfc8785.dumps(json.loads(json.dumps(payload)))
        assert path.read_bytes() == expected
        # RFC 8785 sorts object member names.
        assert path.read_bytes().startswith(b'{"a":1')

    def test_returns_the_written_path(self, tmp_path):
        store = LocalRunStore(tmp_path / "store")
        path = store.create_json_once("ns", "plan-1", {"x": 1})
        assert path == tmp_path / "store" / "ns" / "plan-1.json"

    def test_creates_the_store_root_if_missing(self, tmp_path):
        store = LocalRunStore(tmp_path / "does-not-exist-yet")
        path = store.create_json_once("ns", "plan-1", {"x": 1})
        assert path.exists()

    def test_does_not_synthesize_a_manifest_or_register_as_a_run(self, tmp_path):
        store = LocalRunStore(tmp_path / "store")
        store.create_json_once("ns", "plan-1", {"x": 1})
        assert store.list_runs() == []
        assert not (tmp_path / "store" / "ns" / "manifest.json").exists()

    def test_distinct_namespaces_do_not_collide(self, tmp_path):
        store = LocalRunStore(tmp_path / "store")
        p1 = store.create_json_once("ns-a", "plan-1", {"x": 1})
        p2 = store.create_json_once("ns-b", "plan-1", {"x": 2})
        assert p1 != p2
        assert json.loads(p1.read_bytes()) == {"x": 1}
        assert json.loads(p2.read_bytes()) == {"x": 2}


class TestCreateJsonOnceIdempotency:
    def test_second_write_of_byte_identical_payload_is_idempotent(self, tmp_path):
        store = LocalRunStore(tmp_path / "store")
        payload = {"a": 1, "b": [1, 2, 3]}

        path1 = store.create_json_once("ns", "plan-1", payload)
        bytes1 = path1.read_bytes()
        # A structurally-identical-but-differently-ordered dict must produce
        # the exact same canonical bytes and be accepted as the same write.
        path2 = store.create_json_once("ns", "plan-1", {"b": [1, 2, 3], "a": 1})

        assert path2 == path1
        assert path2.read_bytes() == bytes1

    def test_second_write_of_different_payload_is_rejected(self, tmp_path):
        store = LocalRunStore(tmp_path / "store")
        store.create_json_once("ns", "plan-1", {"a": 1})

        with pytest.raises(RunStoreConflictError):
            store.create_json_once("ns", "plan-1", {"a": 2})

        # The original bytes must be untouched by the rejected write.
        assert json.loads((tmp_path / "store" / "ns" / "plan-1.json").read_bytes()) == {
            "a": 1
        }


class TestCreateJsonOnceSymlinkContainment:
    def test_pre_existing_symlinked_namespace_does_not_escape_root(self, tmp_path):
        store_root = tmp_path / "store"
        store_root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (store_root / "ns").symlink_to(outside, target_is_directory=True)

        store = LocalRunStore(store_root)
        with pytest.raises(PathContainmentError):
            store.create_json_once("ns", "plan-1", {"a": 1})

        assert list(outside.iterdir()) == []

    def test_pre_existing_symlinked_leaf_does_not_escape_root(self, tmp_path):
        store_root = tmp_path / "store"
        (store_root / "ns").mkdir(parents=True)
        outside_target = tmp_path / "outside.json"
        (store_root / "ns" / "plan-1.json").symlink_to(outside_target)

        store = LocalRunStore(store_root)
        with pytest.raises(PathContainmentError):
            store.create_json_once("ns", "plan-1", {"a": 1})

        assert not outside_target.exists()


class TestCreateJsonOnceSecretInvariant:
    def test_rejects_payload_with_a_sensitive_key(self, tmp_path):
        store = LocalRunStore(tmp_path / "store")

        with pytest.raises(SecretInvariantError):
            store.create_json_once(
                "ns", "plan-1", {"condition_id": "c1", "api_key": "should-not-persist"}
            )

        assert not (tmp_path / "store" / "ns" / "plan-1.json").exists()

    def test_rejects_payload_with_embedded_credential_shaped_string(self, tmp_path):
        store = LocalRunStore(tmp_path / "store")

        with pytest.raises(SecretInvariantError):
            store.create_json_once(
                "ns",
                "plan-1",
                {"note": "boot ok; Authorization: Bearer XYZ.TOKEN"},
            )

        assert not (tmp_path / "store" / "ns" / "plan-1.json").exists()

    def test_accepts_a_payload_with_no_secret_shaped_content(self, tmp_path):
        store = LocalRunStore(tmp_path / "store")
        path = store.create_json_once(
            "ns", "plan-1", {"condition_id": "c1", "trial_count": 3}
        )
        assert json.loads(path.read_bytes()) == {"condition_id": "c1", "trial_count": 3}


class TestCreateJsonOnceInputValidation:
    def test_rejects_invalid_namespace(self, tmp_path):
        store = LocalRunStore(tmp_path / "store")
        with pytest.raises(ValueError, match="namespace"):
            store.create_json_once("../escape", "plan-1", {"a": 1})

    def test_rejects_invalid_name(self, tmp_path):
        store = LocalRunStore(tmp_path / "store")
        with pytest.raises(ValueError, match="name"):
            store.create_json_once("ns", "../escape", {"a": 1})

    def test_rejects_non_json_serializable_payload(self, tmp_path):
        store = LocalRunStore(tmp_path / "store")
        payload = {"a": object()}
        with pytest.raises(ValueError):
            store.create_json_once("ns", "plan-1", payload)
