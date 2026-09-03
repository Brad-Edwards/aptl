"""Tests for the REP-003 ready-to-seal provenance record (issue #452).

Covers the preflight's persistence contract: a create-once, canonical record
under the authoritative run identity, idempotent only on identical bytes,
failing closed on conflicting content, and explicitly NOT claiming to be a
seal (issue #444 owns sealing).
"""

import json

import pytest

from aptl.core.provenance.coordinator import ProvenanceCollection, ProvenanceSection
from aptl.core.provenance.outcomes import ProvenanceStatus, limitation_for
from aptl.core.provenance.record import (
    PROVENANCE_RECORD_PATH,
    RECORD_SCHEMA_VERSION,
    build_provenance_record,
    publish_provenance_record,
)
from aptl.core.runstore import LocalRunStore, RunStoreConflictError, SecretInvariantError

_RUN_ID = "run_20260101T000000Z"


def _experiment_section():
    """The admitted-context section the canonical record requires."""
    return ProvenanceSection(
        provider_id="experiment",
        status=ProvenanceStatus.COLLECTED,
        declaration_digest="sha256:" + "e" * 64,
        content_identity="sha256:" + "f" * 64,
        payload={"plan_id": "plan-1"},
        leaf_count=1,
    )


def _collection(sections=None, limitations=()):
    sections = sections or {
        "apparatus": ProvenanceSection(
            provider_id="apparatus",
            status=ProvenanceStatus.COLLECTED,
            declaration_digest="sha256:" + "a" * 64,
            content_identity="sha256:" + "b" * 64,
            payload={"backend": {"name": "aptl"}},
            leaf_count=2,
        ),
        "experiment": _experiment_section(),
    }
    return ProvenanceCollection(
        sections=sections,
        limitations=tuple(limitations),
        aggregate_identity="sha256:" + "c" * 64,
        registry_declaration_digest="sha256:" + "d" * 64,
    )


def _store(tmp_path):
    return LocalRunStore(tmp_path / "runs")


class TestRecordShape:
    """The record composes two namespaces and states what it is."""

    def test_record_is_versioned_and_run_scoped(self):
        record = build_provenance_record(run_id=_RUN_ID, collection=_collection())
        assert record["schema_version"] == RECORD_SCHEMA_VERSION
        assert record["run_id"] == _RUN_ID

    def test_record_declares_ready_to_seal_not_sealed(self):
        """#444 owns sealing; this record must never claim to be one."""
        record = build_provenance_record(run_id=_RUN_ID, collection=_collection())
        assert record["seal_state"] == "ready-to-seal"
        assert "sealed" not in json.dumps(record).replace("ready-to-seal", "")

    def test_record_carries_the_aggregate_identity(self):
        record = build_provenance_record(run_id=_RUN_ID, collection=_collection())
        assert record["aggregate_identity"] == "sha256:" + "c" * 64

    def test_record_carries_sections_and_limitations(self):
        limitation = limitation_for("detection-content", ProvenanceStatus.DENIED)
        record = build_provenance_record(
            run_id=_RUN_ID, collection=_collection(limitations=[limitation])
        )
        assert record["sections"][0]["provider_id"] == "apparatus"
        assert record["limitations"][0]["provider_id"] == "detection-content"

    def test_record_is_deterministic_for_the_same_collection(self):
        first = build_provenance_record(run_id=_RUN_ID, collection=_collection())
        second = build_provenance_record(run_id=_RUN_ID, collection=_collection())
        assert first == second

    def test_record_carries_no_timestamp(self):
        """A volatile timestamp would make an unchanged apparatus look changed."""
        rendered = json.dumps(build_provenance_record(run_id=_RUN_ID, collection=_collection()))
        assert "timestamp" not in rendered
        assert "collected_at" not in rendered


class TestPublication:
    """Publication is create-once, canonical, and fails closed on conflict."""

    def test_publishes_to_the_run_scoped_provenance_path(self, tmp_path):
        store = _store(tmp_path)
        store.create_run(_RUN_ID)
        path = publish_provenance_record(
            store=store, run_id=_RUN_ID, collection=_collection()
        )
        assert path.exists()
        assert path.name == "run-provenance.json"
        assert PROVENANCE_RECORD_PATH.endswith("run-provenance.json")

    def test_published_bytes_are_canonical_json(self, tmp_path):
        store = _store(tmp_path)
        store.create_run(_RUN_ID)
        path = publish_provenance_record(
            store=store, run_id=_RUN_ID, collection=_collection()
        )
        loaded = json.loads(path.read_bytes())
        assert loaded["run_id"] == _RUN_ID

    def test_republishing_identical_content_is_idempotent(self, tmp_path):
        store = _store(tmp_path)
        store.create_run(_RUN_ID)
        first = publish_provenance_record(
            store=store, run_id=_RUN_ID, collection=_collection()
        )
        second = publish_provenance_record(
            store=store, run_id=_RUN_ID, collection=_collection()
        )
        assert first == second

    def test_republishing_different_content_fails_closed(self, tmp_path):
        """Overwrite-capable persistence is exactly what this record must not use."""
        store = _store(tmp_path)
        store.create_run(_RUN_ID)
        publish_provenance_record(store=store, run_id=_RUN_ID, collection=_collection())
        conflicting = _collection(
            sections={
                "apparatus": ProvenanceSection(
                    provider_id="apparatus",
                    status=ProvenanceStatus.COLLECTED,
                    declaration_digest="sha256:" + "9" * 64,
                    content_identity="sha256:" + "8" * 64,
                    leaf_count=1,
                ),
                "experiment": _experiment_section(),
            }
        )
        with pytest.raises(RunStoreConflictError):
            publish_provenance_record(
                store=store, run_id=_RUN_ID, collection=conflicting
            )

    def test_a_secret_shaped_payload_is_refused_by_the_store_invariant(self, tmp_path):
        """Defense in depth behind the providers' allowlist."""
        store = _store(tmp_path)
        store.create_run(_RUN_ID)
        leaky = _collection(
            sections={
                "apparatus": ProvenanceSection(
                    provider_id="apparatus",
                    status=ProvenanceStatus.COLLECTED,
                    declaration_digest="sha256:" + "a" * 64,
                    content_identity="sha256:" + "b" * 64,
                    payload={"password": "hunter2"},
                    leaf_count=1,
                ),
                "experiment": _experiment_section(),
            }
        )
        with pytest.raises(SecretInvariantError):
            publish_provenance_record(store=store, run_id=_RUN_ID, collection=leaky)

    def test_the_record_never_lands_outside_the_run_directory(self, tmp_path):
        store = _store(tmp_path)
        store.create_run(_RUN_ID)
        path = publish_provenance_record(
            store=store, run_id=_RUN_ID, collection=_collection()
        )
        assert path.is_relative_to(store.get_run_path(_RUN_ID))

    def test_limitations_survive_the_round_trip(self, tmp_path):
        store = _store(tmp_path)
        store.create_run(_RUN_ID)
        limitation = limitation_for("detection-content", ProvenanceStatus.UNAVAILABLE)
        path = publish_provenance_record(
            store=store, run_id=_RUN_ID, collection=_collection(limitations=[limitation])
        )
        loaded = json.loads(path.read_bytes())
        assert loaded["limitations"][0]["reason_code"] == limitation.reason_code
