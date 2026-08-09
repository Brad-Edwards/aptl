"""Native materialization + readback orchestration for service-search-index-schema.

Drives :func:`materialize_search_index_schema` with a fake Elasticsearch exec so
the ownership, create, and fresh-readback-proof logic is covered without a live
daemon. The live path is exercised by the integration lab-boot gate.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from aptl.backends import raes_service_index_schema as sis
from aptl.core.deployment import _service_index_materialization as m

_CONTENT = "cortex-job-index-schema"
_INDEX = "cortex_6"
_ADDRESS = "provision.content.cortex-job-index-schema"
_FIELDS = {"key": "exact-token", "status": "exact-token", "relations": "exact-token"}
_DIGEST = sis.canonical_field_schema_digest(_FIELDS)


def _realization(address: str = _ADDRESS, content_name: str = _CONTENT, digest: str = _DIGEST):
    return SimpleNamespace(
        address=address,
        content_name=content_name,
        field_semantics_map=lambda: dict(_FIELDS),
        field_schema_digest=digest,
    )


class _FakeES:
    """Minimal Elasticsearch stub keyed off the stdin script (GET vs PUT)."""

    def __init__(self, initial: dict | None = None) -> None:
        self.state = initial  # None => index absent
        self.puts = 0

    def __call__(self, payload: str):
        # payload is the sh -s script the backend would feed on stdin.
        assert _INDEX in payload
        if "-X PUT" in payload:
            body = payload.split("-d '", 1)[1].rsplit("'", 1)[0]
            self.state = json.loads(body)["mappings"]
            self.puts += 1
            return SimpleNamespace(returncode=0, stdout="\n201")
        if self.state is None:
            return SimpleNamespace(returncode=0, stdout="\n404")
        return SimpleNamespace(returncode=0, stdout=json.dumps({_INDEX: {"mappings": self.state}}) + "\n200")


def test_fresh_create_materializes_and_proves_by_readback() -> None:
    es = _FakeES(initial=None)
    result = m.materialize_search_index_schema(es, _realization())
    assert result.ok is True
    assert result.reason is None
    assert es.puts == 1
    assert result.projection == _FIELDS
    assert result.field_schema_digest == _DIGEST
    # Created index carries the ownership marker binding it to the content address.
    assert es.state["_meta"][sis.OWNER_META_KEY] == _ADDRESS


def test_owned_existing_index_is_idempotent_no_recreate() -> None:
    owned = sis.desired_native_mapping(_FIELDS, owner_address=_ADDRESS, field_schema_digest=_DIGEST)["mappings"]
    es = _FakeES(initial=owned)
    result = m.materialize_search_index_schema(es, _realization())
    assert result.ok is True
    assert es.puts == 0  # never recreates an owned index


def test_unowned_same_name_index_is_a_collision_even_when_empty() -> None:
    # Same-name index with no owner marker (e.g. a foreign/dynamic index).
    foreign = {"properties": {"key": {"type": "keyword"}, "status": {"type": "keyword"}, "relations": {"type": "keyword"}}}
    es = _FakeES(initial=foreign)
    result = m.materialize_search_index_schema(es, _realization())
    assert result.ok is False
    assert result.reason == "unowned-collision"
    assert es.puts == 0  # never deletes or recreates an unowned index


def test_readback_mismatch_fails_closed() -> None:
    # Owned by us, but the native fields were weakened to a non-exact type.
    tampered = sis.desired_native_mapping(_FIELDS, owner_address=_ADDRESS, field_schema_digest=_DIGEST)["mappings"]
    tampered["properties"]["status"] = {"type": "text"}
    es = _FakeES(initial=tampered)
    result = m.materialize_search_index_schema(es, _realization())
    assert result.ok is False
    assert result.reason is not None


def test_missing_native_binding_fails_closed() -> None:
    es = _FakeES(initial=None)
    result = m.materialize_search_index_schema(es, _realization(content_name="unknown-content"))
    assert result.ok is False
    assert result.reason == "no-native-index-binding"
    assert es.puts == 0


def test_native_query_failure_fails_closed() -> None:
    def _broken(payload):
        return SimpleNamespace(returncode=7, stdout="")

    # readiness_timeout=0 so the API-readiness wait gives up after one probe: a
    # persistently unreachable native API fails closed instead of retrying to the
    # full budget.
    result = m.materialize_search_index_schema(
        _broken, _realization(), readiness_timeout=0.0
    )
    assert result.ok is False
    assert result.reason == "native-query-failed"


def test_native_api_not_ready_then_ready_retries_and_succeeds() -> None:
    # The container is healthy but Elasticsearch's HTTP API refuses the first
    # probes (curl exits non-zero); once it answers, materialization proceeds
    # rather than the whole plan being forced to retry (issue #889).
    es = _FakeES(initial=None)
    calls = {"n": 0}

    def _run(payload):
        calls["n"] += 1
        if calls["n"] <= 3:
            return SimpleNamespace(returncode=7, stdout="")
        return es(payload)

    slept: list[float] = []
    result = m.materialize_search_index_schema(
        _run, _realization(), sleep=slept.append
    )
    assert result.ok is True
    assert len(slept) == 3  # waited out three not-ready probes, then succeeded


def test_evidence_carries_only_safe_portable_fields() -> None:
    es = _FakeES(initial=None)
    result = m.materialize_search_index_schema(es, _realization())
    evidence = result.evidence()
    assert evidence["field_schema_digest"] == _DIGEST
    assert evidence["projected_field_semantics"] == _FIELDS
    assert evidence["readback_strength"] == "daemon-observed"
    # No native index name, endpoint, or raw response in the evidence.
    assert _INDEX not in json.dumps(evidence)
