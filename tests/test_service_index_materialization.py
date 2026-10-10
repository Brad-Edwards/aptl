"""Native materialization + readback orchestration for service-search-index-schema.

Drives :func:`materialize_search_index_schema` with a fake Elasticsearch exec so
the ownership, create, and fresh-readback-proof logic is covered without a live
daemon. The live path is exercised by the integration lab-boot gate.
"""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest
from raes_contracts.diagnostics import portable_diagnostic_payload

from aptl.backends import raes_service_index_schema as sis
from aptl.backends.raes_diagnostics import (
    PROVISIONING_ADDRESS,
    diagnostic,
    render_raes_diagnostics,
)
from aptl.core.deployment import _service_index_materialization as m
from aptl.core.deployment._compose_service_index_realization import (
    ComposeRealizationServiceIndexMixin,
)
from aptl.core.lab import _lab_start_failure_error

_ROOT = Path(__file__).parents[1]
_CONTENT = "cortex-job-index-schema"
_INDEX = "cortex_6"
_ADDRESS = "provision.content.cortex-job-index-schema"
_CONTAINER = "aptl-thehive-es"
_FOREIGN_OWNER = "provision.content.another-lab"
_FIELDS = {"key": "exact-token", "status": "exact-token", "relations": "exact-token"}
_DIGEST = sis.canonical_field_schema_digest(_FIELDS)
# curl options that leave a request a GET. Without -X, any other option (-d, -T,
# -XDELETE, --request ...) can change the method, so the stub calls it unmodelled.
_GET_CURL_OPTIONS = frozenset({"-s", "-w"})


def _realization(address: str = _ADDRESS, content_name: str = _CONTENT, digest: str = _DIGEST):
    return SimpleNamespace(
        address=address,
        content_name=content_name,
        field_semantics_map=lambda: dict(_FIELDS),
        field_schema_digest=digest,
    )


def _curl_request(script: str) -> tuple[str, list[str]]:
    """Return the HTTP method and argv of the script's one curl call."""

    (argv,) = [shlex.split(line) for line in script.splitlines() if line.startswith("curl ")]
    if "-X" in argv:
        return argv[argv.index("-X") + 1], argv
    options = {arg for arg in argv[1:] if arg.startswith("-")}
    return ("GET" if options <= _GET_CURL_OPTIONS else "unmodelled"), argv


class _FakeES:
    """Minimal Elasticsearch stub that answers each stdin script by its HTTP method."""

    def __init__(self, initial: dict | None = None) -> None:
        self.state = initial  # None => index absent
        self.puts = 0
        self.methods: list[str] = []  # every request's method, in order

    def __call__(self, payload: str):
        # payload is the sh -s script the backend would feed on stdin.
        assert _INDEX in payload
        method, argv = _curl_request(payload)
        self.methods.append(method)
        if method == "PUT":
            self.state = json.loads(argv[argv.index("-d") + 1])["mappings"]
            self.puts += 1
            return SimpleNamespace(returncode=0, stdout="\n201")
        if method != "GET":
            return SimpleNamespace(returncode=0, stdout="\n405")
        if self.state is None:
            return SimpleNamespace(returncode=0, stdout="\n404")
        return SimpleNamespace(returncode=0, stdout=json.dumps({_INDEX: {"mappings": self.state}}) + "\n200")


class _Backend(ComposeRealizationServiceIndexMixin):
    """The Compose realization step over the fake search service."""

    def __init__(self, es: _FakeES) -> None:
        self.es = es

    def container_exec_with_input(self, name, cmd, payload, *, timeout=None):
        assert (name, cmd) == (_CONTAINER, ["sh", "-s"])
        return self.es(payload)


def _realize_schema(es: _FakeES) -> str:
    """Run the realization step for the Cortex schema and return its error."""

    failure = _Backend(es)._materialize_and_verify_schemas(
        (_realization(),), {_ADDRESS: _CONTAINER}
    )
    assert failure is not None
    assert failure.success is False
    return failure.error


def _handoff_error(error: str) -> str:
    """Render ``error`` as the RAES handoff reports a failed apply."""

    provisioner = diagnostic(
        "aptl.provisioner.backend-start-failed", PROVISIONING_ADDRESS, error
    )
    # Within 512 characters the message passes the portable contract, so RAES
    # does not reject it as "Backend returned invalid diagnostic fields."
    assert portable_diagnostic_payload(provisioner)["message"] == error
    # _with_backend_failure_diagnostics puts the provisioner's report before
    # RAES's own diagnostics (a stand-in here) for the never-realized snapshot.
    sem_218 = diagnostic(
        "runtime.backend-contract-invalid", "provision.node.vm", "stand-in"
    )
    return render_raes_diagnostics([provisioner, sem_218])


def _heading_anchors(relative_path: str) -> set[str]:
    """Return the anchor that each heading of a docs page gets."""

    text = (_ROOT / relative_path).read_text(encoding="utf-8")
    return {
        re.sub(r"[^a-z0-9 -]", "", heading.lower()).replace(" ", "-")
        for heading in re.findall(r"(?m)^#{2,6} (.+)$", text)
    }


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
    relations = es.state["properties"]["relations"]
    assert relations["type"] == "join"
    assert relations["relations"]["organization"] == [
        "worker",
        "workerConfig",
        "dummy-organization",
    ]
    assert relations["relations"]["job"] == ["dummy-job", "report"]


def test_owned_existing_index_is_idempotent_no_recreate() -> None:
    first = _FakeES(initial=None)
    assert m.materialize_search_index_schema(first, _realization()).ok is True
    owned = first.state
    es = _FakeES(initial=owned)
    result = m.materialize_search_index_schema(es, _realization())
    assert result.ok is True
    assert es.puts == 0  # never recreates an owned index


def test_owned_keyword_relations_mapping_fails_the_cortex_product_contract() -> None:
    owned = sis.desired_native_mapping(
        _FIELDS, owner_address=_ADDRESS, field_schema_digest=_DIGEST
    )["mappings"]
    es = _FakeES(initial=owned)

    result = m.materialize_search_index_schema(es, _realization())

    assert result.ok is False
    assert result.reason == "native-product-contract-mismatch"
    assert es.puts == 0


def test_unowned_same_name_index_is_a_collision_even_when_empty() -> None:
    # Same-name index with no owner marker (e.g. a foreign/dynamic index).
    foreign = {"properties": {"key": {"type": "keyword"}, "status": {"type": "keyword"}, "relations": {"type": "keyword"}}}
    es = _FakeES(initial=foreign)
    result = m.materialize_search_index_schema(es, _realization())
    assert result.ok is False
    assert result.reason == "unowned-collision"
    assert es.puts == 0  # never deletes or recreates an unowned index


@pytest.mark.parametrize(
    "marker",
    [
        pytest.param({}, id="unmarked"),
        pytest.param({sis.OWNER_META_KEY: _FOREIGN_OWNER}, id="foreign-owner"),
    ],
)
def test_unowned_index_error_names_the_index_and_its_container(
    marker: dict[str, str],
) -> None:
    # An index left in an older volume: APTL cannot vouch for its data (#990).
    existing = {"_meta": marker, "properties": {"status": {"type": "keyword"}}}
    es = _FakeES(initial=existing)
    error = _realize_schema(es)

    # Refusal kept: every request was a GET, so nothing was adopted or changed.
    assert set(es.methods) == {"GET"}
    assert error in _handoff_error(error)
    for fact in (
        "(reason=unowned-collision)",
        f"search index {_INDEX} in container {_CONTAINER}",
        "cannot prove it owns the index",
        "did not adopt, delete or overwrite it",
    ):
        assert fact in error
    # What the operator runs next is added at the lab-start edge.
    assert "aptl lab" not in error
    # Nothing read from the existing index reaches the message.
    assert _FOREIGN_OWNER not in error
    assert "keyword" not in error


def test_lab_start_adds_backup_then_reset_and_the_section_for_an_unowned_index() -> None:
    error = _realize_schema(_FakeES(initial={"properties": {}}))
    handoff = _handoff_error(error)

    headline, _, hint = _lab_start_failure_error(handoff).partition("\n")

    assert headline == f"Lab start failed: {handoff}"
    assert "Back up the index" in hint
    assert "`aptl lab stop` keeps every lab volume" in hint
    assert hint.index("Back up the index") < hint.index("`aptl lab stop --volumes`")
    assert "permanently deletes every lab volume" in hint
    # The hint ends with this error's section of the published troubleshooting page.
    mkdocs = (_ROOT / "mkdocs.yml").read_text(encoding="utf-8")
    site_url = re.search(r"(?m)^site_url: (\S+)$", mkdocs)
    page, _, anchor = hint.rpartition(" ")[2].partition("#")
    assert page == f"{site_url.group(1)}troubleshooting/"
    assert anchor in _heading_anchors("docs/troubleshooting/index.md")


def test_other_failures_keep_the_plain_message_without_reset_advice() -> None:
    # Owned by this content, but its relations mapping fails Cortex's contract.
    owned = sis.desired_native_mapping(
        _FIELDS, owner_address=_ADDRESS, field_schema_digest=_DIGEST
    )["mappings"]
    error = _realize_schema(_FakeES(initial=owned))

    assert error == (
        f"service materialization failed for {_ADDRESS} "
        "(reason=native-product-contract-mismatch)"
    )
    handoff = _handoff_error(error)
    assert _lab_start_failure_error(handoff) == f"Lab start failed: {handoff}"


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
