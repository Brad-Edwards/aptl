"""Native Elasticsearch materialization + fresh readback for the ADR-088
``service-search-index-schema`` profile (issue #889).

The deployment backend realizes a
:class:`~aptl.core.deployment.realization.DeploymentServiceSearchIndexSchemaRealization`
by ensuring the declared portable field schema exists on the target search
service and proving it by a fresh native readback whose portable projection
reproduces the RAES-compiled ``field_schema_digest``.

Contract points enforced here (RAES ADR-088 / OpenRAE/rae#1011, APTL preflight):

- **Native ids never reach host argv.** The concrete index name, endpoint, and
  request bodies travel on stdin to ``sh -s`` inside the target container; the
  host process only ever runs ``docker exec -i <container> sh -s``. The response
  body is normalized in memory and only a safe portable projection + digest
  crosses back out.
- **Ownership (``reject-unowned-collision``).** An existing same-name index is
  adopted only when its ``_meta`` marker binds it to the exact portable content
  address. An unmarked or foreign-owned index is an unowned collision even when
  empty — never deleted, recreated, or adopted.
- **Proof is fresh native readback.** Success requires a new ``_mapping`` query
  after any mutation, projected to the declared portable semantics, whose
  canonical digest equals the declared digest. A create/PUT response, the stored
  marker, or container health is never accepted as proof.

The native index name is an adapter/configuration concern (ADR-088 keeps native
ids out of the portable SDL): ``cortex_6`` is the Cortex 3.1.8 product job-index
name, known to this backend adapter, not authored in the scenario.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from aptl.backends import raes_service_index_schema as sis

# Adapter/configuration binding from the portable content address (canonical
# ``content.<id>`` identity) to the concrete native index name. This is the one
# place a product-native id lives (ADR-088); it is not the forbidden
# content-id-to-*schema* table — the field schema is authored in the SDL.
_NATIVE_INDEX_NAMES: dict[str, str] = {
    # Cortex 3.1.8 key-auth job index on thehive-es (was scripts/cortex-index-init.sh).
    "cortex-job-index-schema": "cortex_6",
}

# Native index names are embedded into a stdin shell script, so they must be a
# conservative, injection-safe token before use.
_NATIVE_INDEX_RE = re.compile(r"^[a-z0-9_][a-z0-9_.-]*$")

_ES_BASE = "http://localhost:9200"

# Bounded timeout for one native materialization/readback exec; the backend step
# binds this into its ``run_script`` closure.
MATERIALIZATION_TIMEOUT = 60

# A passing container healthcheck does not mean the target search service is
# serving its HTTP API yet: Elasticsearch keeps initializing after the healthcheck
# reports healthy, so the first native query can hit a connection refusal. These
# bound a readiness wait that retries the initial mapping query until the API
# answers, so a clean first boot materializes without a spurious failure that
# would otherwise abort and force a whole-plan retry (issue #889). Generous: an ES
# API cold-start after container health on a loaded fresh machine can take a while.
_API_READINESS_TIMEOUT = 300.0
_API_READINESS_INTERVAL = 3.0

# Runs one ``sh -s`` script inside the target container and returns a
# CompletedProcess-shaped object (``returncode`` + ``stdout``). The backend binds
# it to its selected-daemon ``container_exec_with_input`` so the script (carrying
# the native index name, endpoint, and any request body) travels on stdin.
RunScript = Callable[[str], Any]


@dataclass(frozen=True)
class ServiceIndexMaterializationResult:
    """Outcome of one native materialization + readback attempt.

    On success carries only safe portable evidence (the projected field map, the
    digest, and the readback strength) — never the raw native response.
    """

    ok: bool
    address: str
    content_name: str
    reason: str | None = None
    projection: dict[str, str] = field(default_factory=dict)
    field_schema_digest: str = ""
    readback_strength: str = "daemon-observed"

    def evidence(self) -> dict[str, object]:
        return {
            "address": self.address,
            "content_name": self.content_name,
            "field_schema_digest": self.field_schema_digest,
            "readback_strength": self.readback_strength,
            "projected_field_semantics": dict(self.projection),
        }


def native_index_name(content_name: str) -> str | None:
    """Return the adapter-configured native index name for a content address."""

    return _NATIVE_INDEX_NAMES.get(content_name)


def _render_get_mapping_script(index: str) -> str:
    # Body then a final line with the HTTP status, so the caller can distinguish
    # 404 (absent) from 200 without the status entering host argv.
    return (
        "set -eu\n"
        f"curl -s -w '\\n%{{http_code}}' '{_ES_BASE}/{index}/_mapping'\n"
    )


def _render_put_index_script(index: str, mapping_json: str) -> str:
    # mapping_json is canonical JSON (double quotes only, no single quotes), so
    # single-quote embedding is injection-safe.
    return (
        "set -eu\n"
        f"curl -s -w '\\n%{{http_code}}' -X PUT "
        f"-H 'Content-Type: application/json' '{_ES_BASE}/{index}' "
        f"-d '{mapping_json}'\n"
    )


def _split_body_and_code(stdout: str) -> tuple[str, int | None]:
    """Split ``<body>\\n<http_code>`` stdout into the body and integer status."""

    text = stdout.rstrip("\n")
    if "\n" not in text:
        code_text = text
        body = ""
    else:
        body, _, code_text = text.rpartition("\n")
    try:
        return body, int(code_text.strip())
    except ValueError:
        return body, None


def _index_section(parsed: Mapping[str, Any], index: str) -> Mapping[str, Any] | None:
    section = parsed.get(index)
    return section if isinstance(section, Mapping) else None


def materialize_search_index_schema(
    run_script: RunScript,
    realization: Any,
    *,
    sleep: Callable[[float], None] = time.sleep,
    time_source: Callable[[], float] = time.monotonic,
    readiness_timeout: float = _API_READINESS_TIMEOUT,
    readiness_interval: float = _API_READINESS_INTERVAL,
) -> ServiceIndexMaterializationResult:
    """Ensure the declared portable field schema on the target service and prove it.

    ``run_script(script)`` runs one ``sh -s`` script inside the target container
    with the script on stdin, returning a ``CompletedProcess``-shaped object. The
    caller binds it to the backend's selected-daemon exec surface. ``sleep`` /
    ``time_source`` are injectable so the API-readiness wait is deterministic under
    test.
    """

    address = realization.address
    content_name = realization.content_name
    fields = realization.field_semantics_map()
    digest = realization.field_schema_digest

    def _fail(reason: str) -> ServiceIndexMaterializationResult:
        return ServiceIndexMaterializationResult(
            ok=False, address=address, content_name=content_name, reason=reason
        )

    index = native_index_name(content_name)
    if index is None:
        return _fail("no-native-index-binding")
    if _NATIVE_INDEX_RE.fullmatch(index) is None:
        return _fail("native-index-name-unsafe")

    def _exec(script: str) -> tuple[str, int | None, int]:
        result = run_script(script)
        body, code = _split_body_and_code(getattr(result, "stdout", "") or "")
        return body, code, int(getattr(result, "returncode", 1) or 0)

    # 1. Existence + ownership check (reject-unowned-collision), once the target
    # service's native API accepts queries. The container healthcheck passing does
    # not mean Elasticsearch is serving HTTP yet, so retry the mapping query until
    # it answers with an HTTP status (200/404/...) or the readiness budget is
    # exhausted -- rather than failing the first query and forcing a whole-plan
    # retry. A non-zero exec (docker exec not ready, or curl connection refused)
    # is a not-ready signal, never a materialization verdict.
    deadline = time_source() + readiness_timeout
    while True:
        body, http_code, rc = _exec(_render_get_mapping_script(index))
        if rc == 0 and http_code is not None:
            break
        if time_source() >= deadline:
            return _fail("native-query-failed")
        sleep(readiness_interval)
    if http_code == 200:
        try:
            existing = json.loads(body)
        except json.JSONDecodeError:
            return _fail("native-response-unparsable")
        section = _index_section(existing, index) if isinstance(existing, Mapping) else None
        mappings = section.get("mappings") if isinstance(section, Mapping) else None
        meta = mappings.get("_meta") if isinstance(mappings, Mapping) else None
        owner, _owned_digest = sis.owner_marker(meta if isinstance(meta, Mapping) else {})
        if owner != address:
            return _fail("unowned-collision")
        # Owned index: fall through to a fresh readback (idempotent re-entry).
    elif http_code == 404:
        mapping_body = sis.desired_native_mapping(
            fields, owner_address=address, field_schema_digest=digest
        )
        _pbody, put_code, put_rc = _exec(
            _render_put_index_script(index, json.dumps(mapping_body, separators=(",", ":")))
        )
        if put_rc != 0 or put_code not in (200, 201):
            return _fail("native-create-failed")
    else:
        return _fail("native-unexpected-status")

    # 2. Fresh native readback (proof) — always after any mutation.
    rbody, rcode, rrc = _exec(_render_get_mapping_script(index))
    if rrc != 0 or rcode != 200:
        return _fail("native-readback-failed")
    try:
        observed = json.loads(rbody)
    except json.JSONDecodeError:
        return _fail("native-response-unparsable")
    section = _index_section(observed, index) if isinstance(observed, Mapping) else None
    mappings = section.get("mappings") if isinstance(section, Mapping) else None
    properties = mappings.get("properties") if isinstance(mappings, Mapping) else None
    if not isinstance(properties, Mapping):
        return _fail("native-readback-missing-properties")
    ok, projection, reason = sis.verify_readback(properties, fields, declared_digest=digest)
    if not ok:
        return _fail(reason or "native-readback-mismatch")
    return ServiceIndexMaterializationResult(
        ok=True,
        address=address,
        content_name=content_name,
        projection=projection or {},
        field_schema_digest=digest,
    )
