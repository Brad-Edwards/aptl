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
from typing import TYPE_CHECKING, Any

from aptl.backends import raes_service_index_schema as sis

if TYPE_CHECKING:
    from aptl.core.deployment.realization import (
        DeploymentServiceSearchIndexSchemaRealization,
    )

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


class _MaterializationFailure(Exception):
    """Internal control-flow signal carrying a portable failure reason.

    Raised by the native-exec helper steps below and caught once, at the top of
    :func:`materialize_search_index_schema`, so each step reports its own
    failure without every caller re-threading a reason string back up.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


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


@dataclass(frozen=True)
class _ExecResult:
    """One ``run_script`` call, split into its HTTP body/status and exit code."""

    body: str
    http_code: int | None
    returncode: int


def native_index_name(content_name: str) -> str | None:
    """Return the adapter-configured native index name for a content address."""

    return _NATIVE_INDEX_NAMES.get(content_name)


def _render_get_mapping_script(index: str) -> str:
    """Render the stdin script that fetches ``index``'s current mapping."""

    # Body then a final line with the HTTP status, so the caller can distinguish
    # 404 (absent) from 200 without the status entering host argv.
    return (
        "set -eu\n"
        f"curl -s -w '\\n%{{http_code}}' '{_ES_BASE}/{index}/_mapping'\n"
    )


def _render_put_index_script(index: str, mapping_json: str) -> str:
    """Render the stdin script that creates ``index`` with ``mapping_json``."""

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
    """Return ``parsed[index]`` if it is itself a mapping, else ``None``."""

    section = parsed.get(index)
    return section if isinstance(section, Mapping) else None


def _safe_json(text: str) -> Any | None:
    """Parse JSON, returning ``None`` instead of raising on invalid input."""

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _exec_script(run_script: RunScript, script: str) -> _ExecResult:
    """Run ``script`` via ``run_script`` and split its stdout into an ``_ExecResult``."""

    result = run_script(script)
    body, code = _split_body_and_code(getattr(result, "stdout", "") or "")
    return _ExecResult(
        body=body, http_code=code, returncode=int(getattr(result, "returncode", 1) or 0)
    )


def _wait_for_native_api(
    run_script: RunScript,
    index: str,
    *,
    sleep: Callable[[float], None],
    time_source: Callable[[], float],
    readiness_timeout: float,
    readiness_interval: float,
) -> _ExecResult:
    """Poll the mapping endpoint until the native API answers an HTTP status.

    The container healthcheck passing does not mean Elasticsearch is serving
    HTTP yet, so a non-zero exec (docker exec not ready, or curl connection
    refused) is treated as not-ready and retried until ``readiness_timeout`` is
    exhausted, rather than failing the first query and forcing a whole-plan
    retry.
    """

    deadline = time_source() + readiness_timeout
    while True:
        result = _exec_script(run_script, _render_get_mapping_script(index))
        if result.returncode == 0 and result.http_code is not None:
            return result
        if time_source() >= deadline:
            raise _MaterializationFailure("native-query-failed")
        sleep(readiness_interval)


def _check_ownership(body: str, index: str, address: str) -> None:
    """Raise unless the existing index at ``index`` is owned by ``address``."""

    existing = _safe_json(body)
    if not isinstance(existing, Mapping):
        raise _MaterializationFailure("native-response-unparsable")
    section = _index_section(existing, index)
    mappings = section.get("mappings") if isinstance(section, Mapping) else None
    meta = mappings.get("_meta") if isinstance(mappings, Mapping) else None
    owner, _owned_digest = sis.owner_marker(meta if isinstance(meta, Mapping) else {})
    if owner != address:
        raise _MaterializationFailure("unowned-collision")


def _create_index(
    run_script: RunScript, index: str, address: str, fields: Mapping[str, str], digest: str
) -> None:
    """Create ``index`` with the declared portable schema, raising on failure."""

    mapping_body = sis.desired_native_mapping(
        fields, owner_address=address, field_schema_digest=digest
    )
    result = _exec_script(
        run_script, _render_put_index_script(index, json.dumps(mapping_body, separators=(",", ":")))
    )
    if result.returncode != 0 or result.http_code not in (200, 201):
        raise _MaterializationFailure("native-create-failed")


def _ensure_index_exists(
    run_script: RunScript,
    index: str,
    address: str,
    fields: Mapping[str, str],
    digest: str,
    probe: _ExecResult,
) -> None:
    """Ensure ``index`` exists and is owned by ``address``, creating it if absent."""

    if probe.http_code == 200:
        _check_ownership(probe.body, index, address)
    elif probe.http_code == 404:
        _create_index(run_script, index, address, fields, digest)
    else:
        raise _MaterializationFailure("native-unexpected-status")


def _parse_readback_properties(result: _ExecResult, index: str) -> Mapping[str, Any]:
    """Extract index ``properties`` from a readback exec result, raising on failure."""

    if result.returncode != 0 or result.http_code != 200:
        raise _MaterializationFailure("native-readback-failed")
    observed = _safe_json(result.body)
    if not isinstance(observed, Mapping):
        raise _MaterializationFailure("native-response-unparsable")
    section = _index_section(observed, index)
    mappings = section.get("mappings") if isinstance(section, Mapping) else None
    properties = mappings.get("properties") if isinstance(mappings, Mapping) else None
    if not isinstance(properties, Mapping):
        raise _MaterializationFailure("native-readback-missing-properties")
    return properties


def _read_and_verify_schema(
    run_script: RunScript, index: str, fields: Mapping[str, str], digest: str
) -> dict[str, str]:
    """Fresh native readback (proof), projected and verified against ``digest``."""

    result = _exec_script(run_script, _render_get_mapping_script(index))
    properties = _parse_readback_properties(result, index)
    ok, projection, reason = sis.verify_readback(properties, fields, declared_digest=digest)
    if not ok:
        raise _MaterializationFailure(reason or "native-readback-mismatch")
    return projection or {}


def _validate_native_index(content_name: str) -> tuple[str | None, str | None]:
    """Resolve and validate the native index name for ``content_name``, or a reject reason."""

    index = native_index_name(content_name)
    if index is None:
        return None, "no-native-index-binding"
    if _NATIVE_INDEX_RE.fullmatch(index) is None:
        return None, "native-index-name-unsafe"
    return index, None


def materialize_search_index_schema(
    run_script: RunScript,
    realization: DeploymentServiceSearchIndexSchemaRealization,
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

    index, reason = _validate_native_index(content_name)
    if reason is not None:
        return ServiceIndexMaterializationResult(
            ok=False, address=address, content_name=content_name, reason=reason
        )

    try:
        probe = _wait_for_native_api(
            run_script,
            index,
            sleep=sleep,
            time_source=time_source,
            readiness_timeout=readiness_timeout,
            readiness_interval=readiness_interval,
        )
        # 1. Existence + ownership check (reject-unowned-collision), then 2. a
        # fresh native readback (proof) — always after any mutation.
        _ensure_index_exists(run_script, index, address, fields, digest, probe)
        projection = _read_and_verify_schema(run_script, index, fields, digest)
    except _MaterializationFailure as failure:
        return ServiceIndexMaterializationResult(
            ok=False, address=address, content_name=content_name, reason=failure.reason
        )

    return ServiceIndexMaterializationResult(
        ok=True,
        address=address,
        content_name=content_name,
        projection=projection,
        field_schema_digest=digest,
    )
