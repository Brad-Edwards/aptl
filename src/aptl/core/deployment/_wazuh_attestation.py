"""Pure helpers for declared Wazuh readiness and fact attestation."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from aptl.core.deployment._wazuh_identity import WazuhClusterIdentity
from aptl.core.deployment.realization import DeploymentNodeRealization
from aptl.core.env import (
    EnvVars,
    env_vars_from_dict,
    find_placeholder_env_values,
    load_dotenv,
)
from aptl.utils.curl_safe import basic_auth_header, curl_json

AUTHENTICATED_FACT_ID = "api:authenticated"


def load_stateful_env(project_dir: Path) -> tuple[EnvVars | None, bool]:
    """Load typed credentials and report whether placeholders caused rejection."""

    env: EnvVars | None = None
    placeholder_input = False
    try:
        raw_env = load_dotenv(project_dir / ".env")
        placeholder_input = bool(find_placeholder_env_values(raw_env))
        if not placeholder_input:
            candidate = env_vars_from_dict(raw_env)
            credentials = (
                candidate.indexer_username,
                candidate.indexer_password,
                candidate.api_username,
                candidate.api_password,
            )
            env = candidate if all(credentials) else None
    except (OSError, ValueError):
        env = None
    return env, placeholder_input


def readiness_failure(observations: Mapping[str, object], timeout: int) -> str | None:
    """Render the terminal reason for observations still unready at the deadline."""

    failed = [
        observation
        for _service, observation in sorted(observations.items())
        if not getattr(observation, "ready", False)
    ]
    if not failed:
        return None
    reasons = "; ".join(str(getattr(item, "detail", "")) for item in failed)
    containers = [
        str(getattr(item, "container_name"))
        for item in failed
        if getattr(item, "container_name", None)
    ]
    logs = " and ".join(f"`aptl container logs {name}`" for name in containers)
    action = f" Inspect {logs}." if logs else ""
    return (
        f"Authenticated Wazuh readiness validation failed after {timeout}s: "
        f"{reasons}.{action}"
    )


def declares_wazuh_native_service(
    node: DeploymentNodeRealization, identity: WazuhClusterIdentity
) -> bool:
    """Return whether the admitted runtime authorizes a native Wazuh query."""

    declared = False
    if node.runtime is not None:
        if node.service_name == identity.indexer_service:
            declared = declared_indexer(node) is not None
        elif node.service_name == identity.manager_service:
            declared = any(
                _enum_value(getattr(manager, "implementation", "")) == "wazuh"
                for manager in getattr(node.runtime, "security_monitoring_managers", ())
            )
    return declared


def _enum_value(value: object) -> str:
    """Return an enum-like value as a stable string."""

    return str(getattr(value, "value", value))


def declared_indexer(node: object | None) -> object | None:
    """Return the node's single declared OpenSearch datastore, if present."""

    runtime = getattr(node, "runtime", None)
    stores = [
        store
        for store in getattr(runtime, "datastore_services", ())
        if _enum_value(getattr(store, "engine", "")) in {"opensearch", "elasticsearch"}
    ]
    return stores[0] if len(stores) == 1 else None


def declared_manager_components(node: object | None) -> frozenset[str]:
    """Return manager-owned enabled processes declared by the realization."""

    runtime = getattr(node, "runtime", None)
    managers = [
        manager
        for manager in getattr(runtime, "security_monitoring_managers", ())
        if _enum_value(getattr(manager, "implementation", "")) == "wazuh"
    ]
    if len(managers) != 1:
        return frozenset()
    return frozenset(
        str(component.name)
        for component in getattr(managers[0], "components", ())
        if getattr(component, "enabled", False)
        and str(getattr(component, "name", "")).startswith("wazuh-")
    )


def observe_indexer_declared_facts(
    url: str,
    username: str,
    password: str,
    datastore: object | None,
) -> tuple[dict[str, str], ...]:
    """Compare bounded indexer readback with every declared native fact."""

    if datastore is None:
        return ()
    partitions = tuple(getattr(datastore, "partitions", ()) or ())
    templates = tuple(getattr(datastore, "templates", ()) or ())
    mappings = tuple(getattr(datastore, "mappings", ()) or ())
    if not any((partitions, templates, mappings)):
        return ()
    header = basic_auth_header(username, password)
    base = url.rstrip("/")
    return (
        _observe_partitions(base, header, partitions)
        + _observe_templates(base, header, templates)
        + _observe_mappings(base, header, mappings)
    )


def _observe_partitions(
    base: str, header: str, partitions: tuple[object, ...]
) -> tuple[dict[str, str], ...]:
    """Observe every declared datastore partition."""

    if not partitions:
        return ()
    names = ",".join(str(item.name) for item in partitions)
    payload = curl_json(
        f"{base}/_cluster/state/metadata/{names}",
        auth_header=header,
        insecure=True,
        timeout=30,
    )
    indices = _index_metadata(payload)
    return tuple(
        _partition_observation(item, indices.get(str(item.name))) for item in partitions
    )


def _observe_templates(
    base: str, header: str, templates: tuple[object, ...]
) -> tuple[dict[str, str], ...]:
    """Observe every declared legacy index template."""

    if not templates:
        return ()
    names = ",".join(str(item.name) for item in templates)
    payload = curl_json(
        f"{base}/_template/{names}",
        auth_header=header,
        insecure=True,
        timeout=30,
    )
    return tuple(
        _fact_observation(
            f"template:{item.name}",
            "present",
            "present"
            if isinstance(payload, Mapping) and str(item.name) in payload
            else "missing",
            isinstance(payload, Mapping) and str(item.name) in payload,
            "declared-template-missing",
        )
        for item in templates
    )


def _observe_mappings(
    base: str, header: str, mappings: tuple[object, ...]
) -> tuple[dict[str, str], ...]:
    """Observe every declared index mapping."""

    if not mappings:
        return ()
    names = ",".join(str(item.name) for item in mappings)
    payload = curl_json(
        f"{base}/{names}/_mapping",
        auth_header=header,
        insecure=True,
        timeout=30,
    )
    return tuple(
        _mapping_observation(
            item,
            payload.get(str(item.name)) if isinstance(payload, Mapping) else None,
        )
        for item in mappings
    )


def _fact_observation(
    fact_id: str,
    expected: str,
    observed: str,
    matched: bool,
    failure_category: str,
) -> dict[str, str]:
    """Build one bounded, stable, secret-free declared-fact observation."""

    return {
        "fact_id": fact_id,
        "expected": expected,
        "observed": observed,
        "status": "matched" if matched else "failed",
        "failure_category": "" if matched else failure_category,
    }


def fact_observation(
    fact_id: str,
    expected: str,
    observed: str,
    matched: bool,
    failure_category: str,
) -> dict[str, str]:
    """Expose the stable fact projection to the readiness owner."""

    return _fact_observation(fact_id, expected, observed, matched, failure_category)


def _partition_observation(declared: object, observed: object) -> dict[str, str]:
    """Describe one declared partition and its native readback."""

    expected = f"shards={declared.shard_count},replicas={declared.replica_count}"
    settings = observed.get("settings") if isinstance(observed, Mapping) else None
    index = settings.get("index") if isinstance(settings, Mapping) else None
    actual = (
        f"shards={index.get('number_of_shards')},replicas={index.get('number_of_replicas')}"
        if isinstance(index, Mapping)
        else "missing"
    )
    return _fact_observation(
        f"partition:{declared.name}",
        expected,
        actual,
        _partition_matches(declared, observed),
        "declared-partition-missing-or-mismatched",
    )


def _mapping_observation(declared: object, observed: object) -> dict[str, str]:
    """Describe one declared mapping and its native readback."""

    expected_count = getattr(declared, "top_level_field_count", None)
    mappings = observed.get("mappings") if isinstance(observed, Mapping) else None
    properties = mappings.get("properties") if isinstance(mappings, Mapping) else None
    actual_count = len(properties) if isinstance(properties, Mapping) else None
    return _fact_observation(
        f"mapping:{declared.name}",
        "present" if expected_count is None else f"top-level-fields={expected_count}",
        "missing" if actual_count is None else f"top-level-fields={actual_count}",
        _mapping_matches(declared, observed),
        "declared-mapping-missing-or-mismatched",
    )


def declared_wazuh_fact_ids(node: object) -> frozenset[str]:
    """Return the exact native facts required by one declared Wazuh node."""

    result: frozenset[str] = frozenset()
    name = getattr(node, "name", "")
    if name == "wazuh-indexer":
        store = declared_indexer(node)
        if store is not None:
            result = frozenset(
                [AUTHENTICATED_FACT_ID]
                + [
                    f"partition:{item.name}"
                    for item in getattr(store, "partitions", ())
                ]
                + [f"template:{item.name}" for item in getattr(store, "templates", ())]
                + [f"mapping:{item.name}" for item in getattr(store, "mappings", ())]
            )
    elif name == "wazuh-manager":
        result = frozenset(
            [AUTHENTICATED_FACT_ID]
            + [
                f"component:{component}"
                for component in declared_manager_components(node)
            ]
        )
    return result


def declared_wazuh_facts_match(
    attestation: object, service: str | None, node: object | None = None
) -> bool:
    """Require matched structured observations for the exact declaration."""

    facts = (
        attestation.get(service)
        if isinstance(attestation, Mapping) and service
        else None
    )
    valid_facts = isinstance(facts, (tuple, list)) and bool(facts)
    observed = (
        {
            fact.get("fact_id")
            for fact in facts
            if isinstance(fact, Mapping) and fact.get("status") == "matched"
        }
        if valid_facts
        else set()
    )
    expected = declared_wazuh_fact_ids(node) if node is not None else observed
    return (
        bool(expected)
        and valid_facts
        and len(observed) == len(facts)
        and observed == expected
    )


def _index_metadata(payload: object) -> Mapping[str, object]:
    """Project index metadata from one bounded cluster-state response."""

    metadata = payload.get("metadata") if isinstance(payload, Mapping) else None
    indices = metadata.get("indices") if isinstance(metadata, Mapping) else None
    return indices if isinstance(indices, Mapping) else {}


def _partition_matches(declared: object, observed: object) -> bool:
    """Return whether one partition matches its declared shard topology."""

    settings = observed.get("settings") if isinstance(observed, Mapping) else None
    index = settings.get("index") if isinstance(settings, Mapping) else None
    return (
        isinstance(index, Mapping)
        and str(index.get("number_of_shards")) == str(declared.shard_count)
        and str(index.get("number_of_replicas")) == str(declared.replica_count)
    )


def _mapping_matches(declared: object, observed: object) -> bool:
    """Return whether one mapping matches its declared top-level shape."""

    mappings = observed.get("mappings") if isinstance(observed, Mapping) else None
    properties = mappings.get("properties") if isinstance(mappings, Mapping) else None
    expected = getattr(declared, "top_level_field_count", None)
    return isinstance(properties, Mapping) and (
        expected is None or len(properties) == expected
    )


__all__ = [
    "AUTHENTICATED_FACT_ID",
    "declared_indexer",
    "declared_manager_components",
    "declared_wazuh_fact_ids",
    "declared_wazuh_facts_match",
    "declares_wazuh_native_service",
    "fact_observation",
    "load_stateful_env",
    "observe_indexer_declared_facts",
    "readiness_failure",
]
