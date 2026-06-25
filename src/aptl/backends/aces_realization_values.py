"""Field extraction helpers for ACES-to-APTL realization."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aptl.backends.aces_profiles import normalize_identifier

PLACEMENT_TARGET_KEYS = {
    "account-placement": ("target_address", "node_name"),
    "content-placement": ("target_address", "target_node"),
    "feature-binding": ("node_address", "node_name"),
}


def placement_target_values(
    resource_type: str,
    payload: Mapping[str, Any],
) -> tuple[str, ...]:
    """Return candidate node reference values for a placement resource."""

    return payload_string_values(payload, PLACEMENT_TARGET_KEYS.get(resource_type, ()))


def resolve_target_address(
    target_values: tuple[str, ...],
    node_lookup: dict[str, str],
) -> str | None:
    """Resolve placement target text to a realized node address."""

    for value in target_values:
        if value in node_lookup:
            return node_lookup[value]
        normalized = normalize_identifier(value)
        if normalized in node_lookup:
            return node_lookup[normalized]
    return None


def resource_name(address: str, payload: Mapping[str, Any]) -> str:
    """Return a resource display name, defaulting to its ACES address."""

    return first_nonempty_string(payload_string_values(payload, ("name",))) or address


def runtime_spec(
    payload: Mapping[str, Any],
    spec: Mapping[str, Any] | None,
) -> Mapping[str, Any] | None:
    """Return the runtime-specific payload block when present."""

    for container in (payload, spec):
        if container is None:
            continue
        runtime = container.get("runtime")
        if isinstance(runtime, Mapping):
            return runtime
        aptl = container.get("aptl")
        if isinstance(aptl, Mapping):
            return aptl
    return None


def service_names(node_spec: Mapping[str, Any] | None) -> set[str]:
    """Extract named services from a node specification."""

    if node_spec is None:
        return set()
    services = node_spec.get("services")
    if not isinstance(services, list):
        return set()
    names: set[str] = set()
    for service in services:
        if not isinstance(service, Mapping):
            continue
        name = service.get("name")
        if isinstance(name, str) and name.strip():
            names.add(name)
    return names


def health_status(node_spec: Mapping[str, Any] | None) -> str | None:
    """Extract the declared health status from a node's runtime block.

    ACES carries the SDL ``runtime.health`` declaration into the compiled node
    payload at ``spec.node.runtime.health.status``. The ``status`` is the
    realizable expectation (e.g. ``healthy``) compared against live container
    health; the sibling ``description`` is prose and is not realized.
    """

    runtime = node_spec.get("runtime") if isinstance(node_spec, Mapping) else None
    health = runtime.get("health") if isinstance(runtime, Mapping) else None
    status = health.get("status") if isinstance(health, Mapping) else None
    return status if isinstance(status, str) and status.strip() else None


def network_names(infra_spec: Mapping[str, Any] | None) -> set[str]:
    """Extract linked network names from infrastructure details."""

    if infra_spec is None:
        return set()
    return string_values(infra_spec.get("links"))


def dependency_names(infra_spec: Mapping[str, Any] | None) -> set[str]:
    """Extract declared node dependency names from infrastructure details."""

    if infra_spec is None:
        return set()
    return string_values(infra_spec.get("dependencies"))


def static_addresses(infra_spec: Mapping[str, Any] | None) -> set[str]:
    """Extract static host addresses from infrastructure details."""

    if infra_spec is None:
        return set()
    properties = infra_spec.get("properties")
    addresses: set[str] = set()
    if isinstance(properties, list):
        for item in properties:
            if isinstance(item, Mapping):
                addresses.update(string_values(item.values()))
    elif isinstance(properties, Mapping):
        for key in ("address", "ip", "ipv4_address", "static_address"):
            value = properties.get(key)
            if isinstance(value, str) and value.strip():
                addresses.add(value)
    return addresses


def string_list(
    payload: Mapping[str, Any] | None,
    key: str,
) -> set[str]:
    """Extract a string set from an optional mapping key."""

    if payload is None:
        return set()
    return string_values(payload.get(key))


def string_values(raw: object) -> set[str]:
    """Normalize scalar or collection values into non-empty strings."""

    if isinstance(raw, str):
        return {raw} if raw.strip() else set()
    if isinstance(raw, Mapping):
        raw = raw.values()
    if isinstance(raw, list | tuple | set | frozenset):
        return {str(value) for value in raw if str(value).strip()}
    return set()


def payload_string_values(
    payload: Mapping[str, Any],
    keys: tuple[str, ...],
) -> tuple[str, ...]:
    """Return non-empty string values from payload keys in order."""

    values: list[str] = []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value)
    return tuple(values)


def first_nonempty_string(values: tuple[str, ...]) -> str | None:
    """Return the first non-empty string from a candidate tuple."""

    for value in values:
        if value.strip():
            return value
    return None


def optional_string(
    payload: Mapping[str, Any] | None,
    key: str,
) -> str | None:
    """Return a non-empty string property from an optional mapping."""

    if payload is None:
        return None
    value = payload.get(key)
    return value if isinstance(value, str) and value.strip() else None


def optional_bool(
    payload: Mapping[str, Any] | None,
    key: str,
) -> bool | None:
    """Return a boolean property from an optional mapping."""

    if payload is None:
        return None
    value = payload.get(key)
    return value if isinstance(value, bool) else None


def mapping(value: object) -> Mapping[str, Any] | None:
    """Return mapping values while rejecting scalar payload fragments."""

    return value if isinstance(value, Mapping) else None
