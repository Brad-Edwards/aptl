"""Field extraction helpers for ACES-to-APTL realization."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aptl.backends.aces_profiles import normalize_identifier
from aptl.core.deployment.realization import (
    LOOPBACK_HOST_IP,
    DeploymentPublishedPort,
    DeploymentServicePort,
)

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


def service_names(node_spec: Mapping[str, Any] | None) -> set[str]:
    """Extract named services from a node specification."""

    return {service.name for service in service_ports(node_spec) if service.name}


def service_ports(
    node_spec: Mapping[str, Any] | None,
) -> tuple[DeploymentServicePort, ...]:
    """Extract a node's declared transport bindings from its compiled payload.

    ACES carries SDL ``nodes.<n>.services`` into the compiled node payload at
    ``spec.node.services`` as ``ServicePort`` dumps, each carrying ``port`` and
    ``protocol`` alongside ``name``. A service whose port is a variable that
    never got substituted is not realizable, so it is dropped rather than
    guessed at.
    """

    if not isinstance(node_spec, Mapping):
        return ()
    raw_services = node_spec.get("services")
    if not isinstance(raw_services, list):
        return ()
    services: list[DeploymentServicePort] = []
    for raw in raw_services:
        if not isinstance(raw, Mapping):
            continue
        port = _port_number(raw.get("port"))
        if port is None:
            continue
        services.append(
            DeploymentServicePort(
                name=_nonempty_string(raw.get("name")) or "",
                port=port,
                protocol=_protocol(raw.get("protocol")),
            )
        )
    return tuple(services)


def published_ports(
    node_spec: Mapping[str, Any] | None,
) -> tuple[DeploymentPublishedPort, ...]:
    """Extract a node's host-published port bindings from its compiled payload.

    ACES carries SDL ``nodes.<n>.runtime.network.published_ports`` into the
    compiled node payload at ``spec.node.runtime.network.published_ports`` as
    ``RuntimePublishedPort`` dumps. This is the host-facing exposure surface and
    is kept distinct from ``services`` (container-facing): neither is inferred
    from the other. An omitted ``host_ip`` binds loopback, never all interfaces.
    """

    if not isinstance(node_spec, Mapping):
        return ()
    runtime = mapping(node_spec.get("runtime"))
    network = mapping(runtime.get("network")) if runtime is not None else None
    raw_ports = network.get("published_ports") if network is not None else None
    if not isinstance(raw_ports, list):
        return ()
    bindings: list[DeploymentPublishedPort] = []
    for raw in raw_ports:
        if not isinstance(raw, Mapping):
            continue
        container_port = _port_number(raw.get("container_port"))
        if container_port is None:
            continue
        bindings.append(
            DeploymentPublishedPort(
                container_port=container_port,
                protocol=_protocol(raw.get("protocol")),
                host_ip=_nonempty_string(raw.get("host_ip")) or LOOPBACK_HOST_IP,
                host_port=_port_number(raw.get("host_port")),
            )
        )
    return tuple(bindings)


def _port_number(value: object) -> int | None:
    """Return a realizable TCP/UDP port, or ``None`` for absent/unsubstituted.

    ACES types a port as ``int | str`` so an authored ``${var}`` survives
    compilation. A port that is still a variable at realization time cannot be
    bound, and inventing one would be exactly the silent approximation SEM-218
    forbids — so it yields ``None`` and the binding is dropped.
    """

    if isinstance(value, bool) or not isinstance(value, int | str):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _protocol(value: object) -> str:
    """Return a normalized transport protocol, defaulting to ACES's own ``tcp``."""

    protocol = _nonempty_string(value)
    return protocol.lower() if protocol is not None else "tcp"


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

    return {
        address
        for _, address in static_address_assignments(infra_spec)
    }


def static_address_assignments(
    infra_spec: Mapping[str, Any] | None,
) -> tuple[tuple[str, str], ...]:
    """Extract static host addresses keyed by linked network."""

    if infra_spec is None:
        return ()
    assignments = _static_assignments_from_properties(
        infra_spec.get("properties"),
        infra_spec,
    )
    return tuple(sorted(assignments.items()))


def _static_assignments_from_properties(
    properties: object,
    infra_spec: Mapping[str, Any],
) -> dict[str, str]:
    """Extract static assignments from ACES infrastructure properties."""

    if isinstance(properties, list):
        return _static_assignments_from_property_list(properties)
    if isinstance(properties, Mapping):
        return _static_assignments_from_property_mapping(properties, infra_spec)
    return {}


def _static_assignments_from_property_list(
    properties: list[object],
) -> dict[str, str]:
    """Extract explicit network-to-address property entries."""

    assignments: dict[str, str] = {}
    for item in properties:
        if isinstance(item, Mapping):
            assignments.update(_static_assignments_from_property_item(item))
    return assignments


def _static_assignments_from_property_item(
    item: Mapping[object, object],
) -> dict[str, str]:
    """Extract static addresses from one ACES network-property mapping."""

    assignments: dict[str, str] = {}
    for network, address in item.items():
        network_name = str(network).strip()
        address_value = _nonempty_string(address)
        if network_name and address_value is not None:
            assignments[network_name] = address_value
    return assignments


def _static_assignments_from_property_mapping(
    properties: Mapping[str, Any],
    infra_spec: Mapping[str, Any],
) -> dict[str, str]:
    """Extract a single static address from legacy scalar property forms."""

    address = _first_static_address_value(properties)
    network_values = sorted(network_names(infra_spec))
    if address is not None and len(network_values) == 1:
        return {network_values[0]: address}
    return {}


def _first_static_address_value(properties: Mapping[str, Any]) -> str | None:
    """Return the first non-empty legacy static address property."""

    for key in ("address", "ip", "ipv4_address", "static_address"):
        value = _nonempty_string(properties.get(key))
        if value is not None:
            return value
    return None


def _nonempty_string(value: object) -> str | None:
    """Return a stripped string only when it carries content."""

    return value if isinstance(value, str) and value.strip() else None


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


def placement_spec(payload: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Return the compiled ACES resource spec (the Content/Account dump)."""

    return mapping(payload.get("spec"))


def content_source(spec: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Return the ``source`` sub-mapping of a compiled Content spec, if any."""

    return mapping(spec.get("source"))


def content_source_name(spec: Mapping[str, Any]) -> str | None:
    """Return the checked-in/observed source name declared on a Content spec."""

    source = content_source(spec)
    return optional_string(source, "name") if source is not None else None


def content_text(spec: Mapping[str, Any]) -> str | None:
    """Return the inline text declared on a Content spec, if any."""

    return optional_string(spec, "text")


def account_groups(spec: Mapping[str, Any]) -> tuple[str, ...]:
    """Return the group memberships declared on an Account spec."""

    groups = spec.get("groups")
    if not isinstance(groups, list):
        return ()
    return tuple(sorted({g for g in groups if isinstance(g, str) and g.strip()}))
