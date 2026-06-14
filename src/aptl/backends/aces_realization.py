"""APTL realization contract for ACES provisioning plans."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from aces_contracts.diagnostics import Diagnostic
from aces_contracts.planning import PlannedResource, ProvisioningPlan

from aptl.backends.aces_diagnostics import (
    PROVISIONING_ADDRESS,
    SUPPORTED_RESOURCE_TYPES,
    diagnostic,
    unsupported_resource_diagnostics,
)
from aptl.backends.aces_profiles import (
    ComposeProfileIndex,
    configured_profiles,
    explicit_compose_profile_hints,
    load_compose_profile_index,
    node_aliases,
    normalize_identifier,
)
from aptl.core.config import AptlConfig
from aptl.utils.redaction import redact

PLACEMENT_RESOURCE_TYPES = frozenset(
    {"feature-binding", "content-placement", "account-placement"}
)


@dataclass(frozen=True)
class NodeRealization(object):
    """APTL realization data for one ACES node resource."""

    address: str
    name: str
    aliases: tuple[str, ...]
    profiles: tuple[str, ...]
    services: tuple[str, ...]
    rendered_configs: tuple[str, ...]
    evidence_paths: tuple[str, ...]
    telemetry_paths: tuple[str, ...]
    networks: tuple[str, ...]
    static_addresses: tuple[str, ...]

    def details(self) -> dict[str, object]:
        return {
            "address": self.address,
            "name": self.name,
            "aliases": list(self.aliases),
            "profiles": list(self.profiles),
            "services": list(self.services),
            "rendered_configs": list(self.rendered_configs),
            "evidence_paths": list(self.evidence_paths),
            "telemetry_paths": list(self.telemetry_paths),
            "networks": list(self.networks),
            "static_addresses": list(self.static_addresses),
        }


@dataclass(frozen=True)
class NetworkRealization(object):
    """APTL realization data for one ACES network resource."""

    address: str
    name: str
    cidr: str | None
    gateway: str | None
    internal: bool | None

    def details(self) -> dict[str, object]:
        return {
            "address": self.address,
            "name": self.name,
            "cidr": self.cidr,
            "gateway": self.gateway,
            "internal": self.internal,
        }


@dataclass(frozen=True)
class PlacementRealization(object):
    """APTL realization data for one node-scoped provisioning binding."""

    address: str
    resource_type: str
    name: str
    target_address: str
    target_node: str | None

    def details(self) -> dict[str, object]:
        return {
            "address": self.address,
            "resource_type": self.resource_type,
            "name": self.name,
            "target_address": self.target_address,
            "target_node": self.target_node,
        }


@dataclass(frozen=True)
class AptlRealization(object):
    """Result of interpreting ACES provisioning content for APTL."""

    profiles: frozenset[str]
    nodes: tuple[NodeRealization, ...]
    networks: tuple[NetworkRealization, ...]
    placements: tuple[PlacementRealization, ...]
    diagnostics: tuple[Diagnostic, ...]

    def details(self) -> dict[str, object]:
        resource_counts = {
            "account-placement": sum(
                placement.resource_type == "account-placement"
                for placement in self.placements
            ),
            "content-placement": sum(
                placement.resource_type == "content-placement"
                for placement in self.placements
            ),
            "feature-binding": sum(
                placement.resource_type == "feature-binding"
                for placement in self.placements
            ),
            "network": len(self.networks),
            "node": len(self.nodes),
        }
        return {
            "profiles": sorted(self.profiles),
            "resource_counts": {
                key: value for key, value in sorted(resource_counts.items()) if value
            },
            "nodes": [node.details() for node in self.nodes],
            "networks": [network.details() for network in self.networks],
            "placements": [placement.details() for placement in self.placements],
        }


def interpret_provisioning_plan(
    *,
    plan: ProvisioningPlan,
    project_dir: Path,
    config: AptlConfig,
) -> AptlRealization:
    """Interpret ACES provisioning resources as an APTL realization plan."""

    diagnostics: list[Diagnostic] = []
    diagnostics.extend(unsupported_resource_diagnostics(plan))
    try:
        profile_index = load_compose_profile_index(project_dir)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return _empty_realization(
            [
                *diagnostics,
                diagnostic(
                    "aptl.provisioner.compose-profile-index-failed",
                    PROVISIONING_ADDRESS,
                    redact(str(exc)),
                ),
            ]
        )

    supported_resources = [
        resource
        for resource in plan.resources.values()
        if resource.resource_type in SUPPORTED_RESOURCE_TYPES
    ]
    invalid_payloads = _invalid_payload_diagnostics(supported_resources)
    diagnostics.extend(invalid_payloads)
    payload_resources = [
        resource
        for resource in supported_resources
        if isinstance(resource.payload, Mapping)
    ]

    nodes: list[NodeRealization] = []
    networks: list[NetworkRealization] = []
    placements: list[PlacementRealization] = []
    profiles: set[str] = set()

    for resource in payload_resources:
        payload = resource.payload
        if resource.resource_type == "node":
            node = _realize_node(resource, payload, profile_index)
            nodes.append(node)
            profiles.update(node.profiles)
            if not node.profiles:
                diagnostics.append(
                    diagnostic(
                        "aptl.provisioner.node-profile-unresolved",
                        resource.address,
                        (
                            "ACES node resource does not declare content that "
                            "maps to an APTL compose profile."
                        ),
                    )
                )
        elif resource.resource_type == "network":
            networks.append(_realize_network(resource, payload))

    node_lookup = _node_lookup(nodes)
    for resource in payload_resources:
        if resource.resource_type in PLACEMENT_RESOURCE_TYPES:
            placement, placement_diagnostics = _realize_placement(
                resource,
                resource.payload,
                node_lookup,
            )
            diagnostics.extend(placement_diagnostics)
            if placement is not None:
                placements.append(placement)

    if not profiles:
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.profile-resolution-failed",
                PROVISIONING_ADDRESS,
                (
                    "ACES provisioning plan contained no node resources "
                    "that map to APTL compose profiles."
                ),
            )
        )

    enabled_profiles = configured_profiles(config)
    if enabled_profiles and not (set(enabled_profiles) & profiles):
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.no-configured-profile-matches",
                PROVISIONING_ADDRESS,
                (
                    "ACES provisioning plan did not declare any node "
                    "that maps to an enabled APTL compose profile."
                ),
            )
        )

    return AptlRealization(
        profiles=frozenset(profiles),
        nodes=tuple(sorted(nodes, key=lambda item: item.address)),
        networks=tuple(sorted(networks, key=lambda item: item.address)),
        placements=tuple(sorted(placements, key=lambda item: item.address)),
        diagnostics=tuple(diagnostics),
    )


def _empty_realization(diagnostics: list[Diagnostic]) -> AptlRealization:
    return AptlRealization(
        profiles=frozenset(),
        nodes=(),
        networks=(),
        placements=(),
        diagnostics=tuple(diagnostics),
    )


def _invalid_payload_diagnostics(
    resources: list[PlannedResource],
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for resource in resources:
        if isinstance(resource.payload, Mapping):
            continue
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.invalid-resource-payload",
                resource.address,
                (
                    "APTL provisioner expected ACES resource payload "
                    f"'{resource.resource_type}' to be a mapping."
                ),
            )
        )
    return diagnostics


def _realize_node(
    resource: PlannedResource,
    payload: Mapping[str, Any],
    profile_index: ComposeProfileIndex,
) -> NodeRealization:
    aliases = node_aliases(resource.address, payload)
    profile_hints = explicit_compose_profile_hints(payload)
    profiles = profile_hints | profile_index.profiles_for_aliases(aliases)
    spec = _mapping(payload.get("spec"))
    node_spec = _mapping(spec.get("node")) if spec else None
    infra_spec = _mapping(spec.get("infrastructure")) if spec else None
    runtime_spec = _runtime_spec(payload, spec)
    return NodeRealization(
        address=resource.address,
        name=_resource_name(resource.address, payload),
        aliases=tuple(sorted(aliases)),
        profiles=tuple(sorted(profiles)),
        services=tuple(sorted(_service_names(node_spec))),
        rendered_configs=tuple(sorted(_string_list(runtime_spec, "rendered_configs"))),
        evidence_paths=tuple(sorted(_string_list(runtime_spec, "evidence_paths"))),
        telemetry_paths=tuple(sorted(_string_list(runtime_spec, "telemetry_paths"))),
        networks=tuple(sorted(_network_names(infra_spec))),
        static_addresses=tuple(sorted(_static_addresses(infra_spec))),
    )


def _realize_network(
    resource: PlannedResource,
    payload: Mapping[str, Any],
) -> NetworkRealization:
    spec = _mapping(payload.get("spec"))
    infra_spec = _mapping(spec.get("infrastructure")) if spec else None
    properties = _mapping(infra_spec.get("properties")) if infra_spec else None
    return NetworkRealization(
        address=resource.address,
        name=_resource_name(resource.address, payload),
        cidr=_optional_string(properties, "cidr"),
        gateway=_optional_string(properties, "gateway"),
        internal=_optional_bool(properties, "internal"),
    )


def _realize_placement(
    resource: PlannedResource,
    payload: Mapping[str, Any],
    node_lookup: dict[str, str],
) -> tuple[PlacementRealization | None, list[Diagnostic]]:
    target_values = _placement_target_values(resource.resource_type, payload)
    target_address = _resolve_target_address(target_values, node_lookup)
    if target_address is None:
        return (
            None,
            [
                diagnostic(
                    "aptl.provisioner.binding-target-unresolved",
                    resource.address,
                    (
                        "ACES provisioning binding does not target a "
                        "declared APTL-realizable node."
                    ),
                )
            ],
        )
    return (
        PlacementRealization(
            address=resource.address,
            resource_type=resource.resource_type,
            name=_resource_name(resource.address, payload),
            target_address=target_address,
            target_node=_first_nonempty_string(target_values),
        ),
        [],
    )


def _node_lookup(nodes: list[NodeRealization]) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for node in nodes:
        values = {node.address, node.name, *node.aliases}
        for value in values:
            if not value:
                continue
            lookup[value] = node.address
            normalized = normalize_identifier(value)
            if normalized:
                lookup[normalized] = node.address
    return lookup


def _placement_target_values(
    resource_type: str,
    payload: Mapping[str, Any],
) -> tuple[str, ...]:
    if resource_type == "feature-binding":
        return _payload_string_values(payload, ("node_address", "node_name"))
    if resource_type == "content-placement":
        return _payload_string_values(payload, ("target_address", "target_node"))
    if resource_type == "account-placement":
        return _payload_string_values(payload, ("target_address", "node_name"))
    return ()


def _resolve_target_address(
    target_values: tuple[str, ...],
    node_lookup: dict[str, str],
) -> str | None:
    for value in target_values:
        if value in node_lookup:
            return node_lookup[value]
        normalized = normalize_identifier(value)
        if normalized in node_lookup:
            return node_lookup[normalized]
    return None


def _resource_name(address: str, payload: Mapping[str, Any]) -> str:
    return _first_nonempty_string(_payload_string_values(payload, ("name",))) or address


def _runtime_spec(
    payload: Mapping[str, Any],
    spec: Mapping[str, Any] | None,
) -> Mapping[str, Any] | None:
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


def _service_names(node_spec: Mapping[str, Any] | None) -> set[str]:
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


def _network_names(infra_spec: Mapping[str, Any] | None) -> set[str]:
    if infra_spec is None:
        return set()
    return _string_values(infra_spec.get("links"))


def _static_addresses(infra_spec: Mapping[str, Any] | None) -> set[str]:
    if infra_spec is None:
        return set()
    properties = infra_spec.get("properties")
    addresses: set[str] = set()
    if isinstance(properties, list):
        for item in properties:
            if isinstance(item, Mapping):
                addresses.update(_string_values(item.values()))
    elif isinstance(properties, Mapping):
        for key in ("address", "ip", "ipv4_address", "static_address"):
            value = properties.get(key)
            if isinstance(value, str) and value.strip():
                addresses.add(value)
    return addresses


def _string_list(
    payload: Mapping[str, Any] | None,
    key: str,
) -> set[str]:
    if payload is None:
        return set()
    return _string_values(payload.get(key))


def _string_values(raw: object) -> set[str]:
    if isinstance(raw, str):
        return {raw} if raw.strip() else set()
    if isinstance(raw, Mapping):
        raw = raw.values()
    if isinstance(raw, list | tuple | set | frozenset):
        return {str(value) for value in raw if str(value).strip()}
    return set()


def _payload_string_values(
    payload: Mapping[str, Any],
    keys: tuple[str, ...],
) -> tuple[str, ...]:
    values: list[str] = []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value)
    return tuple(values)


def _first_nonempty_string(values: tuple[str, ...]) -> str | None:
    for value in values:
        if value.strip():
            return value
    return None


def _optional_string(
    payload: Mapping[str, Any] | None,
    key: str,
) -> str | None:
    if payload is None:
        return None
    value = payload.get(key)
    return value if isinstance(value, str) and value.strip() else None


def _optional_bool(
    payload: Mapping[str, Any] | None,
    key: str,
) -> bool | None:
    if payload is None:
        return None
    value = payload.get(key)
    return value if isinstance(value, bool) else None


def _mapping(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None
