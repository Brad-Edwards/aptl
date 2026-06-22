"""APTL realization contract for ACES provisioning plans."""

from __future__ import annotations

from collections.abc import Mapping
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
    explicit_compose_profile_hints,
    load_compose_profile_index,
    node_aliases,
    normalized_identifier_aliases,
    normalize_identifier,
    public_start_profiles,
)
from aptl.backends.aces_realization_model import (
    AptlRealization,
    NetworkRealization,
    NodeRealization,
    PlacementRealization,
)
from aptl.backends.aces_realization_values import (
    dependency_names as _dependency_names,
    first_nonempty_string as _first_nonempty_string,
    mapping as _mapping,
    network_names as _network_names,
    optional_bool as _optional_bool,
    optional_string as _optional_string,
    placement_target_values as _placement_target_values,
    resolve_target_address as _resolve_target_address,
    resource_name as _resource_name,
    runtime_spec as _runtime_spec,
    service_names as _service_names,
    static_addresses as _static_addresses,
    string_list as _string_list,
)
from aptl.core.config import AptlConfig
from aptl.utils.redaction import redact

PLACEMENT_RESOURCE_TYPES = frozenset(
    {"feature-binding", "content-placement", "account-placement"}
)


def interpret_provisioning_plan(
    *,
    plan: ProvisioningPlan,
    project_dir: Path,
    config: AptlConfig,
) -> AptlRealization:
    """Interpret ACES provisioning resources as an APTL realization plan."""

    diagnostics: list[Diagnostic] = []
    diagnostics.extend(unsupported_resource_diagnostics(plan))
    profile_index = _load_profile_index(project_dir, diagnostics)
    if profile_index is None:
        return _empty_realization(diagnostics)

    payload_resources = _payload_resources(plan, diagnostics)
    nodes, networks, profiles = _realize_nodes_and_networks(
        payload_resources,
        profile_index,
        diagnostics,
    )
    _append_dependency_closure(
        payload_resources,
        nodes,
        networks,
        profile_index,
        config,
        profiles,
        diagnostics,
    )
    placements = _realize_placements(payload_resources, _node_lookup(nodes), diagnostics)
    _append_profile_diagnostics(profiles, config, diagnostics)

    return _realization_from_parts(nodes, networks, placements, profiles, diagnostics)


def _load_profile_index(
    project_dir: Path,
    diagnostics: list[Diagnostic],
) -> ComposeProfileIndex | None:
    """Load the compose profile index and record redacted load failures."""

    try:
        return load_compose_profile_index(project_dir)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.compose-profile-index-failed",
                PROVISIONING_ADDRESS,
                redact(str(exc)),
            )
        )
        return None


def _payload_resources(
    plan: ProvisioningPlan,
    diagnostics: list[Diagnostic],
) -> list[PlannedResource]:
    """Return supported resources with mapping payloads and report invalid ones."""

    supported_resources = [
        resource
        for resource in plan.resources.values()
        if resource.resource_type in SUPPORTED_RESOURCE_TYPES
    ]
    diagnostics.extend(_invalid_payload_diagnostics(supported_resources))
    return [
        resource
        for resource in supported_resources
        if isinstance(resource.payload, Mapping)
    ]


def _realize_nodes_and_networks(
    payload_resources: list[PlannedResource],
    profile_index: ComposeProfileIndex,
    diagnostics: list[Diagnostic],
) -> tuple[list[NodeRealization], list[NetworkRealization], set[str]]:
    """Realize node and network resources before resolving placements."""

    nodes: list[NodeRealization] = []
    networks: list[NetworkRealization] = []
    profiles: set[str] = set()
    for resource in payload_resources:
        payload = resource.payload
        if resource.resource_type == "node":
            node = _realize_node(resource, payload, profile_index)
            nodes.append(node)
            profiles.update(node.profiles)
            if not node.profiles:
                _append_node_profile_diagnostic(resource, diagnostics)
        elif resource.resource_type == "network":
            networks.append(_realize_network(resource, payload))
    return nodes, networks, profiles


def _append_node_profile_diagnostic(
    resource: PlannedResource,
    diagnostics: list[Diagnostic],
) -> None:
    """Record a diagnostic for a node without an APTL profile mapping."""

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


def _append_dependency_closure(
    payload_resources: list[PlannedResource],
    nodes: list[NodeRealization],
    networks: list[NetworkRealization],
    profile_index: ComposeProfileIndex,
    config: AptlConfig,
    profiles: set[str],
    diagnostics: list[Diagnostic],
) -> None:
    """Expand profiles required by selected ACES and Compose dependencies."""

    selected_profiles = set(public_start_profiles(config))
    service_by_address = _service_by_node_address(nodes, profile_index, diagnostics)
    selected_node_addresses = {
        node.address
        for node in nodes
        if set(node.profiles) & selected_profiles
    }
    seed_services = {
        service_name
        for address, service_name in service_by_address.items()
        if address in selected_node_addresses
    }
    seed_services.update(
        _aces_dependency_services(
            payload_resources,
            selected_node_addresses,
            networks,
            profile_index,
            diagnostics,
        )
    )
    if not seed_services:
        return

    closure_services, missing_dependencies = profile_index.dependency_closure_for_services(
        seed_services
    )
    _append_missing_compose_dependency_diagnostics(missing_dependencies, diagnostics)
    _append_disabled_dependency_diagnostics(
        closure_services,
        selected_profiles,
        profile_index,
        diagnostics,
    )
    profiles.update(profile_index.profiles_for_services(set(closure_services)))


def _service_by_node_address(
    nodes: list[NodeRealization],
    profile_index: ComposeProfileIndex,
    diagnostics: list[Diagnostic],
) -> dict[str, str]:
    """Return unambiguous Compose service matches for realized nodes."""

    service_by_address: dict[str, str] = {}
    for node in nodes:
        matches = profile_index.service_names_for_aliases(set(node.aliases))
        if len(matches) > 1:
            diagnostics.append(
                diagnostic(
                    "aptl.provisioner.node-compose-service-ambiguous",
                    node.address,
                    (
                        "ACES node aliases match multiple APTL Compose "
                        f"services: {', '.join(sorted(matches))}."
                    ),
                )
            )
            continue
        if matches:
            service_by_address[node.address] = next(iter(matches))
    return service_by_address


def _aces_dependency_services(
    payload_resources: list[PlannedResource],
    selected_node_addresses: set[str],
    networks: list[NetworkRealization],
    profile_index: ComposeProfileIndex,
    diagnostics: list[Diagnostic],
) -> set[str]:
    """Resolve selected ACES node dependencies to Compose service names."""

    dependency_services: set[str] = set()
    network_aliases = _network_reference_aliases(networks) | set(
        profile_index.network_aliases()
    )
    seen: set[tuple[str, str]] = set()
    for resource in payload_resources:
        if (
            resource.resource_type != "node"
            or resource.address not in selected_node_addresses
            or not isinstance(resource.payload, Mapping)
        ):
            continue
        for dependency in _node_dependency_values(resource, resource.payload):
            key = (resource.address, dependency)
            if key in seen:
                continue
            seen.add(key)
            if _is_network_dependency(dependency, network_aliases):
                continue
            matches = profile_index.service_names_for_aliases(
                _dependency_reference_aliases(dependency)
            )
            if not matches:
                diagnostics.append(
                    diagnostic(
                        "aptl.provisioner.dependency-unresolved",
                        resource.address,
                        (
                            "ACES node dependency does not map to an APTL "
                            f"Compose service: {dependency}."
                        ),
                    )
                )
                continue
            if len(matches) > 1:
                diagnostics.append(
                    diagnostic(
                        "aptl.provisioner.dependency-ambiguous",
                        resource.address,
                        (
                            "ACES node dependency maps to multiple APTL "
                            "Compose services: "
                            f"{dependency} -> {', '.join(sorted(matches))}."
                        ),
                    )
                )
                continue
            dependency_services.add(next(iter(matches)))
    return dependency_services


def _node_dependency_values(
    resource: PlannedResource,
    payload: Mapping[str, Any],
) -> set[str]:
    """Return dependency references declared by one planned ACES node."""

    values = {
        str(value)
        for value in (*resource.ordering_dependencies, *resource.refresh_dependencies)
        if str(value).strip()
    }
    spec = _mapping(payload.get("spec"))
    infra_spec = _mapping(spec.get("infrastructure")) if spec else None
    values.update(_dependency_names(infra_spec))
    return values


def _network_reference_aliases(networks: list[NetworkRealization]) -> set[str]:
    """Return normalized ACES network aliases that are not service dependencies."""

    aliases: set[str] = set()
    for network in networks:
        aliases.update(_dependency_reference_aliases(network.address))
        aliases.update(_dependency_reference_aliases(network.name))
    return aliases


def _is_network_dependency(dependency: str, network_aliases: set[str]) -> bool:
    """Return whether a dependency reference names an ACES network resource."""

    return ".network." in dependency or bool(
        _dependency_reference_aliases(dependency) & network_aliases
    )


def _dependency_reference_aliases(reference: str) -> set[str]:
    """Return normalized aliases for an ACES dependency reference."""

    aliases = normalized_identifier_aliases(reference)
    if "." in reference:
        aliases.update(normalized_identifier_aliases(reference.rsplit(".", 1)[-1]))
    return aliases


def _append_missing_compose_dependency_diagnostics(
    missing_dependencies: dict[str, tuple[str, ...]],
    diagnostics: list[Diagnostic],
) -> None:
    """Record diagnostics for Compose ``depends_on`` edges without services."""

    for service_name, dependencies in sorted(missing_dependencies.items()):
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.compose-dependency-unresolved",
                PROVISIONING_ADDRESS,
                (
                    "APTL Compose service dependency is not declared as a "
                    f"service: {service_name} -> {', '.join(dependencies)}."
                ),
            )
        )


def _append_disabled_dependency_diagnostics(
    closure_services: frozenset[str],
    selected_profiles: set[str],
    profile_index: ComposeProfileIndex,
    diagnostics: list[Diagnostic],
) -> None:
    """Record diagnostics for required services outside enabled profiles."""

    for service_name in sorted(closure_services):
        service = profile_index.services.get(service_name)
        if service is None or not service.profiles:
            continue
        if service.profiles.isdisjoint(selected_profiles):
            diagnostics.append(
                diagnostic(
                    "aptl.provisioner.dependency-profile-disabled",
                    PROVISIONING_ADDRESS,
                    (
                        "Required APTL Compose dependency is disabled by "
                        "configuration: "
                        f"{service_name} requires profile(s) "
                        f"{', '.join(sorted(service.profiles))}."
                    ),
                )
            )


def _realize_placements(
    payload_resources: list[PlannedResource],
    node_lookup: dict[str, str],
    diagnostics: list[Diagnostic],
) -> list[PlacementRealization]:
    """Resolve supported placement resources against realized nodes."""

    placements: list[PlacementRealization] = []
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
    return placements


def _append_profile_diagnostics(
    profiles: set[str],
    config: AptlConfig,
    diagnostics: list[Diagnostic],
) -> None:
    """Record diagnostics for missing or disabled compose-profile matches."""

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

    start_profiles = public_start_profiles(config)
    if start_profiles and not (set(start_profiles) & profiles):
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.no-configured-profile-matches",
                PROVISIONING_ADDRESS,
                (
                    "ACES provisioning plan did not declare any node "
                    "that maps to a public-start APTL compose profile."
                ),
            )
        )


def _realization_from_parts(
    nodes: list[NodeRealization],
    networks: list[NetworkRealization],
    placements: list[PlacementRealization],
    profiles: set[str],
    diagnostics: list[Diagnostic],
) -> AptlRealization:
    """Build the stable realization value from collected resource parts."""

    return AptlRealization(
        profiles=frozenset(profiles),
        nodes=tuple(sorted(nodes, key=lambda item: item.address)),
        networks=tuple(sorted(networks, key=lambda item: item.address)),
        placements=tuple(sorted(placements, key=lambda item: item.address)),
        diagnostics=tuple(diagnostics),
    )


def _empty_realization(diagnostics: list[Diagnostic]) -> AptlRealization:
    """Build an empty realization that carries validation diagnostics."""

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
    """Report supported resources whose payload cannot be interpreted."""

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
    """Realize a node resource into APTL profile and runtime details."""

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
    """Realize a network resource into APTL network details."""

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
    """Realize a placement resource or return its diagnostics."""

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
    """Index node addresses and aliases for placement target resolution."""

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
