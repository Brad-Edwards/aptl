"""APTL realization contract for ACES provisioning plans."""

from __future__ import annotations

from collections.abc import Mapping
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
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
from aptl.backends.aces_dependency_closure import append_dependency_closure
from aptl.backends.aces_image_realization import resolve_node_image
from aptl.backends.aces_profiles import (
    ComposeProfileIndex,
    explicit_compose_profile_hints,
    load_compose_profile_index,
    node_aliases,
    normalize_identifier,
    public_start_profiles,
)
from aptl.backends.aces_realization_model import (
    AptlRealization,
    NetworkRealization,
    NodeRealization,
    PlacementRealization,
    _single_or_none,
)
from aptl.backends.aces_realization_values import (
    first_nonempty_string as _first_nonempty_string,
    health_status as _health_status,
    mapping as _mapping,
    network_names as _network_names,
    optional_bool as _optional_bool,
    optional_string as _optional_string,
    placement_target_values as _placement_target_values,
    resolve_target_address as _resolve_target_address,
    resource_name as _resource_name,
    service_names as _service_names,
    static_address_assignments as _static_address_assignments,
    static_addresses as _static_addresses,
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
        project_dir,
        diagnostics,
    )
    append_dependency_closure(
        payload_resources,
        nodes,
        networks,
        profile_index,
        config,
        profiles,
        diagnostics,
    )
    _append_network_topology_diagnostics(nodes, networks, diagnostics)
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
    project_dir: Path,
    diagnostics: list[Diagnostic],
) -> tuple[list[NodeRealization], list[NetworkRealization], set[str]]:
    """Realize node and network resources before resolving placements."""

    nodes: list[NodeRealization] = []
    networks: list[NetworkRealization] = []
    profiles: set[str] = set()
    for resource in payload_resources:
        payload = resource.payload
        if resource.resource_type == "node":
            node = _realize_node(
                resource,
                payload,
                profile_index,
                project_dir,
                diagnostics,
            )
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
    project_dir: Path,
    diagnostics: list[Diagnostic],
) -> NodeRealization:
    """Realize a node resource into APTL profile and runtime details."""

    aliases = node_aliases(resource.address, payload)
    profile_hints = explicit_compose_profile_hints(payload)
    backend_services = profile_index.service_names_for_aliases(aliases)
    profiles = (
        profile_hints
        | profile_index.profiles_for_aliases(aliases)
        | profile_index.profiles_for_services(set(backend_services))
    )
    spec = _mapping(payload.get("spec"))
    node_spec = _mapping(spec.get("node")) if spec else None
    infra_spec = _mapping(spec.get("infrastructure")) if spec else None
    service_name = _single_or_none(tuple(sorted(backend_services)))
    return NodeRealization(
        address=resource.address,
        name=_resource_name(resource.address, payload),
        aliases=tuple(sorted(aliases)),
        profiles=tuple(sorted(profiles)),
        backend_services=tuple(sorted(backend_services)),
        container_name=_container_name(profile_index, backend_services),
        services=tuple(sorted(_service_names(node_spec))),
        networks=tuple(sorted(_network_names(infra_spec))),
        static_addresses=tuple(sorted(_static_addresses(infra_spec))),
        static_address_assignments=_static_address_assignments(infra_spec),
        declared_health=_health_status(node_spec),
        image=resolve_node_image(
            resource=resource,
            payload=payload,
            project_dir=project_dir,
            service_name=service_name,
            diagnostics=diagnostics,
        ),
    )


def _container_name(
    profile_index: ComposeProfileIndex,
    service_names: frozenset[str],
) -> str | None:
    """Return the concrete container name for an unambiguous service binding."""

    if len(service_names) != 1:
        return None
    service = profile_index.services.get(next(iter(service_names)))
    if service is None:
        return None
    return service.container_name or service.name


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


def _append_network_topology_diagnostics(
    nodes: list[NodeRealization],
    networks: list[NetworkRealization],
    diagnostics: list[Diagnostic],
) -> None:
    """Validate provider-relevant network topology before backend side effects."""

    parsed_networks = _parsed_networks(networks, diagnostics)
    _append_network_name_diagnostics(networks, diagnostics)
    seen_addresses: dict[tuple[str, str], str] = {}
    for node in nodes:
        linked_networks = set(node.networks)
        for network_name, raw_address in node.static_address_assignments:
            if network_name not in linked_networks:
                diagnostics.append(
                    diagnostic(
                        "aptl.provisioner.network-static-address-unlinked",
                        node.address,
                        (
                            "ACES node static address references a network "
                            "that is not declared in the node links."
                        ),
                    )
                )
            parsed_address = _parsed_static_address(
                node.address,
                raw_address,
                diagnostics,
            )
            if parsed_address is None:
                continue
            network_key = _network_identity_key(network_name)
            parsed_network = parsed_networks.get(network_key)
            if parsed_network is not None and parsed_address not in parsed_network:
                diagnostics.append(
                    diagnostic(
                        "aptl.provisioner.network-static-address-out-of-range",
                        node.address,
                        (
                            "ACES node static address is outside the "
                            "declared network CIDR."
                        ),
                    )
                )
            owner_key = (network_key, str(parsed_address))
            prior_owner = seen_addresses.get(owner_key)
            if prior_owner is not None and prior_owner != node.address:
                diagnostics.append(
                    diagnostic(
                        "aptl.provisioner.network-static-address-duplicate",
                        node.address,
                        "ACES node static address duplicates another node.",
                    )
                )
            else:
                seen_addresses[owner_key] = node.address


def _parsed_networks(
    networks: list[NetworkRealization],
    diagnostics: list[Diagnostic],
) -> dict[str, IPv4Network]:
    """Return parsed network CIDRs keyed by backend identity stem."""

    parsed: dict[str, IPv4Network] = {}
    for network in networks:
        key = _network_identity_key(network.name)
        parsed_network = _parsed_cidr(network, diagnostics)
        if parsed_network is not None:
            parsed[key] = parsed_network
        _append_gateway_diagnostics(network, parsed_network, diagnostics)
    return parsed


def _parsed_cidr(
    network: NetworkRealization,
    diagnostics: list[Diagnostic],
) -> IPv4Network | None:
    """Parse a network CIDR and append a diagnostic on invalid input."""

    if network.cidr is None:
        return None
    try:
        parsed = ip_network(network.cidr, strict=True)
    except ValueError:
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.network-cidr-invalid",
                network.address,
                "ACES network CIDR is not a valid IPv4 network.",
            )
        )
        return None
    if not isinstance(parsed, IPv4Network):
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.network-cidr-invalid",
                network.address,
                "ACES network CIDR is not a valid IPv4 network.",
            )
        )
        return None
    return parsed


def _append_gateway_diagnostics(
    network: NetworkRealization,
    parsed_network: IPv4Network | None,
    diagnostics: list[Diagnostic],
) -> None:
    """Validate a network gateway, if one was authored."""

    if network.gateway is None:
        return
    try:
        parsed_gateway = ip_address(network.gateway)
    except ValueError:
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.network-gateway-invalid",
                network.address,
                "ACES network gateway is not a valid IPv4 address.",
            )
        )
        return
    if not isinstance(parsed_gateway, IPv4Address):
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.network-gateway-invalid",
                network.address,
                "ACES network gateway is not a valid IPv4 address.",
            )
        )
        return
    if parsed_network is not None and parsed_gateway not in parsed_network:
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.network-gateway-out-of-range",
                network.address,
                "ACES network gateway is outside the declared CIDR.",
            )
        )


def _parsed_static_address(
    node_address: str,
    raw_address: str,
    diagnostics: list[Diagnostic],
) -> IPv4Address | None:
    """Parse a node static address and append a diagnostic on invalid input."""

    try:
        parsed = ip_address(raw_address)
    except ValueError:
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.network-static-address-invalid",
                node_address,
                "ACES node static address is not a valid IPv4 address.",
            )
        )
        return None
    if not isinstance(parsed, IPv4Address):
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.network-static-address-invalid",
                node_address,
                "ACES node static address is not a valid IPv4 address.",
            )
        )
        return None
    return parsed


def _append_network_name_diagnostics(
    networks: list[NetworkRealization],
    diagnostics: list[Diagnostic],
) -> None:
    """Report networks that normalize to the same backend identity stem."""

    index: dict[str, NetworkRealization] = {}
    for network in networks:
        key = _network_identity_key(network.name)
        prior = index.get(key)
        if prior is not None and prior.address != network.address:
            diagnostics.append(
                diagnostic(
                    "aptl.provisioner.network-name-ambiguous",
                    network.address,
                    "ACES network names normalize to the same backend network.",
                )
            )
            continue
        index[key] = network


def _network_identity_key(name: str) -> str:
    """Return the project-scoped backend network identity stem."""

    normalized = normalize_identifier(name)
    if normalized.endswith("-net"):
        normalized = normalized.removesuffix("-net")
    if normalized.startswith("aptl-"):
        normalized = normalized.removeprefix("aptl-")
    return normalized
