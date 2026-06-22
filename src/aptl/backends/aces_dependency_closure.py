"""Dependency closure support for ACES-backed APTL realization."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

from aces_contracts.diagnostics import Diagnostic
from aces_contracts.planning import PlannedResource

from aptl.backends.aces_diagnostics import PROVISIONING_ADDRESS, diagnostic
from aptl.backends.aces_profiles import (
    ComposeProfileIndex,
    normalized_identifier_aliases,
    public_start_profiles,
)
from aptl.backends.aces_realization_model import NetworkRealization, NodeRealization
from aptl.backends.aces_realization_values import (
    dependency_names as _dependency_names,
    mapping as _mapping,
)
from aptl.core.config import AptlConfig


def append_dependency_closure(
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
    for resource, payload in _selected_node_payloads(
        payload_resources,
        selected_node_addresses,
    ):
        for dependency in _node_dependency_values(resource, payload):
            if _has_seen_dependency(resource.address, dependency, seen):
                continue
            is_network, matches = _dependency_service_matches(
                dependency,
                network_aliases,
                profile_index,
            )
            if is_network:
                continue
            _append_dependency_resolution_diagnostics(
                resource.address,
                dependency,
                matches,
                diagnostics,
            )
            if len(matches) == 1:
                dependency_services.add(next(iter(matches)))
    return dependency_services


def _selected_node_payloads(
    payload_resources: list[PlannedResource],
    selected_node_addresses: set[str],
) -> Iterator[tuple[PlannedResource, Mapping[str, Any]]]:
    """Yield selected ACES node resources with mapping payloads."""

    for resource in payload_resources:
        if resource.resource_type != "node":
            continue
        if resource.address not in selected_node_addresses:
            continue
        if isinstance(resource.payload, Mapping):
            yield resource, resource.payload


def _has_seen_dependency(
    resource_address: str,
    dependency: str,
    seen: set[tuple[str, str]],
) -> bool:
    """Return whether a node dependency was already processed."""

    key = (resource_address, dependency)
    if key in seen:
        return True
    seen.add(key)
    return False


def _dependency_service_matches(
    dependency: str,
    network_aliases: set[str],
    profile_index: ComposeProfileIndex,
) -> tuple[bool, set[str]]:
    """Return whether a dependency is a network and its Compose service matches."""

    is_network = _is_network_dependency(dependency, network_aliases)
    matches: set[str] = set()
    if not is_network:
        matches = profile_index.service_names_for_aliases(
            _dependency_reference_aliases(dependency)
        )
    return is_network, matches


def _append_dependency_resolution_diagnostics(
    resource_address: str,
    dependency: str,
    matches: set[str],
    diagnostics: list[Diagnostic],
) -> None:
    """Record diagnostics for non-network dependency resolution failures."""

    if not matches:
        _append_dependency_unresolved_diagnostic(
            resource_address,
            dependency,
            diagnostics,
        )
    elif len(matches) > 1:
        _append_dependency_ambiguous_diagnostic(
            resource_address,
            dependency,
            matches,
            diagnostics,
        )


def _append_dependency_unresolved_diagnostic(
    resource_address: str,
    dependency: str,
    diagnostics: list[Diagnostic],
) -> None:
    """Record a dependency reference that does not match Compose."""

    diagnostics.append(
        diagnostic(
            "aptl.provisioner.dependency-unresolved",
            resource_address,
            (
                "ACES node dependency does not map to an APTL "
                f"Compose service: {dependency}."
            ),
        )
    )


def _append_dependency_ambiguous_diagnostic(
    resource_address: str,
    dependency: str,
    matches: set[str],
    diagnostics: list[Diagnostic],
) -> None:
    """Record a dependency reference that matches multiple Compose services."""

    diagnostics.append(
        diagnostic(
            "aptl.provisioner.dependency-ambiguous",
            resource_address,
            (
                "ACES node dependency maps to multiple APTL "
                "Compose services: "
                f"{dependency} -> {', '.join(sorted(matches))}."
            ),
        )
    )


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
