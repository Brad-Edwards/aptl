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
from aptl.backends.aces_dependency_closure import append_dependency_closure
from aces_sdl.runtime_configuration import RuntimeConfiguration

from aptl.backends.aces_image_realization import resolve_node_image
from aptl.backends.aces_placement_realization import (
    placement_node_lookup as _node_lookup,
    realize_placements as _realize_placements,
)
from aptl.backends.aces_profiles import (
    ComposeProfileIndex,
    explicit_compose_profile_hints,
    load_compose_profile_index,
    node_aliases,
    public_start_profiles,
)
from aptl.backends.aces_realization_networks import (
    append_network_topology_diagnostics,
)
from aptl.backends.aces_stateful_realization import realize_stateful_resources
from aptl.backends.aces_realization_model import (
    AptlRealization,
    NetworkRealization,
    NodeRealization,
    PlacementRealization,
    _single_or_none,
)
from aptl.backends.aces_realization_values import (
    mapping as _mapping,
    network_names as _network_names,
    optional_bool as _optional_bool,
    optional_string as _optional_string,
    published_ports as _published_ports,
    resource_name as _resource_name,
    service_names as _service_names,
    service_ports as _service_ports,
    static_address_assignments as _static_address_assignments,
    static_addresses as _static_addresses,
)
from aptl.core.config import AptlConfig
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactRealization,
    DeploymentPersistentVolumeRealization,
)
from aptl.utils.redaction import redact


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
        config,
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
    append_network_topology_diagnostics(nodes, networks, diagnostics)
    placements = _realize_placements(
        payload_resources,
        _node_lookup(nodes),
        {node.address: node for node in nodes},
        project_dir,
        diagnostics,
    )
    generated_artifacts, persistent_volumes = realize_stateful_resources(
        payload_resources,
        nodes,
        diagnostics,
    )
    if not _all_nodes_image_free(nodes):
        _append_profile_diagnostics(profiles, config, diagnostics)

    return _realization_from_parts(
        nodes,
        networks,
        placements,
        generated_artifacts,
        persistent_volumes,
        profiles,
        diagnostics,
    )


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
    config: AptlConfig,
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
                config,
                diagnostics,
            )
            nodes.append(node)
            profiles.update(node.profiles)
            if not node.profiles and not _is_materializable_node(node):
                _append_node_profile_diagnostic(resource, diagnostics)
        elif resource.resource_type == "network":
            networks.append(_realize_network(resource, payload))
    return nodes, networks, profiles


def _is_materializable_node(node: NodeRealization) -> bool:
    """Whether a node is realized image-free by the generic materializer (ADR-048).

    Such a node declares an OS and typed runtime desired state and carries no
    appliance image, so it legitimately maps to no compose profile.
    """

    return bool(node.os and node.runtime is not None and node.image is None)


def _all_nodes_image_free(nodes: list[NodeRealization]) -> bool:
    """Whether every OS-bearing node is materialized image-free."""

    os_nodes = [node for node in nodes if node.os]
    return bool(os_nodes) and all(_is_materializable_node(node) for node in os_nodes)


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
    generated_artifacts: list[DeploymentGeneratedArtifactRealization],
    persistent_volumes: list[DeploymentPersistentVolumeRealization],
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
        generated_artifacts=tuple(
            sorted(generated_artifacts, key=lambda item: item.address)
        ),
        persistent_volumes=tuple(
            sorted(persistent_volumes, key=lambda item: item.address)
        ),
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
    config: AptlConfig,
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
    if not profiles and _is_aces_conformance_probe_node(resource, payload):
        backend_services = _conformance_probe_services(profile_index, config)
        profiles = profile_index.profiles_for_services(set(backend_services))
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
        services=_service_ports(node_spec),
        networks=tuple(sorted(_network_names(infra_spec))),
        static_addresses=tuple(sorted(_static_addresses(infra_spec))),
        static_address_assignments=_static_address_assignments(infra_spec),
        published_ports=_published_ports(node_spec),
        image=resolve_node_image(
            resource=resource,
            payload=payload,
            project_dir=project_dir,
            service_name=service_name,
            diagnostics=diagnostics,
        ),
        ordering_dependencies=resource.ordering_dependencies,
        os=_node_os(node_spec),
        os_version=_node_os_version(node_spec),
        runtime=_node_runtime(node_spec),
    )


def _node_os(node_spec: Mapping[str, Any] | None) -> str:
    """Return the node's declared OS family, or empty when undeclared."""

    return str(node_spec.get("os") or "") if node_spec else ""


def _node_os_version(node_spec: Mapping[str, Any] | None) -> str:
    """Return the node's declared OS version, or empty when undeclared."""

    return str(node_spec.get("os_version") or "") if node_spec else ""


def _node_runtime(node_spec: Mapping[str, Any] | None) -> RuntimeConfiguration | None:
    """Reconstruct the typed ACES RuntimeConfiguration from a node payload.

    Best-effort: a node with no declared runtime returns None. A malformed
    runtime block returns None rather than aborting the whole realization; the
    materializer/manifest gates surface the missing desired state downstream.
    """

    raw = node_spec.get("runtime") if node_spec else None
    if not isinstance(raw, Mapping):
        return None
    try:
        return RuntimeConfiguration.model_validate(dict(raw))
    except (ValueError, TypeError):
        return None


def _is_aces_conformance_probe_node(
    resource: PlannedResource,
    payload: Mapping[str, Any],
) -> bool:
    """Return whether a node is ACES' backend-neutral live probe."""

    spec = _mapping(payload.get("spec"))
    node_spec = _mapping(spec.get("node")) if spec else None
    infra_spec = _mapping(spec.get("infrastructure")) if spec else None
    return (
        _has_aces_conformance_probe_identity(resource, payload)
        and _has_empty_aces_probe_node_spec(node_spec)
        and _has_empty_aces_probe_infra_spec(infra_spec)
    )


def _has_aces_conformance_probe_identity(
    resource: PlannedResource,
    payload: Mapping[str, Any],
) -> bool:
    """Return whether resource identity matches ACES' generic VM probe."""

    return (
        resource.address,
        str(payload.get("name", "")),
        str(payload.get("node_name", "")),
        str(payload.get("node_type", "")),
        str(payload.get("os_family", "")),
    ) == ("provision.node.vm", "vm", "vm", "vm", "linux")


def _has_empty_aces_probe_node_spec(
    node_spec: Mapping[str, Any] | None,
) -> bool:
    """Return whether the generic probe has no concrete service source."""

    return (
        bool(node_spec)
        and node_spec.get("source") is None
        and not _service_names(node_spec)
    )


def _has_empty_aces_probe_infra_spec(
    infra_spec: Mapping[str, Any] | None,
) -> bool:
    """Return whether the generic probe has no scenario network intent."""

    return not _network_names(infra_spec) and not _static_addresses(infra_spec)


def _conformance_probe_services(
    profile_index: ComposeProfileIndex,
    config: AptlConfig,
) -> frozenset[str]:
    """Bind ACES' generic probe to one enabled APTL service, if available."""

    for profile in public_start_profiles(config):
        for service_name, service in sorted(profile_index.services.items()):
            if profile in service.profiles:
                return frozenset({service_name})
    return frozenset()


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
