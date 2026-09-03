"""APTL realization contract for RAES provisioning plans."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from raes_contracts.diagnostics import Diagnostic
from raes_contracts.planning import PlannedResource, ProvisioningPlan

from aptl.backends.raes_diagnostics import (
    PROVISIONING_ADDRESS,
    SUPPORTED_RESOURCE_TYPES,
    diagnostic,
    unsupported_resource_diagnostics,
)
from aptl.backends.raes_dependency_closure import append_dependency_closure
from aptl.backends.raes_acl_realization import realize_acls
from raes.runtime_configuration import RuntimeConfiguration

from aptl.backends._raes_realization_diagnostics import (
    _append_node_profile_diagnostic,
    _append_profile_diagnostics,
    _invalid_payload_diagnostics,
)
from aptl.backends.raes_base_substrate import base_container_spec
from aptl.backends.pack_interaction import ResolvedPackBackendInteraction
from aptl.backends.raes_pack_interaction import apply_pack_interaction
from aptl.backends.raes_image_realization import (
    node_source_is_dynamic_composition,
    resolve_node_image,
)
from aptl.backends.raes_placement_realization import (
    placement_node_lookup as _node_lookup,
    realize_placements as _realize_placements,
)
from aptl.backends.raes_profiles import (
    ComposeProfileIndex,
    load_compose_profile_index,
    node_aliases,
)
from aptl.backends.raes_realization_networks import (
    append_network_topology_diagnostics,
)
from aptl.backends.raes_stateful_realization import realize_stateful_resources
from aptl.backends.raes_realization_model import (
    AptlRealization,
    NetworkRealization,
    NodeRealization,
    _single_or_none,
)
from aptl.backends._raes_conformance_probe import (
    _conformance_probe_services,
    _is_raes_conformance_probe_node,
)
from aptl.backends.raes_realization_values import (
    mapping as _mapping,
    network_names as _network_names,
    optional_bool as _optional_bool,
    optional_string as _optional_string,
    published_ports as _published_ports,
    resource_name as _resource_name,
    service_ports as _service_ports,
    static_address_assignments as _static_address_assignments,
    static_addresses as _static_addresses,
)
from aptl.core.config import AptlConfig
from aptl.core.scenario_bundle import ScenarioBundle
from aptl.utils.redaction import redact


def interpret_provisioning_plan(
    *,
    plan: ProvisioningPlan,
    config: AptlConfig,
    bundle: ScenarioBundle,
    component_root: Path | None = None,
) -> AptlRealization:
    """Interpret RAES provisioning resources as an APTL realization plan.

    ``bundle`` supplies the root every scenario-declared *content* input is
    anchored to (placements, seeds). ``component_root`` is the engine checkout
    that supplies APTL's own component software — the ``containers/`` build
    contexts a ``materialization-specification`` node builds from (ADR-051). A
    pack ships no ``containers/``, so build contexts must resolve from the engine
    tree, not the bundle. It defaults to ``bundle.root`` so an in-tree scenario
    (where ``bundle.root == project_dir.resolve()``) is behaviourally unchanged
    (issues #874, #875).
    """

    content_root = bundle.root
    component_root = component_root if component_root is not None else bundle.root

    diagnostics: list[Diagnostic] = []
    diagnostics.extend(unsupported_resource_diagnostics(plan))
    # The Compose model binds scenario nodes to concrete services and profiles,
    # so it is scenario-bundle input, not engine infrastructure: index it from
    # the bundle root. The two roots coincide only for an in-tree scenario.
    profile_index = _load_profile_index(content_root, diagnostics)
    if profile_index is None:
        return _empty_realization(diagnostics)

    payload_resources = _payload_resources(plan, diagnostics)
    nodes, networks, profiles = _realize_nodes_and_networks(
        payload_resources,
        profile_index,
        component_root,
        config,
        diagnostics,
    )
    pack_interaction: ResolvedPackBackendInteraction | None = None
    if bundle.pack_identity is not None:
        nodes, pack_interaction = apply_pack_interaction(
            nodes,
            bundle,
            config,
            diagnostics,
        )
        profiles = {profile for node in nodes for profile in node.profiles}
    else:
        _append_unresolved_node_profile_diagnostics(
            payload_resources, nodes, diagnostics
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
    acls = realize_acls(payload_resources, networks, diagnostics)
    # Scenario content resolves against the bundle root, not the engine's
    # checkout. They are the same directory for an in-tree scenario, so this is
    # behaviour-preserving today and is the single point that changes when a
    # scenario is handed over from somewhere else.
    placements = _realize_placements(
        payload_resources,
        _node_lookup(nodes),
        {node.address: node for node in nodes},
        content_root,
        diagnostics,
    )
    generated_artifacts, persistent_volumes = realize_stateful_resources(
        payload_resources,
        nodes,
        diagnostics,
    )
    if bundle.pack_identity is None and not _all_nodes_image_free(nodes):
        _append_profile_diagnostics(profiles, config, diagnostics)

    return AptlRealization(
        profiles=frozenset(profiles),
        nodes=tuple(sorted(nodes, key=lambda item: item.address)),
        networks=tuple(sorted(networks, key=lambda item: item.address)),
        placements=tuple(sorted(placements, key=lambda item: item.address)),
        diagnostics=tuple(diagnostics),
        acls=tuple(acls),
        generated_artifacts=tuple(
            sorted(generated_artifacts, key=lambda item: item.address)
        ),
        persistent_volumes=tuple(
            sorted(persistent_volumes, key=lambda item: item.address)
        ),
        pack_identity=bundle.pack_identity,
        pack_interaction=pack_interaction,
    )


def _append_unresolved_node_profile_diagnostics(
    resources: list[PlannedResource],
    nodes: list[NodeRealization],
    diagnostics: list[Diagnostic],
) -> None:
    """Preserve legacy static-Compose diagnostics for project-tree scenarios."""

    resources_by_address = {resource.address: resource for resource in resources}
    for node in nodes:
        if node.profiles or _is_materializable_node(node):
            continue
        resource = resources_by_address.get(node.address)
        if resource is not None:
            _append_node_profile_diagnostic(resource, diagnostics)


def _load_profile_index(
    content_root: Path,
    diagnostics: list[Diagnostic],
) -> ComposeProfileIndex | None:
    """Load the compose profile index and record redacted load failures.

    ``content_root`` is the scenario bundle root — the Compose model is a
    scenario-declared input, so it is read from the bundle, never the engine
    checkout.
    """

    try:
        return load_compose_profile_index(content_root)
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
    component_root: Path,
    config: AptlConfig,
    diagnostics: list[Diagnostic],
) -> tuple[list[NodeRealization], list[NetworkRealization], set[str]]:
    """Realize node and network resources before resolving placements.

    ``component_root`` is the engine checkout a node's ``containers/`` build
    context is resolved against (APTL component software, ADR-051), not the
    scenario bundle. The two coincide only for a scenario that still lives
    in-tree (issue #875).
    """

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
                component_root,
                config,
                diagnostics,
            )
            nodes.append(node)
            profiles.update(node.profiles)
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


def _empty_realization(diagnostics: list[Diagnostic]) -> AptlRealization:
    """Build an empty realization that carries validation diagnostics."""

    return AptlRealization(
        profiles=frozenset(),
        nodes=(),
        networks=(),
        placements=(),
        diagnostics=tuple(diagnostics),
    )


def _realize_node(
    resource: PlannedResource,
    payload: Mapping[str, Any],
    profile_index: ComposeProfileIndex,
    component_root: Path,
    config: AptlConfig,
    diagnostics: list[Diagnostic],
) -> NodeRealization:
    """Realize a node resource into APTL profile and runtime details.

    ``component_root`` is the engine checkout a ``materialization-specification``
    node's build context is resolved against (ADR-051), not the scenario bundle.
    """

    aliases = node_aliases(resource.address, payload)
    backend_services = profile_index.service_names_for_aliases(aliases)
    node_name = resource.address.rsplit(".", 1)[-1]
    # Project-tree scenarios retain their static Compose membership. A pack
    # has no static Compose model, so this remains empty until the exact
    # pack/backend interaction is resolved after all nodes have been lowered.
    profiles = profile_index.profiles_for_aliases(
        aliases
    ) | profile_index.profiles_for_services(set(backend_services))
    if not profiles and _is_raes_conformance_probe_node(resource, payload):
        backend_services = _conformance_probe_services(profile_index, config)
        profiles = profile_index.profiles_for_services(set(backend_services))
    spec = _mapping(payload.get("spec"))
    node_spec = _mapping(spec.get("node")) if spec else None
    infra_spec = _mapping(spec.get("infrastructure")) if spec else None
    if not backend_services:
        # Env-pack path (issue #875): with no static compose to index, the
        # node's own identity is its Compose service name. In-tree scenarios
        # ship a compose file, so this fallback never fires there.
        backend_services = frozenset({node_name})
    service_name = _single_or_none(tuple(sorted(backend_services)))
    node_os = _node_os(node_spec)
    node_os_version = _node_os_version(node_spec)
    node_runtime = _node_runtime(node_spec)
    container_name = _resolved_container_name(
        resource,
        profile_index,
        backend_services,
        node_name,
        node_os=node_os,
        node_os_version=node_os_version,
        node_runtime=node_runtime,
    )
    return NodeRealization(
        address=resource.address,
        name=_resource_name(resource.address, payload),
        aliases=tuple(sorted(aliases)),
        profiles=tuple(sorted(profiles)),
        backend_services=tuple(sorted(backend_services)),
        container_name=container_name,
        services=_service_ports(node_spec),
        networks=tuple(sorted(_network_names(infra_spec))),
        static_addresses=tuple(sorted(_static_addresses(infra_spec))),
        static_address_assignments=_static_address_assignments(infra_spec),
        published_ports=_published_ports(node_spec),
        image=resolve_node_image(
            resource=resource,
            payload=payload,
            project_dir=component_root,
            service_name=service_name,
            diagnostics=diagnostics,
        ),
        ordering_dependencies=resource.ordering_dependencies,
        os=node_os,
        os_version=node_os_version,
        runtime=node_runtime,
        dynamic_composition=node_source_is_dynamic_composition(
            payload, resource.address
        ),
    )


def _resolved_container_name(
    resource: PlannedResource,
    profile_index: ComposeProfileIndex,
    backend_services: frozenset[str],
    node_name: str,
    *,
    node_os: str,
    node_os_version: str,
    node_runtime: RuntimeConfiguration | None,
) -> str:
    """Return the container name the node realizes to.

    Preference order: the static compose service's own container name; then the
    ``base_container_spec`` name derived from the node's declared runtime; and
    finally APTL's ``aptl-<node>`` convention.
    """

    container_name = _container_name(profile_index, backend_services)
    if container_name is None and node_runtime is not None and node_os:
        container_name = base_container_spec(
            resource.address,
            os=node_os,
            os_version=node_os_version,
            runtime=node_runtime,
        ).container_name
    if container_name is None:
        # Env-pack image node (issue #875): no static compose service to read a
        # container name from, so use APTL's ``aptl-<node>`` convention (the
        # same one base_container_spec applies to image-free nodes). A node
        # whose own id already carries the prefix is not doubled.
        container_name = (
            node_name if node_name.startswith("aptl-") else f"aptl-{node_name}"
        )
    return container_name


def _node_os(node_spec: Mapping[str, Any] | None) -> str:
    """Return the node's declared OS family, or empty when undeclared."""

    return str(node_spec.get("os") or "") if node_spec else ""


def _node_os_version(node_spec: Mapping[str, Any] | None) -> str:
    """Return the node's declared OS version, or empty when undeclared."""

    return str(node_spec.get("os_version") or "") if node_spec else ""


def _node_runtime(node_spec: Mapping[str, Any] | None) -> RuntimeConfiguration | None:
    """Reconstruct the typed RAES RuntimeConfiguration from a node payload.

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
