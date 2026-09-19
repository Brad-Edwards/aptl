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

from aptl.backends._raes_realization_diagnostics import (
    _append_node_profile_diagnostic,
    _append_profile_diagnostics,
    _invalid_payload_diagnostics,
)
from aptl.backends import _raes_node_realization
from aptl.backends.pack_interaction import ResolvedPackBackendInteraction
from aptl.backends.raes_pack_interaction import apply_pack_interaction
from aptl.backends.raes_placement_realization import (
    placement_node_lookup as _node_lookup,
    realize_placements as _realize_placements,
)
from aptl.backends.raes_profiles import (
    ComposeProfileIndex,
    load_compose_profile_index,
)
from aptl.backends.raes_realization_networks import (
    append_network_topology_diagnostics,
)
from aptl.backends.raes_stateful_realization import realize_stateful_resources
from aptl.backends.raes_realization_model import (
    AptlRealization,
    NetworkRealization,
    NodeRealization,
)
from aptl.backends.raes_realization_values import (
    mapping as _mapping,
    optional_bool as _optional_bool,
    optional_string as _optional_string,
    resource_name as _resource_name,
)
from aptl.core.config import AptlConfig
from aptl.core.deployment.realization import DeploymentGeneratedArtifactRealization
from aptl.core.scenario_bundle import ScenarioBundle
from aptl.utils.redaction import redact

_realize_node = _raes_node_realization._realize_node
# Compatibility exports used by focused node-realization tests and downstream
# diagnostics. The implementation lives in the split node module.
_container_name = _raes_node_realization._container_name
_node_os = _raes_node_realization._node_os
_node_os_version = _raes_node_realization._node_os_version
_node_runtime = _raes_node_realization._node_runtime


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
        plan,
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
    generated_artifacts = _merge_backend_generated_artifacts(
        generated_artifacts,
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
    plan: ProvisioningPlan,
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
                plan,
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


def _merge_backend_generated_artifacts(
    authored: list[DeploymentGeneratedArtifactRealization],
    nodes: list[NodeRealization],
    diagnostics: list[Diagnostic],
) -> list[DeploymentGeneratedArtifactRealization]:
    """Add backend-selected prerequisites without overriding authored state."""

    merged = list(authored)
    by_name = {artifact.name: artifact for artifact in authored}
    for candidate in (
        artifact for node in nodes for artifact in node.backend_generated_artifacts
    ):
        candidate = _canonical_ordering_dependencies(candidate, by_name)
        existing = by_name.get(candidate.name)
        if existing is None:
            merged.append(candidate)
            by_name[candidate.name] = candidate
            continue
        if _same_generated_artifact_contract(existing, candidate):
            continue
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.backend-generated-artifact-conflict",
                candidate.address,
                "A backend-selected generated artifact conflicts with an authored artifact.",
            )
        )
    return merged


def _canonical_ordering_dependencies(
    candidate: DeploymentGeneratedArtifactRealization,
    authored: dict[str, DeploymentGeneratedArtifactRealization],
) -> DeploymentGeneratedArtifactRealization:
    """Rewrite a backend artifact's ordering references to realized addresses.

    A backend profile names its producer the way the SDL does
    (``generated_artifacts.<name>``) because it is selected per node and cannot
    see the address realization will assign. Everything downstream -- stateful
    validation, cycle detection, and execution ordering -- compares exact
    addresses, so the reference is canonicalized once here rather than resolved
    differently by each of them. A reference naming nothing authored is left as
    it is, so validation still reports it instead of it quietly disappearing.
    """

    if not candidate.ordering_dependencies:
        return candidate
    resolved = tuple(
        authored[reference.rsplit(".", 1)[-1]].address
        if reference not in authored and reference.rsplit(".", 1)[-1] in authored
        else reference
        for reference in candidate.ordering_dependencies
    )
    if resolved == candidate.ordering_dependencies:
        return candidate
    return DeploymentGeneratedArtifactRealization(
        address=candidate.address,
        name=candidate.name,
        generator=candidate.generator,
        lifecycle=candidate.lifecycle,
        provenance=candidate.provenance,
        outputs=candidate.outputs,
        consumers=candidate.consumers,
        environment_consumers=candidate.environment_consumers,
        ordering_dependencies=resolved,
        refresh_dependencies=candidate.refresh_dependencies,
    )


def _same_generated_artifact_contract(
    left: DeploymentGeneratedArtifactRealization,
    right: DeploymentGeneratedArtifactRealization,
) -> bool:
    """Compare artifact behavior while allowing authored/backend addresses to differ."""

    return (
        left.name == right.name
        and left.generator == right.generator
        and left.lifecycle == right.lifecycle
        and left.provenance == right.provenance
        and left.outputs == right.outputs
        and left.consumers == right.consumers
        and left.environment_consumers == right.environment_consumers
        and left.ordering_dependencies == right.ordering_dependencies
        and left.refresh_dependencies == right.refresh_dependencies
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
