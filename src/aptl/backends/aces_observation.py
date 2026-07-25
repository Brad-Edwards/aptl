"""Backend-observed realization state for the SEM-218 runtime gate (issue #578).

The SEM-218 non-approximation gate compares the value an author *declared* for a
realization concern against the value the backend *realized*, reading the latter
out of the snapshot the backend returns. APTL used to build that snapshot by
copying each planned resource's payload verbatim and marking it ``ready``, which
made the gate compare the plan against itself: it could never reject anything,
and a node the backend silently failed to start was still reported realized.

This module supplies the other half — what the deployment backend can actually
be *seen* to have done — so the snapshot records reality:

* a **node** is realized when its container is running (its ``os_family`` is read
  from the container's platform, so a linux-declared node backed by a windows
  container is caught);
* a **switch** node compiles to a network resource and is realized when the
  network exists;
* a resource the backend did not realize gets **no snapshot entry at all**, which
  is what the gate needs: an EXACT concern whose value is absent from the
  returned snapshot is a silent approximation and is rejected. Absence is the
  finding, not a gap to paper over.

The concern registry is imported from ACES rather than restated, so APTL cannot
drift from the set of concerns the gate actually enforces.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from aces_contracts.planning import PlannedResource, ProvisioningPlan
from aces_processor.semantics.realization import CONCERN_PAYLOAD_PATH

from aptl.backends._aces_observation_helpers import (
    ObservedResource,
    container_realized as _container_realized,
    network_realized as _network_realized,
    observed_content_type as _observed_content_type,
    observed_domain_topology as _observed_domain_topology,
    observed_os_family as _observed_os_family,
    realized_network_names as _realized_network_names,
    settled_inspect as _settled_inspect,
)
from aptl.backends._aces_stateful_observation import (
    _observe_generated_artifact,
    _observe_persistent_volume,
)
from aptl.backends.aces_realization_model import AptlRealization
from aptl.utils.logging import get_logger

log = get_logger("realization-observe")

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.deployment.realization import DeploymentContentRealization

# Compose defaults the project name to "aptl"; a backend that scopes to a
# different project exposes its own ``project_name``.
_DEFAULT_PROJECT_NAME = "aptl"

# ACES node vocabulary for the two things APTL can realize. A VM node becomes a
# container; a switch node compiles to a network resource and becomes a Docker
# network. These are what APTL *realized*, reported only once the corresponding
# object is observed to exist — never read back off the plan.
_REALIZED_NODE_TYPE = "vm"
_REALIZED_SWITCH_TYPE = "switch"

_NODE_TYPE_PATH = CONCERN_PAYLOAD_PATH["node-type"]
_OS_FAMILY_PATH = CONCERN_PAYLOAD_PATH["os-family"]
_CONTENT_TYPE_PATH = CONCERN_PAYLOAD_PATH["content-type"]
_DOMAIN_TOPOLOGY_PATH = CONCERN_PAYLOAD_PATH["domain-topology"]


def observe_realization(
    backend: "DeploymentBackend",
    realization: AptlRealization,
    plan: ProvisioningPlan,
) -> dict[str, ObservedResource]:
    """Return, per planned address, what the backend actually realized."""

    observations: dict[str, ObservedResource] = {}
    node_containers = {
        node.address: node.container_name
        for node in realization.nodes
        if node.container_name
    }
    network_names = {network.address: network.name for network in realization.networks}
    placement_targets = {
        placement.address: placement.target_address
        for placement in realization.placements
    }
    artifacts = {item.address: item for item in realization.generated_artifacts}
    volumes = {item.address: item for item in realization.persistent_volumes}
    placement_content = {
        placement.address: placement.content
        for placement in realization.placements
        if placement.content is not None
    }
    project_name = getattr(backend, "project_name", _DEFAULT_PROJECT_NAME)
    realized_networks = _realized_network_names(backend, project_name)

    for address, resource in plan.resources.items():
        if resource.resource_type == "node":
            observations[address] = _observe_node(
                backend,
                node_containers.get(address),
                declared_domain_topology=_declared_domain_topology(resource),
            )
        elif resource.resource_type == "network":
            observations[address] = _observe_network(
                network_names.get(address), realized_networks, project_name
            )
        elif resource.resource_type == "generated-artifact":
            observations[address] = _observe_generated_artifact(
                backend,
                artifacts.get(address),
                node_containers,
            )
        elif resource.resource_type == "persistent-volume":
            observations[address] = _observe_persistent_volume(
                backend,
                volumes.get(address),
                node_containers,
                project_name,
            )
        else:
            observations[address] = _observe_placement(
                backend,
                node_containers,
                placement_targets.get(address),
                placement_content.get(address),
            )
    return observations


def observation_evidence(
    observations: Mapping[str, ObservedResource],
) -> dict[str, dict[str, object]]:
    """Return only non-secret evidence for successfully observed resources."""

    return {
        address: dict(observed.evidence)
        for address, observed in observations.items()
        if observed.realized and observed.evidence
    }


def _declared_domain_topology(resource: "PlannedResource") -> Mapping[str, object] | None:
    """Return the node's declared domain topology when the plan carries one."""

    payload = resource.payload
    if not isinstance(payload, Mapping):
        return None
    topology = payload.get("domain_topology")
    return topology if isinstance(topology, Mapping) else None


def _observe_node(
    backend: "DeploymentBackend",
    container_name: str | None,
    declared_domain_topology: Mapping[str, object] | None = None,
) -> ObservedResource:
    """Observe one ACES node through the container the backend realized for it."""

    if not container_name:
        return ObservedResource(realized=False)
    info = _settled_inspect(backend, container_name)
    if not _container_realized(info):
        return ObservedResource(realized=False)

    concerns: dict[tuple[str, ...], object] = {
        _NODE_TYPE_PATH: _REALIZED_NODE_TYPE,
    }
    os_family = _observed_os_family(info)
    if os_family is not None:
        concerns[_OS_FAMILY_PATH] = os_family
    if declared_domain_topology is not None:
        topology = _observed_domain_topology(
            backend, container_name, declared_domain_topology
        )
        if topology is not None:
            concerns[_DOMAIN_TOPOLOGY_PATH] = topology
    return ObservedResource(realized=True, concerns=concerns)


def _observe_network(
    network_name: str | None,
    realized_networks: set[str],
    project_name: str,
) -> ObservedResource:
    """Observe one ACES network, which is how a switch node gets realized."""

    if not network_name or not _network_realized(
        network_name, realized_networks, project_name
    ):
        return ObservedResource(realized=False)
    return ObservedResource(
        realized=True,
        concerns={_NODE_TYPE_PATH: _REALIZED_SWITCH_TYPE},
    )


def _observe_placement(
    backend: "DeploymentBackend",
    node_containers: dict[str, str],
    target_address: str | None,
    content: DeploymentContentRealization | None,
) -> ObservedResource:
    """Observe a node-scoped placement through the node that received it.

    A content or account placement is realized into a node's container, so the
    container running and settled *is* the observable that the placement landed
    somewhere real. A placement whose target node never came up — or came up
    unhealthy — is not realized. ``target_address`` is the node address the real
    placement resolver already resolved for this placement (content, account, or
    feature binding), so this does not re-derive it from the raw payload.
    """

    container_name = node_containers.get(target_address) if target_address else None
    if not container_name:
        return ObservedResource(realized=False)
    if not _container_realized(_settled_inspect(backend, container_name)):
        return ObservedResource(realized=False)

    concerns: dict[tuple[str, ...], object] = {}
    content_type = _observed_content_type(backend, content, container_name)
    if content_type is not None:
        concerns[_CONTENT_TYPE_PATH] = content_type
    return ObservedResource(realized=True, concerns=concerns)
