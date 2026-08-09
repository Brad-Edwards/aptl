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

The concern registry is imported from RAES rather than restated, so APTL cannot
drift from the set of concerns the gate actually enforces.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from raes_contracts.planning import PlannedResource, ProvisioningPlan
from raes_processor.semantics.realization import CONCERN_PAYLOAD_PATH

from aptl.backends._raes_observation_helpers import (
    ObservedResource,
    container_realized as _container_realized,
    network_realized as _network_realized,
    observed_content_type as _observed_content_type,
    observed_domain_topology as _observed_domain_topology,
    observed_os_family as _observed_os_family,
    realized_network_names as _realized_network_names,
    settled_inspect as _settled_inspect,
)
from aptl.backends._raes_stateful_observation import (
    _observe_generated_artifact,
    _observe_persistent_volume,
)
from aptl.backends.raes_realization_model import (
    AptlRealization,
    ParticipantDatasetRealization,
)
from aptl.backends.raes_runtime_observation import observe_runtime_concerns
from aptl.utils.logging import get_logger

log = get_logger("realization-observe")

if TYPE_CHECKING:
    from raes.runtime_configuration import RuntimeConfiguration

    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.deployment.realization import (
        DeploymentContentRealization,
        DeploymentNodeRealization,
        DeploymentServiceMaterializationObservation,
        DeploymentServiceMaterializationRealization,
    )

# Compose defaults the project name to "aptl"; a backend that scopes to a
# different project exposes its own ``project_name``.
_DEFAULT_PROJECT_NAME = "aptl"

# RAES node vocabulary for the two things APTL can realize. A VM node becomes a
# container; a switch node compiles to a network resource and becomes a Docker
# network. These are what APTL *realized*, reported only once the corresponding
# object is observed to exist — never read back off the plan.
_REALIZED_NODE_TYPE = "vm"
_REALIZED_SWITCH_TYPE = "switch"

_NODE_TYPE_PATH = CONCERN_PAYLOAD_PATH["node-type"]
_OS_FAMILY_PATH = CONCERN_PAYLOAD_PATH["os-family"]
_CONTENT_TYPE_PATH = CONCERN_PAYLOAD_PATH["content-type"]
_SERVICE_SCHEMA_PATH = CONCERN_PAYLOAD_PATH[
    "service-search-index-schema-materialization"
]
_DOMAIN_TOPOLOGY_PATH = CONCERN_PAYLOAD_PATH["domain-topology"]


def observe_realization(
    backend: "DeploymentBackend",
    realization: AptlRealization,
    plan: ProvisioningPlan,
    scenario_root: Path,
) -> dict[str, ObservedResource]:
    """Return, per planned address, what the backend actually realized.

    ``scenario_root`` is the bundle root the scenario's declared inputs resolve
    against (issue #874). Generated artifacts are *produced* under the backend's
    own writable realization root rather than written back into a pristine
    staged pack, so they are read back from there (issue #875); in-tree the two
    roots coincide.
    """

    observations: dict[str, ObservedResource] = {}
    realization_root = _realization_root(backend, scenario_root)
    image_free = _image_free_addresses(realization)
    node_containers = {
        node.address: node.container_name
        for node in realization.nodes
        if node.container_name
    }
    node_runtimes = {
        node.address: node.runtime
        for node in realization.nodes
        if node.runtime is not None
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
    placement_datasets = {
        placement.address: placement.dataset
        for placement in realization.placements
        if placement.dataset is not None
    }
    placement_service_materializations = {
        placement.address: placement.service_materialization
        for placement in realization.placements
        if placement.service_materialization is not None
    }
    deployment_nodes = realization.deployment_spec(sorted(realization.profiles)).nodes
    project_name = getattr(backend, "project_name", _DEFAULT_PROJECT_NAME)
    realized_networks = _realized_network_names(backend, project_name)

    for address, resource in plan.resources.items():
        if resource.resource_type == "node":
            observations[address] = _observe_node(
                backend,
                node_containers.get(address),
                declared_domain_topology=_declared_domain_topology(resource),
                declared_runtime=node_runtimes.get(address),
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
                realization_root,
                image_free,
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
                placement_datasets.get(address),
                placement_service_materializations.get(address),
                deployment_nodes,
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


def _realization_root(backend: "DeploymentBackend", scenario_root: Path) -> Path:
    """Return the root the backend wrote its generated realization output to.

    The backend publishes it so the write side and the read-back side share one
    authority: reading generated artifacts back out of the pristine scenario
    bundle they were deliberately *not* written into makes every one of them
    look unrealized, and the SEM-218 gate then rejects an apply that succeeded
    (issue #875). A backend that publishes no root realizes in place, so the
    bundle root is the honest fallback.
    """

    root = getattr(backend, "realization_root", None)
    return root if isinstance(root, Path) else scenario_root


def _image_free_addresses(realization: AptlRealization) -> frozenset[str]:
    """Return the node addresses that are not Compose services.

    Only a node with a backing image becomes a Compose service and can carry a
    Compose bind; an image-free node receives its generated-artifact outputs as
    files placed into its container instead (issue #875). Observation has to
    distinguish the two or it demands a bind mount that realization never
    emitted.
    """

    return frozenset(node.address for node in realization.nodes if node.image is None)


def _declared_domain_topology(
    resource: "PlannedResource",
) -> Mapping[str, object] | None:
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
    declared_runtime: RuntimeConfiguration | None = None,
) -> ObservedResource:
    """Observe one RAES node through the container the backend realized for it."""

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
    concerns.update(
        observe_runtime_concerns(backend, container_name, info, declared_runtime)
    )
    return ObservedResource(realized=True, concerns=concerns)


def _observe_network(
    network_name: str | None,
    realized_networks: set[str],
    project_name: str,
) -> ObservedResource:
    """Observe one RAES network, which is how a switch node gets realized."""

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
    dataset: ParticipantDatasetRealization | None,
    service_materialization: "DeploymentServiceMaterializationRealization | None",
    deployment_nodes: tuple["DeploymentNodeRealization", ...],
) -> ObservedResource:
    """Observe a node-scoped placement through the node that received it.

    A content or account placement is realized into a node's container, so the
    container running and settled *is* the observable that the placement landed
    somewhere real. A placement whose target node never came up — or came up
    unhealthy — is not realized. ``target_address`` is the node address the real
    placement resolver already resolved for this placement (content, account, or
    feature binding), so this does not re-derive it from the raw payload.
    """

    observed: ObservedResource
    if service_materialization is not None:
        observed = _observe_service_materialization(
            backend, service_materialization, deployment_nodes
        )
    elif dataset is not None:
        observed = ObservedResource(
            realized=True,
            concerns={_CONTENT_TYPE_PATH: "dataset"},
            evidence={
                "storage_kind": dataset.storage_kind,
                "item_names": list(dataset.item_names),
            },
        )
    else:
        container_name = node_containers.get(target_address) if target_address else None
        info = _settled_inspect(backend, container_name) if container_name else {}
        if not container_name or not _container_realized(info):
            observed = ObservedResource(realized=False)
        else:
            concerns: dict[tuple[str, ...], object] = {}
            content_type = _observed_content_type(
                backend, content, container_name, info
            )
            if content_type is not None:
                concerns[_CONTENT_TYPE_PATH] = content_type
            observed = ObservedResource(realized=True, concerns=concerns)
    return observed


def _observe_service_materialization(
    backend: "DeploymentBackend",
    service_materialization: "DeploymentServiceMaterializationRealization",
    deployment_nodes: tuple["DeploymentNodeRealization", ...],
) -> ObservedResource:
    observer = getattr(backend, "observe_service_materialization", None)
    if observer is None:
        return ObservedResource(realized=False)
    readback: DeploymentServiceMaterializationObservation = observer(
        service_materialization, deployment_nodes
    )
    if not readback.realized or readback.binding is None:
        return ObservedResource(
            realized=False,
            evidence=dict(readback.evidence or {}),
        )
    return ObservedResource(
        realized=True,
        concerns={
            _CONTENT_TYPE_PATH: "dataset",
            _SERVICE_SCHEMA_PATH: dict(readback.binding),
        },
        evidence=dict(readback.evidence or {}),
    )
