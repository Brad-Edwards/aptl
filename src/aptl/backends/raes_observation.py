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
from raes_contracts.realization_observation import ObservedOperatingSystemIdentity
from raes_processor.semantics.realization import CONCERN_PAYLOAD_PATH

from aptl.backends._raes_observation_helpers import (
    ObservedResource,
    container_realized as _container_realized,
    network_realized as _network_realized,
    observed_content_type as _observed_content_type,
    observed_domain_topology as _observed_domain_topology,
    observed_os_family as _observed_os_family,
    settled_inspect as _settled_inspect,
)
from aptl.backends._raes_guest_os_observation import (
    guest_operating_system as _guest_operating_system,
)
from aptl.backends._raes_operational_observation import (
    operational_realization_observations as _operational_realization_observations,
)
from aptl.backends._raes_observation_index import (
    RealizationObservationIndex,
    build_observation_index,
)
from aptl.backends._raes_stateful_observation import (
    _observe_generated_artifact,
    _observe_persistent_volume,
)
from aptl.backends.raes_realization_model import (
    AptlRealization,
    ParticipantDatasetRealization,
)
from aptl.backends.raes_runtime_attestation import (
    observe_techvault_attested_concerns,
)
from aptl.backends.raes_runtime_observation import observe_runtime_concerns
from aptl.core.deployment._compose_service_health import runtime_expects_completion
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.utils.logging import get_logger

log = get_logger("realization-observe")

operational_realization_observations = _operational_realization_observations

if TYPE_CHECKING:
    from raes.runtime_configuration import RuntimeConfiguration

    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.deployment.observation import DeploymentObservationContext
    from aptl.core.deployment.realization import DeploymentContentRealization

# RAES node vocabulary for the two things APTL can realize. A compute node becomes a
# container; a switch node compiles to a network resource and becomes a Docker
# network. These are what APTL *realized*, reported only once the corresponding
# object is observed to exist — never read back off the plan.
_REALIZED_NODE_TYPE = "compute"
_REALIZED_SWITCH_TYPE = "switch"

_NODE_TYPE_PATH = CONCERN_PAYLOAD_PATH["node-type"]
_OS_FAMILY_PATH = CONCERN_PAYLOAD_PATH["os-family"]
_CONTENT_TYPE_PATH = CONCERN_PAYLOAD_PATH["content-type"]
_DOMAIN_TOPOLOGY_PATH = CONCERN_PAYLOAD_PATH["domain-topology"]
_SERVICE_INDEX_SCHEMA_PATH = CONCERN_PAYLOAD_PATH[
    "service-search-index-schema-materialization"
]


def observe_realization(
    backend: "DeploymentBackend",
    realization: AptlRealization,
    plan: ProvisioningPlan,
    scenario_root: Path,
    observation_context: DeploymentObservationContext | None = None,
) -> dict[str, ObservedResource]:
    """Return, per planned address, what the backend actually realized.

    ``scenario_root`` is the bundle root the scenario's declared inputs resolve
    against (issue #874). Generated artifacts are *produced* under the backend's
    own writable realization root rather than written back into a pristine
    staged pack, so they are read back from there (issue #875); in-tree the two
    roots coincide.
    """

    index = build_observation_index(backend, realization, plan, scenario_root)
    observations = {
        address: _observe_planned_resource(
            backend, address, resource, index, observation_context
        )
        for address, resource in plan.resources.items()
    }
    _add_techvault_runtime_attestations(
        backend,
        realization,
        observations,
        observation_context,
    )
    return observations


def _observe_planned_resource(
    backend: "DeploymentBackend",
    address: str,
    resource: PlannedResource,
    index: RealizationObservationIndex,
    observation_context: DeploymentObservationContext | None,
) -> ObservedResource:
    """Route one planned resource to its substrate-backed observer."""

    if resource.resource_type == "node":
        observed = _observe_node(
            backend,
            index.node_containers.get(address),
            declared_domain_topology=_declared_domain_topology(resource),
            declared_runtime=index.node_runtimes.get(address),
            observe_operating_system=address in index.operating_system_addresses,
            observe_backend_process_defaults=(
                address in index.open_process_limit_addresses
            ),
            observation_context=observation_context,
        )
    elif resource.resource_type == "network":
        observed = _observe_network(
            index.network_names.get(address),
            index.realized_networks,
            index.project_name,
        )
    elif resource.resource_type == "generated-artifact":
        observed = _observe_generated_artifact(
            backend,
            index.artifacts.get(address),
            index.node_containers,
            index.realization_root,
            index.image_free,
        )
    elif resource.resource_type == "persistent-volume":
        observed = _observe_persistent_volume(
            backend,
            index.volumes.get(address),
            index.node_containers,
            index.project_name,
        )
    elif address in index.placement_service_index_schemas:
        observed = _observe_service_content(backend, address, resource.payload)
    else:
        observed = _observe_placement(
            backend,
            index.node_containers,
            index.placement_targets.get(address),
            index.placement_content.get(address),
            index.placement_datasets.get(address),
        )
    return observed


def _add_techvault_runtime_attestations(
    backend: "DeploymentBackend",
    realization: AptlRealization,
    observations: dict[str, ObservedResource],
    observation_context: DeploymentObservationContext | None,
) -> None:
    """Attach only implementation-bound TechVault configuration disclosures."""

    for node in realization.nodes:
        observed_node = observations.get(node.address)
        if observed_node is None or not observed_node.realized:
            continue
        content, content_verified = _node_content_verification(
            realization, node.address, observations
        )
        if content and not content_verified:
            continue
        try:
            concerns = observe_techvault_attested_concerns(
                backend,
                node,
                realization.pack_identity,
                content_verified=content_verified,
                observation_context=observation_context,
            )
        except (BackendTimeoutError, OSError, TypeError, ValueError):
            concerns = {}
        if concerns:
            observed_node.concerns.update(concerns)


def _node_content_verification(
    realization: AptlRealization,
    node_address: str,
    observations: Mapping[str, ObservedResource],
) -> tuple[tuple[object, ...], bool]:
    """Return node content and whether every placement was read back."""

    content = tuple(
        placement
        for placement in realization.placements
        if placement.target_address == node_address and placement.content is not None
    )
    verified = bool(content) and all(
        (
            (observed := observations.get(placement.address)) is not None
            and observed.realized
            and _CONTENT_TYPE_PATH in observed.concerns
        )
        for placement in content
    )
    return content, verified


def observation_evidence(
    observations: Mapping[str, ObservedResource],
) -> dict[str, dict[str, object]]:
    """Return only non-secret evidence for successfully observed resources."""

    return {
        address: dict(observed.evidence)
        for address, observed in observations.items()
        if observed.realized and observed.evidence
    }


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
    observe_operating_system: bool = False,
    observe_backend_process_defaults: bool = False,
    observation_context: DeploymentObservationContext | None = None,
) -> ObservedResource:
    """Observe one RAES node through the container the backend realized for it."""

    if not container_name:
        return ObservedResource(realized=False)
    expect_completion = runtime_expects_completion(declared_runtime)
    info = _settled_inspect(backend, container_name)
    if expect_completion and not info and observation_context is not None:
        info = observation_context.completed_inspect(container_name)
    if not _container_realized(
        info,
        expect_completion=expect_completion,
    ):
        return ObservedResource(realized=False)

    concerns: dict[tuple[str, ...], object] = {
        _NODE_TYPE_PATH: _REALIZED_NODE_TYPE,
    }
    operating_system = _record_operating_system_concern(
        backend,
        container_name,
        info,
        observe_operating_system,
        observation_context,
        concerns,
    )
    _record_domain_topology_concern(
        backend, container_name, declared_domain_topology, concerns
    )
    concerns.update(
        observe_runtime_concerns(
            backend,
            container_name,
            info,
            declared_runtime,
            observe_backend_process_defaults=observe_backend_process_defaults,
            observation_context=observation_context,
        )
    )
    return ObservedResource(
        realized=True,
        concerns=concerns,
        operating_system=operating_system,
    )


def _record_operating_system_concern(
    backend: "DeploymentBackend",
    container_name: str,
    info: Mapping[str, object],
    observe_operating_system: bool,
    observation_context: DeploymentObservationContext | None,
    concerns: dict[tuple[str, ...], object],
) -> ObservedOperatingSystemIdentity | None:
    """Record the strongest admitted OS observation and return its identity."""

    operating_system = None
    if observe_operating_system:
        operating_system = _guest_operating_system(
            backend, container_name, observation_context
        )
        if operating_system is not None:
            concerns[_OS_FAMILY_PATH] = operating_system.family
    else:
        os_family = _observed_os_family(info)
        if os_family is not None:
            concerns[_OS_FAMILY_PATH] = os_family
    return operating_system


def _record_domain_topology_concern(
    backend: "DeploymentBackend",
    container_name: str,
    declared: Mapping[str, object] | None,
    concerns: dict[tuple[str, ...], object],
) -> None:
    """Record domain topology only when daemon readback establishes it."""

    topology = (
        _observed_domain_topology(backend, container_name, declared)
        if declared is not None
        else None
    )
    if topology is not None:
        concerns[_DOMAIN_TOPOLOGY_PATH] = topology


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
    if dataset is not None:
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


def _observe_service_content(
    backend: "DeploymentBackend",
    address: str,
    resource_payload: object,
) -> ObservedResource:
    """Observe an ADR-088 service-search-index-schema materialization.

    The materializer established the declared portable field schema on the target
    service and proved it by a fresh native readback during realization (issue
    #889), disclosing a safe portable receipt keyed by this content address. The
    exact ``service_materialization`` concern is emitted only when that
    corroboration is present; absence yields no concern, so the RAES
    non-approximation gate rejects an unproven materialization rather than
    accepting planned state (SEM-218). The receipt carries the portable field
    projection, digest, and readback strength — never a raw native response.
    """

    evidence_by_address = getattr(
        backend, "_service_index_materialization_evidence", {}
    )
    receipt = (
        evidence_by_address.get(address)
        if isinstance(evidence_by_address, Mapping)
        else None
    )
    binding = (
        resource_payload.get("service_materialization")
        if isinstance(resource_payload, Mapping)
        else None
    )
    if receipt is None or not isinstance(binding, Mapping):
        return ObservedResource(realized=False)
    # A service-materialization content-placement also compiles the ordinary
    # content-type EXACT concern (its ``spec.type`` — here ``dataset``). This
    # observer is the sole realization report for the address, so it must emit
    # that concern alongside the materialization concern; otherwise the
    # non-approximation gate reads content-type as an unrealized (omitted) exact
    # requirement and rejects the placement (issue #889).
    spec = (
        resource_payload.get("spec") if isinstance(resource_payload, Mapping) else None
    )
    content_type = spec.get("type") if isinstance(spec, Mapping) else None
    concerns: dict[tuple[str, ...], object] = {
        _SERVICE_INDEX_SCHEMA_PATH: dict(binding)
    }
    if isinstance(content_type, str) and content_type:
        concerns[_CONTENT_TYPE_PATH] = content_type
    return ObservedResource(
        realized=True,
        concerns=concerns,
        evidence=dict(receipt),
    )
