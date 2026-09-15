"""Indexes used while projecting an APTL realization into observations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from raes.runtime_configuration import RuntimeConfiguration
from raes_contracts.planning import ProvisioningPlan
from raes_contracts.realization_authority import RealizationAuthorityMode

from aptl.backends._raes_observation_helpers import realized_network_names
from aptl.backends.raes_realization_model import (
    AptlRealization,
    ParticipantDatasetRealization,
)
from aptl.core.deployment.realization import (
    DeploymentContentRealization,
    DeploymentGeneratedArtifactRealization,
    DeploymentPersistentVolumeRealization,
)

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

_DEFAULT_PROJECT_NAME = "aptl"


@dataclass(frozen=True)
class RealizationObservationIndex:
    """Address-indexed realization inputs shared by resource observers."""

    realization_root: Path
    image_free: frozenset[str]
    node_containers: dict[str, str]
    node_runtimes: dict[str, RuntimeConfiguration]
    network_names: dict[str, str]
    placement_targets: dict[str, str]
    artifacts: dict[str, DeploymentGeneratedArtifactRealization]
    volumes: dict[str, DeploymentPersistentVolumeRealization]
    placement_content: dict[str, DeploymentContentRealization]
    placement_datasets: dict[str, ParticipantDatasetRealization]
    placement_service_index_schemas: frozenset[str]
    project_name: str
    realized_networks: set[str]
    operating_system_addresses: frozenset[str]
    open_process_limit_addresses: frozenset[str]


def build_observation_index(
    backend: DeploymentBackend,
    realization: AptlRealization,
    plan: ProvisioningPlan,
    scenario_root: Path,
) -> RealizationObservationIndex:
    """Build all address maps once before observing the planned resources."""

    project_name = getattr(backend, "project_name", _DEFAULT_PROJECT_NAME)
    return RealizationObservationIndex(
        realization_root=_realization_root(backend, scenario_root),
        image_free=frozenset(
            node.address for node in realization.nodes if node.image is None
        ),
        node_containers={
            node.address: node.container_name
            for node in realization.nodes
            if node.container_name
        },
        node_runtimes={
            node.address: node.runtime
            for node in realization.nodes
            if node.runtime is not None
        },
        network_names={item.address: item.name for item in realization.networks},
        placement_targets={
            item.address: item.target_address for item in realization.placements
        },
        artifacts={item.address: item for item in realization.generated_artifacts},
        volumes={item.address: item for item in realization.persistent_volumes},
        placement_content={
            item.address: item.content
            for item in realization.placements
            if item.content is not None
        },
        placement_datasets={
            item.address: item.dataset
            for item in realization.placements
            if item.dataset is not None
        },
        placement_service_index_schemas=frozenset(
            item.address
            for item in realization.placements
            if item.service_index_schema is not None
        ),
        project_name=project_name,
        realized_networks=realized_network_names(backend, project_name),
        operating_system_addresses=frozenset(
            authority.address
            for authority in plan.realization_authority
            if authority.requirement_kind == "os-family"
            and authority.verification_scope is not None
        ),
        open_process_limit_addresses=frozenset(
            authority.address
            for authority in plan.realization_authority
            if authority.requirement_kind == "process-resource-limits"
            and authority.mode is RealizationAuthorityMode.OPEN
        ),
    )


def _realization_root(backend: DeploymentBackend, scenario_root: Path) -> Path:
    """Return the backend's generated-output root or the scenario root."""

    root = getattr(backend, "realization_root", None)
    return root if isinstance(root, Path) else scenario_root


__all__ = ("RealizationObservationIndex", "build_observation_index")
