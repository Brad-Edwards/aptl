"""Effective Compose validation for admitted persistent volumes."""

from __future__ import annotations

from collections.abc import Mapping

from aptl.core.deployment._compose_stateful_constants import (
    REALIZATION_ADDRESS_LABEL,
    REALIZATION_LIFECYCLE_LABEL,
    REALIZATION_PROJECT_LABEL,
)
from aptl.core.deployment.realization import (
    DeploymentPersistentVolumeRealization,
    DeploymentRealizationSpec,
)


def effective_volume_errors(
    payload: Mapping[str, object],
    project_name: str,
    realization: DeploymentRealizationSpec,
    non_compose_addresses: frozenset[str],
) -> list[str]:
    """Return identity/label mismatches for effective persistent volumes."""

    compose_volumes = _compose_persistent_volumes(realization, non_compose_addresses)
    if not compose_volumes:
        return []
    observed = payload.get("volumes")
    if not isinstance(observed, Mapping):
        return ["Effective Compose model has no volumes mapping."]
    return [
        f"Effective persistent volume {volume.address} has unexpected identity."
        for volume in compose_volumes
        if not _effective_volume_matches(
            observed.get(volume.name),
            project_name,
            volume.name,
            expected_volume_labels(
                volume.address,
                volume.lifecycle,
                project_name,
            ),
        )
    ]


def _compose_persistent_volumes(
    realization: DeploymentRealizationSpec,
    non_compose_addresses: frozenset[str],
) -> list[DeploymentPersistentVolumeRealization]:
    """Return persistent volumes mounted by at least one Compose service."""

    return [
        volume
        for volume in realization.persistent_volumes
        if any(
            consumer.target_address not in non_compose_addresses
            for consumer in volume.consumers
        )
    ]


def _effective_volume_matches(
    definition: object,
    project_name: str,
    volume_name: str,
    expected_labels: dict[str, str],
) -> bool:
    """Return whether one effective volume has the admitted identity."""

    return bool(
        isinstance(definition, Mapping)
        and definition.get("labels") == expected_labels
        and definition.get("name") == f"{project_name}_{volume_name}"
    )


def expected_volume_labels(
    address: str,
    lifecycle: str,
    project_name: str,
) -> dict[str, str]:
    """Return required labels for a project-scoped persistent volume."""

    return {
        REALIZATION_ADDRESS_LABEL: address,
        REALIZATION_LIFECYCLE_LABEL: lifecycle,
        REALIZATION_PROJECT_LABEL: project_name,
    }


__all__ = ("effective_volume_errors", "expected_volume_labels")
