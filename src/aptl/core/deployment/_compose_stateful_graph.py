"""Fail-closed validation for typed stateful realization graphs."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from aptl.core.deployment._compose_stateful_constants import (
    OWNED_WAZUH_SERVICES,
    WAZUH_INDEXER_SERVICE,
    WAZUH_MANAGER_SERVICE,
)
from aptl.core.deployment.realization import DeploymentRealizationSpec


def stateful_realization_errors(
    realization: DeploymentRealizationSpec,
    *,
    local_artifacts: bool,
) -> list[str]:
    """Return fail-closed graph errors before any backend side effect."""

    if realization.generated_artifacts and not local_artifacts:
        return [
            "Generated artifacts cannot be materialized for a remote Docker daemon."
        ]
    errors = _artifact_errors(realization)
    errors.extend(_volume_errors(realization))
    errors.extend(_dependency_errors(realization))
    errors.extend(_mount_conflicts(realization))
    errors.extend(_wazuh_definition_errors(realization))
    return errors


def owned_wazuh_services(realization: DeploymentRealizationSpec) -> set[str]:
    """Return Wazuh services whose stateful resources are graph-owned."""

    return {
        consumer.service_name
        for resource in (
            *realization.generated_artifacts,
            *realization.persistent_volumes,
        )
        for consumer in resource.consumers
        if consumer.service_name in OWNED_WAZUH_SERVICES
    }


def compose_version(value: str) -> tuple[int, int, int] | None:
    """Parse a Compose semantic version without backtracking regular expressions."""

    version: tuple[int, int, int] | None = None
    for token in value.split():
        candidate = token.strip("()[],").removeprefix("v").split("-", maxsplit=1)[0]
        parts = candidate.split(".")
        if len(parts) >= 3 and all(part.isdigit() for part in parts[:3]):
            version = (int(parts[0]), int(parts[1]), int(parts[2]))
            break
    return version


def _wazuh_definition_errors(realization: DeploymentRealizationSpec) -> list[str]:
    """Return errors for incomplete graph-owned Wazuh definitions."""

    owned = owned_wazuh_services(realization)
    nodes = {node.service_name: node for node in realization.nodes}
    images = {image.service_name for image in realization.images}
    errors = [
        f"Stateful service {service} has an incomplete node definition."
        for service in sorted(owned)
        if (
            (node := nodes.get(service)) is None
            or not node.container_name
            or not node.network_attachments
        )
    ]
    errors.extend(
        f"Stateful service {service} has no trusted image realization."
        for service in sorted(owned - images)
    )
    manager = nodes.get(WAZUH_MANAGER_SERVICE)
    indexer = nodes.get(WAZUH_INDEXER_SERVICE)
    dependency_missing = (
        manager is not None
        and WAZUH_MANAGER_SERVICE in owned
        and (indexer is None or indexer.address not in manager.ordering_dependencies)
    )
    if dependency_missing:
        errors.append("Wazuh manager does not depend on the realized indexer node.")
    return errors


def _artifact_errors(realization: DeploymentRealizationSpec) -> list[str]:
    """Return generated-artifact provider, access, and path errors."""

    errors: list[str] = []
    for artifact in realization.generated_artifacts:
        if (
            artifact.generator == "certificate_bundle"
            and artifact.provenance != "config/certs.yml"
        ):
            errors.append(
                f"Generated artifact {artifact.address} has unsupported provenance."
            )
        if artifact.generator == "rendered_config" and len(artifact.outputs) != 1:
            errors.append(
                f"Rendered config {artifact.address} must declare exactly one output."
            )
        if any(consumer.access_mode != "read_only" for consumer in artifact.consumers):
            errors.append(
                f"Generated artifact {artifact.address} must be mounted read-only."
            )
        if any(not _safe_relative(output.path) for output in artifact.outputs):
            errors.append(
                f"Generated artifact {artifact.address} has an unsafe output path."
            )
    return errors


def _volume_errors(realization: DeploymentRealizationSpec) -> list[str]:
    """Return persistent-volume writer cardinality and access errors."""

    errors: list[str] = []
    for volume in realization.persistent_volumes:
        writers = {
            consumer.target_address
            for consumer in volume.consumers
            if consumer.access_mode == "read_write"
        }
        if volume.access_mode == "read_write_once" and len(writers) > 1:
            errors.append(
                f"Persistent volume {volume.address} has multiple writer nodes."
            )
        if volume.access_mode == "read_only_many" and writers:
            errors.append(
                f"Persistent volume {volume.address} is read-only but has a writer."
            )
    return errors


def _dependency_errors(realization: DeploymentRealizationSpec) -> list[str]:
    """Return unresolved dependency and ordering-cycle errors."""

    resources = {
        item.address: item
        for item in (
            *realization.generated_artifacts,
            *realization.persistent_volumes,
        )
    }
    errors: list[str] = []
    known_addresses = set(resources)
    for resource in resources.values():
        dependencies = (
            *resource.ordering_dependencies,
            *resource.refresh_dependencies,
        )
        if set(dependencies) - known_addresses:
            errors.append(
                f"Stateful resource {resource.address} has an unresolved dependency."
            )
    if _has_ordering_cycle(resources):
        errors.append("Stateful realization ordering dependencies contain a cycle.")
    return errors


def _has_ordering_cycle(resources: dict[str, Any]) -> bool:
    """Return whether the stateful ordering dependency graph contains a cycle."""

    pending = {
        address: set(resource.ordering_dependencies)
        for address, resource in resources.items()
    }
    cycle_found = False
    while pending and not cycle_found:
        ready = {
            address for address, dependencies in pending.items() if not dependencies
        }
        cycle_found = not ready
        if not cycle_found:
            pending = {
                address: dependencies - ready
                for address, dependencies in pending.items()
                if address not in ready
            }
    return cycle_found


def _mount_conflicts(realization: DeploymentRealizationSpec) -> list[str]:
    """Return an error when two resources claim one consumer destination."""

    occupied: set[tuple[str, str]] = set()
    conflict_found = False
    for resource in (
        *realization.generated_artifacts,
        *realization.persistent_volumes,
    ):
        for consumer in resource.consumers:
            destination = (consumer.target_address, consumer.mount_destination)
            conflict_found = conflict_found or destination in occupied
            occupied.add(destination)
    return (
        ["Stateful resources claim the same consumer mount destination."]
        if conflict_found
        else []
    )


def _safe_relative(value: str) -> bool:
    """Return whether a generated output is a canonical POSIX relative path."""

    path = PurePosixPath(value)
    return bool(
        value
        and not path.is_absolute()
        and ".." not in path.parts
        and str(path) == value
        and "\\" not in value
    )
