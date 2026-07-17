"""Shared provider-readback helpers for ACES realization observation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from aptl.core.deployment._compose_realization_networks import (
    _match_managed_network,
)
from aptl.core.deployment._compose_service_health import (
    container_health,
    container_running,
)
from aptl.core.deployment.errors import (
    BackendSeedError,
    BackendTimeoutError,
)
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactRealization,
    DeploymentPersistentVolumeRealization,
    DeploymentStatefulConsumer,
)
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.deployment.realization import DeploymentContentRealization

log = get_logger("realization-observe")


def consumer_mount_evidence(
    consumers: tuple[DeploymentStatefulConsumer, ...],
) -> list[dict[str, str]]:
    """Describe each verified consumer mount without secret material."""

    return [
        {
            "target_address": consumer.target_address,
            "destination": consumer.mount_destination,
            "access_mode": consumer.access_mode,
            "service_health": "healthy",
        }
        for consumer in consumers
    ]


def mount_present(
    info: Mapping[str, Any],
    consumer: DeploymentStatefulConsumer,
    *,
    mount_type: str,
    source: str,
    destination: str | None = None,
) -> bool:
    """Return whether container inspection shows the exact desired mount."""

    mounts = info.get("Mounts")
    if not isinstance(mounts, list):
        return False
    for mount in mounts:
        if not isinstance(mount, Mapping):
            continue
        observed_source = (
            mount.get("Name") if mount_type == "volume" else mount.get("Source")
        )
        if (
            mount.get("Type") == mount_type
            and observed_source == source
            and mount.get("Destination") == (destination or consumer.mount_destination)
            and bool(mount.get("RW")) == (consumer.access_mode == "read_write")
        ):
            return True
    return False


def artifact_spec(
    artifact: DeploymentGeneratedArtifactRealization,
) -> dict[str, object]:
    """Render the ACES concern value observed for a generated artifact."""

    return {
        "generator": artifact.generator,
        "lifecycle": artifact.lifecycle,
        "provenance": artifact.provenance,
        "outputs": [output.details() for output in artifact.outputs],
        "consumers": [consumer_spec(consumer) for consumer in artifact.consumers],
    }


def volume_spec(volume: DeploymentPersistentVolumeRealization) -> dict[str, object]:
    """Render the ACES concern value observed for a persistent volume."""

    return {
        "lifecycle": volume.lifecycle,
        "access_mode": volume.access_mode,
        "consumers": [consumer_spec(consumer) for consumer in volume.consumers],
    }


def consumer_spec(consumer: DeploymentStatefulConsumer) -> dict[str, object]:
    """Render one stateful consumer as a non-secret concern value."""

    return {
        "node": consumer.node_name,
        "mount_destination": consumer.mount_destination,
        "access_mode": consumer.access_mode,
        "target_address": consumer.target_address,
    }


def safe_inspect(backend: "DeploymentBackend", name: str) -> dict[str, Any]:
    """Inspect a project-owned container, treating uncertainty as absent."""

    try:
        if not backend.container_exists(name):
            return {}
        info = backend.container_inspect(name)
    except (BackendTimeoutError, OSError) as exc:
        log.warning(
            "could not inspect project container %s (%s)",
            name,
            type(exc).__name__,
        )
        return {}
    return info if isinstance(info, dict) else {}


def container_realized(info: Mapping[str, Any]) -> bool:
    """Return whether an inspected container is running and healthy if checked."""

    if not info or not container_running(info):
        return False
    health = container_health(info)
    return not health or health == "healthy"


def observed_content_type(
    backend: "DeploymentBackend",
    content: DeploymentContentRealization | None,
) -> str | None:
    """Return the destination kind observed by the deployment provider."""

    if content is None:
        return None
    try:
        observed = backend.observe_content_type(content)
    except (BackendSeedError, BackendTimeoutError, OSError) as exc:
        log.warning(
            "could not observe content type for %s (%s)",
            content.address,
            type(exc).__name__,
        )
        return None
    return observed if observed in ("file", "directory") else None


def observed_os_family(info: Mapping[str, Any]) -> str | None:
    """Return the container platform in the ACES OS-family vocabulary."""

    platform = info.get("Platform")
    if isinstance(platform, str) and platform.strip():
        return platform.strip().lower()
    return None


def realized_network_names(
    backend: "DeploymentBackend",
    project_name: str,
) -> set[str]:
    """Return only the current Compose project's realized Docker networks."""

    try:
        names = backend.host_list_lab_networks(project_name)
    except (BackendTimeoutError, OSError) as exc:
        log.warning("could not list realized networks (%s)", type(exc).__name__)
        return set()
    return set(names) if isinstance(names, list | tuple | set) else set()


def network_realized(
    network_name: str,
    realized: set[str],
    project_name: str,
) -> bool:
    """Return whether a managed scenario network exists in provider readback."""

    return _match_managed_network(network_name, realized, project_name) is not None
