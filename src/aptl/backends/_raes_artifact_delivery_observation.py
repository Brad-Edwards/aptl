"""Generated-artifact delivery readback for RAES stateful observation."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from aptl.backends._raes_observation_helpers import (
    container_realized,
    mount_present,
    settled_inspect,
)
from aptl.core.deployment._compose_stateful_model import (
    _consumer_output_names,
    _uses_per_output_mounts,
)
from aptl.core.deployment._compose_stateful_readiness import (
    declared_wazuh_facts_match,
)
from aptl.core.deployment.backend import DeploymentBackend
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactRealization,
    DeploymentStatefulConsumer,
)
from aptl.utils.logging import get_logger

log = get_logger("realization-observe")


def artifact_environment_delivered(
    backend: DeploymentBackend,
    artifact: DeploymentGeneratedArtifactRealization,
    node_containers: dict[str, str],
    source: Path,
) -> bool:
    """Verify every generated environment value against daemon readback."""

    outputs = {output.name: source / output.path for output in artifact.outputs}
    return all(
        _environment_consumer_delivered(backend, consumer, node_containers, outputs)
        for consumer in artifact.environment_consumers
    )


def _environment_consumer_delivered(
    backend: DeploymentBackend,
    consumer: object,
    node_containers: dict[str, str],
    outputs: Mapping[str, Path],
) -> bool:
    """Verify one generated output against one realized environment binding."""

    target_address = getattr(consumer, "target_address", "")
    output_name = getattr(consumer, "output_name", "")
    variable = getattr(consumer, "environment_variable", "")
    container = node_containers.get(target_address)
    output = outputs.get(output_name)
    if not container or output is None:
        return False
    expected = _read_expected_value(output)
    realized = _container_environment(backend, container)
    return expected is not None and realized.get(variable) == expected


def _read_expected_value(output: Path) -> str | None:
    """Read one non-empty generated environment value."""

    try:
        value = output.read_text(encoding="utf-8").strip()
    except OSError:
        value = ""
    return value or None


def _container_environment(
    backend: DeploymentBackend, container: str
) -> dict[str, str]:
    """Read a settled container's daemon-observed environment mapping."""

    info = settled_inspect(backend, container)
    config = info.get("Config") if isinstance(info, Mapping) else None
    entries = config.get("Env") if isinstance(config, Mapping) else None
    realized: dict[str, str] = {}
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, str) and "=" in entry:
                name, _, value = entry.partition("=")
                realized[name] = value
    return realized


def consumers_mounted(
    backend: DeploymentBackend,
    consumers: tuple[DeploymentStatefulConsumer, ...],
    node_containers: dict[str, str],
    *,
    mount_type: str,
    source: str,
) -> bool:
    """Return whether every consumer has the exact observed mount contract."""

    return all(
        _consumer_volume_mounted(
            backend, consumer, node_containers, mount_type=mount_type, source=source
        )
        for consumer in consumers
    )


def _consumer_volume_mounted(
    backend: DeploymentBackend,
    consumer: DeploymentStatefulConsumer,
    node_containers: dict[str, str],
    *,
    mount_type: str,
    source: str,
) -> bool:
    """Return whether one consumer's container shows the desired mount."""

    container = node_containers.get(consumer.target_address)
    if not container:
        log.warning(
            "consumer %s has no realized container to observe",
            consumer.target_address,
        )
        return False
    info = settled_inspect(backend, container)
    if not container_realized(info):
        log.warning(
            "consumer container %s not settled/healthy for observation",
            container,
        )
        return False
    mounted = mount_present(info, consumer, mount_type=mount_type, source=source)
    if not mounted:
        log.warning(
            "consumer container %s missing %s mount of %s",
            container,
            mount_type,
            source,
        )
    return mounted


def artifact_consumers_mounted(
    backend: DeploymentBackend,
    artifact: DeploymentGeneratedArtifactRealization,
    node_containers: dict[str, str],
    source: Path,
    image_free_addresses: frozenset[str],
) -> bool:
    """Return whether every consumer received exactly its declared outputs."""

    return all(
        _artifact_consumer_realized(
            backend,
            artifact,
            consumer,
            node_containers,
            source,
            consumer.target_address in image_free_addresses,
        )
        for consumer in artifact.consumers
    )


def _artifact_consumer_realized(
    backend: DeploymentBackend,
    artifact: DeploymentGeneratedArtifactRealization,
    consumer: DeploymentStatefulConsumer,
    node_containers: dict[str, str],
    source: Path,
    image_free: bool,
) -> bool:
    """Observe one artifact through its actual bind or file-placement mechanism."""

    settled = _settled_consumer_container(backend, consumer, node_containers)
    if settled is None:
        return False
    container, info = settled
    if image_free:
        return _placed_outputs_present(backend, artifact, consumer, container)
    return all(
        mount_present(
            info,
            consumer,
            mount_type="bind",
            source=mount_source,
            destination=destination,
        )
        for mount_source, destination in _expected_consumer_mounts(
            artifact, consumer, source
        )
    )


def _settled_consumer_container(
    backend: DeploymentBackend,
    consumer: DeploymentStatefulConsumer,
    node_containers: dict[str, str],
) -> tuple[str, dict[str, Any]] | None:
    """Return one consumer's settled container identity and inspect record."""

    container = node_containers.get(consumer.target_address)
    if not container:
        log.warning(
            "artifact consumer %s has no realized container to observe",
            consumer.target_address,
        )
        return None
    info = settled_inspect(backend, container)
    if not container_realized(info):
        log.warning(
            "artifact consumer container %s not settled/healthy for observation",
            container,
        )
        return None
    return container, info


def _expected_consumer_mounts(
    artifact: DeploymentGeneratedArtifactRealization,
    consumer: DeploymentStatefulConsumer,
    source: Path,
) -> list[tuple[str, str]]:
    """Return the exact host-source/container-destination binds realization emitted."""

    if not _uses_per_output_mounts(artifact, consumer):
        return [(str(source), consumer.mount_destination)]
    by_name = {output.name: output for output in artifact.outputs}
    return [
        (
            str(source / by_name[name].path),
            str(PurePosixPath(consumer.mount_destination) / by_name[name].path),
        )
        for name in _consumer_output_names(artifact, consumer)
    ]


def _placed_outputs_present(
    backend: DeploymentBackend,
    artifact: DeploymentGeneratedArtifactRealization,
    consumer: DeploymentStatefulConsumer,
    container: str,
) -> bool:
    """Return whether an image-free consumer holds every selected output."""

    by_name = {output.name: output for output in artifact.outputs}
    names = _consumer_output_names(artifact, consumer)
    if not names:
        log.warning(
            "artifact %s places no output into image-free consumer %s",
            artifact.address,
            consumer.target_address,
        )
        return False
    return all(
        _placed_output_present(
            backend,
            artifact,
            consumer,
            container,
            str(PurePosixPath(consumer.mount_destination) / by_name[name].path),
        )
        for name in names
    )


def _placed_output_present(
    backend: DeploymentBackend,
    artifact: DeploymentGeneratedArtifactRealization,
    consumer: DeploymentStatefulConsumer,
    container: str,
    destination: str,
) -> bool:
    """Return whether one placed output exists at its container destination."""

    try:
        placed = (
            backend.container_exec(container, ["test", "-f", destination]).returncode
            == 0
        )
    except (BackendTimeoutError, OSError) as exc:
        log.warning(
            "could not observe placed artifact output in %s (%s)",
            container,
            type(exc).__name__,
        )
        return False
    if not placed:
        log.warning(
            "artifact %s output missing from image-free consumer %s",
            artifact.address,
            consumer.target_address,
        )
    return placed


def authenticated_consumers_ready(
    backend: DeploymentBackend,
    consumers: tuple[DeploymentStatefulConsumer, ...],
) -> bool:
    """Require declared-fact attestation for every Wazuh artifact consumer."""

    expected = {
        consumer.service_name
        for consumer in consumers
        if consumer.service_name in {"wazuh.indexer", "wazuh.manager"}
    }
    if not expected:
        return True
    readiness = getattr(backend, "declared_wazuh_attestation", {})
    ready = isinstance(readiness, Mapping) and all(
        declared_wazuh_facts_match(readiness, service) for service in expected
    )
    if not ready:
        log.warning(
            "declared Wazuh attestation not recorded for %s (map=%s)",
            sorted(expected),
            dict(readiness) if isinstance(readiness, Mapping) else type(readiness),
        )
    return ready


__all__ = (
    "artifact_consumers_mounted",
    "artifact_environment_delivered",
    "authenticated_consumers_ready",
    "consumers_mounted",
)
