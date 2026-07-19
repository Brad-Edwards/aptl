"""Stateful artifact and volume observation for the SEM-218 runtime gate.

Split from :mod:`aptl.backends.aces_observation` (python:S104): this module
owns the generated-artifact and persistent-volume observers — outputs-present
verification, consumer mount readback, authenticated Wazuh readiness, and
non-secret evidence assembly. Node, network, and placement observation stay
in :mod:`aptl.backends.aces_observation`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from aces_processor.semantics.realization import CONCERN_PAYLOAD_PATH

from aptl.backends._aces_observation_helpers import (
    ObservedResource,
    artifact_spec as _artifact_spec,
    consumer_mount_evidence as _consumer_mount_evidence,
    container_realized as _container_realized,
    mount_present as _mount_present,
    settled_inspect as _settled_inspect,
    volume_spec as _volume_spec,
)
from aptl.core.deployment._compose_stateful_realization import artifact_source_path
from aptl.core.deployment._stateful_certificates import certificate_bundle_evidence
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactRealization,
    DeploymentPersistentVolumeRealization,
    DeploymentStatefulConsumer,
)
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

log = get_logger("realization-observe")


def _observe_generated_artifact(
    backend: "DeploymentBackend",
    artifact: DeploymentGeneratedArtifactRealization | None,
    node_containers: dict[str, str],
) -> ObservedResource:
    """Observe verified outputs and read-only bind mounts for one artifact."""

    project_dir = getattr(backend, "project_dir", None)
    if artifact is None or not isinstance(project_dir, Path):
        return ObservedResource(realized=False)
    source = artifact_source_path(project_dir, artifact)
    outputs_present = _artifact_outputs_present(source, artifact)
    consumers_mounted = outputs_present and _artifact_consumers_mounted(
        backend, artifact, node_containers, source
    )
    consumers_ready = consumers_mounted and _authenticated_consumers_ready(
        backend, artifact.consumers
    )
    realized = consumers_ready
    evidence = (
        _artifact_evidence(backend, project_dir, source, artifact) if realized else {}
    )
    realized = realized and (
        artifact.generator != "certificate_bundle" or "certificate" in evidence
    )
    if not realized:
        # An unrealized observation always fails the SEM-218 gate, so the
        # failing predicate must be diagnosable from the log (names and
        # booleans only — never artifact bytes).
        log.warning(
            "artifact %s not observed as realized "
            "(outputs=%s consumers_mounted=%s consumers_ready=%s evidence=%s)",
            artifact.address,
            outputs_present,
            consumers_mounted,
            consumers_ready,
            bool(evidence),
        )
        return ObservedResource(realized=False)
    return ObservedResource(
        realized=True,
        concerns={CONCERN_PAYLOAD_PATH["generated-artifact"]: _artifact_spec(artifact)},
        evidence=evidence,
    )


def _artifact_outputs_present(
    source: Path,
    artifact: DeploymentGeneratedArtifactRealization,
) -> bool:
    """Return whether every declared artifact output exists at its source."""

    if source.is_dir():
        return all((source / output.path).is_file() for output in artifact.outputs)
    return source.is_file() and len(artifact.outputs) == 1


def _observe_persistent_volume(
    backend: "DeploymentBackend",
    volume: DeploymentPersistentVolumeRealization | None,
    node_containers: dict[str, str],
    project_name: str,
) -> ObservedResource:
    """Observe project-scoped named-volume mounts for one desired volume."""

    if volume is None:
        return ObservedResource(realized=False)
    mounted = _consumers_mounted(
        backend,
        volume.consumers,
        node_containers,
        mount_type="volume",
        source=f"{project_name}_{volume.name}",
    )
    ready = mounted and _authenticated_consumers_ready(backend, volume.consumers)
    if not ready:
        log.warning(
            "volume %s not observed as realized (mounted=%s ready=%s)",
            volume.address,
            mounted,
            ready,
        )
        return ObservedResource(realized=False)
    return ObservedResource(
        realized=True,
        concerns={CONCERN_PAYLOAD_PATH["persistent-volume"]: _volume_spec(volume)},
        evidence={
            "address": volume.address,
            "status": "ready",
            "volume_identity": f"{project_name}_{volume.name}",
            "lifecycle": volume.lifecycle,
            "consumer_mounts": _consumer_mount_evidence(volume.consumers),
        },
    )



def _artifact_evidence(
    backend: "DeploymentBackend",
    project_dir: Path,
    source: Path,
    artifact: DeploymentGeneratedArtifactRealization,
) -> dict[str, object]:
    """Build non-secret evidence for an artifact verified by provider readback."""

    evidence: dict[str, object] = {
        "address": artifact.address,
        "status": "ready",
        "consumer_mounts": _consumer_mount_evidence(artifact.consumers),
    }
    readiness = getattr(backend, "authenticated_readiness", {})
    if isinstance(readiness, Mapping):
        observed_readiness = {
            consumer.service_name: bool(readiness[consumer.service_name])
            for consumer in artifact.consumers
            if consumer.service_name in readiness
        }
        if observed_readiness:
            evidence["authenticated_readiness"] = observed_readiness
    if artifact.generator == "rendered_config" and source.is_file():
        evidence["configuration_sha256"] = hashlib.sha256(
            source.read_bytes()
        ).hexdigest()
    elif artifact.generator == "certificate_bundle":
        certificate = certificate_bundle_evidence(
            source,
            artifact.outputs,
            project_dir / artifact.provenance,
        )
        if certificate is not None:
            evidence["certificate"] = certificate
    return evidence


def _consumers_mounted(
    backend: "DeploymentBackend",
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
    backend: "DeploymentBackend",
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
    info = _settled_inspect(backend, container)
    if not _container_realized(info):
        log.warning(
            "consumer container %s not settled/healthy for observation",
            container,
        )
        return False
    mounted = _mount_present(info, consumer, mount_type=mount_type, source=source)
    if not mounted:
        log.warning(
            "consumer container %s missing %s mount of %s",
            container,
            mount_type,
            source,
        )
    return mounted


def _artifact_consumers_mounted(
    backend: "DeploymentBackend",
    artifact: DeploymentGeneratedArtifactRealization,
    node_containers: dict[str, str],
    source: Path,
) -> bool:
    """Return whether every consumer sees only its declared artifact outputs."""

    return all(
        _artifact_consumer_mounted(
            backend,
            artifact,
            consumer,
            node_containers,
            source,
        )
        for consumer in artifact.consumers
    )


def _artifact_consumer_mounted(
    backend: "DeploymentBackend",
    artifact: DeploymentGeneratedArtifactRealization,
    consumer: DeploymentStatefulConsumer,
    node_containers: dict[str, str],
    source: Path,
) -> bool:
    """Return whether one artifact consumer has every declared bind mount."""

    container = node_containers.get(consumer.target_address)
    if not container:
        log.warning(
            "artifact consumer %s has no realized container to observe",
            consumer.target_address,
        )
        return False
    info = _settled_inspect(backend, container)
    if not _container_realized(info):
        log.warning(
            "artifact consumer container %s not settled/healthy for observation",
            container,
        )
        return False
    expected = (
        [
            (
                str(source / output.path),
                str(PurePosixPath(consumer.mount_destination) / output.path),
            )
            for output in artifact.outputs
        ]
        if artifact.generator == "certificate_bundle"
        else [(str(source), consumer.mount_destination)]
    )
    return all(
        _mount_present(
            info,
            consumer,
            mount_type="bind",
            source=mount_source,
            destination=destination,
        )
        for mount_source, destination in expected
    )


def _authenticated_consumers_ready(
    backend: "DeploymentBackend",
    consumers: tuple[DeploymentStatefulConsumer, ...],
) -> bool:
    """Require authenticated readback for every Wazuh artifact consumer."""

    expected = {
        consumer.service_name
        for consumer in consumers
        if consumer.service_name in {"wazuh.indexer", "wazuh.manager"}
    }
    if not expected:
        return True
    readiness = getattr(backend, "authenticated_readiness", {})
    ready = isinstance(readiness, Mapping) and all(
        readiness.get(service) is True for service in expected
    )
    if not ready:
        log.warning(
            "authenticated readiness not recorded for %s (map=%s)",
            sorted(expected),
            dict(readiness) if isinstance(readiness, Mapping) else type(readiness),
        )
    return ready
