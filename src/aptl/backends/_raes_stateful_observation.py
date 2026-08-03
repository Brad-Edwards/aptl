"""Stateful artifact and volume observation for the SEM-218 runtime gate.

Split from :mod:`aptl.backends.raes_observation` (python:S104): this module
owns the generated-artifact and persistent-volume observers — outputs-present
verification, consumer mount readback, authenticated Wazuh readiness, and
non-secret evidence assembly. Node, network, and placement observation stay
in :mod:`aptl.backends.raes_observation`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from raes_processor.semantics.realization import CONCERN_PAYLOAD_PATH

from aptl.backends._raes_observation_helpers import (
    ObservedResource,
    artifact_spec as _artifact_spec,
    consumer_mount_evidence as _consumer_mount_evidence,
    container_realized as _container_realized,
    mount_present as _mount_present,
    settled_inspect as _settled_inspect,
    volume_spec as _volume_spec,
)
from aptl.core.deployment._compose_stateful_constants import (
    CERTIFICATE_PROVENANCE,
    SOC_CERT_PROFILE,
)
from aptl.core.deployment._compose_stateful_model import (
    _consumer_output_names,
    _uses_per_output_mounts,
)
from aptl.core.deployment._compose_stateful_realization import artifact_source_path
from aptl.core.deployment._stateful_certificates import certificate_bundle_evidence
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactRealization,
    DeploymentPersistentVolumeRealization,
    DeploymentStatefulConsumer,
)
from aptl.core.soc_ca import soc_bundle_evidence
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

log = get_logger("realization-observe")


def _observe_generated_artifact(
    backend: "DeploymentBackend",
    artifact: DeploymentGeneratedArtifactRealization | None,
    node_containers: dict[str, str],
    realization_root: Path,
    image_free_addresses: frozenset[str],
) -> ObservedResource:
    """Observe verified outputs and realized delivery for one artifact.

    A generated artifact is read back from ``realization_root`` -- the writable
    root the backend produced it under -- never from the pristine scenario
    bundle it was deliberately not written into (issue #875). In-tree the two
    coincide. ``image_free_addresses`` names the consumers that receive their
    outputs as placed files rather than Compose binds.
    """

    if artifact is None or not isinstance(realization_root, Path):
        return ObservedResource(realized=False)
    source = artifact_source_path(realization_root, artifact)
    outputs_present = _artifact_outputs_present(source, artifact)
    consumers_mounted = outputs_present and _artifact_consumers_mounted(
        backend, artifact, node_containers, source, image_free_addresses
    )
    consumers_ready = consumers_mounted and _authenticated_consumers_ready(
        backend, artifact.consumers
    )
    realized = consumers_ready
    evidence = (
        _artifact_evidence(backend, realization_root, source, artifact)
        if realized
        else {}
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
    realization_root: Path,
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
        certificate = _certificate_evidence(realization_root, source, artifact)
        if certificate is not None:
            evidence["certificate"] = certificate
    return evidence


def _certificate_evidence(
    realization_root: Path,
    source: Path,
    artifact: DeploymentGeneratedArtifactRealization,
) -> dict[str, object] | None:
    """Validate a realized certificate bundle in the shape its generator issued.

    Two bundle shapes exist and neither validator can read the other. The Wazuh
    shape is ``root-ca.pem`` plus ``*-key.pem`` leaves; the SOC shape carries its
    own CA name, ``.key`` private keys, and PKCS#12 keystores. Running one
    validator over both reports a correctly issued bundle as invalid, which
    strips its whole snapshot entry and makes the SEM-218 gate reject
    certificates APTL had just generated and verified (issue #875).

    Every shape is still cryptographically validated -- nothing is accepted on
    file presence. Only the identity-versus-provenance-document comparison is
    conditional, because only the in-tree bundle ships that document; an env-pack
    declares its bundle by profile identity instead, which is the same carve-out
    realization already makes before validating.
    """

    if artifact.provenance == SOC_CERT_PROFILE:
        return soc_bundle_evidence(
            source, tuple(output.path for output in artifact.outputs)
        )
    return certificate_bundle_evidence(
        source,
        artifact.outputs,
        realization_root / artifact.provenance
        if artifact.provenance == CERTIFICATE_PROVENANCE
        else None,
    )


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
    backend: "DeploymentBackend",
    artifact: DeploymentGeneratedArtifactRealization,
    consumer: DeploymentStatefulConsumer,
    node_containers: dict[str, str],
    source: Path,
    image_free: bool,
) -> bool:
    """Return whether one consumer received the artifact the way it was delivered.

    Delivery is not one shape: only a Compose service can carry a bind, so an
    image-free node's outputs are placed into its container as files instead
    (issue #875). Observing every consumer as if it were bind-mounted demands a
    mount realization never emitted and reports a delivered artifact as
    unrealized, so each consumer is read back through the mechanism that
    actually delivered it.
    """

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
    if image_free:
        return _placed_outputs_present(backend, artifact, consumer, container)
    return all(
        _mount_present(
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


def _expected_consumer_mounts(
    artifact: DeploymentGeneratedArtifactRealization,
    consumer: DeploymentStatefulConsumer,
    source: Path,
) -> list[tuple[str, str]]:
    """Return the (host source, container destination) binds realization emitted.

    Derived from the same two functions the Compose stateful override is built
    from, so the observed contract cannot drift from the realized one. A
    consumer receives only its selected, non-``producer_private`` outputs -- a
    whole-directory expectation would demand mounts of material realization
    deliberately withheld from it.
    """

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
    backend: "DeploymentBackend",
    artifact: DeploymentGeneratedArtifactRealization,
    consumer: DeploymentStatefulConsumer,
    container: str,
) -> bool:
    """Return whether an image-free consumer holds every output placed into it.

    The generic materializer writes each selected output as a file at
    ``<mount_destination>/<output path>``, so the readback is the presence of
    those exact paths in the container. Nothing is read out -- only existence is
    observed -- and a probe that cannot be completed observes nothing, so the
    SEM-218 gate rejects rather than assumes delivery.
    """

    by_name = {output.name: output for output in artifact.outputs}
    names = _consumer_output_names(artifact, consumer)
    if not names:
        log.warning(
            "artifact %s places no output into image-free consumer %s",
            artifact.address,
            consumer.target_address,
        )
        return False
    for name in names:
        destination = str(
            PurePosixPath(consumer.mount_destination) / by_name[name].path
        )
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
            return False
    return True


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
