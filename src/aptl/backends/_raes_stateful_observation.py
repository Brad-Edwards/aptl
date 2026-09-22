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
from pathlib import Path
from typing import TYPE_CHECKING

from raes_processor.semantics.realization import CONCERN_PAYLOAD_PATH

from aptl.backends._raes_observation_helpers import (
    ObservedResource,
    artifact_spec as _artifact_spec,
    consumer_mount_evidence as _consumer_mount_evidence,
    volume_spec as _volume_spec,
)
from aptl.core.deployment._compose_stateful_constants import (
    CERTIFICATE_PROVENANCE,
    SOC_CERT_PROFILE,
)
from aptl.backends._raes_artifact_delivery_observation import (
    artifact_consumers_mounted as _artifact_consumers_mounted,
    artifact_environment_delivered as _artifact_environment_delivered,
    authenticated_consumers_ready as _authenticated_consumers_ready,
    consumers_mounted as _consumers_mounted,
)
from aptl.core.deployment._compose_stateful_realization import artifact_source_path
from aptl.core.deployment._stateful_certificates import certificate_bundle_evidence
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactRealization,
    DeploymentPersistentVolumeRealization,
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
    realized, outputs_present, consumers_mounted, consumers_ready, evidence = (
        _artifact_realization_state(
            backend,
            artifact,
            node_containers,
            realization_root,
            source,
            image_free_addresses,
        )
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


def _artifact_realization_state(
    backend: "DeploymentBackend",
    artifact: DeploymentGeneratedArtifactRealization,
    node_containers: dict[str, str],
    realization_root: Path,
    source: Path,
    image_free_addresses: frozenset[str],
) -> tuple[bool, bool, bool, bool, dict[str, object]]:
    """Compute artifact output, delivery, readiness, and evidence state."""

    outputs_present = _artifact_outputs_present(source, artifact)
    consumers_mounted = outputs_present and _artifact_consumers_mounted(
        backend, artifact, node_containers, source, image_free_addresses
    )
    environment_delivered = outputs_present and _artifact_environment_delivered(
        backend, artifact, node_containers, source
    )
    consumers_ready = (
        consumers_mounted
        and environment_delivered
        and _authenticated_consumers_ready(backend, artifact.consumers)
    )
    evidence = (
        _artifact_evidence(backend, realization_root, source, artifact)
        if consumers_ready
        else {}
    )
    realized = consumers_ready and (
        artifact.generator != "certificate_bundle" or "certificate" in evidence
    )
    return (
        realized,
        outputs_present,
        consumers_mounted,
        consumers_ready,
        evidence,
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
        "environment_bindings": [
            {
                "target_address": consumer.target_address,
                "environment_variable": consumer.environment_variable,
                "output": consumer.output_name,
                "status": "present",
            }
            for consumer in artifact.environment_consumers
        ],
    }
    readiness = getattr(backend, "declared_wazuh_attestation", {})
    if isinstance(readiness, Mapping):
        observed_readiness = {
            consumer.service_name: [
                dict(fact) for fact in readiness[consumer.service_name]
            ]
            for consumer in artifact.consumers
            if consumer.service_name in readiness
        }
        if observed_readiness:
            evidence["declared_wazuh_attestation"] = observed_readiness
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
