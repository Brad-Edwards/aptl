"""Compose model generation and readback validation for stateful resources."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path, PurePosixPath

from aptl.core.credentials import RENDERED_MANAGER_RELPATH
from aptl.core.deployment._flag_signing_keys import FLAG_SIGNING_PROFILE_V2
from aptl.core.deployment._compose_stateful_constants import (
    CERTIFICATE_ROOT_RELPATH,
    FLAG_SIGNING_ROOT_RELPATH,
    SOC_CERT_PROFILE,
    SOC_CERTS_ROOT_RELPATH,
    SSH_KEY_BUNDLE_ROOT_RELPATH,
    WAZUH_MANAGER_CONFIG_PROVENANCES,
    REALIZATION_ADDRESS_LABEL,
    REALIZATION_LIFECYCLE_LABEL,
    REALIZATION_PROJECT_LABEL,
)
from aptl.core.deployment._compose_stateful_services import (
    wazuh_service_definitions,
)
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactRealization,
    DeploymentPersistentVolumeRealization,
    DeploymentRealizationSpec,
)


# Rendered-config provenances that bind as a single whole file (source file ->
# target file), not per output: the wazuh manager config, in-tree and env-pack.
# Both declared producer identities live in one set so the realizer's dispatch
# and this binding decision cannot drift apart (issue #875).
_WHOLE_FILE_RENDERED_CONFIG = WAZUH_MANAGER_CONFIG_PROVENANCES


def stateful_override_payload(
    scenario_root: Path,
    project_name: str,
    realization: DeploymentRealizationSpec,
) -> dict[str, object]:
    """Return the complete generated stateful Compose model."""

    services = wazuh_service_definitions()
    _append_artifact_mounts(services, scenario_root, realization)
    volumes = _append_volume_mounts(services, project_name, realization)
    payload: dict[str, object] = {"services": services}
    if volumes:
        payload["volumes"] = volumes
    return payload


def effective_stateful_model_errors(
    payload: object,
    scenario_root: Path,
    project_name: str,
    realization: DeploymentRealizationSpec,
) -> list[str]:
    """Validate the in-memory effective Compose model against admitted state."""

    if not isinstance(payload, Mapping):
        return ["Effective Compose model is not a mapping."]
    observed_services = payload.get("services")
    if not isinstance(observed_services, Mapping):
        return ["Effective Compose model has no services mapping."]
    expected = stateful_override_payload(scenario_root, project_name, realization)
    expected_services = expected["services"]
    assert isinstance(expected_services, Mapping)
    errors = _effective_service_errors(expected_services, observed_services)
    errors.extend(
        _certificate_exposure_errors(
            observed_services,
            scenario_root,
            realization,
        )
    )
    errors.extend(_effective_volume_errors(payload, project_name, realization))
    return errors


def artifact_source_path(
    scenario_root: Path,
    artifact: DeploymentGeneratedArtifactRealization,
) -> Path:
    """Return the canonical host source for a supported artifact provider.

    A generated artifact is scenario-local: it is produced and read back under
    the scenario bundle root, not the engine checkout. For an in-tree scenario
    the two coincide (issue #874).
    """

    provenance = getattr(artifact, "provenance", None)
    if provenance == SOC_CERT_PROFILE:
        relative = Path(SOC_CERTS_ROOT_RELPATH)
    elif artifact.generator == "certificate_bundle":
        relative = Path(CERTIFICATE_ROOT_RELPATH)
    elif artifact.generator == "ssh_key_bundle":
        relative = Path(SSH_KEY_BUNDLE_ROOT_RELPATH) / artifact.name
    elif provenance == FLAG_SIGNING_PROFILE_V2:
        relative = Path(FLAG_SIGNING_ROOT_RELPATH) / artifact.name
    else:
        relative = Path(RENDERED_MANAGER_RELPATH)
    return scenario_root.resolve() / relative


def _consumer_output_names(
    artifact: DeploymentGeneratedArtifactRealization, consumer: object
) -> list[str]:
    """Return the output names one consumer receives, excluding producer-private.

    A consumer that names ``selected_outputs`` gets exactly those; one that names
    none gets every ``consumer_selected`` output (the pre-selection default a
    certificate consumer relied on). A ``producer_private`` output is never
    included, so it is never bind-mounted into any consumer.
    """

    selected = tuple(getattr(consumer, "selected_outputs", ()) or ())
    by_name = {output.name: output for output in artifact.outputs}
    if selected:
        names = [name for name in selected if name in by_name]
    else:
        names = [output.name for output in artifact.outputs]
    return [
        name for name in names if by_name[name].disposition != "producer_private"
    ]


def _non_compose_consumer_addresses(
    realization: DeploymentRealizationSpec,
) -> frozenset[str]:
    """Return node addresses that are not Compose services.

    Only a node with a backing image becomes a Compose service. An image-free
    node (declared runtime, no image) is realized by the generic materializer,
    and a node with neither image nor runtime is not realized as a container at
    all — so neither can carry a Compose bind. Emitting one puts a mount-only
    service with no image into the stateful override, which makes
    ``docker compose config`` reject the whole project ("has neither an image
    nor a build context"). Their consumers are therefore excluded from the
    Compose stateful override (issue #875).
    """

    imaged = {image.address for image in realization.images}
    return frozenset(
        node.address for node in realization.nodes if node.address not in imaged
    )


def _append_artifact_mounts(
    services: dict[str, dict[str, object]],
    scenario_root: Path,
    realization: DeploymentRealizationSpec,
) -> None:
    """Append every declared generated-artifact bind mount for Compose nodes."""

    image_free = _non_compose_consumer_addresses(realization)
    for artifact in realization.generated_artifacts:
        source = artifact_source_path(scenario_root, artifact)
        for consumer in artifact.consumers:
            if consumer.target_address in image_free:
                continue
            if _uses_per_output_mounts(artifact, consumer):
                _append_selected_output_mounts(services, source, artifact, consumer)
            else:
                _mounts(services, consumer.service_name).append(
                    {
                        "type": "bind",
                        "source": str(source),
                        "target": consumer.mount_destination,
                        "read_only": True,
                    }
                )


def _uses_per_output_mounts(
    artifact: DeploymentGeneratedArtifactRealization, consumer: object
) -> bool:
    """Whether a consumer must receive individual outputs, not the whole dir.

    A whole-directory bind would expose every output, including any
    ``producer_private`` one (the flag-signing seed), so per-output mounts are
    required whenever the artifact keeps private material or the consumer
    selected a subset. Certificate and SSH bundles always mount per output.
    """

    if artifact.generator in ("certificate_bundle", "ssh_key_bundle"):
        return True
    if getattr(artifact, "provenance", None) in _WHOLE_FILE_RENDERED_CONFIG:
        # The wazuh manager config is a single rendered file whose mount target
        # is a file path (``.../etc/ossec.conf``). It must be bound whole-file
        # (source file -> target file); a per-output bind would append the
        # output name and mount the file as a directory (issue #875).
        return False
    return bool(getattr(consumer, "selected_outputs", ())) or any(
        output.disposition == "producer_private" for output in artifact.outputs
    )


def _append_selected_output_mounts(
    services: dict[str, dict[str, object]],
    source: Path,
    artifact: DeploymentGeneratedArtifactRealization,
    consumer: object,
) -> None:
    """Append only a consumer's selected, non-producer-private outputs.

    Each output is a separate read-only file bind, so a consumer physically
    receives only the material it selected — a producer-private key never appears
    in any consumer's mount set.
    """

    service_name = str(getattr(consumer, "service_name"))
    destination = str(getattr(consumer, "mount_destination"))
    by_name = {output.name: output for output in artifact.outputs}
    for name in _consumer_output_names(artifact, consumer):
        output = by_name[name]
        _mounts(services, service_name).append(
            {
                "type": "bind",
                "source": str(source / output.path),
                "target": str(PurePosixPath(destination) / output.path),
                "read_only": True,
            }
        )


def _append_volume_mounts(
    services: dict[str, dict[str, object]],
    project_name: str,
    realization: DeploymentRealizationSpec,
) -> dict[str, dict[str, object]]:
    """Append persistent-volume mounts and return their declarations."""

    non_compose = _non_compose_consumer_addresses(realization)
    volumes: dict[str, dict[str, object]] = {}
    for volume in realization.persistent_volumes:
        compose_consumers = [
            consumer
            for consumer in volume.consumers
            if consumer.target_address not in non_compose
        ]
        # A volume mounted only by non-Compose nodes (image-free or imageless)
        # is delivered by the generic materializer, not Compose. Declaring it in
        # the override would leave a top-level volume no Compose service mounts,
        # which docker compose config prunes and the effective-model check then
        # reports as a missing identity (issue #875).
        if not compose_consumers:
            continue
        volumes[volume.name] = {
            "labels": _expected_volume_labels(
                volume.address,
                volume.lifecycle,
                project_name,
            )
        }
        for consumer in compose_consumers:
            _mounts(services, consumer.service_name).append(
                {
                    "type": "volume",
                    "source": volume.name,
                    "target": consumer.mount_destination,
                    "read_only": consumer.access_mode == "read_only",
                }
            )
    return volumes


def _mounts(
    services: dict[str, dict[str, object]],
    service_name: str,
) -> list[dict[str, object]]:
    """Return the mutable long-form mount list for one generated service."""

    service = services.setdefault(service_name, {"volumes": []})
    volumes = service.setdefault("volumes", [])
    if not isinstance(volumes, list):
        raise ValueError("Generated service volumes are not a list.")
    return volumes


def _effective_service_errors(
    expected_services: Mapping[object, object],
    observed_services: Mapping[object, object],
) -> list[str]:
    """Return model mismatches for generated mount-only services.

    Every stateful service is now realized generically: the stateful override
    contributes only mount merges (certs, rendered config, volumes) on top of the
    generated base compose. The effective model is valid as long as every
    declared mount is present in the observed service — the base compose owns the
    rest of the definition (issue #875). Wazuh is no longer special-cased here.
    """

    errors: list[str] = []
    for service_name, expected_service in expected_services.items():
        observed_service = observed_services.get(service_name)
        if not isinstance(expected_service, Mapping) or not isinstance(
            observed_service,
            Mapping,
        ):
            errors.append(f"Effective stateful service {service_name} is absent.")
        elif not _mount_contract(expected_service).issubset(
            _mount_contract(observed_service)
        ):
            errors.append(
                f"Effective stateful service {service_name} is missing a declared mount."
            )
    return errors


def _mount_contract(service: Mapping[str, object]) -> set[tuple[object, ...]]:
    """Return the comparable long-form mount contract for one service."""

    mounts = service.get("volumes")
    if not isinstance(mounts, list):
        return set()
    return {
        (
            mount.get("type"),
            mount.get("source"),
            mount.get("target"),
            bool(mount.get("read_only")),
        )
        for mount in mounts
        if isinstance(mount, Mapping)
    }


def _certificate_exposure_errors(
    services: Mapping[object, object],
    scenario_root: Path,
    realization: DeploymentRealizationSpec,
) -> list[str]:
    """Return errors for certificate mounts beyond the declared output set."""

    cert_roots = {
        str(artifact_source_path(scenario_root, artifact))
        for artifact in realization.generated_artifacts
        if artifact.generator == "certificate_bundle"
    }
    expected = _expected_certificate_mounts(scenario_root, realization)
    return [
        f"Effective stateful service {service_name} exposes undeclared "
        "certificate material."
        for service_name, allowed in expected.items()
        if _observed_certificate_mounts(
            services.get(service_name),
            cert_roots,
        )
        != allowed
    ]


def _expected_certificate_mounts(
    scenario_root: Path,
    realization: DeploymentRealizationSpec,
) -> dict[str, set[tuple[str, str]]]:
    """Return declared certificate source/target pairs by consumer service.

    Each certificate bundle resolves its own source root (a wazuh bundle under
    the indexer cert dir, the SOC bundle under ``config/soc_certs``), so a
    consumer's expected mounts are keyed off that bundle's root, not one shared
    directory (issue #875).
    """

    expected: dict[str, set[tuple[str, str]]] = {}
    for artifact in realization.generated_artifacts:
        if artifact.generator != "certificate_bundle":
            continue
        source = artifact_source_path(scenario_root, artifact)
        by_name = {output.name: output for output in artifact.outputs}
        for consumer in artifact.consumers:
            expected.setdefault(consumer.service_name, set()).update(
                {
                    (
                        str(source / by_name[name].path),
                        str(
                            PurePosixPath(consumer.mount_destination)
                            / by_name[name].path
                        ),
                    )
                    for name in _consumer_output_names(artifact, consumer)
                }
            )
    return expected


def _observed_certificate_mounts(
    service: object,
    cert_roots: set[str],
) -> set[tuple[str, str]]:
    """Return certificate-root mounts observed on one effective service."""

    if not isinstance(service, Mapping):
        return set()
    mounts = service.get("volumes")
    if not isinstance(mounts, list):
        return set()
    return {
        (str(mount.get("source")), str(mount.get("target")))
        for mount in mounts
        if isinstance(mount, Mapping)
        and any(
            _under_certificate_root(str(mount.get("source", "")), cert_root)
            for cert_root in cert_roots
        )
    }


def _under_certificate_root(source: str, cert_root: str) -> bool:
    """Return whether a mount source is the certificate root or one child."""

    return source == cert_root or source.startswith(f"{cert_root}/")


def _compose_persistent_volumes(
    realization: DeploymentRealizationSpec,
) -> list[DeploymentPersistentVolumeRealization]:
    """Return the persistent volumes at least one Compose service mounts.

    Only volumes with a Compose consumer appear in the override (a volume used
    solely by a non-Compose node is delivered by the generic materializer).
    """

    non_compose = _non_compose_consumer_addresses(realization)
    return [
        volume
        for volume in realization.persistent_volumes
        if any(
            consumer.target_address not in non_compose
            for consumer in volume.consumers
        )
    ]


def _effective_volume_errors(
    payload: Mapping[str, object],
    project_name: str,
    realization: DeploymentRealizationSpec,
) -> list[str]:
    """Return identity/label mismatches for effective persistent volumes."""

    compose_volumes = _compose_persistent_volumes(realization)
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
            _expected_volume_labels(
                volume.address,
                volume.lifecycle,
                project_name,
            ),
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


def _expected_volume_labels(
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
