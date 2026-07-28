"""Compose model generation and readback validation for stateful resources."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path, PurePosixPath

from aptl.core.credentials import RENDERED_MANAGER_RELPATH
from aptl.core.deployment._compose_stateful_constants import (
    CERTIFICATE_ROOT_RELPATH,
    OWNED_WAZUH_SERVICES,
    REALIZATION_ADDRESS_LABEL,
    REALIZATION_LIFECYCLE_LABEL,
    REALIZATION_PROJECT_LABEL,
)
from aptl.core.deployment._compose_stateful_services import (
    wazuh_service_definitions,
)
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactRealization,
    DeploymentRealizationSpec,
)


def stateful_override_payload(
    project_dir: Path,
    project_name: str,
    realization: DeploymentRealizationSpec,
) -> dict[str, object]:
    """Return the complete generated stateful Compose model."""

    services = wazuh_service_definitions(project_dir, realization)
    _append_artifact_mounts(services, project_dir, realization)
    volumes = _append_volume_mounts(services, project_name, realization)
    payload: dict[str, object] = {"services": services}
    if volumes:
        payload["volumes"] = volumes
    return payload


def effective_stateful_model_errors(
    payload: object,
    project_dir: Path,
    project_name: str,
    realization: DeploymentRealizationSpec,
) -> list[str]:
    """Validate the in-memory effective Compose model against admitted state."""

    if not isinstance(payload, Mapping):
        return ["Effective Compose model is not a mapping."]
    observed_services = payload.get("services")
    if not isinstance(observed_services, Mapping):
        return ["Effective Compose model has no services mapping."]
    expected = stateful_override_payload(project_dir, project_name, realization)
    expected_services = expected["services"]
    assert isinstance(expected_services, Mapping)
    errors = _effective_service_errors(expected_services, observed_services)
    errors.extend(
        _certificate_exposure_errors(
            observed_services,
            project_dir,
            realization,
        )
    )
    errors.extend(_effective_volume_errors(payload, project_name, realization))
    return errors


def artifact_source_path(
    project_dir: Path,
    artifact: DeploymentGeneratedArtifactRealization,
) -> Path:
    """Return the canonical host source for a supported artifact provider."""

    relative = (
        CERTIFICATE_ROOT_RELPATH
        if artifact.generator == "certificate_bundle"
        else RENDERED_MANAGER_RELPATH
    )
    return project_dir.resolve() / relative


def _append_artifact_mounts(
    services: dict[str, dict[str, object]],
    project_dir: Path,
    realization: DeploymentRealizationSpec,
) -> None:
    """Append every declared generated-artifact bind mount."""

    for artifact in realization.generated_artifacts:
        source = artifact_source_path(project_dir, artifact)
        for consumer in artifact.consumers:
            if artifact.generator == "certificate_bundle":
                _append_certificate_mounts(services, source, artifact, consumer)
            else:
                _mounts(services, consumer.service_name).append(
                    {
                        "type": "bind",
                        "source": str(source),
                        "target": consumer.mount_destination,
                        "read_only": True,
                    }
                )


def _append_certificate_mounts(
    services: dict[str, dict[str, object]],
    source: Path,
    artifact: DeploymentGeneratedArtifactRealization,
    consumer: object,
) -> None:
    """Append declared certificate outputs for one typed consumer."""

    service_name = str(getattr(consumer, "service_name"))
    destination = str(getattr(consumer, "mount_destination"))
    for output in artifact.outputs:
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

    volumes: dict[str, dict[str, object]] = {}
    for volume in realization.persistent_volumes:
        volumes[volume.name] = {
            "labels": _expected_volume_labels(
                volume.address,
                volume.lifecycle,
                project_name,
            )
        }
        for consumer in volume.consumers:
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
    """Return model mismatches for generated and mount-only services."""

    errors: list[str] = []
    for service_name, expected_service in expected_services.items():
        observed_service = observed_services.get(service_name)
        if not isinstance(expected_service, Mapping) or not isinstance(
            observed_service,
            Mapping,
        ):
            errors.append(f"Effective stateful service {service_name} is absent.")
        elif service_name in OWNED_WAZUH_SERVICES:
            errors.extend(
                _owned_service_model_errors(
                    str(service_name),
                    expected_service,
                    observed_service,
                )
            )
        elif not _mount_contract(expected_service).issubset(
            _mount_contract(observed_service)
        ):
            errors.append(
                f"Effective stateful service {service_name} is missing a declared mount."
            )
    return errors


def _owned_service_model_errors(
    service_name: str,
    expected: Mapping[str, object],
    observed: Mapping[str, object],
) -> list[str]:
    """Return strict model mismatches for one graph-owned service."""

    fields = (
        "image",
        "container_name",
        "hostname",
        "restart",
        "profiles",
        "ports",
        "environment",
        "ulimits",
        "healthcheck",
        "deploy",
        "networks",
    )
    errors: list[str] = []
    if any(observed.get(field) != expected.get(field) for field in fields):
        errors.append(
            f"Effective stateful service {service_name} does not match "
            "its admitted definition."
        )
    if _normalized_dependencies(observed.get("depends_on")) != (
        _normalized_dependencies(expected.get("depends_on"))
    ):
        errors.append(
            f"Effective stateful service {service_name} has unexpected dependencies."
        )
    if _mount_contract(observed) != _mount_contract(expected):
        errors.append(
            f"Effective stateful service {service_name} has unexpected mounts."
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


def _normalized_dependencies(value: object) -> dict[str, str]:
    """Normalize long-form Compose service dependencies for comparison."""

    if not isinstance(value, Mapping):
        return {}
    return {
        str(service): str(details.get("condition"))
        for service, details in value.items()
        if isinstance(details, Mapping)
    }


def _certificate_exposure_errors(
    services: Mapping[object, object],
    project_dir: Path,
    realization: DeploymentRealizationSpec,
) -> list[str]:
    """Return errors for certificate mounts beyond the declared output set."""

    cert_root = str(project_dir.resolve() / CERTIFICATE_ROOT_RELPATH)
    expected = _expected_certificate_mounts(cert_root, realization)
    return [
        f"Effective stateful service {service_name} exposes undeclared "
        "certificate material."
        for service_name, allowed in expected.items()
        if _observed_certificate_mounts(
            services.get(service_name),
            cert_root,
        )
        != allowed
    ]


def _expected_certificate_mounts(
    cert_root: str,
    realization: DeploymentRealizationSpec,
) -> dict[str, set[tuple[str, str]]]:
    """Return declared certificate source/target pairs by consumer service."""

    expected: dict[str, set[tuple[str, str]]] = {}
    for artifact in realization.generated_artifacts:
        if artifact.generator != "certificate_bundle":
            continue
        for consumer in artifact.consumers:
            expected.setdefault(consumer.service_name, set()).update(
                {
                    (
                        str(Path(cert_root) / output.path),
                        str(PurePosixPath(consumer.mount_destination) / output.path),
                    )
                    for output in artifact.outputs
                }
            )
    return expected


def _observed_certificate_mounts(
    service: object,
    cert_root: str,
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
        and _under_certificate_root(str(mount.get("source", "")), cert_root)
    }


def _under_certificate_root(source: str, cert_root: str) -> bool:
    """Return whether a mount source is the certificate root or one child."""

    return source == cert_root or source.startswith(f"{cert_root}/")


def _effective_volume_errors(
    payload: Mapping[str, object],
    project_name: str,
    realization: DeploymentRealizationSpec,
) -> list[str]:
    """Return identity/label mismatches for effective persistent volumes."""

    if not realization.persistent_volumes:
        return []
    observed = payload.get("volumes")
    if not isinstance(observed, Mapping):
        return ["Effective Compose model has no volumes mapping."]
    return [
        f"Effective persistent volume {volume.address} has unexpected identity."
        for volume in realization.persistent_volumes
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
