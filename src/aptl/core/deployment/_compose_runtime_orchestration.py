"""Compose lowering and effective-model checks for runtime authorities."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.lab_types import LabResult
from aptl.runtime_authority import (
    DOCKER_SOCKET_PATH,
    DeploymentDockerAuthorityAdmission,
    DeploymentSpawnImageRequirement,
    mount_exposes_or_mentions_docker_socket,
)

DOCKER_SOCKET_HOST = "unix:///var/run/docker.sock"


def _admission_endpoint_is_supported(
    admission: DeploymentDockerAuthorityAdmission,
) -> bool:
    """Whether a carried decision names the one endpoint this backend lowers."""

    return bool(
        admission.engine == "docker"
        and admission.privilege_class == "host_root_equivalent"
        and admission.endpoint_kind == "unix_socket"
        and admission.endpoint_source == DOCKER_SOCKET_PATH
        and admission.endpoint_target == DOCKER_SOCKET_PATH
        and admission.endpoint_read_write
    )


def _spawn_requirement_is_complete(
    requirement: DeploymentSpawnImageRequirement,
    *,
    node_address: str,
) -> bool:
    """Whether a carried child contract contains every field core code consumes."""

    return bool(
        requirement.node_address == node_address
        and requirement.authority_id
        and requirement.template_id
        and requirement.image_ref
        and requirement.child_label.partition("=")[0]
        and requirement.child_label.partition("=")[2]
        and isinstance(requirement.execution_timeout_seconds, int)
        and not isinstance(requirement.execution_timeout_seconds, bool)
        and requirement.execution_timeout_seconds > 0
        and isinstance(requirement.expected_count, int)
        and not isinstance(requirement.expected_count, bool)
        and requirement.expected_count > 0
    )


def docker_socket_volume(
    admission: DeploymentDockerAuthorityAdmission | None,
) -> dict[str, object] | None:
    """Return the sole admitted Compose socket bind for one node."""

    if admission is None:
        return None
    if not _admission_endpoint_is_supported(admission):
        raise ValueError(
            "aptl.provisioner.runtime-authority-admission-invalid: "
            f"Docker authority is not admitted on {admission.node_address}."
        )
    return {
        "type": "bind",
        "source": DOCKER_SOCKET_PATH,
        "target": DOCKER_SOCKET_PATH,
        "read_only": False,
    }


def docker_authority_admissions(
    realization: DeploymentRealizationSpec,
) -> tuple[DeploymentDockerAuthorityAdmission, ...]:
    """Return complete carried admissions after backend-neutral integrity checks."""

    admissions = realization.docker_authority_admissions
    nodes = {node.address: node for node in realization.nodes}
    addresses = [admission.node_address for admission in admissions]
    services = [admission.service_name for admission in admissions]
    labels = [
        requirement.child_label
        for admission in admissions
        for requirement in admission.spawn_requirements
    ]
    valid = bool(
        len(addresses) == len(set(addresses))
        and len(services) == len(set(services))
        and len(labels) == len(set(labels))
        and all(
            admission.node_address in nodes
            and nodes[admission.node_address].service_name == admission.service_name
            and _admission_endpoint_is_supported(admission)
            and admission.spawn_requirements
            and all(
                _spawn_requirement_is_complete(
                    requirement,
                    node_address=admission.node_address,
                )
                for requirement in admission.spawn_requirements
            )
            for admission in admissions
        )
    )
    if admissions and not valid:
        raise ValueError(
            "aptl.provisioner.runtime-authority-admission-invalid: "
            "Docker authority graph admission is incomplete or stale."
        )
    return admissions


def docker_authority_admissions_by_address(
    realization: DeploymentRealizationSpec,
) -> dict[str, DeploymentDockerAuthorityAdmission]:
    """Index the complete carried authority decisions by compiled node address."""

    return {
        admission.node_address: admission
        for admission in docker_authority_admissions(realization)
    }


def deployment_spawn_image_requirements(
    realization: DeploymentRealizationSpec,
) -> tuple[DeploymentSpawnImageRequirement, ...]:
    """Flatten child-image contracts from complete carried admissions."""

    return tuple(
        requirement
        for admission in docker_authority_admissions(realization)
        for requirement in admission.spawn_requirements
    )


def realization_has_docker_authority(realization: DeploymentRealizationSpec) -> bool:
    """Whether the realization contains an admitted Docker authority."""

    return bool(docker_authority_admissions(realization))


def _environment_names(raw: object) -> set[str]:
    """Normalize Compose mapping/list environment forms to variable names."""

    if isinstance(raw, Mapping):
        return {str(name) for name in raw}
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        return {str(item).split("=", 1)[0] for item in raw}
    return set()


def _mount_is_exact_socket(mount: object) -> bool:
    """Whether one effective mount is the canonical admitted socket bind."""

    return bool(
        isinstance(mount, Mapping)
        and mount.get("type") == "bind"
        and mount.get("source") == DOCKER_SOCKET_PATH
        and mount.get("target") == DOCKER_SOCKET_PATH
        and mount.get("read_only", False) is False
    )


def _mount_mentions_socket(mount: object) -> bool:
    """Whether one effective mount exposes or targets the Docker socket."""

    return mount_exposes_or_mentions_docker_socket(
        mount,
        source_key="source",
        target_key="target",
        type_key="type",
        bind_type="bind",
    )


def _service_volumes(raw_service: Mapping[object, object]) -> Sequence[object]:
    """Return a service's normalized effective volume sequence."""

    mounts = raw_service.get("volumes")
    if isinstance(mounts, Sequence) and not isinstance(mounts, (str, bytes)):
        return mounts
    return ()


def _authority_service_errors(
    service_name: object,
    raw_service: Mapping[object, object],
    socket_mounts: list[object],
) -> list[str]:
    """Validate one service selected by a carried authority admission."""

    errors: list[str] = []
    if len(socket_mounts) != 1 or not _mount_is_exact_socket(socket_mounts[0]):
        errors.append(
            f"Docker authority service {service_name} must have exactly one "
            "canonical read-write socket bind."
        )
    names = _environment_names(raw_service.get("environment"))
    if names & {"DOCKER_HOST", "DOCKER_CONTEXT"}:
        errors.append(
            f"Docker authority service {service_name} has a Docker endpoint override."
        )
    if raw_service.get("privileged") is True:
        errors.append(
            f"Docker authority service {service_name} must not be privileged."
        )
    return errors


def _effective_service_errors(
    service_name: object,
    raw_service: object,
    holders: Mapping[str, str],
) -> list[str]:
    """Return authority-containment errors for one effective service."""

    if not isinstance(raw_service, Mapping):
        return []
    socket_mounts = [
        mount
        for mount in _service_volumes(raw_service)
        if _mount_mentions_socket(mount)
    ]
    if service_name in holders:
        return _authority_service_errors(service_name, raw_service, socket_mounts)
    if socket_mounts:
        return [f"Docker socket bind appears on unauthorized service {service_name}."]
    return []


def effective_orchestration_model_errors(
    payload: object,
    realization: DeploymentRealizationSpec,
) -> list[str]:
    """Return fail-closed errors for the effective Compose authority model."""

    services = payload.get("services") if isinstance(payload, Mapping) else None
    if not isinstance(services, Mapping):
        return ["Effective Compose model has no services map."]

    try:
        admissions = docker_authority_admissions(realization)
    except ValueError as exc:
        return [str(exc)]
    holders = {
        admission.service_name: admission.node_address for admission in admissions
    }

    errors = [
        error
        for service_name, raw_service in services.items()
        for error in _effective_service_errors(service_name, raw_service, holders)
    ]
    errors.extend(
        f"Docker authority service {holder} is absent from Compose model."
        for holder in holders
        if holder not in services
    )
    return errors


class ComposeRuntimeOrchestrationRouteMixin:
    """Validate and bind carried runtime-authority admissions before mutation."""

    @staticmethod
    def _validate_runtime_orchestration_route(
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Require every Docker authority holder to be Compose image-backed."""

        image_addresses = {image.address for image in realization.images}
        try:
            admissions = docker_authority_admissions(realization)
        except ValueError as exc:
            return LabResult(success=False, error=str(exc))
        missing = next(
            (
                admission.node_address
                for admission in admissions
                if admission.node_address not in image_addresses
            ),
            None,
        )
        if missing is None:
            return None
        return LabResult(
            success=False,
            error=f"Docker control authority requires a Compose image for {missing}.",
        )

    def _bind_runtime_orchestration(
        self, realization: DeploymentRealizationSpec
    ) -> LabResult | None:
        """Validate child closure and bind the exact local control endpoint."""

        try:
            required = realization_has_docker_authority(realization)
            deployment_spawn_image_requirements(realization)
        except ValueError as exc:
            return LabResult(success=False, error=str(exc))
        if not required:
            return None
        endpoint = (
            self.revalidate_local_docker_socket()
            if getattr(self, "_docker_socket_identity", None) is not None
            else self.bind_local_docker_socket()
        )
        return None if endpoint.success else endpoint

    def _runtime_orchestration_preflight(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Validate the route and bind its endpoint as one ordered preflight."""

        failure = self._validate_runtime_orchestration_route(realization)
        if failure is None:
            failure = self._bind_runtime_orchestration(realization)
        return failure
