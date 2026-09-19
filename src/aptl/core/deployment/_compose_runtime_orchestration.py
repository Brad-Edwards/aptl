"""Compose lowering and effective-model checks for runtime authorities."""

from __future__ import annotations

from pathlib import Path

from collections.abc import Mapping, Sequence

from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.lab_types import LabResult
from aptl.core.deployment._compose_docker_authority import (
    AUTHORITY_SERVICE,
    authority_declaration_error,
)
from aptl.runtime_authority import (
    DOCKER_SOCKET_PATH,
    DeploymentDockerAuthorityAdmission,
    DeploymentSpawnImageRequirement,
    is_mediated_authority_socket,
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
    """Whether a carried child contract contains every field core code consumes.

    Image identity and the execution deadline are required of every carried
    requirement. The correlation pair is required only when one was authored:
    a template the pack pinned without declaring an expected child inventory
    carries neither a label nor a count, and demanding them would reject the
    very requirement that exists to gate what the authority may launch.
    """

    correlated = bool(requirement.child_label) or bool(requirement.expected_count)
    return bool(
        _spawn_requirement_identity_is_complete(
            requirement,
            node_address=node_address,
            correlated=correlated,
        )
        and _positive_int(requirement.execution_timeout_seconds)
        and (not correlated or _positive_int(requirement.expected_count))
    )


def _spawn_requirement_identity_is_complete(
    requirement: DeploymentSpawnImageRequirement,
    *,
    node_address: str,
    correlated: bool,
) -> bool:
    """Whether a child contract carries its complete immutable identity."""

    label_name, _separator, label_value = requirement.child_label.partition("=")
    return bool(
        requirement.node_address == node_address
        and requirement.authority_id
        and requirement.template_id
        and requirement.image_ref
        and (not correlated or (label_name and label_value))
    )


def _positive_int(value: object) -> bool:
    """Whether a value is a positive integer rather than a Boolean."""

    return bool(isinstance(value, int) and not isinstance(value, bool) and value > 0)


def _declared_node_networks(node: object) -> set[str]:
    """Return the carried network names from either node representation."""

    return {
        str(network) for network in getattr(node, "networks", ()) or () if str(network)
    } | {
        str(getattr(attachment, "network", ""))
        for attachment in getattr(node, "network_attachments", ()) or ()
        if str(getattr(attachment, "network", ""))
    }


def docker_socket_volume(
    admission: DeploymentDockerAuthorityAdmission | None,
    mediated_socket: Path | None = None,
) -> dict[str, object] | None:
    """Return the sole admitted Compose socket bind for one node.

    The declared endpoint is satisfied either way -- the holder sees a
    read-write Docker socket at the path its scenario declared. What differs is
    which socket: with a mediated source the holder reaches the authorization
    boundary, and the host's own socket never enters the container at all.

    ``mediated_socket`` is absent only where no apparatus was composed, which
    the authority declaration check refuses separately rather than silently
    falling back to the host socket here.
    """

    if admission is None:
        return None
    if not _admission_endpoint_is_supported(admission):
        raise ValueError(
            "aptl.provisioner.runtime-authority-admission-invalid: "
            f"Docker authority is not admitted on {admission.node_address}."
        )
    if mediated_socket is None:
        raise ValueError(
            "aptl.provisioner.docker-authority-unmediated: "
            f"Docker authority on {admission.node_address} has no mediated socket."
        )
    return {
        "type": "bind",
        "source": str(mediated_socket),
        "target": DOCKER_SOCKET_PATH,
        "read_only": False,
    }


def docker_authority_admissions(
    realization: DeploymentRealizationSpec,
) -> tuple[DeploymentDockerAuthorityAdmission, ...]:
    """Return complete carried admissions after backend-neutral integrity checks."""

    admissions = realization.docker_authority_admissions
    nodes = {node.address: node for node in realization.nodes}
    valid = _authority_identifiers_are_unique(admissions) and all(
        _authority_admission_is_complete(admission, nodes.get(admission.node_address))
        for admission in admissions
    )
    if admissions and not valid:
        raise ValueError(
            "aptl.provisioner.runtime-authority-admission-invalid: "
            "Docker authority graph admission is incomplete or stale."
        )
    return admissions


def _authority_identifiers_are_unique(
    admissions: tuple[DeploymentDockerAuthorityAdmission, ...],
) -> bool:
    """Return whether one authority owns unique node, service, and child ids."""

    addresses = [admission.node_address for admission in admissions]
    services = [admission.service_name for admission in admissions]
    labels = [
        requirement.child_label
        for admission in admissions
        for requirement in admission.spawn_requirements
        if requirement.child_label
    ]
    return bool(
        len(admissions) <= 1
        and len(addresses) == len(set(addresses))
        and len(services) == len(set(services))
        and len(labels) == len(set(labels))
    )


def _authority_admission_is_complete(
    admission: DeploymentDockerAuthorityAdmission, node: object | None
) -> bool:
    """Validate one carried authority against its realized node and children."""

    if node is None:
        return False
    return bool(
        getattr(node, "service_name", None) == admission.service_name
        and set(admission.allowed_networks) == _declared_node_networks(node)
        and _admission_endpoint_is_supported(admission)
        and all(
            _spawn_requirement_is_complete(
                requirement,
                node_address=admission.node_address,
            )
            for requirement in admission.spawn_requirements
        )
    )


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
    """Whether one effective mount is the canonical admitted socket bind.

    The declared path is what the holder must see; the host's own socket is
    what it must not be given. A bind whose source is the host socket is the
    unmediated grant this issue removed, so it is not canonical (issue #912).
    """

    if not isinstance(mount, Mapping):
        return False
    return bool(mount.get("type") == "bind") and is_mediated_authority_socket(
        source=mount.get("source"),
        target=mount.get("target"),
        read_write=mount.get("read_only", False) is False,
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


def _mount_is_host_socket(mount: object) -> bool:
    """Whether one mount is the apparatus's exact daemon-socket grant."""

    return bool(
        isinstance(mount, Mapping)
        and mount.get("type") == "bind"
        and mount.get("source") == DOCKER_SOCKET_PATH
        and mount.get("target") == DOCKER_SOCKET_PATH
        and mount.get("read_only", False) is False
    )


def _apparatus_service_errors(
    raw_service: Mapping[object, object],
    socket_mounts: list[object],
) -> list[str]:
    """Validate the sole backend-owned service allowed to hold the host socket."""

    errors: list[str] = []
    if len(socket_mounts) != 1 or not _mount_is_host_socket(socket_mounts[0]):
        errors.append(
            "Docker authority apparatus must have exactly one canonical host socket bind."
        )
    if raw_service.get("network_mode") != "none":
        errors.append("Docker authority apparatus must use network_mode none.")
    if raw_service.get("read_only") is not True:
        errors.append("Docker authority apparatus root filesystem must be read-only.")
    if raw_service.get("privileged") is True:
        errors.append("Docker authority apparatus must not be privileged.")
    if raw_service.get("cap_drop") != ["ALL"]:
        errors.append("Docker authority apparatus must drop all capabilities.")
    security = raw_service.get("security_opt")
    if not isinstance(security, Sequence) or "no-new-privileges:true" not in security:
        errors.append("Docker authority apparatus must prevent privilege escalation.")
    return errors


def _effective_service_errors(
    service_name: object,
    raw_service: object,
    holders: Mapping[str, str],
    *,
    apparatus_expected: bool,
) -> list[str]:
    """Return authority-containment errors for one effective service."""

    errors: list[str] = []
    if isinstance(raw_service, Mapping):
        socket_mounts = [
            mount
            for mount in _service_volumes(raw_service)
            if _mount_mentions_socket(mount)
        ]
        if service_name == AUTHORITY_SERVICE and apparatus_expected:
            errors = _apparatus_service_errors(raw_service, socket_mounts)
        elif service_name in holders:
            errors = _authority_service_errors(
                service_name,
                raw_service,
                socket_mounts,
            )
        elif socket_mounts:
            errors = [
                f"Docker socket bind appears on unauthorized service {service_name}."
            ]
    return errors


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
        for error in _effective_service_errors(
            service_name,
            raw_service,
            holders,
            apparatus_expected=bool(admissions),
        )
    ]
    errors.extend(
        f"Docker authority service {holder} is absent from Compose model."
        for holder in holders
        if holder not in services
    )
    if admissions and AUTHORITY_SERVICE not in services:
        errors.append("Docker authority apparatus is absent from Compose model.")
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

        outcome: LabResult | None = None
        try:
            required = realization_has_docker_authority(realization)
            spawn_requirements = deployment_spawn_image_requirements(realization)
        except ValueError as exc:
            outcome = LabResult(success=False, error=str(exc))
        else:
            isolated = getattr(self, "_attempt_isolated_docker_daemon", False)
            if required and spawn_requirements and not isolated:
                outcome = LabResult(
                    success=False,
                    error=(
                        "Backend resource ownership conflict: runtime-spawned "
                        "children require an attempt-isolated Docker daemon."
                    ),
                )
            elif required:
                endpoint = (
                    self.revalidate_local_docker_socket()
                    if getattr(self, "_docker_socket_identity", None) is not None
                    else self.bind_local_docker_socket()
                )
                outcome = None if endpoint.success else endpoint
        return outcome

    def _runtime_orchestration_preflight(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Validate the route and bind its endpoint as one ordered preflight."""

        error = authority_declaration_error(realization)
        if error is not None:
            return LabResult(success=False, error=error)
        failure = self._validate_runtime_orchestration_route(realization)
        if failure is None:
            failure = self._bind_runtime_orchestration(realization)
        return failure
