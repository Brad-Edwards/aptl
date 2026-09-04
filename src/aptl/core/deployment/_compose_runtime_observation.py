"""Post-start observation for admitted runtime orchestration authorities."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from aptl.core.deployment._compose_child_lifecycle import (
    ComposeSpawnedChildLifecycleMixin,
)
from aptl.core.deployment._compose_runtime_orchestration import (
    deployment_spawn_image_requirements,
    docker_authority_admissions,
)
from aptl.core.deployment._docker_image_identity import (
    EXACT_IMAGE_INSPECT_FORMAT,
    exact_inspected_image_identity,
)
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.core.lab_types import LabResult
from aptl.runtime_authority import (
    DeploymentDockerAuthorityAdmission,
    DeploymentSpawnImageRequirement,
    has_undeclared_runtime_mounts,
    mount_exposes_or_mentions_docker_socket,
)


def _spawn_failure(
    condition: str,
    requirement: DeploymentSpawnImageRequirement,
    *,
    separator: str = " for ",
) -> LabResult:
    """Build one stable child-observation diagnostic."""

    return LabResult(
        success=False,
        error=(
            f"{condition}{separator}"
            f"{requirement.node_address}/{requirement.template_id}."
        ),
    )


def _inspect_mounts(info: object) -> Sequence[object]:
    """Return normalized Docker inspect mount entries."""

    mounts = info.get("Mounts") if isinstance(info, Mapping) else None
    if isinstance(mounts, Sequence) and not isinstance(mounts, (str, bytes)):
        return mounts
    return ()


def _inspect_environment(info: object) -> Sequence[object]:
    """Return normalized Docker inspect environment entries."""

    config = info.get("Config") if isinstance(info, Mapping) else None
    raw_env = config.get("Env") if isinstance(config, Mapping) else None
    if isinstance(raw_env, Sequence) and not isinstance(raw_env, (str, bytes)):
        return raw_env
    return ()


def _inspect_has_endpoint_override(info: object) -> bool:
    """Whether inspect environment redirects Docker commands elsewhere."""

    return any(
        str(item).split("=", 1)[0] in {"DOCKER_HOST", "DOCKER_CONTEXT"}
        for item in _inspect_environment(info)
    )


def _inspect_is_privileged(info: object) -> bool:
    """Whether Docker inspect reports a privileged container."""

    host_config = info.get("HostConfig") if isinstance(info, Mapping) else None
    return bool(
        isinstance(host_config, Mapping) and host_config.get("Privileged") is True
    )


def _inspect_has_socket_route(info: object) -> bool:
    """Whether any observed bind contains or targets the Docker socket."""

    return any(
        mount_exposes_or_mentions_docker_socket(
            mount,
            source_key="Source",
            target_key="Destination",
            type_key="Type",
            bind_type="bind",
        )
        for mount in _inspect_mounts(info)
    )


def _mount_is_canonical_authority_socket(mount: object) -> bool:
    """Whether one observed mount is the admitted canonical socket bind."""

    return bool(
        isinstance(mount, Mapping)
        and mount.get("Type") == "bind"
        and mount.get("Source") == "/var/run/docker.sock"
        and mount.get("Destination") == "/var/run/docker.sock"
        and mount.get("RW") is True
    )


def _authority_mount_is_valid(
    entries: Sequence[object],
    admission: DeploymentDockerAuthorityAdmission,
) -> bool:
    """Whether a holder exposes only its admitted runtime mount footprint."""

    socket_mounts = [
        mount
        for mount in entries
        if mount_exposes_or_mentions_docker_socket(
            mount,
            source_key="Source",
            target_key="Destination",
            type_key="Type",
            bind_type="bind",
        )
    ]
    return bool(
        len(socket_mounts) == 1
        and _mount_is_canonical_authority_socket(socket_mounts[0])
        and not has_undeclared_runtime_mounts(
            entries,
            allowed_targets=set(admission.allowed_mount_targets),
            docker_authority_admitted=True,
        )
    )


class ComposeRuntimeOrchestrationObservationMixin(
    ComposeSpawnedChildLifecycleMixin,
):
    """Attest authority holders and their exact child closure after startup."""

    def _verify_runtime_orchestration(
        self,
        realization: DeploymentRealizationSpec,
        *,
        require_children: bool = False,
    ) -> LabResult | None:
        """Read back the exact socket footprint and same-daemon reachability."""

        try:
            admissions = docker_authority_admissions(realization)
        except ValueError as exc:
            return LabResult(success=False, error=str(exc))
        admitted_addresses = {item.node_address for item in admissions}
        authority_nodes = tuple(
            node for node in realization.nodes if node.address in admitted_addresses
        )
        failure: LabResult | None = None
        if authority_nodes:
            endpoint = self.revalidate_local_docker_socket()
            failure = None if endpoint.success else endpoint
        if failure is None and authority_nodes:
            failure = self._verify_authority_holders(authority_nodes, admissions)
        if failure is None and authority_nodes:
            failure = self._verify_spawned_child_containment(
                realization,
                require_children=require_children,
            )
        if failure is None and authority_nodes:
            failure = self._verify_authority_non_propagation(
                realization,
                admitted_addresses,
            )
        return failure

    def _verify_authority_holders(
        self,
        authority_nodes: tuple[DeploymentNodeRealization, ...],
        admissions: tuple[DeploymentDockerAuthorityAdmission, ...],
    ) -> LabResult | None:
        """Attest the admitted socket and daemon identity on each holder."""

        admissions_by_address = {
            admission.node_address: admission for admission in admissions
        }
        failure = None
        for node in authority_nodes:
            if not node.container_name or not self._runtime_authority_matches(
                node.container_name,
                admissions_by_address[node.address],
            ):
                failure = LabResult(
                    success=False,
                    error=(
                        "Docker authority runtime observation failed for "
                        f"{node.service_name or node.address}."
                    ),
                )
                break
        return failure

    def _verify_authority_non_propagation(
        self,
        realization: DeploymentRealizationSpec,
        admitted_addresses: set[str],
    ) -> LabResult | None:
        """Reject a Docker control route on any non-admitted service."""

        failure = None
        for node in realization.nodes:
            should_inspect = bool(
                node.address not in admitted_addresses and node.container_name
            )
            if should_inspect and self._container_has_docker_authority(
                node.container_name
            ):
                failure = LabResult(
                    success=False,
                    error=(
                        "Docker authority propagated to unauthorized service "
                        f"{node.service_name or node.address}."
                    ),
                )
                break
        return failure

    def _verify_spawned_child_containment(
        self,
        realization: DeploymentRealizationSpec,
        *,
        require_children: bool,
    ) -> LabResult | None:
        """Attest the exact label-correlated child set on the bound daemon."""

        try:
            requirements = deployment_spawn_image_requirements(realization)
        except ValueError as exc:
            return LabResult(success=False, error=str(exc))
        failure = None
        for requirement in requirements:
            failure = self._verify_spawn_requirement(
                requirement,
                require_children=require_children,
            )
            if failure is not None:
                break
        return failure

    def _verify_spawn_requirement(
        self,
        requirement: DeploymentSpawnImageRequirement,
        *,
        require_children: bool,
    ) -> LabResult | None:
        """Attest one template's correlated child set and lifecycle."""

        failure, container_ids = self._correlated_child_ids(
            requirement,
            require_children=require_children,
        )
        expected_image_id = None
        if failure is None and container_ids:
            expected_image_id = self._exact_spawn_image_id(
                requirement.image_ref,
                timeout=requirement.execution_timeout_seconds,
            )
            if expected_image_id is None:
                failure = _spawn_failure(
                    "Spawned-child image identity unavailable",
                    requirement,
                )
        if failure is None and expected_image_id is not None:
            for container_id in container_ids:
                failure = self._verify_spawned_child(
                    container_id,
                    expected_image_id,
                    requirement,
                )
                if failure is not None:
                    break
        return failure

    def _correlated_child_ids(
        self,
        requirement: DeploymentSpawnImageRequirement,
        *,
        require_children: bool,
    ) -> tuple[LabResult | None, tuple[str, ...]]:
        """Query one exact image-label pair and enforce its declared count."""

        try:
            result = self._run(
                [
                    "docker",
                    "ps",
                    "-aq",
                    "--filter",
                    f"ancestor={requirement.image_ref}",
                    "--filter",
                    f"label={requirement.child_label}",
                ],
                timeout=requirement.execution_timeout_seconds,
            )
        except BackendTimeoutError:
            result = None
        failure = None
        container_ids: tuple[str, ...] = ()
        if result is None or result.returncode != 0:
            failure = _spawn_failure("Spawned-child observation failed", requirement)
        else:
            container_ids = tuple(
                dict.fromkeys(
                    container_id.strip()
                    for container_id in result.stdout.splitlines()
                    if container_id.strip()
                )
            )
        count_required = bool(container_ids or require_children)
        if (
            failure is None
            and count_required
            and len(container_ids) != requirement.expected_count
        ):
            failure = _spawn_failure(
                "Spawned-child correlation count mismatch",
                requirement,
            )
        return failure, container_ids

    def _verify_spawned_child(
        self,
        container_id: str,
        expected_image_id: str,
        requirement: DeploymentSpawnImageRequirement,
    ) -> LabResult | None:
        """Attest one child's identity, correlation, isolation, and deadline."""

        info = self.container_inspect(container_id)
        failure: LabResult | None = None
        if not info:
            failure = _spawn_failure("Spawned-child observation failed", requirement)
        if failure is None and info.get("Image") != expected_image_id:
            failure = _spawn_failure(
                "Spawned-child image identity mismatch",
                requirement,
            )
        if failure is None and not self._child_has_correlation(info, requirement):
            failure = _spawn_failure(
                "Spawned-child correlation unavailable",
                requirement,
            )
        if failure is None and self._inspected_container_has_docker_authority(info):
            failure = _spawn_failure(
                "Docker authority propagated to spawned child",
                requirement,
                separator=" ",
            )
        if failure is None:
            failure = self._enforce_spawned_child_deadline(
                container_id,
                info,
                timeout=requirement.execution_timeout_seconds,
                node_address=requirement.node_address,
                template_id=requirement.template_id,
            )
        return failure

    @staticmethod
    def _child_has_correlation(
        info: object,
        requirement: DeploymentSpawnImageRequirement,
    ) -> bool:
        """Whether inspect output carries the exact admitted child label."""

        config = info.get("Config") if isinstance(info, Mapping) else None
        labels = config.get("Labels") if isinstance(config, Mapping) else None
        label_name, label_value = requirement.child_label.split("=", 1)
        return bool(
            isinstance(labels, Mapping) and labels.get(label_name) == label_value
        )

    def _exact_spawn_image_id(self, image_ref: str, *, timeout: int) -> str | None:
        """Return the daemon-local ID only for the authored exact repo digest."""

        try:
            result = self._run(
                [
                    "docker",
                    "image",
                    "inspect",
                    "--format",
                    EXACT_IMAGE_INSPECT_FORMAT,
                    image_ref,
                ],
                timeout=timeout,
            )
        except BackendTimeoutError:
            return None
        identity = None
        if result.returncode == 0:
            identity = exact_inspected_image_identity(result.stdout, image_ref)
        return identity.image_id if identity is not None else None

    def _runtime_authority_matches(
        self,
        container_name: str,
        admission: DeploymentDockerAuthorityAdmission,
    ) -> bool:
        """Whether one holder exposes only the admitted endpoint to the same daemon."""

        info = self.container_inspect(container_name)
        daemon_id = getattr(self, "_docker_daemon_id", None)
        configuration_ok = bool(
            _authority_mount_is_valid(_inspect_mounts(info), admission)
            and not _inspect_has_endpoint_override(info)
            and not _inspect_is_privileged(info)
            and daemon_id
        )
        if not configuration_ok:
            return False
        try:
            observed = self.container_exec(
                container_name,
                ["docker", "info", "--format", "{{.ID}}"],
                timeout=30,
            )
        except BackendTimeoutError:
            return False
        return observed.returncode == 0 and observed.stdout.strip() == daemon_id

    def _container_has_docker_authority(self, container_name: str) -> bool:
        """Whether an unauthorized service carries a Docker control route."""

        info = self.container_inspect(container_name)
        return self._inspected_container_has_docker_authority(info)

    @staticmethod
    def _inspected_container_has_docker_authority(info: object) -> bool:
        """Whether inspect output exposes the socket, an override, or privilege."""

        return bool(
            _inspect_has_socket_route(info)
            or _inspect_has_endpoint_override(info)
            or _inspect_is_privileged(info)
        )
