"""Post-start observation for admitted runtime orchestration authorities."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
import re
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
    DeploymentSpawnedChildObservation,
    has_undeclared_runtime_mounts,
    mount_exposes_or_mentions_docker_socket,
    runtime_child_correlation_id,
)

_SAFE_CONTAINER_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")


@dataclass(frozen=True)
class _OwnedChildCandidate:
    """One inspected child whose ownership must pass before any mutation."""

    container_id: str
    parent_container_id: str
    image_id: str
    info: object
    requirement: DeploymentSpawnImageRequirement
    admission: DeploymentDockerAuthorityAdmission
    product_execution_id: str


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


def _inspect_environment_value(info: object, name: str) -> str | None:
    """Return one exact non-empty environment value, rejecting ambiguity."""

    prefix = f"{name}="
    values = [
        str(item)[len(prefix) :]
        for item in _inspect_environment(info)
        if str(item).startswith(prefix)
    ]
    return values[0] if len(values) == 1 and values[0] else None


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
    *,
    allow_holder_mounts: bool = True,
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
    holder_targets = (
        set(admission.allowed_mount_targets) if allow_holder_mounts else set()
    )
    return bool(
        len(socket_mounts) == 1
        and _mount_is_canonical_authority_socket(socket_mounts[0])
        and not has_undeclared_runtime_mounts(
            entries,
            allowed_targets=holder_targets,
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
        self._runtime_orchestration_observations = ()
        admitted_addresses = {item.node_address for item in admissions}
        authority_nodes = tuple(
            node for node in realization.nodes if node.address in admitted_addresses
        )
        failure: LabResult | None = None
        if authority_nodes:
            endpoint = self.revalidate_local_docker_socket()
            failure = None if endpoint.success else endpoint
        holder_ids: dict[str, str] = {}
        if failure is None and authority_nodes:
            failure, holder_ids = self._verify_authority_holders(
                authority_nodes,
                admissions,
                require_identity=require_children,
            )
        if failure is None and authority_nodes and require_children:
            failure = self._verify_spawned_child_containment(
                realization,
                admissions,
                holder_ids,
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
        *,
        require_identity: bool,
    ) -> tuple[LabResult | None, dict[str, str]]:
        """Attest the admitted socket and daemon identity on each holder."""

        admissions_by_address = {
            admission.node_address: admission for admission in admissions
        }
        failure = None
        holder_ids: dict[str, str] = {}
        for node in authority_nodes:
            matched = False
            container_id = None
            if node.container_name:
                matched, container_id = self._runtime_authority_identity(
                    node.container_name,
                    admissions_by_address[node.address],
                )
            if not matched or (require_identity and not container_id):
                failure = LabResult(
                    success=False,
                    error=(
                        "Docker authority runtime observation failed for "
                        f"{node.service_name or node.address}."
                    ),
                )
                break
            if container_id is not None:
                holder_ids[node.address] = container_id
        return failure, holder_ids

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
        admissions: tuple[DeploymentDockerAuthorityAdmission, ...],
        holder_ids: Mapping[str, str],
    ) -> LabResult | None:
        """Prove the whole parent/image graph before supervising owned children."""

        try:
            requirements = deployment_spawn_image_requirements(realization)
        except ValueError as exc:
            return LabResult(success=False, error=str(exc))
        admissions_by_authority = {
            (admission.node_address, admission.spawn_requirements[0].authority_id): (
                admission
            )
            for admission in admissions
        }
        ordered = tuple(
            requirement
            for delegated in (True, False)
            for requirement in requirements
            if requirement.delegated_docker_authority is delegated
        )
        candidates: list[_OwnedChildCandidate] = []
        delegated_ids: dict[tuple[str, str, str], set[str]] = {}
        seen_ids: set[str] = set()
        failure = None
        for requirement in ordered:
            admission = admissions_by_authority.get(
                (requirement.node_address, requirement.authority_id)
            )
            if admission is None:
                failure = _spawn_failure(
                    "Spawned-child correlation unavailable",
                    requirement,
                )
                break
            failure, discovered = self._owned_spawn_candidates(
                requirement,
                admission,
                holder_ids,
                delegated_ids,
            )
            if failure is not None:
                break
            for candidate in discovered:
                if candidate.container_id in seen_ids:
                    failure = _spawn_failure(
                        "Spawned-child correlation unavailable",
                        requirement,
                    )
                    break
                seen_ids.add(candidate.container_id)
                candidates.append(candidate)
                if requirement.delegated_docker_authority:
                    delegated_ids.setdefault(
                        (
                            requirement.node_address,
                            requirement.authority_id,
                            candidate.product_execution_id,
                        ),
                        set(),
                    ).add(candidate.container_id)
            if failure is not None:
                break
        if failure is None:
            failure = self._supervise_owned_children(candidates)
        return failure

    def _owned_spawn_candidates(
        self,
        requirement: DeploymentSpawnImageRequirement,
        admission: DeploymentDockerAuthorityAdmission,
        holder_ids: Mapping[str, str],
        delegated_ids: Mapping[tuple[str, str, str], set[str]],
    ) -> tuple[LabResult | None, tuple[_OwnedChildCandidate, ...]]:
        """Inspect and validate every image-matching child without mutation."""

        admitted_execution_ids = set(admission.product_execution_ids)
        if not admitted_execution_ids:
            return (
                _spawn_failure("Spawned-child correlation unavailable", requirement),
                (),
            )
        runtime_ref = requirement.runtime_alias or requirement.image_ref
        try:
            result = self._run(
                [
                    "docker",
                    "ps",
                    "-aq",
                    "--filter",
                    f"ancestor={runtime_ref}",
                ],
                timeout=requirement.execution_timeout_seconds,
            )
        except BackendTimeoutError:
            result = None
        failure: LabResult | None = None
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
        if failure is None and not container_ids:
            failure = _spawn_failure(
                "Spawned-child correlation unavailable",
                requirement,
            )
        expected_image_id = None
        if failure is None:
            expected_image_id = self._exact_spawn_image_id(
                requirement.image_ref,
                timeout=requirement.execution_timeout_seconds,
            )
            if expected_image_id is None:
                failure = _spawn_failure(
                    "Spawned-child image identity unavailable",
                    requirement,
                )
        candidates: list[_OwnedChildCandidate] = []
        if failure is None and expected_image_id is not None:
            for query_id in container_ids:
                failure, candidate = self._inspect_owned_child(
                    query_id,
                    expected_image_id,
                    requirement,
                    admission,
                    holder_ids,
                    delegated_ids,
                )
                if failure is not None:
                    break
                if candidate is not None:
                    candidates.append(candidate)
        if failure is None:
            observed_execution_ids = {
                candidate.product_execution_id for candidate in candidates
            }
            if observed_execution_ids != admitted_execution_ids:
                failure = _spawn_failure(
                    "Spawned-child correlation unavailable",
                    requirement,
                )
        return failure, tuple(candidates)

    def _inspect_owned_child(
        self,
        query_id: str,
        expected_image_id: str,
        requirement: DeploymentSpawnImageRequirement,
        admission: DeploymentDockerAuthorityAdmission,
        holder_ids: Mapping[str, str],
        delegated_ids: Mapping[tuple[str, str, str], set[str]],
    ) -> tuple[LabResult | None, _OwnedChildCandidate | None]:
        """Prove immutable identity, parent ownership, and authority footprint."""

        info = self.container_inspect(query_id)
        product_execution_id = _inspect_environment_value(info, "EXECUTIONID")
        if product_execution_id not in admission.product_execution_ids:
            return None, None
        container_id = self._inspect_container_id(info)
        parent_id = self._inspect_parent_container_id(info)
        failure: LabResult | None = None
        if container_id is None or parent_id is None:
            failure = _spawn_failure(
                "Spawned-child correlation unavailable",
                requirement,
            )
        elif not isinstance(info, Mapping) or info.get("Image") != expected_image_id:
            failure = _spawn_failure(
                "Spawned-child image identity mismatch",
                requirement,
            )
        elif requirement.delegated_docker_authority:
            if parent_id != holder_ids.get(requirement.node_address):
                failure = _spawn_failure(
                    "Spawned-child correlation unavailable",
                    requirement,
                )
            elif not self._delegated_authority_is_valid(info, admission):
                failure = _spawn_failure(
                    "Delegated Docker authority unavailable",
                    requirement,
                )
        else:
            owned_workers = delegated_ids.get(
                (
                    requirement.node_address,
                    requirement.authority_id,
                    product_execution_id,
                ),
                set(),
            )
            if parent_id not in owned_workers:
                failure = _spawn_failure(
                    "Spawned-child correlation unavailable",
                    requirement,
                )
            elif self._inspected_container_has_docker_authority(
                info
            ) or self._inspected_container_has_host_bind(info):
                failure = _spawn_failure(
                    "Docker authority propagated to spawned child",
                    requirement,
                    separator=" ",
                )
        candidate = None
        if failure is None and container_id is not None and parent_id is not None:
            candidate = _OwnedChildCandidate(
                container_id=container_id,
                parent_container_id=parent_id,
                image_id=expected_image_id,
                info=info,
                requirement=requirement,
                admission=admission,
                product_execution_id=product_execution_id,
            )
        return failure, candidate

    def _supervise_owned_children(
        self,
        candidates: Sequence[_OwnedChildCandidate],
    ) -> LabResult | None:
        """Enforce deadlines only after the complete candidate set is owned."""

        observations: list[DeploymentSpawnedChildObservation] = []
        failure = None
        for candidate in candidates:
            requirement = candidate.requirement
            failure = self._enforce_spawned_child_deadline(
                candidate.container_id,
                candidate.info,
                timeout=requirement.execution_timeout_seconds,
                node_address=requirement.node_address,
                template_id=requirement.template_id,
            )
            if failure is not None:
                break
            observations.append(
                DeploymentSpawnedChildObservation(
                    node_address=requirement.node_address,
                    authority_id=requirement.authority_id,
                    template_id=requirement.template_id,
                    correlation_id=runtime_child_correlation_id(
                        candidate.admission,
                        requirement,
                        candidate.product_execution_id,
                    ),
                    authority_correlation_id=candidate.admission.correlation_id,
                    run_id=candidate.admission.run_id,
                    attempt_id=candidate.admission.attempt_id,
                    product_execution_id=candidate.product_execution_id,
                    container_id=candidate.container_id,
                    image_id=candidate.image_id,
                    parent_container_id=candidate.parent_container_id,
                    delegated_docker_authority=(requirement.delegated_docker_authority),
                    terminal=True,
                )
            )
        if failure is None:
            self._runtime_orchestration_observations = tuple(observations)
        return failure

    @staticmethod
    def _inspect_container_id(info: object) -> str | None:
        """Return the inspect-native child ID, never the query alias."""

        raw = info.get("Id") if isinstance(info, Mapping) else None
        normalized = str(raw or "").strip()
        return normalized if _SAFE_CONTAINER_ID.fullmatch(normalized) else None

    @staticmethod
    def _inspect_parent_container_id(info: object) -> str | None:
        """Return an exact Docker container-network parent identity."""

        host = info.get("HostConfig") if isinstance(info, Mapping) else None
        mode = host.get("NetworkMode") if isinstance(host, Mapping) else None
        raw = str(mode or "")
        parent = raw.removeprefix("container:") if raw.startswith("container:") else ""
        return parent if _SAFE_CONTAINER_ID.fullmatch(parent) else None

    @staticmethod
    def _delegated_authority_is_valid(
        info: object,
        admission: DeploymentDockerAuthorityAdmission,
    ) -> bool:
        """Whether a delegated worker has only the exact admitted control route."""

        return bool(
            _authority_mount_is_valid(
                _inspect_mounts(info),
                admission,
                allow_holder_mounts=False,
            )
            and not _inspect_has_endpoint_override(info)
            and not _inspect_is_privileged(info)
        )

    def runtime_orchestration_observations(self) -> tuple[dict[str, object], ...]:
        """Return redaction-safe evidence from the last complete attestation."""

        return tuple(
            asdict(item)
            for item in getattr(self, "_runtime_orchestration_observations", ())
            if isinstance(item, DeploymentSpawnedChildObservation)
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

        matched, _container_id = self._runtime_authority_identity(
            container_name,
            admission,
        )
        return matched

    def _runtime_authority_identity(
        self,
        container_name: str,
        admission: DeploymentDockerAuthorityAdmission,
    ) -> tuple[bool, str | None]:
        """Attest one holder and return its inspect-native parent identity."""

        info = self.container_inspect(container_name)
        container_id = self._inspect_container_id(info)
        daemon_id = getattr(self, "_docker_daemon_id", None)
        socket_identity = getattr(self, "_docker_socket_identity", None)
        configuration_ok = bool(
            _authority_mount_is_valid(_inspect_mounts(info), admission)
            and not _inspect_has_endpoint_override(info)
            and not _inspect_is_privileged(info)
            and daemon_id
        )
        if not configuration_ok:
            return False, None
        try:
            observed = self.container_exec(
                container_name,
                ["docker", "info", "--format", "{{.ID}}"],
                timeout=30,
            )
        except BackendTimeoutError:
            observed = None
        matched = bool(
            observed is not None
            and observed.returncode == 0
            and observed.stdout.strip() == daemon_id
        )
        if not matched and socket_identity is not None:
            matched = self._runtime_authority_socket_identity_matches(
                container_name,
                socket_identity,
            )
        return matched, container_id

    def _runtime_authority_socket_identity_matches(
        self,
        container_name: str,
        expected: tuple[int, int],
    ) -> bool:
        """Prove the holder sees the exact host socket when no CLI is shipped."""

        try:
            observed = self.container_exec(
                container_name,
                ["stat", "-Lc", "%d:%i", "/var/run/docker.sock"],
                timeout=30,
            )
        except BackendTimeoutError:
            return False
        return bool(
            observed.returncode == 0
            and observed.stdout.strip() == f"{expected[0]}:{expected[1]}"
        )

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

    @staticmethod
    def _inspected_container_has_host_bind(info: object) -> bool:
        """Whether a product child has any ungranted host bind."""

        return any(
            isinstance(mount, Mapping) and mount.get("Type") == "bind"
            for mount in _inspect_mounts(info)
        )
