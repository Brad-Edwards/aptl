"""Post-start observation for admitted runtime orchestration authorities."""

from __future__ import annotations

from collections.abc import Mapping
from aptl.core.deployment._compose_child_lifecycle import (
    ComposeSpawnedChildLifecycleMixin,
)
from aptl.core.deployment._compose_resource_ownership import OwnershipConflictError
from aptl.core.deployment._compose_runtime_observation_helpers import (
    authority_mount_is_valid as _authority_mount_is_valid,
    child_query as _child_query,
    container_ids as _container_ids,
    inspect_has_endpoint_override as _inspect_has_endpoint_override,
    inspect_has_socket_route as _inspect_has_socket_route,
    inspect_mounts as _inspect_mounts,
    spawn_failure as _spawn_failure,
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

        # An uncorrelated template identifies an allowed image, not a spawned
        # child. A shared daemon cannot attribute other containers with that
        # image to this lab, so never inspect foreign containers by image alone.
        if not requirement.child_label:
            return None, ()
        failure, container_ids = self._query_correlated_child_ids(requirement)
        # A count can only be enforced against an authored one. A template
        # without a declared child inventory says which image may run, not how
        # many may run, so its children are identity-checked and not counted.
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

    def _query_correlated_child_ids(
        self, requirement: DeploymentSpawnImageRequirement
    ) -> tuple[LabResult | None, tuple[str, ...]]:
        """Query exact child labels and capture isolated-daemon ownership."""

        query = _child_query(requirement)
        try:
            result = self._run(
                query,
                timeout=requirement.execution_timeout_seconds,
            )
        except BackendTimeoutError:
            result = None
        if result is None or result.returncode != 0:
            return _spawn_failure("Spawned-child observation failed", requirement), ()
        container_ids = _container_ids(result.stdout)
        if container_ids and getattr(self, "_attempt_isolated_docker_daemon", False):
            return (
                self._record_child_receipts(container_ids, requirement),
                container_ids,
            )
        return None, container_ids

    def _record_child_receipts(
        self,
        container_ids: tuple[str, ...],
        requirement: DeploymentSpawnImageRequirement,
    ) -> LabResult | None:
        """Record isolated-daemon child ownership, or return one failure."""

        failure = None
        try:
            self._record_isolated_child_receipts(container_ids, requirement)
        except OwnershipConflictError:
            failure = _spawn_failure(
                "Spawned-child ownership could not be established",
                requirement,
            )
        return failure

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

        if not requirement.child_label:
            # Nothing was authored to correlate against. The child's image
            # identity is still verified by the caller; only the label match is
            # vacuous here, and claiming a match that was never declared would
            # be the false positive this check exists to avoid.
            return True
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
            and daemon_id
        )
        if not configuration_ok:
            return False
        return self._holder_reaches_daemon(container_name, str(daemon_id))

    def _holder_reaches_daemon(self, container_name: str, daemon_id: str) -> bool:
        """Whether the holder's own Docker CLI corroborates the same daemon.

        The holder is not required to ship a Docker CLI. Real socket holders
        drive the daemon over its API -- Shuffle's orborus is one -- and exec
        answers 126/127 when the binary is absent. There is then nothing to
        corroborate, and the caller has already established the boundary: the
        mount is exactly the admitted host socket and no endpoint override
        redirects it. A CLI that does answer, for a different daemon, is still
        a failure.
        """

        try:
            observed = self.container_exec(
                container_name,
                ["docker", "info", "--format", "{{.ID}}"],
                timeout=30,
            )
        except BackendTimeoutError:
            return False
        if observed.returncode in (126, 127):
            return True
        return observed.returncode == 0 and observed.stdout.strip() == daemon_id

    def _container_has_docker_authority(self, container_name: str) -> bool:
        """Whether an unauthorized service carries a Docker control route."""

        info = self.container_inspect(container_name)
        return self._inspected_container_has_docker_authority(info)

    @staticmethod
    def _inspected_container_has_docker_authority(info: object) -> bool:
        """Whether inspect output exposes Docker control, not mere privilege."""

        return bool(
            _inspect_has_socket_route(info) or _inspect_has_endpoint_override(info)
        )
