"""Post-start observation for admitted runtime orchestration authorities."""

from __future__ import annotations

from aptl.core.deployment._compose_runtime_observation_helpers import (
    authority_mount_is_valid as _authority_mount_is_valid,
    inspect_has_endpoint_override as _inspect_has_endpoint_override,
    inspect_has_socket_route as _inspect_has_socket_route,
    inspect_mounts as _inspect_mounts,
)
from aptl.core.deployment._compose_runtime_orchestration import (
    docker_authority_admissions,
)
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.core.lab_types import LabResult
from aptl.runtime_authority import DeploymentDockerAuthorityAdmission


class ComposeRuntimeOrchestrationObservationMixin:
    """Attest the socket footprint of the services APTL lowers.

    Scope is what APTL itself configures. Containers the holder creates on
    the daemon are not observed here: APTL never configured them, and a
    host-root-equivalent holder is not attenuated by judging its children
    after the fact. Issue #1128 owns identifying containers APTL caused.
    """

    def _verify_runtime_orchestration(
        self,
        realization: DeploymentRealizationSpec,
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
