"""Post-start realization reconciliation (issue #875).

Split out of ``_compose_realization.py`` (module-length budget): everything that
happens after ``compose up`` returns. ``compose up -d`` only proves the
containers were *created*, so a resource counts as realized only once the
backend has started and observed it (ADR-046 runtime addendum): networks are
reconciled, service health is awaited, authenticated readiness is verified, and
only then are accounts realized.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import time

from aptl.core.deployment._compose_service_health import wait_for_realized_health
from aptl.core.deployment._docker_image_identity import (
    EXACT_IMAGE_INSPECT_FORMAT,
    exact_inspected_image_identity,
)
from aptl.core.deployment._compose_runtime_orchestration import (
    deployment_spawn_image_requirements,
    docker_authority_admissions,
)
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.lab_types import LabResult
from aptl.runtime_authority import (
    DeploymentDockerAuthorityAdmission,
    has_undeclared_runtime_mounts,
    mount_exposes_or_mentions_docker_socket,
)


def _docker_timestamp(value: object) -> datetime | None:
    """Parse a Docker RFC3339 timestamp as an aware UTC datetime."""

    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None


class ComposeRealizationPostStartMixin:
    """Reconcile, observe and finish a realization after Compose startup."""

    def _realization_result(
        self,
        start_result: LabResult,
        realization: DeploymentRealizationSpec,
    ) -> LabResult:
        """Return the final result after start, network, health, and accounts.

        Ordering is load-bearing: networks are reconciled, then services must be
        observed healthy, then accounts are realized. Account realization execs
        into the running node containers (``container_exec``), so it cannot run
        until those containers are up and healthy — the health wait gates it.
        """

        if not start_result.success:
            return start_result
        return self._post_start_result(realization)

    def _post_start_result(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult:
        """Reconcile networks, await health, then realize accounts, in order.

        The steps are sequential and short-circuit: a network failure returns
        before the health wait runs, and accounts are realized only once the
        services are observed healthy (account realization execs into the running
        containers). First failure wins.
        """

        result: LabResult | None = None
        network_failures = self._reconcile_realization_networks(realization)
        if network_failures:
            result = LabResult(
                success=False,
                error="; ".join(network_failures[:5]),
            )
        if result is None:
            health_failures = self._await_realized_service_health(realization)
            if health_failures:
                result = LabResult(
                    success=False,
                    error="; ".join(health_failures[:5]),
                )
        if result is None:
            result = self._verify_stateful_authenticated_readiness(realization)
        if result is None:
            result = self._verify_runtime_orchestration(realization)
        if result is None:
            result = self._realize_accounts_step(realization) or LabResult(
                success=True,
                message="Lab realized",
            )
        return result

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
        authority_nodes = [
            node for node in realization.nodes if node.address in admitted_addresses
        ]
        if not authority_nodes:
            return None
        endpoint = self.revalidate_local_docker_socket()
        if not endpoint.success:
            return endpoint
        admissions_by_address = {
            admission.node_address: admission for admission in admissions
        }
        for node in authority_nodes:
            if not node.container_name or not self._runtime_authority_matches(
                node.container_name, admissions_by_address[node.address]
            ):
                return LabResult(
                    success=False,
                    error=(
                        "Docker authority runtime observation failed for "
                        f"{node.service_name or node.address}."
                    ),
                )
        child_result = self._verify_spawned_child_containment(
            realization, require_children=require_children
        )
        if child_result is not None:
            return child_result
        authority_addresses = {node.address for node in authority_nodes}
        for node in realization.nodes:
            if node.address in authority_addresses or not node.container_name:
                continue
            if self._container_has_docker_authority(node.container_name):
                return LabResult(
                    success=False,
                    error=(
                        "Docker authority propagated to unauthorized service "
                        f"{node.service_name or node.address}."
                    ),
                )
        return None

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
        for requirement in requirements:
            node_address = requirement.node_address
            template_id = requirement.template_id
            timeout = requirement.execution_timeout_seconds
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
                    timeout=timeout,
                )
            except BackendTimeoutError:
                result = None
            if result is None or result.returncode != 0:
                return LabResult(
                    success=False,
                    error=(
                        "Spawned-child observation failed for "
                        f"{node_address}/{template_id}."
                    ),
                )
            container_ids = tuple(
                dict.fromkeys(
                    container_id.strip()
                    for container_id in result.stdout.splitlines()
                    if container_id.strip()
                )
            )
            if not container_ids and not require_children:
                continue
            if len(container_ids) != requirement.expected_count:
                return LabResult(
                    success=False,
                    error=(
                        "Spawned-child correlation count mismatch for "
                        f"{node_address}/{template_id}."
                    ),
                )
            expected_image_id = self._exact_spawn_image_id(
                requirement.image_ref, timeout=timeout
            )
            if expected_image_id is None:
                return LabResult(
                    success=False,
                    error=(
                        "Spawned-child image identity unavailable for "
                        f"{node_address}/{template_id}."
                    ),
                )
            label_name, label_value = requirement.child_label.split("=", 1)
            for container_id in container_ids:
                info = self.container_inspect(container_id)
                if not info:
                    return LabResult(
                        success=False,
                        error=(
                            "Spawned-child observation failed for "
                            f"{node_address}/{template_id}."
                        ),
                    )
                if info.get("Image") != expected_image_id:
                    return LabResult(
                        success=False,
                        error=(
                            "Spawned-child image identity mismatch for "
                            f"{node_address}/{template_id}."
                        ),
                    )
                config = info.get("Config") if isinstance(info, Mapping) else None
                labels = config.get("Labels") if isinstance(config, Mapping) else None
                if (
                    not isinstance(labels, Mapping)
                    or labels.get(label_name) != label_value
                ):
                    return LabResult(
                        success=False,
                        error=(
                            "Spawned-child correlation unavailable for "
                            f"{node_address}/{template_id}."
                        ),
                    )
                if self._inspected_container_has_docker_authority(info):
                    return LabResult(
                        success=False,
                        error=(
                            "Docker authority propagated to spawned child "
                            f"{node_address}/{template_id}."
                        ),
                    )
                lifecycle = self._enforce_spawned_child_deadline(
                    container_id,
                    info,
                    timeout=timeout,
                    node_address=node_address,
                    template_id=template_id,
                )
                if lifecycle is not None:
                    return lifecycle
        return None

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
        if result.returncode != 0:
            return None
        identity = exact_inspected_image_identity(result.stdout, image_ref)
        return identity.image_id if identity is not None else None

    def _enforce_spawned_child_deadline(
        self,
        container_id: str,
        info: object,
        *,
        timeout: int,
        node_address: str,
        template_id: str,
    ) -> LabResult | None:
        """Stop an over-deadline running child and prove it became terminal."""

        observed = info
        state = observed.get("State") if isinstance(observed, Mapping) else None
        if not isinstance(state, Mapping):
            return LabResult(
                success=False,
                error=(
                    "Spawned-child lifecycle observation failed for "
                    f"{node_address}/{template_id}."
                ),
            )
        if state.get("Running") is not True:
            return None
        started = _docker_timestamp(state.get("StartedAt"))
        if started is None:
            return LabResult(
                success=False,
                error=(
                    "Spawned-child lifecycle observation failed for "
                    f"{node_address}/{template_id}."
                ),
            )
        deadline = started.timestamp() + timeout
        while (
            state.get("Running") is True
            and datetime.now(timezone.utc).timestamp() < deadline
        ):
            remaining = deadline - datetime.now(timezone.utc).timestamp()
            time.sleep(min(2.0, max(0.0, remaining)))
            observed = self.container_inspect(container_id)
            state = observed.get("State") if isinstance(observed, Mapping) else None
            if not isinstance(state, Mapping):
                return LabResult(
                    success=False,
                    error=(
                        "Spawned-child lifecycle observation failed for "
                        f"{node_address}/{template_id}."
                    ),
                )
        if state.get("Running") is not True:
            return None
        try:
            stopped = self._run(
                ["docker", "stop", "--time", "10", container_id], timeout=30
            )
            if stopped.returncode != 0:
                stopped = self._run(["docker", "kill", container_id], timeout=30)
        except BackendTimeoutError:
            stopped = None
        observed = self.container_inspect(container_id)
        observed_state = (
            observed.get("State") if isinstance(observed, Mapping) else None
        )
        terminal = bool(
            stopped is not None
            and stopped.returncode == 0
            and isinstance(observed_state, Mapping)
            and observed_state.get("Running") is False
        )
        diagnostic = (
            "Spawned child exceeded lifecycle deadline for "
            if terminal
            else "Spawned child lifecycle termination failed for "
        )
        return LabResult(
            success=False,
            error=f"{diagnostic}{node_address}/{template_id}.",
        )

    def _runtime_authority_matches(
        self,
        container_name: str,
        admission: DeploymentDockerAuthorityAdmission,
    ) -> bool:
        """Whether one holder exposes only the admitted endpoint to the same daemon."""

        info = self.container_inspect(container_name)
        mounts = info.get("Mounts") if isinstance(info, Mapping) else None
        entries = mounts if isinstance(mounts, Sequence) else ()
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
        mount_ok = bool(
            len(socket_mounts) == 1
            and socket_mounts[0].get("Type") == "bind"
            and socket_mounts[0].get("Source") == "/var/run/docker.sock"
            and socket_mounts[0].get("Destination") == "/var/run/docker.sock"
            and socket_mounts[0].get("RW") is True
        )
        mount_ok = mount_ok and not has_undeclared_runtime_mounts(
            entries,
            allowed_targets=set(admission.allowed_mount_targets),
            docker_authority_admitted=True,
        )
        config = info.get("Config") if isinstance(info, Mapping) else None
        raw_env = config.get("Env") if isinstance(config, Mapping) else None
        env = (
            raw_env
            if isinstance(raw_env, Sequence) and not isinstance(raw_env, (str, bytes))
            else ()
        )
        environment_ok = not any(
            str(item).split("=", 1)[0] in {"DOCKER_HOST", "DOCKER_CONTEXT"}
            for item in env
        )
        host_config = info.get("HostConfig") if isinstance(info, Mapping) else None
        privilege_ok = not (
            isinstance(host_config, Mapping) and host_config.get("Privileged") is True
        )
        daemon_id = getattr(self, "_docker_daemon_id", None)
        if not (mount_ok and environment_ok and privilege_ok and daemon_id):
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

        mounts = info.get("Mounts") if isinstance(info, Mapping) else None
        entries = (
            mounts
            if isinstance(mounts, Sequence) and not isinstance(mounts, (str, bytes))
            else ()
        )
        socket = any(
            mount_exposes_or_mentions_docker_socket(
                mount,
                source_key="Source",
                target_key="Destination",
                type_key="Type",
                bind_type="bind",
            )
            for mount in entries
        )
        config = info.get("Config") if isinstance(info, Mapping) else None
        raw_env = config.get("Env") if isinstance(config, Mapping) else None
        env = (
            raw_env
            if isinstance(raw_env, Sequence) and not isinstance(raw_env, (str, bytes))
            else ()
        )
        endpoint_override = any(
            str(item).split("=", 1)[0] in {"DOCKER_HOST", "DOCKER_CONTEXT"}
            for item in env
        )
        host_config = info.get("HostConfig") if isinstance(info, Mapping) else None
        privileged = bool(
            isinstance(host_config, Mapping) and host_config.get("Privileged") is True
        )
        return socket or endpoint_override or privileged

    def _await_realized_service_health(
        self,
        realization: DeploymentRealizationSpec,
    ) -> list[str]:
        """Wait for the declared services to actually come up.

        ``compose up -d`` only proves the containers were *created*. A resource
        counts as realized only once the backend has started and observed it
        (ADR-046 runtime addendum), so the realization does not return success
        until every realized container is running and every container carrying a
        healthcheck reports healthy.
        """

        containers = [
            node.container_name for node in realization.nodes if node.container_name
        ]
        return wait_for_realized_health(self, containers)

    def _realize_accounts_step(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Realize account placements post-start; fail closed on a backend timeout.

        Returns ``None`` on success (or nothing to realize). Account readiness
        and verification failures already arrive as a fail-closed
        :class:`LabResult`; a mid-mutation ``BackendTimeoutError`` from
        ``container_exec`` is converted into the same bounded envelope here.
        """

        try:
            return self.realize_accounts(realization.accounts, realization.nodes)
        except BackendTimeoutError as exc:
            return LabResult(
                success=False,
                error=f"Account realization timed out: {exc}",
            )
