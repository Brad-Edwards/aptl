"""Docker Compose network realization helpers."""

from __future__ import annotations

from typing import Any

from aptl.core.deployment._compose_network_conflicts import (
    _network_subnet_conflicts,
    _planned_networks_to_create,
)
from aptl.core.deployment._compose_realization_networks import (
    _COMPOSE_NETWORK_LABEL,
    _COMPOSE_PROJECT_LABEL,
    _REALIZATION_NETWORK_LABEL,
    _REALIZATION_NETWORK_LABEL_VALUE,
    _compose_network_key,
    _concrete_network_name,
    _container_network_ip,
    _container_networks,
    _match_managed_network,
    _network_policy_mismatches,
    _node_network_aliases,
    _node_network_attachments,
    _resolve_realization_network_attachments,
)
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.realization import (
    DeploymentNetworkAttachment,
    DeploymentNetworkRealization,
    DeploymentRealizationSpec,
)
from aptl.core.lab_types import LabResult

_REALIZATION_TIMEOUT = 30

# Docker's fixed built-in default network. `docker run` with no `--network`
# flag (the generic materializer's node creation, ADR-048) implicitly attaches
# it; Compose-started containers never do. It is disconnected explicitly
# below rather than folded into "unmanaged" cleanup, which deliberately never
# touches a network APTL did not create (issue #581) - "bridge" is the one
# accidental attachment, not a user's own network APTL should leave alone.
_DEFAULT_BRIDGE_NETWORK = "bridge"


class ComposeRealizationNetworkMixin:
    """Realize typed scenario networks through Docker Compose."""

    def _ensure_realization_networks(
        self,
        realization: DeploymentRealizationSpec,
    ) -> list[str]:
        """Create scenario-declared project networks that do not exist."""

        if not realization.networks:
            return []
        managed_networks = set(self.host_list_lab_networks(self._project_name))
        conflicts = self._realization_network_subnet_conflicts(
            realization,
            managed_networks,
        )
        if conflicts:
            return conflicts
        failures: list[str] = []
        for network in realization.networks:
            match = _match_managed_network(
                network.name,
                managed_networks,
                self._project_name,
            )
            if match is not None:
                failures.extend(
                    self._realization_network_reuse_failures(match, network)
                )
                continue
            result = self.create_network(network)
            if result.success:
                managed_networks.add(
                    _concrete_network_name(network.name, self._project_name)
                )
            else:
                failures.append(
                    result.error
                    or f"Failed to create realized network {network.name}."
                )
        return failures

    def _realization_network_subnet_conflicts(
        self,
        realization: DeploymentRealizationSpec,
        managed_networks: set[str],
    ) -> list[str]:
        """Return preflight failures for Docker subnet overlaps."""

        planned_networks = _planned_networks_to_create(
            realization,
            managed_networks,
            self._project_name,
        )
        if not planned_networks:
            return []
        existing_networks = self._host_network_inspection_details()
        if not existing_networks:
            return []
        return [
            failure
            for network in planned_networks
            for failure in _network_subnet_conflicts(network, existing_networks)
        ]

    def _host_network_inspection_details(self) -> list[dict[str, Any]]:
        """Return inspectable Docker network details for overlap checks."""

        return [
            details
            for name in self.host_list_networks()
            if (details := self.host_inspect_network(name))
        ]

    def _realization_network_reuse_failures(
        self,
        network_name: str,
        network: DeploymentNetworkRealization,
    ) -> list[str]:
        """Return fail-closed errors for an existing realized network."""

        compose_key = _compose_network_key(network.name)
        if not compose_key:
            return ["Invalid network realization name."]
        details = self.host_inspect_network(network_name)
        if not details:
            return [
                f"Existing network {network_name} was not inspectable "
                f"for realized network {network.name}."
            ]

        labels = details.get("labels")
        if not isinstance(labels, dict):
            labels = {}
        mismatches = _network_policy_mismatches(
            details,
            labels,
            network,
            project_name=self._project_name,
            compose_key=compose_key,
        )
        return [
            f"Existing network {network_name} does not match realized "
            f"network {network.name}: {mismatch}."
            for mismatch in mismatches
        ]

    def _reconcile_realization_networks(
        self,
        realization: DeploymentRealizationSpec,
    ) -> list[str]:
        """Align realized containers with the scenario-declared networks."""

        managed_networks = set(self.host_list_lab_networks(self._project_name))
        if not managed_networks:
            return ["APTL managed networks were not visible after startup."]

        failures: list[str] = []
        for node in realization.nodes:
            if not node.container_name or not node.networks:
                continue
            desired, missing = _resolve_realization_network_attachments(
                _node_network_attachments(node),
                managed_networks,
                self._project_name,
            )
            if missing:
                failures.append(
                    "No managed Docker network matched ACES network(s) "
                    f"{', '.join(missing)} for node {node.name}."
                )
                continue
            info = self.container_inspect(node.container_name)
            if not info:
                failures.append(
                    f"Container {node.container_name} was not inspectable "
                    f"for realized node {node.name}."
                )
                continue
            current = _container_networks(info) & managed_networks
            reattach, reattach_failures = self._reconnect_static_ip_drifts(
                node.container_name,
                info,
                desired,
            )
            failures.extend(reattach_failures)
            current = current - set(reattach)
            aliases = _node_network_aliases(node)
            failures.extend(
                self._disconnect_extra_networks(
                    node.container_name,
                    current,
                    set(desired),
                )
            )
            failures.extend(
                self._connect_missing_networks(
                    node.container_name,
                    current,
                    desired,
                    aliases,
                )
            )
            failures.extend(
                self._disconnect_default_bridge(node.container_name, info, desired)
            )
        return failures

    def _disconnect_default_bridge(
        self,
        container_name: str,
        info: dict[str, Any],
        desired: dict[str, DeploymentNetworkAttachment],
    ) -> list[str]:
        """Detach a node's implicit default-bridge attachment, if any.

        Runs after the declared networks are connected, so a generic-
        materializer node keeps outbound connectivity (e.g. for its own
        package installs, which run before this reconciliation step) right
        up until its real attachments are in place.
        """

        if (
            _DEFAULT_BRIDGE_NETWORK not in _container_networks(info)
            or _DEFAULT_BRIDGE_NETWORK in desired
        ):
            return []
        result = self.disconnect_container_network(
            container_name, _DEFAULT_BRIDGE_NETWORK
        )
        if not result.success:
            return [
                result.error
                or f"Failed to disconnect {container_name} from "
                f"{_DEFAULT_BRIDGE_NETWORK}."
            ]
        return []

    def _reconnect_static_ip_drifts(
        self,
        container_name: str,
        info: dict[str, Any],
        desired: dict[str, DeploymentNetworkAttachment],
    ) -> tuple[list[str], list[str]]:
        """Disconnect already-attached networks whose static IP is wrong."""

        reattach: list[str] = []
        failures: list[str] = []
        for network_name, attachment in desired.items():
            if not attachment.ipv4_address:
                continue
            current_ip = _container_network_ip(info, network_name)
            if current_ip and current_ip != attachment.ipv4_address:
                result = self.disconnect_container_network(container_name, network_name)
                if result.success:
                    reattach.append(network_name)
                else:
                    failures.append(
                        result.error
                        or (
                            f"Failed to disconnect {container_name} "
                            f"from {network_name}."
                        )
                    )
        return reattach, failures

    def _disconnect_extra_networks(
        self,
        container_name: str,
        current: set[str],
        desired: set[str],
    ) -> list[str]:
        """Detach a realized container from project networks outside its spec."""

        failures: list[str] = []
        for network_name in sorted(current - desired):
            result = self.disconnect_container_network(container_name, network_name)
            if not result.success:
                failures.append(
                    result.error
                    or f"Failed to disconnect {container_name} from {network_name}."
                )
        return failures

    def _connect_missing_networks(
        self,
        container_name: str,
        current: set[str],
        desired: dict[str, DeploymentNetworkAttachment],
        aliases: tuple[str, ...],
    ) -> list[str]:
        """Attach a realized container to declared project networks it lacks."""

        failures: list[str] = []
        for network_name in sorted(set(desired) - current):
            attachment = desired[network_name]
            result = self.connect_container_network(
                container_name,
                network_name,
                ipv4_address=attachment.ipv4_address,
                aliases=aliases,
            )
            if not result.success:
                failures.append(
                    result.error
                    or f"Failed to connect {container_name} to {network_name}."
                )
        return failures

    def create_network(self, network: DeploymentNetworkRealization) -> LabResult:
        """Create one project-scoped Docker bridge network."""

        concrete_name = _concrete_network_name(network.name, self._project_name)
        compose_key = _compose_network_key(network.name)
        if not concrete_name or not compose_key:
            return LabResult(success=False, error="Invalid network realization name.")
        cmd = [
            "docker",
            "network",
            "create",
            "--driver",
            "bridge",
            "--label",
            f"{_COMPOSE_PROJECT_LABEL}={self._project_name}",
            "--label",
            f"{_COMPOSE_NETWORK_LABEL}={compose_key}",
            "--label",
            f"{_REALIZATION_NETWORK_LABEL}={_REALIZATION_NETWORK_LABEL_VALUE}",
        ]
        if network.internal is True:
            cmd.append("--internal")
        if network.cidr:
            cmd.extend(["--subnet", network.cidr])
        if network.gateway:
            cmd.extend(["--gateway", network.gateway])
        cmd.append(concrete_name)
        result = self._run(cmd, timeout=_REALIZATION_TIMEOUT)
        if result.returncode != 0:
            return LabResult(
                success=False,
                error=(
                    f"Failed to create realized network {network.name}: "
                    f"{result.stderr.strip()}"
                ),
            )
        return LabResult(success=True, message=concrete_name)

    def connect_container_network(
        self,
        container_name: str,
        network_name: str,
        *,
        ipv4_address: str | None = None,
        aliases: tuple[str, ...] = (),
    ) -> LabResult:
        """Connect one container to one Docker network."""

        cmd = ["docker", "network", "connect"]
        if ipv4_address:
            cmd.extend(["--ip", ipv4_address])
        for alias in dict.fromkeys(alias for alias in aliases if alias):
            cmd.extend(["--alias", alias])
        cmd.extend([network_name, container_name])
        result = self._run(cmd, timeout=_REALIZATION_TIMEOUT)
        if result.returncode != 0:
            return LabResult(
                success=False,
                error=(
                    f"Failed to connect {container_name} to {network_name}: "
                    f"{result.stderr.strip()}"
                ),
            )
        return LabResult(success=True, message="connected")

    def disconnect_container_network(
        self,
        container_name: str,
        network_name: str,
    ) -> LabResult:
        """Disconnect one container from one Docker network."""

        result = self._run(
            ["docker", "network", "disconnect", network_name, container_name],
            timeout=_REALIZATION_TIMEOUT,
        )
        if result.returncode != 0:
            return LabResult(
                success=False,
                error=(
                    f"Failed to disconnect {container_name} from {network_name}: "
                    f"{result.stderr.strip()}"
                ),
            )
        return LabResult(success=True, message="disconnected")

    def remove_project_networks(self) -> list[str]:
        """Remove leftover project-scoped realization networks."""

        failures: list[str] = []
        try:
            result = self._run(
                [
                    "docker",
                    "network",
                    "ls",
                    "--filter",
                    f"label={_COMPOSE_PROJECT_LABEL}={self._project_name}",
                    "--filter",
                    (
                        f"label={_REALIZATION_NETWORK_LABEL}="
                        f"{_REALIZATION_NETWORK_LABEL_VALUE}"
                    ),
                    "--filter",
                    f"name={self._project_name}",
                    "--format",
                    "{{.Name}}",
                ],
                timeout=_REALIZATION_TIMEOUT,
            )
        except (BackendTimeoutError, OSError) as exc:
            return [f"Failed to list project networks for cleanup: {exc}"]
        if result.returncode != 0:
            return [
                "Failed to list project networks for cleanup: "
                f"{result.stderr.strip()}"
            ]
        network_names = [
            line.strip() for line in result.stdout.splitlines() if line.strip()
        ]
        for network_name in network_names:
            try:
                result = self._run(
                    ["docker", "network", "rm", network_name],
                    timeout=_REALIZATION_TIMEOUT,
                )
            except (BackendTimeoutError, OSError) as exc:
                failures.append(
                    f"Failed to remove project network {network_name}: {exc}"
                )
                continue
            if result.returncode != 0:
                failures.append(
                    f"Failed to remove project network {network_name}: "
                    f"{result.stderr.strip()}"
                )
        return failures
