"""Receipt-backed creation of directly realized Docker networks."""

from __future__ import annotations

from aptl.core.deployment._compose_resource_ownership import OwnershipConflictError
from aptl.core.deployment._compose_realization_networks import (
    _COMPOSE_NETWORK_LABEL,
    _COMPOSE_PROJECT_LABEL,
    _REALIZATION_NETWORK_LABEL,
    _REALIZATION_NETWORK_LABEL_VALUE,
    _compose_network_key,
    _concrete_network_name,
)
from aptl.core.deployment.realization import DeploymentNetworkRealization
from aptl.core.lab_types import LabResult

_REALIZATION_TIMEOUT = 30


class ComposeDirectNetworkMixin:
    """Create direct networks with complete labels and immutable receipts."""

    def _create_attempt_network(
        self,
        network: DeploymentNetworkRealization,
        *,
        attempt_id: str,
        ip_range: str | None,
    ) -> LabResult:
        """Create and receipt one network for the bound attempt."""

        concrete_name = _concrete_network_name(network.name, self._project_name)
        compose_key = _compose_network_key(network.name)
        if not concrete_name or not compose_key:
            return LabResult(success=False, error="Invalid network realization name.")
        command = self._network_create_command(
            network,
            attempt_id=attempt_id,
            compose_key=compose_key,
            concrete_name=concrete_name,
            ip_range=ip_range,
        )
        result = self._run(command, timeout=_REALIZATION_TIMEOUT)
        if result.returncode != 0:
            return LabResult(
                success=False,
                error=f"Failed to create realized network {network.name}: {result.stderr.strip()}",
            )
        return self._receipt_created_network(
            network,
            native_id=result.stdout.strip(),
            concrete_name=concrete_name,
            attempt_id=attempt_id,
        )

    def _network_create_command(
        self,
        network: DeploymentNetworkRealization,
        *,
        attempt_id: str,
        compose_key: str,
        concrete_name: str,
        ip_range: str | None,
    ) -> list[str]:
        """Build the exact direct network-create command."""

        command = [
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
        command.extend(
            item
            for label, value in self._ensure_resource_ownership()
            .labels(attempt_id=attempt_id)
            .items()
            for item in ("--label", f"{label}={value}")
        )
        options = (
            (network.internal is True, ("--internal",)),
            (bool(network.cidr), ("--subnet", str(network.cidr))),
            (bool(network.gateway), ("--gateway", str(network.gateway))),
            (bool(ip_range), ("--ip-range", str(ip_range))),
        )
        command.extend(
            item for enabled, values in options if enabled for item in values
        )
        command.append(concrete_name)
        return command

    def _receipt_created_network(
        self,
        network: DeploymentNetworkRealization,
        *,
        native_id: str,
        concrete_name: str,
        attempt_id: str,
    ) -> LabResult:
        """Record a direct network or remove it if authority cannot be stored."""

        if not native_id:
            return LabResult(
                success=False,
                error=f"Docker did not return an identity for realized network {network.name}.",
            )
        try:
            self._record_created_network(
                network,
                native_id=native_id,
                external_name=concrete_name,
                attempt_id=attempt_id,
            )
        except OwnershipConflictError:
            self._run(
                ["docker", "network", "rm", native_id],
                timeout=_REALIZATION_TIMEOUT,
            )
            return LabResult(
                success=False,
                error=f"Could not record ownership for realized network {network.name}.",
            )
        return LabResult(success=True, message=concrete_name)
