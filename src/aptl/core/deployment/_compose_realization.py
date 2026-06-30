"""Docker Compose realization helpers for typed ACES deployment specs."""

from __future__ import annotations

import re
from typing import Any

from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.lab_types import LabResult

_NETWORK_TOKEN_SEPARATORS = re.compile(r"[^a-z0-9]+")
_REALIZATION_TIMEOUT = 30


def _container_networks(container_info: dict[str, Any]) -> set[str]:
    """Return Docker network names from one container inspect payload."""

    networks = (
        container_info.get("NetworkSettings", {}).get("Networks")
        if isinstance(container_info, dict)
        else None
    )
    if not isinstance(networks, dict):
        return set()
    return {str(network_name) for network_name in networks if str(network_name)}


def _resolve_realization_networks(
    declared_networks: tuple[str, ...],
    managed_networks: set[str],
    project_name: str,
) -> tuple[set[str], list[str]]:
    """Resolve ACES network names to concrete project Docker network names."""

    desired: set[str] = set()
    missing: list[str] = []
    for declared in declared_networks:
        match = _match_managed_network(declared, managed_networks, project_name)
        if match is None:
            missing.append(declared)
        else:
            desired.add(match)
    return desired, missing


def _match_managed_network(
    declared: str,
    managed_networks: set[str],
    project_name: str,
) -> str | None:
    """Return the managed Docker network matching an ACES declaration."""

    for candidate in _network_name_candidates(declared, project_name):
        if candidate in managed_networks:
            return candidate
    return None


def _network_name_candidates(declared: str, project_name: str) -> tuple[str, ...]:
    """Return likely Compose network names for an ACES network identifier."""

    normalized = _network_token(declared)
    if not normalized:
        return ()
    stems = {normalized}
    if normalized.endswith("-net"):
        stems.add(normalized.removesuffix("-net"))
    if normalized.startswith("aptl-"):
        stems.add(normalized.removeprefix("aptl-"))
    candidates: list[str] = []
    for stem in sorted(stems):
        candidates.extend(
            [
                stem,
                f"aptl-{stem}",
                f"{project_name}_{stem}",
                f"{project_name}_aptl-{stem}",
                f"{project_name}-{stem}",
                f"{project_name}-aptl-{stem}",
            ]
        )
    return tuple(dict.fromkeys(candidates))


def _network_token(raw: str) -> str:
    """Normalize a network identifier for candidate-name generation."""

    return _NETWORK_TOKEN_SEPARATORS.sub("-", raw.strip().lower()).strip("-")


class ComposeRealizationMixin:
    """Realize typed scenario specs through Docker Compose network membership."""

    def realize(
        self,
        realization: DeploymentRealizationSpec,
        *,
        build: bool = True,
    ) -> LabResult:
        """Realize a typed scenario deployment through Docker Compose."""

        profiles = list(realization.profiles)
        start_result = self.start(profiles, build=build)
        if not start_result.success:
            return start_result
        failures = self._reconcile_realization_networks(realization)
        if failures:
            return LabResult(
                success=False,
                error="; ".join(failures[:5]),
            )
        return LabResult(success=True, message="Lab realized")

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
            desired, missing = _resolve_realization_networks(
                node.networks,
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
            failures.extend(
                self._disconnect_extra_networks(node.container_name, current, desired)
            )
            failures.extend(
                self._connect_missing_networks(node.container_name, current, desired)
            )
        return failures

    def _disconnect_extra_networks(
        self,
        container_name: str,
        current: set[str],
        desired: set[str],
    ) -> list[str]:
        """Detach a realized container from project networks outside its spec."""

        return self._change_network_memberships(
            container_name=container_name,
            network_names=current - desired,
            action="disconnect",
            preposition="from",
        )

    def _connect_missing_networks(
        self,
        container_name: str,
        current: set[str],
        desired: set[str],
    ) -> list[str]:
        """Attach a realized container to declared project networks it lacks."""

        return self._change_network_memberships(
            container_name=container_name,
            network_names=desired - current,
            action="connect",
            preposition="to",
        )

    def _change_network_memberships(
        self,
        *,
        container_name: str,
        network_names: set[str],
        action: str,
        preposition: str,
    ) -> list[str]:
        """Run one Docker network membership action across sorted networks."""

        failures: list[str] = []
        for network_name in sorted(network_names):
            result = self._run(
                ["docker", "network", action, network_name, container_name],
                timeout=_REALIZATION_TIMEOUT,
            )
            if result.returncode != 0:
                failures.append(
                    f"Failed to {action} {container_name} "
                    f"{preposition} {network_name}: "
                    f"{result.stderr.strip()}"
                )
        return failures
