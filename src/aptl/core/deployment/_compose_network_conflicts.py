"""Docker network subnet conflict helpers."""

from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Any

from aptl.core.deployment._compose_realization_networks import (
    _match_managed_network,
)
from aptl.core.deployment.realization import (
    DeploymentNetworkRealization,
    DeploymentRealizationSpec,
)

_ParsedNetwork = IPv4Network | IPv6Network


def _parse_subnet(value: object) -> _ParsedNetwork | None:
    """Return a parsed CIDR network, or ``None`` for missing/invalid input."""

    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def _subnet_conflict_message(
    network: DeploymentNetworkRealization,
    details: dict[str, Any],
    existing_subnet: _ParsedNetwork,
) -> str:
    """Build an actionable overlap error for a planned Docker network."""

    docker_name = str(details.get("name") or "unknown")
    containers = details.get("containers")
    container_note = ""
    if isinstance(containers, list):
        names = ", ".join(str(name) for name in containers if name)
        if names:
            container_note = (
                f" Stop/remove attached container(s) first: {names}."
            )
    return (
        f"APTL cannot create realized network {network.name} ({network.cidr}) "
        f"because Docker network {docker_name} already uses {existing_subnet}."
        f"{container_note} Remove that network with "
        f"`docker network rm {docker_name}` after confirming it is stale, "
        "or configure non-overlapping APTL subnets, then rerun "
        "`aptl lab start`."
    )


def _needs_network_creation(
    network: DeploymentNetworkRealization,
    managed_networks: set[str],
    project_name: str,
) -> bool:
    """Return whether a realized network has to be created."""

    if not network.cidr:
        return False
    return _match_managed_network(
        network.name,
        managed_networks,
        project_name,
    ) is None


def _planned_networks_to_create(
    realization: DeploymentRealizationSpec,
    managed_networks: set[str],
    project_name: str,
) -> list[DeploymentNetworkRealization]:
    """Return declared CIDR networks missing from the managed network set."""

    return [
        network
        for network in realization.networks
        if _needs_network_creation(network, managed_networks, project_name)
    ]


def _subnets_overlap(
    planned_subnet: _ParsedNetwork,
    existing_subnet: _ParsedNetwork,
) -> bool:
    """Return whether two parsed Docker subnets overlap."""

    return (
        planned_subnet.version == existing_subnet.version
        and planned_subnet.overlaps(existing_subnet)
    )


def _network_subnet_conflicts(
    network: DeploymentNetworkRealization,
    existing_networks: list[dict[str, Any]],
) -> list[str]:
    """Return overlap errors for one planned realized network."""

    planned_subnet = _parse_subnet(network.cidr)
    if planned_subnet is None:
        return []
    return [
        _subnet_conflict_message(network, details, existing_subnet)
        for details in existing_networks
        if (existing_subnet := _parse_subnet(details.get("subnet"))) is not None
        and _subnets_overlap(planned_subnet, existing_subnet)
    ]
