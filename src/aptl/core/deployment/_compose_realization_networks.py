"""Pure network helpers for Docker Compose realization."""

from __future__ import annotations

import re
from typing import Any

from aptl.core.deployment.realization import (
    DeploymentNetworkAttachment,
    DeploymentNetworkRealization,
    DeploymentNodeRealization,
)

_NETWORK_TOKEN_SEPARATORS = re.compile(r"[^a-z0-9]+")
_COMPOSE_PROJECT_LABEL = "com.docker.compose.project"
_COMPOSE_NETWORK_LABEL = "com.docker.compose.network"
_REALIZATION_NETWORK_LABEL = "org.aptl.realization.network"
_REALIZATION_NETWORK_LABEL_VALUE = "true"


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


def _container_network_ip(
    container_info: dict[str, Any],
    network_name: str,
) -> str:
    """Return a container's IPv4 address on one Docker network."""

    networks = (
        container_info.get("NetworkSettings", {}).get("Networks")
        if isinstance(container_info, dict)
        else None
    )
    if not isinstance(networks, dict):
        return ""
    endpoint = networks.get(network_name)
    if not isinstance(endpoint, dict):
        return ""
    address = endpoint.get("IPAddress")
    return address if isinstance(address, str) else ""


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


def _resolve_realization_network_attachments(
    attachments: tuple[DeploymentNetworkAttachment, ...],
    managed_networks: set[str],
    project_name: str,
) -> tuple[dict[str, DeploymentNetworkAttachment], list[str]]:
    """Resolve declared attachments to concrete backend network names."""

    desired: dict[str, DeploymentNetworkAttachment] = {}
    missing: list[str] = []
    for attachment in attachments:
        match = _match_managed_network(
            attachment.network,
            managed_networks,
            project_name,
        )
        if match is None:
            missing.append(attachment.network)
        else:
            desired[match] = attachment
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


def _network_stem(raw: str) -> str:
    """Return the APTL network stem used for concrete backend names."""

    normalized = _network_token(raw)
    if normalized.endswith("-net"):
        normalized = normalized.removesuffix("-net")
    if normalized.startswith("aptl-"):
        normalized = normalized.removeprefix("aptl-")
    return normalized


def _compose_network_key(declared: str) -> str:
    """Return the Compose-style network key for one declared network."""

    stem = _network_stem(declared)
    return f"aptl-{stem}" if stem else ""


def _concrete_network_name(declared: str, project_name: str) -> str:
    """Return the project-scoped Docker network name for a declaration."""

    key = _compose_network_key(declared)
    return f"{project_name}_{key}" if key else ""


def _network_policy_mismatches(
    details: dict[str, Any],
    labels: dict[str, Any],
    network: DeploymentNetworkRealization,
    *,
    project_name: str,
    compose_key: str,
) -> list[str]:
    """Return mismatches between Docker state and typed network intent."""

    mismatches: list[str] = []
    expected_labels = {
        _COMPOSE_PROJECT_LABEL: project_name,
        _COMPOSE_NETWORK_LABEL: compose_key,
        _REALIZATION_NETWORK_LABEL: _REALIZATION_NETWORK_LABEL_VALUE,
    }
    for label, expected in expected_labels.items():
        actual = labels.get(label, "")
        if actual != expected:
            mismatches.append(
                f"label {label} expected {expected!r}, found {actual!r}"
            )
    if network.internal is not None and (
        bool(details.get("internal")) != network.internal
    ):
        mismatches.append(
            "internal expected "
            f"{network.internal!r}, found {bool(details.get('internal'))!r}"
        )
    if network.cidr and details.get("subnet", "") != network.cidr:
        mismatches.append(
            f"subnet expected {network.cidr!r}, found {details.get('subnet', '')!r}"
        )
    if network.gateway and details.get("gateway", "") != network.gateway:
        mismatches.append(
            "gateway expected "
            f"{network.gateway!r}, found {details.get('gateway', '')!r}"
        )
    return mismatches


def _node_network_attachments(
    node: DeploymentNodeRealization,
) -> tuple[DeploymentNetworkAttachment, ...]:
    """Return explicit attachments, falling back to legacy network names."""

    if node.network_attachments:
        return node.network_attachments
    return tuple(
        DeploymentNetworkAttachment(network=network)
        for network in node.networks
    )


def _node_network_aliases(node: DeploymentNodeRealization) -> tuple[str, ...]:
    """Return stable DNS aliases to preserve on manual Docker connects."""

    return tuple(
        dict.fromkeys(
            alias
            for alias in (node.service_name, node.name)
            if alias
        )
    )
