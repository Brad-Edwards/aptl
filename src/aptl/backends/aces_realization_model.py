"""Structured APTL realization data produced from ACES resources."""

from __future__ import annotations

from dataclasses import dataclass

from aces_contracts.diagnostics import Diagnostic

from aptl.core.deployment.realization import (
    DeploymentContentPlacement,
    DeploymentImageRealization,
    DeploymentNetworkAttachment,
    DeploymentNetworkRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)


@dataclass(frozen=True)
class NodeRealization(object):
    """APTL realization data for one ACES node resource."""

    address: str
    name: str
    aliases: tuple[str, ...]
    profiles: tuple[str, ...]
    backend_services: tuple[str, ...]
    container_name: str | None
    services: tuple[str, ...]
    networks: tuple[str, ...]
    static_addresses: tuple[str, ...]
    static_address_assignments: tuple[tuple[str, str], ...] = ()
    declared_health: str | None = None
    image: DeploymentImageRealization | None = None

    def details(self) -> dict[str, object]:
        details: dict[str, object] = {
            "address": self.address,
            "name": self.name,
            "aliases": list(self.aliases),
            "profiles": list(self.profiles),
            "backend_services": list(self.backend_services),
            "container_name": self.container_name,
            "services": list(self.services),
            "networks": list(self.networks),
            "static_addresses": list(self.static_addresses),
            "static_address_assignments": [
                {"network": network, "ipv4_address": address}
                for network, address in self.static_address_assignments
            ],
            "declared_health": self.declared_health,
        }
        if self.image is not None:
            details["image"] = self.image.details()
        return details


@dataclass(frozen=True)
class NetworkRealization(object):
    """APTL realization data for one ACES network resource."""

    address: str
    name: str
    cidr: str | None
    gateway: str | None
    internal: bool | None

    def details(self) -> dict[str, object]:
        return {
            "address": self.address,
            "name": self.name,
            "cidr": self.cidr,
            "gateway": self.gateway,
            "internal": self.internal,
        }


@dataclass(frozen=True)
class PlacementRealization(object):
    """APTL realization data for one node-scoped provisioning binding."""

    address: str
    resource_type: str
    name: str
    target_address: str
    target_node: str | None

    def details(self) -> dict[str, object]:
        return {
            "address": self.address,
            "resource_type": self.resource_type,
            "name": self.name,
            "target_address": self.target_address,
            "target_node": self.target_node,
        }


@dataclass(frozen=True)
class AptlRealization(object):
    """Result of interpreting ACES provisioning content for APTL."""

    profiles: frozenset[str]
    nodes: tuple[NodeRealization, ...]
    networks: tuple[NetworkRealization, ...]
    placements: tuple[PlacementRealization, ...]
    diagnostics: tuple[Diagnostic, ...]
    content_placements: tuple[DeploymentContentPlacement, ...] = ()

    def deployment_spec(self, profiles: list[str]) -> DeploymentRealizationSpec:
        """Return typed backend realization input for this ACES realization."""

        return DeploymentRealizationSpec(
            profiles=tuple(profiles),
            nodes=tuple(
                _deployment_node_realization(node)
                for node in self.nodes
                if node.backend_services or node.container_name
            ),
            networks=tuple(
                DeploymentNetworkRealization(
                    name=network.name,
                    cidr=network.cidr,
                    gateway=network.gateway,
                    internal=network.internal,
                )
                for network in self.networks
            ),
            images=tuple(node.image for node in self.nodes if node.image is not None),
            content=self.content_placements,
        )

    def details(self) -> dict[str, object]:
        resource_counts = {
            "account-placement": sum(
                placement.resource_type == "account-placement"
                for placement in self.placements
            ),
            "content-placement": sum(
                placement.resource_type == "content-placement"
                for placement in self.placements
            ),
            "feature-binding": sum(
                placement.resource_type == "feature-binding"
                for placement in self.placements
            ),
            "network": len(self.networks),
            "node": len(self.nodes),
        }
        return {
            "profiles": sorted(self.profiles),
            "resource_counts": {
                key: value for key, value in sorted(resource_counts.items()) if value
            },
            "nodes": [node.details() for node in self.nodes],
            "networks": [network.details() for network in self.networks],
            "placements": [placement.details() for placement in self.placements],
            "content_placements": [
                content.details() for content in self.content_placements
            ],
        }


def _single_or_none(values: tuple[str, ...]) -> str | None:
    """Return the only value from a tuple, or ``None`` for empty/ambiguous."""

    if len(values) == 1:
        return values[0]
    return None


def _deployment_node_realization(
    node: NodeRealization,
) -> DeploymentNodeRealization:
    """Return backend-facing node input with per-network static IPs."""

    assignments = dict(node.static_address_assignments)
    return DeploymentNodeRealization(
        address=node.address,
        name=node.name,
        service_name=_single_or_none(node.backend_services),
        container_name=node.container_name,
        networks=node.networks,
        network_attachments=tuple(
            DeploymentNetworkAttachment(
                network=network,
                ipv4_address=assignments.get(network),
            )
            for network in node.networks
        ),
    )
