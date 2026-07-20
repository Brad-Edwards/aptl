"""Structured APTL realization data produced from ACES resources."""

from __future__ import annotations

from dataclasses import dataclass

from aces_contracts.diagnostics import Diagnostic
from aces_sdl.runtime_configuration import RuntimeConfiguration

from aptl.core.deployment.realization import (
    DeploymentAccountRealization,
    DeploymentContentRealization,
    DeploymentGeneratedArtifactRealization,
    DeploymentImageRealization,
    DeploymentNetworkAttachment,
    DeploymentNetworkRealization,
    DeploymentNodeRealization,
    DeploymentPublishedPort,
    DeploymentPersistentVolumeRealization,
    DeploymentRealizationSpec,
    DeploymentServicePort,
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
    services: tuple[DeploymentServicePort, ...]
    networks: tuple[str, ...]
    static_addresses: tuple[str, ...]
    static_address_assignments: tuple[tuple[str, str], ...] = ()
    published_ports: tuple[DeploymentPublishedPort, ...] = ()
    image: DeploymentImageRealization | None = None
    ordering_dependencies: tuple[str, ...] = ()
    # ADR-047: the declared desired state the generic materializer realizes onto
    # a base substrate. `os`/`os_version` choose the generic base; `runtime`
    # carries the compiled ACES RuntimeConfiguration (packages, identity, service
    # units, ...). None until the node payload declares them.
    os: str = ""
    os_version: str = ""
    runtime: RuntimeConfiguration | None = None

    def service_names(self) -> tuple[str, ...]:
        """Return the declared service names, for profile/alias matching."""

        return tuple(sorted({s.name for s in self.services if s.name}))

    def details(self) -> dict[str, object]:
        details: dict[str, object] = {
            "address": self.address,
            "name": self.name,
            "aliases": list(self.aliases),
            "profiles": list(self.profiles),
            "backend_services": list(self.backend_services),
            "container_name": self.container_name,
            "services": [service.details() for service in self.services],
            "networks": list(self.networks),
            "static_addresses": list(self.static_addresses),
            "static_address_assignments": [
                {"network": network, "ipv4_address": address}
                for network, address in self.static_address_assignments
            ],
            "published_ports": [binding.details() for binding in self.published_ports],
            "ordering_dependencies": list(self.ordering_dependencies),
        }
        if self.os:
            details["os"] = self.os
        if self.os_version:
            details["os_version"] = self.os_version
        if self.runtime is not None:
            details["runtime"] = {
                "packages": len(self.runtime.packages),
                "software_components": len(self.runtime.software_components),
                "local_users": (
                    len(self.runtime.local_identity.users)
                    if self.runtime.local_identity is not None
                    else 0
                ),
                "service_units": len(self.runtime.service_manager_units),
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
    content: DeploymentContentRealization | None = None
    account: DeploymentAccountRealization | None = None

    def details(self) -> dict[str, object]:
        details: dict[str, object] = {
            "address": self.address,
            "resource_type": self.resource_type,
            "name": self.name,
            "target_address": self.target_address,
            "target_node": self.target_node,
        }
        if self.content is not None:
            details["content"] = self.content.details()
        if self.account is not None:
            details["account"] = self.account.details()
        return details


@dataclass(frozen=True)
class AptlRealization(object):
    """Result of interpreting ACES provisioning content for APTL."""

    profiles: frozenset[str]
    nodes: tuple[NodeRealization, ...]
    networks: tuple[NetworkRealization, ...]
    placements: tuple[PlacementRealization, ...]
    diagnostics: tuple[Diagnostic, ...]
    generated_artifacts: tuple[DeploymentGeneratedArtifactRealization, ...] = ()
    persistent_volumes: tuple[DeploymentPersistentVolumeRealization, ...] = ()

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
            content=tuple(
                placement.content
                for placement in self.placements
                if placement.content is not None
            ),
            accounts=tuple(
                placement.account
                for placement in self.placements
                if placement.account is not None
            ),
            generated_artifacts=self.generated_artifacts,
            persistent_volumes=self.persistent_volumes,
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
            "generated-artifact": len(self.generated_artifacts),
            "persistent-volume": len(self.persistent_volumes),
        }
        return {
            "profiles": sorted(self.profiles),
            "resource_counts": {
                key: value for key, value in sorted(resource_counts.items()) if value
            },
            "nodes": [node.details() for node in self.nodes],
            "networks": [network.details() for network in self.networks],
            "placements": [placement.details() for placement in self.placements],
            "generated_artifacts": [
                artifact.details() for artifact in self.generated_artifacts
            ],
            "persistent_volumes": [
                volume.details() for volume in self.persistent_volumes
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
        services=node.services,
        published_ports=node.published_ports,
        ordering_dependencies=node.ordering_dependencies,
    )
