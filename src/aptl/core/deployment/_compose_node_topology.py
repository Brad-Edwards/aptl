"""Network attachments, dependencies, and IPAM for generated Compose nodes."""

from __future__ import annotations

import ipaddress

from aptl.core.deployment._compose_realization_networks import _compose_network_key
from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)


def service_networks(
    node: DeploymentNodeRealization, *, aliases: tuple[str, ...] = ()
) -> dict[str, dict[str, object]]:
    """Return the Compose network attachment map for a node."""

    attachments = node.network_attachments or tuple(
        _Attachment(network) for network in node.networks
    )
    networks: dict[str, dict[str, object]] = {}
    for attachment in attachments:
        key = _compose_network_key(attachment.network)
        if not key:
            continue
        options: dict[str, object] = {}
        address = getattr(attachment, "ipv4_address", None)
        if address:
            options["ipv4_address"] = address
        selected_aliases = [alias for alias in aliases if alias != node.service_name]
        if selected_aliases:
            options["aliases"] = selected_aliases
        networks[key] = options
    return networks


def network_namespace_container(node: DeploymentNodeRealization) -> str | None:
    """Return the container whose network namespace this node joins."""

    runtime = node.runtime
    container = getattr(runtime, "container", None) if runtime is not None else None
    namespaces = (
        getattr(container, "namespaces", None) if container is not None else None
    )
    network = getattr(namespaces, "network", None) if namespaces is not None else None
    ref = getattr(network, "target_node_ref", None) if network is not None else None
    if not ref:
        return None
    tail = ref.rsplit(".", 1)[-1]
    return tail if tail.startswith("aptl-") else f"aptl-{tail}"


def service_dependencies(
    node: DeploymentNodeRealization,
    service_names: set[str],
    completion_services: set[str],
) -> list[str] | dict[str, dict[str, str]]:
    """Return ordering dependencies restricted to emitted services."""

    depends: list[str] = []
    for dependency in node.ordering_dependencies:
        name = dependency.rsplit(".", 1)[-1]
        if name in service_names and name != node.service_name and name not in depends:
            depends.append(name)
    if not any(name in completion_services for name in depends):
        return depends
    return {
        name: {
            "condition": (
                "service_completed_successfully"
                if name in completion_services
                else "service_started"
            )
        }
        for name in depends
    }


def pinned_addresses_by_network(
    spec: DeploymentRealizationSpec,
) -> dict[str, set[str]]:
    """Return statically pinned node addresses grouped by network."""

    pinned: dict[str, set[str]] = {}
    for node in spec.nodes:
        for attachment in node.network_attachments:
            if attachment.ipv4_address:
                pinned.setdefault(attachment.network, set()).add(
                    attachment.ipv4_address
                )
    return pinned


def dynamic_ip_range(cidr: str, gateway: str | None, pinned: set[str]) -> str | None:
    """Return an upper-half dynamic pool that cannot consume pinned addresses."""

    if not pinned:
        return None
    subnet = ipaddress.ip_network(cidr, strict=False)
    upper = list(subnet.subnets(prefixlen_diff=1))[1]
    intruders = sorted(
        str(address)
        for address in (*pinned, *((gateway,) if gateway else ()))
        if ipaddress.ip_address(address) in upper
    )
    if intruders:
        raise ValueError(
            f"network {cidr}: pinned/gateway address(es) {', '.join(intruders)} "
            f"fall in the dynamic pool {upper}; the upper-half split no longer "
            "isolates static addresses from dynamic allocation (issue #875)."
        )
    return str(upper)


def render_networks(
    spec: DeploymentRealizationSpec,
) -> dict[str, dict[str, object]]:
    """Return the Compose networks section for the realized networks."""

    pinned_by_network = pinned_addresses_by_network(spec)
    networks: dict[str, dict[str, object]] = {}
    for network in spec.networks:
        key = _compose_network_key(network.name)
        if not key:
            continue
        definition: dict[str, object] = {"driver": "bridge"}
        if network.internal:
            definition["internal"] = True
        ipam_config: dict[str, str] = {}
        if network.cidr:
            ipam_config["subnet"] = network.cidr
            ip_range = dynamic_ip_range(
                network.cidr,
                network.gateway,
                pinned_by_network.get(network.name, set()),
            )
            if ip_range:
                ipam_config["ip_range"] = ip_range
        if network.gateway:
            ipam_config["gateway"] = network.gateway
        if ipam_config:
            definition["ipam"] = {"config": [ipam_config]}
        networks[key] = definition
    return networks


class _Attachment:
    """Minimal network attachment for a node declaring only bare names."""

    __slots__ = ("network", "ipv4_address")

    def __init__(self, network: str) -> None:
        self.network = network
        self.ipv4_address = None


__all__ = (
    "dynamic_ip_range",
    "network_namespace_container",
    "pinned_addresses_by_network",
    "render_networks",
    "service_dependencies",
    "service_networks",
)
