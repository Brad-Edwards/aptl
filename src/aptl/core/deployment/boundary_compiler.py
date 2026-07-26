"""Bind the two boundary authorities to observed backend identities."""

from __future__ import annotations

from collections.abc import Sequence

from aptl.core.appliance_boundary import ApplianceBoundaryPolicy
from aptl.core.deployment.boundary import (
    AcesAclOwnerBinding,
    AcesBoundarySpec,
    BoundaryNetwork,
    BoundaryWorkload,
    PlatformBoundarySpec,
    PlatformCrossing,
)
from aptl.core.deployment.realization import DeploymentRealizationSpec


class BoundaryCompileError(ValueError):
    """A desired boundary could not be bound without widening it."""


def compile_aces_boundary(
    realization: DeploymentRealizationSpec,
    networks: Sequence[BoundaryNetwork],
    *,
    owner: str,
) -> AcesBoundarySpec:
    """Bind admitted ACES ACLs to concrete networks and owner addresses."""

    if not realization.acls:
        return AcesBoundarySpec.empty(owner)
    if any(network.ipv6_cidr is not None for network in networks):
        raise BoundaryCompileError(
            "ACES ACL networks must remain IPv4-only for this backend"
        )
    network_index = {network.name: network for network in networks}
    missing = sorted(
        {
            reference
            for rule in realization.acls
            for reference in (rule.from_network, rule.to_network)
            if reference is not None and reference not in network_index
        }
    )
    if missing:
        raise BoundaryCompileError("ACES ACL network binding is incomplete")
    nodes = {node.address: node for node in realization.nodes}
    bindings: list[AcesAclOwnerBinding] = []
    for owner_address in sorted({rule.owner_address for rule in realization.acls}):
        rules = [
            rule for rule in realization.acls if rule.owner_address == owner_address
        ]
        first = rules[0]
        if any(
            rule.owner_resource_type != first.owner_resource_type
            or rule.owner_name != first.owner_name
            for rule in rules
        ):
            raise BoundaryCompileError("ACES ACL owner binding is ambiguous")
        if first.owner_resource_type == "network":
            if first.owner_name not in network_index:
                raise BoundaryCompileError("ACES network ACL owner is not observed")
            bindings.append(
                AcesAclOwnerBinding(
                    owner_address=owner_address,
                    owner_resource_type="network",
                )
            )
            continue
        node = nodes.get(owner_address)
        if node is None:
            raise BoundaryCompileError("ACES node ACL owner is not realized")
        addresses = tuple(
            sorted(
                (attachment.network, attachment.ipv4_address)
                for attachment in node.network_attachments
                if attachment.ipv4_address is not None
            )
        )
        required = _required_owner_networks(rules)
        if required - {network for network, _address in addresses}:
            raise BoundaryCompileError(
                "ACES node ACL owner requires exact admitted addresses"
            )
        if not addresses:
            raise BoundaryCompileError(
                "ACES node ACL owner requires at least one exact address"
            )
        bindings.append(
            AcesAclOwnerBinding(
                owner_address=owner_address,
                owner_resource_type="node",
                ipv4_by_network=addresses,
            )
        )
    ordered_rules = tuple(
        sorted(
            realization.acls,
            key=lambda rule: (rule.owner_address, rule.order, rule.name),
        )
    )
    return AcesBoundarySpec(
        owner=owner,
        networks=tuple(sorted(networks, key=lambda item: item.name)),
        owner_bindings=tuple(bindings),
        rules=ordered_rules,
    )


def compile_platform_boundary(
    policy: ApplianceBoundaryPolicy,
    *,
    policy_digest: str,
    networks: Sequence[BoundaryNetwork],
    workloads: Sequence[BoundaryWorkload],
    owner: str,
) -> PlatformBoundarySpec:
    """Resolve exact platform workload selectors without reading ACES topology."""

    selected_networks: dict[str, BoundaryNetwork] = {}
    for zone in ("participant", "management", "egress"):
        selector = getattr(policy.platform_networks, zone)
        key, value = selector.split("=", 1)
        matches = [
            network for network in networks if dict(network.labels).get(key) == value
        ]
        if len(matches) != 1:
            raise BoundaryCompileError("platform network did not resolve exactly once")
        if matches[0].ipv6_cidr is not None:
            raise BoundaryCompileError(
                "platform network IPv6 is unsupported and must remain disabled"
            )
        selected_networks[zone] = matches[0]
    if len({network.name for network in selected_networks.values()}) != 3:
        raise BoundaryCompileError("platform networks must be distinct")

    anchors: list[tuple[str, BoundaryWorkload]] = []
    for zone in ("participant", "management", "egress"):
        selector = getattr(policy.platform_anchors, zone)
        key, value = selector.split("=", 1)
        matches = [
            workload
            for workload in workloads
            if dict(workload.labels).get(key) == value
        ]
        if len(matches) != 1:
            raise BoundaryCompileError(
                "platform boundary anchor did not resolve exactly once"
            )
        network_name = selected_networks[zone].name
        workload = matches[0]
        admitted_networks = {network.name for network in selected_networks.values()}
        ipv4 = tuple(
            item for item in workload.ipv4_by_network if item[0] in admitted_networks
        )
        ipv6 = tuple(
            item for item in workload.ipv6_by_network if item[0] in admitted_networks
        )
        if (
            not ipv4
            or ipv6
            or network_name not in {network for network, _address in ipv4}
        ):
            raise BoundaryCompileError(
                "platform boundary anchor requires its IPv4 policy domain"
            )
        anchors.append(
            (
                zone,
                BoundaryWorkload(
                    identity=workload.identity,
                    labels=workload.labels,
                    ipv4_by_network=ipv4,
                    ipv6_by_network=ipv6,
                ),
            )
        )
    anchor_index = dict(anchors)
    for crossing in policy.fixed_crossings:
        source_networks = {
            network
            for network, _address in anchor_index[crossing.source].ipv4_by_network
        }
        destination_networks = {
            network
            for network, _address in anchor_index[crossing.destination].ipv4_by_network
        }
        if not source_networks & destination_networks:
            raise BoundaryCompileError(
                "platform crossing endpoints have no shared policy path"
            )
    return PlatformBoundarySpec(
        owner=owner,
        policy_digest=policy_digest,
        networks=tuple(sorted(selected_networks.values(), key=lambda item: item.name)),
        zone_networks=tuple(
            (zone, selected_networks[zone].name)
            for zone in ("participant", "management", "egress")
        ),
        anchors=tuple(anchors),  # type: ignore[arg-type]
        crossings=tuple(
            PlatformCrossing(
                source=item.source,
                destination=item.destination,
                protocol=item.protocol,
                ports=tuple(item.ports),
                purpose=item.purpose,
            )
            for item in policy.fixed_crossings
        ),
        egress_ports=tuple(sorted({item.port for item in policy.egress_authorities})),
    )


def _required_owner_networks(rules: Sequence[object]) -> set[str]:
    required: set[str] = set()
    for rule in rules:
        direction = getattr(rule, "direction")
        if direction in {"in", "inout"}:
            destination = getattr(rule, "to_network")
            if destination is not None:
                required.add(destination)
        if direction in {"out", "inout"}:
            source = getattr(rule, "from_network")
            if source is not None:
                required.add(source)
    return required
