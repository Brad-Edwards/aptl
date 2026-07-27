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


def compile_raes_boundary(
    realization: DeploymentRealizationSpec,
    networks: Sequence[BoundaryNetwork],
    *,
    owner: str,
) -> AcesBoundarySpec:
    """Bind admitted RAES ACLs to concrete networks and owner addresses."""

    if not realization.acls:
        return AcesBoundarySpec.empty(owner)
    network_index = _validate_raes_networks(realization, networks)
    nodes = {node.address: node for node in realization.nodes}
    bindings: list[AcesAclOwnerBinding] = []
    for owner_address in sorted({rule.owner_address for rule in realization.acls}):
        rules = [
            rule for rule in realization.acls if rule.owner_address == owner_address
        ]
        bindings.append(
            _compile_owner_binding(
                owner_address,
                rules,
                nodes,
                network_index,
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
    """Resolve exact platform workload selectors without reading RAES topology."""

    selected_networks = _select_platform_networks(policy, networks)
    anchors = _select_platform_anchors(policy, workloads, selected_networks)
    _validate_crossing_paths(policy, anchors)
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
    """Return the owner attachment networks needed by directional ACL rules."""

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


def _validate_raes_networks(
    realization: DeploymentRealizationSpec,
    networks: Sequence[BoundaryNetwork],
) -> dict[str, BoundaryNetwork]:
    """Require IPv4-only observations for every referenced RAES network."""

    if any(network.ipv6_cidr is not None for network in networks):
        raise BoundaryCompileError(
            "RAES ACL networks must remain IPv4-only for this backend"
        )
    network_index = {network.name: network for network in networks}
    missing = {
        reference
        for rule in realization.acls
        for reference in (rule.from_network, rule.to_network)
        if reference is not None and reference not in network_index
    }
    if missing:
        raise BoundaryCompileError("RAES ACL network binding is incomplete")
    return network_index


def _compile_owner_binding(
    owner_address: str,
    rules: Sequence[object],
    nodes: dict[str, object],
    network_index: dict[str, BoundaryNetwork],
) -> AcesAclOwnerBinding:
    """Compile one unambiguous RAES node or network owner binding."""

    first = rules[0]
    owner_type = getattr(first, "owner_resource_type")
    owner_name = getattr(first, "owner_name")
    if any(
        getattr(rule, "owner_resource_type") != owner_type
        or getattr(rule, "owner_name") != owner_name
        for rule in rules
    ):
        raise BoundaryCompileError("RAES ACL owner binding is ambiguous")
    if owner_type == "network":
        if owner_name not in network_index:
            raise BoundaryCompileError("RAES network ACL owner is not observed")
        return AcesAclOwnerBinding(
            owner_address=owner_address,
            owner_resource_type="network",
        )
    node = nodes.get(owner_address)
    if node is None:
        raise BoundaryCompileError("RAES node ACL owner is not realized")
    attachments = getattr(node, "network_attachments")
    addresses = tuple(
        sorted(
            (attachment.network, attachment.ipv4_address)
            for attachment in attachments
            if attachment.ipv4_address is not None
        )
    )
    required = _required_owner_networks(rules)
    if required - {network for network, _address in addresses}:
        raise BoundaryCompileError(
            "RAES node ACL owner requires exact admitted addresses"
        )
    if not addresses:
        raise BoundaryCompileError(
            "RAES node ACL owner requires at least one exact address"
        )
    return AcesAclOwnerBinding(
        owner_address=owner_address,
        owner_resource_type="node",
        ipv4_by_network=addresses,
    )


def _select_platform_networks(
    policy: ApplianceBoundaryPolicy,
    networks: Sequence[BoundaryNetwork],
) -> dict[str, BoundaryNetwork]:
    """Resolve one distinct IPv4 network for each exact signed selector."""

    selected: dict[str, BoundaryNetwork] = {}
    for zone in ("participant", "management", "egress"):
        key, value = getattr(policy.platform_networks, zone).split("=", 1)
        matches = [
            network for network in networks if dict(network.labels).get(key) == value
        ]
        if len(matches) != 1:
            raise BoundaryCompileError("platform network did not resolve exactly once")
        if matches[0].ipv6_cidr is not None:
            raise BoundaryCompileError(
                "platform network IPv6 is unsupported and must remain disabled"
            )
        selected[zone] = matches[0]
    if len({network.name for network in selected.values()}) != 3:
        raise BoundaryCompileError("platform networks must be distinct")
    return selected


def _select_platform_anchors(
    policy: ApplianceBoundaryPolicy,
    workloads: Sequence[BoundaryWorkload],
    selected_networks: dict[str, BoundaryNetwork],
) -> list[tuple[str, BoundaryWorkload]]:
    """Resolve one exact workload anchor per platform zone."""

    admitted = {network.name for network in selected_networks.values()}
    anchors: list[tuple[str, BoundaryWorkload]] = []
    for zone in ("participant", "management", "egress"):
        key, value = getattr(policy.platform_anchors, zone).split("=", 1)
        matches = [
            workload
            for workload in workloads
            if dict(workload.labels).get(key) == value
        ]
        if len(matches) != 1:
            raise BoundaryCompileError(
                "platform boundary anchor did not resolve exactly once"
            )
        anchors.append(
            (
                zone,
                _scope_platform_anchor(matches[0], selected_networks[zone], admitted),
            )
        )
    return anchors


def _scope_platform_anchor(
    workload: BoundaryWorkload,
    zone_network: BoundaryNetwork,
    admitted_networks: set[str],
) -> BoundaryWorkload:
    """Restrict one anchor observation to signed platform networks."""

    ipv4 = tuple(
        item for item in workload.ipv4_by_network if item[0] in admitted_networks
    )
    ipv6 = tuple(
        item for item in workload.ipv6_by_network if item[0] in admitted_networks
    )
    if (
        not ipv4
        or ipv6
        or zone_network.name not in {network for network, _address in ipv4}
    ):
        raise BoundaryCompileError(
            "platform boundary anchor requires its IPv4 policy domain"
        )
    return BoundaryWorkload(
        identity=workload.identity,
        labels=workload.labels,
        ipv4_by_network=ipv4,
        ipv6_by_network=ipv6,
    )


def _validate_crossing_paths(
    policy: ApplianceBoundaryPolicy,
    anchors: Sequence[tuple[str, BoundaryWorkload]],
) -> None:
    """Require every fixed crossing to share an observed platform path."""

    anchor_index = dict(anchors)
    for crossing in policy.fixed_crossings:
        source = {
            network
            for network, _address in anchor_index[crossing.source].ipv4_by_network
        }
        destination = {
            network
            for network, _address in anchor_index[crossing.destination].ipv4_by_network
        }
        if not source & destination:
            raise BoundaryCompileError(
                "platform crossing endpoints have no shared policy path"
            )
