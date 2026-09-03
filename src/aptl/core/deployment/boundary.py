"""Typed, authority-preserving appliance boundary enforcement values."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Literal

from aptl.core.deployment.realization import DeploymentAclRealization

_OWNER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$")
_BRIDGE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$")
_PLATFORM_ZONES = {"participant", "management", "egress"}


@dataclass(frozen=True)
class BoundaryNetwork:
    """One observed backend network used to bind authored references."""

    name: str
    bridge: str
    ipv4_cidr: str | None = None
    ipv6_cidr: str | None = None
    labels: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.name or not _BRIDGE.fullmatch(self.bridge):
            raise ValueError("invalid boundary network")
        for cidr in (self.ipv4_cidr, self.ipv6_cidr):
            if cidr is not None:
                ipaddress.ip_network(cidr, strict=False)
        if list(self.labels) != sorted(self.labels) or len(dict(self.labels)) != len(
            self.labels
        ):
            raise ValueError("boundary network labels must be unique and sorted")

    def details(self) -> dict[str, object]:
        return {
            "name": self.name,
            "bridge": self.bridge,
            "ipv4_cidr": self.ipv4_cidr,
            "ipv6_cidr": self.ipv6_cidr,
            "labels": [list(item) for item in self.labels],
        }


@dataclass(frozen=True)
class AcesAclOwnerBinding:
    """Observed addresses that scope one RAES ACL owner."""

    owner_address: str
    owner_resource_type: Literal["node", "network"]
    ipv4_by_network: tuple[tuple[str, str], ...] = ()
    ipv6_by_network: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.owner_address:
            raise ValueError("ACL owner address is required")
        for network, address in (*self.ipv4_by_network, *self.ipv6_by_network):
            if not network:
                raise ValueError("ACL owner network is required")
            ipaddress.ip_address(address)

    def details(self) -> dict[str, object]:
        return {
            "owner_address": self.owner_address,
            "owner_resource_type": self.owner_resource_type,
            "ipv4_by_network": [list(item) for item in self.ipv4_by_network],
            "ipv6_by_network": [list(item) for item in self.ipv6_by_network],
        }


@dataclass(frozen=True)
class BoundaryWorkload:
    """One observed platform workload and its exact network addresses."""

    identity: str
    labels: tuple[tuple[str, str], ...]
    ipv4_by_network: tuple[tuple[str, str], ...]
    ipv6_by_network: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.identity or list(self.labels) != sorted(self.labels):
            raise ValueError("invalid boundary workload identity")
        if len(dict(self.labels)) != len(self.labels):
            raise ValueError("boundary workload labels must be unique")
        if not self.ipv4_by_network and not self.ipv6_by_network:
            raise ValueError("boundary workload must have an observed address")
        for network, address in (*self.ipv4_by_network, *self.ipv6_by_network):
            if not network:
                raise ValueError("boundary workload network is required")
            ipaddress.ip_address(address)

    def details(self) -> dict[str, object]:
        return {
            "identity": self.identity,
            "labels": [list(item) for item in self.labels],
            "ipv4_by_network": [list(item) for item in self.ipv4_by_network],
            "ipv6_by_network": [list(item) for item in self.ipv6_by_network],
        }


@dataclass(frozen=True)
class AcesBoundarySpec:
    """Concrete enforcement input for the admitted RAES authority only."""

    owner: str
    networks: tuple[BoundaryNetwork, ...]
    owner_bindings: tuple[AcesAclOwnerBinding, ...]
    rules: tuple[DeploymentAclRealization, ...]

    authority: Literal["raes"] = "raes"

    def __post_init__(self) -> None:
        _validate_owner(self.owner)
        _validate_networks(self.networks)
        bindings = {item.owner_address: item for item in self.owner_bindings}
        if len(bindings) != len(self.owner_bindings):
            raise ValueError("ACL owner bindings must be unique")
        known = {network.name for network in self.networks}
        _validate_raes_rules(self.rules, bindings, known)

    @classmethod
    def empty(cls, owner: str) -> AcesBoundarySpec:
        return cls(owner=owner, networks=(), owner_bindings=(), rules=())

    def details(self) -> dict[str, object]:
        return {
            "authority": self.authority,
            "owner": self.owner,
            "networks": [item.details() for item in self.networks],
            "owner_bindings": [item.details() for item in self.owner_bindings],
            "rules": [item.details() for item in self.rules],
        }

    def canonical_json(self) -> str:
        return _canonical(self.details())

    def digest(self) -> str:
        return _digest(self.canonical_json())


@dataclass(frozen=True)
class PlatformCrossing:
    """One compiled transport crossing between platform policy anchors."""

    source: Literal["participant", "management", "egress"]
    destination: Literal["participant", "management", "egress"]
    protocol: Literal["tcp", "udp"]
    ports: tuple[int, ...]
    purpose: str

    def __post_init__(self) -> None:
        if (
            not self.ports
            or len(self.ports) != len(set(self.ports))
            or any(not 0 < port <= 65535 for port in self.ports)
            or not self.purpose
        ):
            raise ValueError("invalid platform crossing")

    def details(self) -> dict[str, object]:
        return {
            "source": self.source,
            "destination": self.destination,
            "protocol": self.protocol,
            "ports": list(self.ports),
            "purpose": self.purpose,
        }


@dataclass(frozen=True)
class PlatformBoundarySpec:
    """Concrete enforcement input for signed platform policy only."""

    owner: str
    policy_digest: str
    networks: tuple[BoundaryNetwork, ...]
    zone_networks: tuple[
        tuple[Literal["participant", "management", "egress"], str],
        ...,
    ]
    anchors: tuple[
        tuple[Literal["participant", "management", "egress"], BoundaryWorkload],
        ...,
    ]
    crossings: tuple[PlatformCrossing, ...]
    egress_ports: tuple[int, ...]
    default_deny: Literal[True] = True
    authority: Literal["platform"] = "platform"

    def __post_init__(self) -> None:
        _validate_owner(self.owner)
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", self.policy_digest):
            raise ValueError("invalid platform policy digest")
        known = _validate_platform_networks(self.networks)
        zone_networks = _validate_zone_networks(self.zone_networks, known)
        _validate_platform_anchors(self.anchors, known, zone_networks)
        _validate_egress_ports(self.egress_ports)

    def details(self) -> dict[str, object]:
        return {
            "authority": self.authority,
            "owner": self.owner,
            "policy_digest": self.policy_digest,
            "networks": [network.details() for network in self.networks],
            "zone_networks": [
                {"zone": zone, "network": network}
                for zone, network in self.zone_networks
            ],
            "anchors": [
                {"zone": zone, "workload": workload.details()}
                for zone, workload in self.anchors
            ],
            "crossings": [item.details() for item in self.crossings],
            "egress_ports": list(self.egress_ports),
            "default_deny": self.default_deny,
        }

    def canonical_json(self) -> str:
        return _canonical(self.details())

    def digest(self) -> str:
        return _digest(self.canonical_json())


BoundaryEnforcementSpec = AcesBoundarySpec | PlatformBoundarySpec


def _validate_owner(owner: str) -> None:
    """Require a bounded project/seat ownership token."""

    if not _OWNER.fullmatch(owner):
        raise ValueError("invalid boundary owner")


def _validate_networks(networks: tuple[BoundaryNetwork, ...]) -> None:
    """Require unique concrete network and bridge identities."""

    names = [network.name for network in networks]
    bridges = [network.bridge for network in networks]
    if len(names) != len(set(names)) or len(bridges) != len(set(bridges)):
        raise ValueError("boundary networks must have unique names and bridges")


def _canonical(details: dict[str, object]) -> str:
    """Serialize enforcement input deterministically for hashing and transport."""

    return json.dumps(details, sort_keys=True, separators=(",", ":"))


def _digest(payload: str) -> str:
    """Return the lowercase SHA-256 identity of canonical policy text."""

    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()


def _validate_raes_rules(
    rules: tuple[DeploymentAclRealization, ...],
    bindings: dict[str, AcesAclOwnerBinding],
    known_networks: set[str],
) -> None:
    """Require exact owner bindings, known endpoints, and deterministic order."""

    prior: tuple[str, int, str] | None = None
    for rule in rules:
        binding = bindings.get(rule.owner_address)
        if binding is None or binding.owner_resource_type != rule.owner_resource_type:
            raise ValueError("ACL rule has no exact owner binding")
        endpoints = (rule.from_network, rule.to_network)
        if any(item is not None and item not in known_networks for item in endpoints):
            raise ValueError("ACL rule references an unknown network")
        current = (rule.owner_address, rule.order, rule.name)
        if prior is not None and current < prior:
            raise ValueError("ACL rules must have deterministic owner order")
        prior = current


def _validate_platform_networks(
    networks: tuple[BoundaryNetwork, ...],
) -> set[str]:
    """Require exactly three distinct IPv4-only platform policy domains."""

    _validate_networks(networks)
    if len(networks) != 3 or any(network.ipv6_cidr is not None for network in networks):
        raise ValueError("platform networks must be three IPv4 policy domains")
    return {network.name for network in networks}


def _validate_zone_networks(
    entries: tuple[
        tuple[Literal["participant", "management", "egress"], str],
        ...,
    ],
    known_networks: set[str],
) -> dict[str, str]:
    """Require an exact one-to-one mapping from zones to platform networks."""

    zone_networks = dict(entries)
    if (
        set(zone_networks) != _PLATFORM_ZONES
        or len(entries) != 3
        or set(zone_networks.values()) != known_networks
    ):
        raise ValueError("platform zone networks must be exact and distinct")
    return zone_networks


def _validate_platform_anchors(
    anchors: tuple[
        tuple[Literal["participant", "management", "egress"], BoundaryWorkload],
        ...,
    ],
    known_networks: set[str],
    zone_networks: dict[str, str],
) -> None:
    """Require one IPv4 anchor per zone on only signed platform networks."""

    zones = [zone for zone, _workload in anchors]
    if set(zones) != _PLATFORM_ZONES or len(zones) != 3:
        raise ValueError("platform anchors must cover each policy zone")
    for zone, workload in anchors:
        attached = (*workload.ipv4_by_network, *workload.ipv6_by_network)
        if any(network not in known_networks for network, _address in attached):
            raise ValueError("platform workload references an unknown network")
        ipv4_networks = {network for network, _address in workload.ipv4_by_network}
        if (
            not ipv4_networks
            or workload.ipv6_by_network
            or zone_networks[zone] not in ipv4_networks
        ):
            raise ValueError("platform workload requires its IPv4 policy attachment")


def _validate_egress_ports(ports: tuple[int, ...]) -> None:
    """Require unique, valid external TCP port numbers."""

    if len(ports) != len(set(ports)) or any(not 0 < port <= 65535 for port in ports):
        raise ValueError("invalid platform egress ports")
