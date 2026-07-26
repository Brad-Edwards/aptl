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
    """Observed addresses that scope one ACES ACL owner."""

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
    """Concrete enforcement input for the admitted ACES authority only."""

    owner: str
    networks: tuple[BoundaryNetwork, ...]
    owner_bindings: tuple[AcesAclOwnerBinding, ...]
    rules: tuple[DeploymentAclRealization, ...]

    authority: Literal["aces"] = "aces"

    def __post_init__(self) -> None:
        _validate_owner(self.owner)
        _validate_networks(self.networks)
        bindings = {item.owner_address: item for item in self.owner_bindings}
        if len(bindings) != len(self.owner_bindings):
            raise ValueError("ACL owner bindings must be unique")
        known = {network.name for network in self.networks}
        prior: tuple[str, int, str] | None = None
        for rule in self.rules:
            binding = bindings.get(rule.owner_address)
            if (
                binding is None
                or binding.owner_resource_type != rule.owner_resource_type
            ):
                raise ValueError("ACL rule has no exact owner binding")
            if (rule.from_network is not None and rule.from_network not in known) or (
                rule.to_network is not None and rule.to_network not in known
            ):
                raise ValueError("ACL rule references an unknown network")
            current = (rule.owner_address, rule.order, rule.name)
            if prior is not None and current < prior:
                raise ValueError("ACL rules must have deterministic owner order")
            prior = current

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
        zones = [zone for zone, _network in self.anchors]
        if set(zones) != _PLATFORM_ZONES or len(zones) != 3:
            raise ValueError("platform anchors must cover each policy zone")
        _validate_networks(self.networks)
        if len(self.networks) != 3 or any(
            network.ipv6_cidr is not None for network in self.networks
        ):
            raise ValueError("platform networks must be three IPv4 policy domains")
        known = {network.name for network in self.networks}
        zone_networks = dict(self.zone_networks)
        if (
            set(zone_networks) != _PLATFORM_ZONES
            or len(self.zone_networks) != 3
            or set(zone_networks.values()) != known
        ):
            raise ValueError("platform zone networks must be exact and distinct")
        for zone, workload in self.anchors:
            if any(
                network not in known
                for network, _address in (
                    *workload.ipv4_by_network,
                    *workload.ipv6_by_network,
                )
            ):
                raise ValueError("platform workload references an unknown network")
            if (
                not workload.ipv4_by_network
                or workload.ipv6_by_network
                or zone_networks[zone]
                not in {network for network, _address in workload.ipv4_by_network}
            ):
                raise ValueError(
                    "platform workload requires its IPv4 policy attachment"
                )
        if len(self.egress_ports) != len(set(self.egress_ports)) or any(
            not 0 < port <= 65535 for port in self.egress_ports
        ):
            raise ValueError("invalid platform egress ports")

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
    if not _OWNER.fullmatch(owner):
        raise ValueError("invalid boundary owner")


def _validate_networks(networks: tuple[BoundaryNetwork, ...]) -> None:
    names = [network.name for network in networks]
    bridges = [network.bridge for network in networks]
    if len(names) != len(set(names)) or len(bridges) != len(set(bridges)):
        raise ValueError("boundary networks must have unique names and bridges")


def _canonical(details: dict[str, object]) -> str:
    return json.dumps(details, sort_keys=True, separators=(",", ":"))


def _digest(payload: str) -> str:
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()
