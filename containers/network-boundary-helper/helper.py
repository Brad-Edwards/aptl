#!/usr/bin/env python3
"""Closed nftables apply/observe/cleanup helper for one boundary authority."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence

_TOKEN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,159}$")
_BRIDGE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_ACTIONS = frozenset({"allow", "deny"})
_PROTOCOLS = frozenset({"any", "tcp", "udp", "icmp"})
_DIRECTIONS = frozenset({"in", "out", "inout"})
_ZONES = frozenset({"participant", "management", "egress"})


def _canonical(policy: Mapping[str, object]) -> str:
    return json.dumps(policy, sort_keys=True, separators=(",", ":"))


def _digest(policy: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(policy).encode()).hexdigest()


def _table_name(owner: str, authority: str) -> str:
    suffix = hashlib.sha256(f"{owner}:{authority}".encode()).hexdigest()[:12]
    return f"aptl_bnd_{suffix}"


def _owner_marker(owner: str) -> str:
    return hashlib.sha256(owner.encode()).hexdigest()[:16]


def _rule_marker(identity: str) -> str:
    return "aptl-rule=" + hashlib.sha256(identity.encode()).hexdigest()[:24]


def _quoted(value: str) -> str:
    return json.dumps(value)


def validate_policy(policy: object) -> dict[str, object]:
    """Validate one closed authority payload before rendering native syntax."""

    if not isinstance(policy, dict):
        raise ValueError("policy must be an object")
    authority = policy.get("authority")
    if authority == "raes":
        return _validate_raes(policy)
    if authority == "platform":
        return _validate_platform(policy)
    raise ValueError("policy authority is invalid")


def _validate_common(policy: Mapping[str, object], fields: set[str]) -> None:
    if set(policy) != fields:
        raise ValueError("policy fields are invalid")
    owner = policy.get("owner")
    if not isinstance(owner, str) or not _TOKEN.fullmatch(owner):
        raise ValueError("owner is invalid")


def _validate_network(network: object) -> dict[str, object]:
    fields = {"name", "bridge", "ipv4_cidr", "ipv6_cidr", "labels"}
    if not isinstance(network, dict) or set(network) != fields:
        raise ValueError("network is invalid")
    name = network["name"]
    bridge = network["bridge"]
    labels = network["labels"]
    if (
        not isinstance(name, str)
        or not _TOKEN.fullmatch(name)
        or not isinstance(bridge, str)
        or not _BRIDGE.fullmatch(bridge)
        or not isinstance(labels, list)
    ):
        raise ValueError("network identity is invalid")
    for key, version in (("ipv4_cidr", 4), ("ipv6_cidr", 6)):
        value = network[key]
        if value is not None:
            if not isinstance(value, str):
                raise ValueError("network CIDR is invalid")
            if ipaddress.ip_network(value, strict=False).version != version:
                raise ValueError("network CIDR family is invalid")
    _validate_labels(labels)
    return network


def _validate_labels(labels: object) -> None:
    if (
        not isinstance(labels, list)
        or any(
            not isinstance(item, list)
            or len(item) != 2
            or not all(isinstance(value, str) for value in item)
            for item in labels
        )
        or labels != sorted(labels)
        or len({item[0] for item in labels}) != len(labels)
    ):
        raise ValueError("network labels are invalid")


def _validate_raes(policy: dict[str, object]) -> dict[str, object]:
    _validate_common(
        policy,
        {"authority", "owner", "networks", "owner_bindings", "rules"},
    )
    networks = policy["networks"]
    bindings = policy["owner_bindings"]
    rules = policy["rules"]
    if not all(isinstance(value, list) for value in (networks, bindings, rules)):
        raise ValueError("RAES policy collections must be lists")
    network_index = _validated_network_index(networks, authority="RAES")
    if any(network["ipv6_cidr"] is not None for network in network_index.values()):
        raise ValueError("RAES ACL networks must remain IPv4-only")
    binding_index: dict[str, dict[str, object]] = {}
    for binding in bindings:
        _validate_raes_binding(binding, network_index, binding_index)
    prior: tuple[str, int, str] | None = None
    seen_orders: set[tuple[str, int]] = set()
    seen_names: set[tuple[str, str]] = set()
    for rule in rules:
        current = _validate_raes_rule(
            rule,
            binding_index,
            network_index,
            seen_orders,
            seen_names,
        )
        if prior is not None and current < prior:
            raise ValueError("RAES rules are not deterministically ordered")
        prior = current
    return policy


def _validated_network_index(
    networks: Sequence[object],
    *,
    authority: str,
) -> dict[str, dict[str, object]]:
    index: dict[str, dict[str, object]] = {}
    for network in networks:
        validated = _validate_network(network)
        name = str(validated["name"])
        if name in index:
            raise ValueError(f"{authority} network identities must be unique")
        index[name] = validated
    return index


def _validate_address_pairs(
    pairs: object,
    family_key: str,
    version: int,
    networks: Mapping[str, Mapping[str, object]],
) -> None:
    if not isinstance(pairs, list):
        raise ValueError("boundary owner addresses are invalid")
    seen_networks: set[str] = set()
    for pair in pairs:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or not isinstance(pair[0], str)
            or pair[0] not in networks
            or not isinstance(pair[1], str)
            or pair[0] in seen_networks
        ):
            raise ValueError("boundary owner address is invalid")
        parsed = ipaddress.ip_address(pair[1])
        cidr = networks[pair[0]][family_key.replace("_by_network", "_cidr")]
        if (
            parsed.version != version
            or not isinstance(cidr, str)
            or parsed not in ipaddress.ip_network(cidr, strict=False)
        ):
            raise ValueError("boundary owner address is outside its network")
        seen_networks.add(pair[0])


def _validate_raes_binding(
    binding: object,
    networks: Mapping[str, Mapping[str, object]],
    index: dict[str, dict[str, object]],
) -> None:
    if not isinstance(binding, dict) or set(binding) != {
        "owner_address",
        "owner_resource_type",
        "ipv4_by_network",
        "ipv6_by_network",
    }:
        raise ValueError("RAES owner binding is invalid")
    owner = binding["owner_address"]
    kind = binding["owner_resource_type"]
    if (
        not isinstance(owner, str)
        or not _TOKEN.fullmatch(owner)
        or not isinstance(kind, str)
        or kind not in {"node", "network"}
        or owner in index
    ):
        raise ValueError("RAES owner identity is invalid")
    _validate_address_pairs(binding["ipv4_by_network"], "ipv4_by_network", 4, networks)
    _validate_address_pairs(binding["ipv6_by_network"], "ipv6_by_network", 6, networks)
    if binding["ipv6_by_network"]:
        raise ValueError("RAES ACL owner addresses must remain IPv4-only")
    if kind == "node" and not (
        binding["ipv4_by_network"] or binding["ipv6_by_network"]
    ):
        raise ValueError("RAES node owner has no exact address")
    index[owner] = binding


def _validate_raes_rule(
    rule: object,
    bindings: Mapping[str, Mapping[str, object]],
    networks: Mapping[str, Mapping[str, object]],
    seen_orders: set[tuple[str, int]],
    seen_names: set[tuple[str, str]],
) -> tuple[str, int, str]:
    fields = {
        "owner_address",
        "owner_resource_type",
        "owner_name",
        "name",
        "order",
        "direction",
        "from_network",
        "to_network",
        "protocol",
        "ports",
        "action",
    }
    if not isinstance(rule, dict) or set(rule) != fields:
        raise ValueError("RAES rule is invalid")
    owner = rule["owner_address"]
    binding = bindings.get(owner) if isinstance(owner, str) else None
    if binding is None or binding["owner_resource_type"] != rule["owner_resource_type"]:
        raise ValueError("RAES rule owner is invalid")
    _validate_raes_rule_semantics(rule, binding, networks)
    identity = str(rule["name"])
    order = int(rule["order"])
    order_key = (owner, order)
    name_key = (owner, identity)
    if order_key in seen_orders or name_key in seen_names:
        raise ValueError("RAES rule identity is not unique")
    seen_orders.add(order_key)
    seen_names.add(name_key)
    return owner, order, identity


def _validate_raes_rule_semantics(
    rule: Mapping[str, object],
    binding: Mapping[str, object],
    networks: Mapping[str, Mapping[str, object]],
) -> None:
    direction = rule["direction"]
    protocol = rule["protocol"]
    action = rule["action"]
    owner_name = rule["owner_name"]
    identity = rule["name"]
    order = rule["order"]
    if not isinstance(direction, str) or direction not in _DIRECTIONS:
        raise ValueError("RAES rule direction is invalid")
    if (
        not isinstance(protocol, str)
        or protocol not in _PROTOCOLS
        or not isinstance(action, str)
        or action not in _ACTIONS
    ):
        raise ValueError("RAES rule semantics are invalid")
    if any(
        rule[endpoint] is not None
        and (not isinstance(rule[endpoint], str) or rule[endpoint] not in networks)
        for endpoint in ("from_network", "to_network")
    ):
        raise ValueError("RAES rule endpoint is invalid")
    _validate_ports(rule["ports"], protocol)
    if (
        not isinstance(identity, str)
        or not _TOKEN.fullmatch(identity)
        or not isinstance(owner_name, str)
        or not _TOKEN.fullmatch(owner_name)
        or not isinstance(order, int)
        or isinstance(order, bool)
        or order < 0
    ):
        raise ValueError("RAES rule ordering is invalid")
    if binding["owner_resource_type"] == "network" and owner_name not in networks:
        raise ValueError("RAES network owner is unresolved")


def _validate_platform(policy: dict[str, object]) -> dict[str, object]:
    _validate_common(
        policy,
        {
            "authority",
            "owner",
            "policy_digest",
            "networks",
            "zone_networks",
            "anchors",
            "crossings",
            "egress_ports",
            "default_deny",
        },
    )
    if not isinstance(policy["policy_digest"], str) or not _DIGEST.fullmatch(
        policy["policy_digest"]
    ):
        raise ValueError("platform policy digest is invalid")
    if policy["default_deny"] is not True:
        raise ValueError("platform policy must be default deny")
    anchors = policy["anchors"]
    zone_networks = policy["zone_networks"]
    crossings = policy["crossings"]
    networks = policy["networks"]
    egress_ports = policy["egress_ports"]
    if (
        not isinstance(anchors, list)
        or not isinstance(zone_networks, list)
        or not isinstance(crossings, list)
        or not isinstance(networks, list)
    ):
        raise ValueError("platform policy collections must be lists")
    network_index = _validated_platform_networks(networks)
    _validate_ports(egress_ports, "tcp")
    zone_network_index = _validated_zone_networks(zone_networks, network_index)
    zones: set[str] = set()
    for anchor in anchors:
        zones.add(
            _validate_platform_anchor(
                anchor,
                networks=network_index,
                zone_networks=zone_network_index,
                seen=zones,
            )
        )
    if zones != _ZONES:
        raise ValueError("platform zones are incomplete")
    for crossing in crossings:
        _validate_platform_crossing(crossing, zones)
    return policy


def _validated_platform_networks(
    networks: Sequence[object],
) -> dict[str, dict[str, object]]:
    index = _validated_network_index(networks, authority="platform")
    if len(index) != 3 or any(
        network["ipv6_cidr"] is not None for network in index.values()
    ):
        raise ValueError("platform requires three IPv4-only networks")
    return index


def _validated_zone_networks(
    values: Sequence[object],
    networks: Mapping[str, object],
) -> dict[str, str]:
    index: dict[str, str] = {}
    for item in values:
        if not isinstance(item, dict) or set(item) != {"zone", "network"}:
            raise ValueError("platform zone network is invalid")
        zone = item["zone"]
        network = item["network"]
        if (
            not isinstance(zone, str)
            or not isinstance(network, str)
            or zone not in _ZONES
            or zone in index
            or network not in networks
        ):
            raise ValueError("platform zone network is invalid")
        index[zone] = network
    if set(index) != _ZONES or set(index.values()) != set(networks):
        raise ValueError("platform zone networks must be exact and distinct")
    return index


def _validate_platform_anchor(
    anchor: object,
    *,
    networks: Mapping[str, Mapping[str, object]],
    zone_networks: Mapping[str, str],
    seen: set[str],
) -> str:
    if not isinstance(anchor, dict) or set(anchor) != {"zone", "workload"}:
        raise ValueError("platform anchor is invalid")
    zone = anchor["zone"]
    if not isinstance(zone, str) or zone not in _ZONES or zone in seen:
        raise ValueError("platform anchor is invalid")
    workload = anchor["workload"]
    fields = {"identity", "labels", "ipv4_by_network", "ipv6_by_network"}
    if not isinstance(workload, dict) or set(workload) != fields:
        raise ValueError("platform workload is invalid")
    _validate_labels(workload["labels"])
    identity = workload["identity"]
    if not isinstance(identity, str) or not _TOKEN.fullmatch(identity):
        raise ValueError("platform workload identity is invalid")
    ipv4 = workload["ipv4_by_network"]
    if not isinstance(ipv4, list) or not ipv4 or workload["ipv6_by_network"] != []:
        raise ValueError("platform workload must have an IPv4 attachment")
    _validate_address_pairs(ipv4, "ipv4_by_network", 4, networks)
    _validate_address_pairs(workload["ipv6_by_network"], "ipv6_by_network", 6, networks)
    attached = {
        str(pair[0]) for pair in ipv4 if isinstance(pair, list) and len(pair) == 2
    }
    if zone_networks[zone] not in attached:
        raise ValueError("platform anchor is absent from its policy network")
    return zone


def _validate_platform_crossing(
    crossing: object,
    zones: set[str],
) -> None:
    fields = {"source", "destination", "protocol", "ports", "purpose"}
    if not isinstance(crossing, dict) or set(crossing) != fields:
        raise ValueError("platform crossing is invalid")
    source = crossing["source"]
    destination = crossing["destination"]
    protocol = crossing["protocol"]
    purpose = crossing["purpose"]
    if (
        not isinstance(source, str)
        or not isinstance(destination, str)
        or not isinstance(protocol, str)
        or source not in zones
        or destination not in zones
        or protocol not in {"tcp", "udp"}
        or not isinstance(purpose, str)
        or not purpose
    ):
        raise ValueError("platform crossing semantics are invalid")
    _validate_ports(crossing["ports"], protocol, required=True)


def _validate_ports(value: object, protocol: str, *, required: bool = False) -> None:
    if (
        not isinstance(value, list)
        or (required and not value)
        or any(
            not isinstance(port, int) or isinstance(port, bool) or not 0 < port <= 65535
            for port in value
        )
        or (value and protocol not in {"tcp", "udp"})
    ):
        raise ValueError("ports are invalid")


def _network_index(policy: Mapping[str, object]) -> dict[str, dict[str, object]]:
    networks = policy["networks"]
    assert isinstance(networks, list)
    return {
        str(network["name"]): network
        for network in networks
        if isinstance(network, dict)
    }


def _transport(rule: Mapping[str, object]) -> str:
    protocol = str(rule["protocol"])
    if protocol in {"tcp", "udp"}:
        ports = rule["ports"]
        suffix = ""
        if isinstance(ports, list) and ports:
            rendered = (
                str(ports[0])
                if len(ports) == 1
                else "{ " + ", ".join(str(port) for port in ports) + " }"
            )
            suffix = f" dport {rendered}"
        return f"{protocol}{suffix}"
    if protocol == "icmp":
        return "meta l4proto icmp"
    return ""


def _interface_expression(
    source: str | None,
    destination: str | None,
    networks: Mapping[str, Mapping[str, object]],
    *,
    family: str,
) -> list[str]:
    parts: list[str] = []
    ingress = "ibrname" if family == "bridge" else "iifname"
    egress = "obrname" if family == "bridge" else "oifname"
    if source is not None:
        parts.extend([ingress, _quoted(str(networks[source]["bridge"]))])
    if destination is not None:
        parts.extend([egress, _quoted(str(networks[destination]["bridge"]))])
    return parts


def _address_expression(
    source: str | None,
    destination: str | None,
    networks: Mapping[str, Mapping[str, object]],
) -> list[str]:
    parts: list[str] = []
    for reference, direction in ((source, "saddr"), (destination, "daddr")):
        if reference is None:
            continue
        network = networks[reference]
        cidr = network.get("ipv4_cidr")
        if isinstance(cidr, str):
            parts.extend(["ip", direction, cidr])
    return parts


def _binding_addresses(binding: Mapping[str, object], network: str | None) -> list[str]:
    pairs = binding["ipv4_by_network"]
    assert isinstance(pairs, list)
    return [
        str(pair[1])
        for pair in pairs
        if isinstance(pair, list) and (network is None or pair[0] == network)
    ]


def _raes_rule_expressions(
    policy: Mapping[str, object],
    rule: Mapping[str, object],
    *,
    family: str,
) -> list[str]:
    networks = _network_index(policy)
    bindings = policy["owner_bindings"]
    assert isinstance(bindings, list)
    binding = next(
        item
        for item in bindings
        if isinstance(item, dict) and item["owner_address"] == rule["owner_address"]
    )
    directions = (
        ("in", "out") if rule["direction"] == "inout" else (str(rule["direction"]),)
    )
    expressions: list[str] = []
    for direction in directions:
        source = rule["from_network"]
        destination = rule["to_network"]
        source_ref = source if isinstance(source, str) else None
        destination_ref = destination if isinstance(destination, str) else None
        parts = _interface_expression(
            source_ref, destination_ref, networks, family=family
        )
        if family == "inet":
            parts.extend(_address_expression(source_ref, destination_ref, networks))
        if binding["owner_resource_type"] == "network":
            owner_name = str(rule["owner_name"])
            if direction == "in":
                parts.extend(
                    _interface_expression(None, owner_name, networks, family=family)
                )
            else:
                parts.extend(
                    _interface_expression(owner_name, None, networks, family=family)
                )
        else:
            owner_network = destination_ref if direction == "in" else source_ref
            addresses = _binding_addresses(binding, owner_network)
            if not addresses:
                raise ValueError("node ACL owner has no exact address")
            rendered = (
                addresses[0]
                if len(addresses) == 1
                else "{ " + ", ".join(addresses) + " }"
            )
            parts.extend(["ip", "daddr" if direction == "in" else "saddr", rendered])
        transport = _transport(rule)
        if transport:
            parts.append(transport)
        parts.append("return" if rule["action"] == "allow" else "drop")
        identity = f"{rule['owner_address']}/{rule['name']}/{direction}"
        parts.extend(["comment", _quoted(_rule_marker(identity))])
        expressions.append("    " + " ".join(parts))
    return expressions


def _raes_table(
    policy: Mapping[str, object], family: str, table_name: str
) -> list[str]:
    owner = str(policy["owner"])
    digest = _digest(policy)
    bindings = policy["owner_bindings"]
    rules = policy["rules"]
    assert isinstance(bindings, list)
    assert isinstance(rules, list)
    lines = [
        f"table {family} {table_name} {{",
        (
            "  comment "
            + _quoted(
                f"aptl-owner={_owner_marker(owner)},authority=raes,digest={digest}"
            )
        ),
    ]
    chain_by_owner: dict[str, str] = {}
    for binding in bindings:
        if not isinstance(binding, Mapping):
            continue
        owner_address = str(binding["owner_address"])
        chain = "owner_" + hashlib.sha256(owner_address.encode()).hexdigest()[:12]
        chain_by_owner[owner_address] = chain
        lines.append(f"  chain {chain} {{")
        for rule in rules:
            if isinstance(rule, Mapping) and rule["owner_address"] == owner_address:
                lines.extend(_raes_rule_expressions(policy, rule, family=family))
        lines.extend(
            [
                (
                    "    return comment "
                    + _quoted(_rule_marker(f"{owner_address}/default"))
                ),
                "  }",
            ]
        )
    lines.extend(
        [
            "  chain forward {",
            "    type filter hook forward priority -200; policy accept;",
        ]
    )
    networks = _network_index(policy)
    for binding in bindings:
        if not isinstance(binding, Mapping):
            continue
        owner_address = str(binding["owner_address"])
        chain = chain_by_owner[owner_address]
        if binding["owner_resource_type"] == "node":
            addresses = _binding_addresses(binding, None)
            rendered = (
                addresses[0]
                if len(addresses) == 1
                else "{ " + ", ".join(addresses) + " }"
            )
            lines.append(
                f"    ip daddr {rendered} jump {chain} comment "
                + _quoted(_rule_marker(f"{owner_address}/dispatch/in"))
            )
            lines.append(
                f"    ip saddr {rendered} jump {chain} comment "
                + _quoted(_rule_marker(f"{owner_address}/dispatch/out"))
            )
        else:
            owner_rules = [
                rule
                for rule in rules
                if isinstance(rule, Mapping) and rule["owner_address"] == owner_address
            ]
            owner_names = {str(rule["owner_name"]) for rule in owner_rules}
            for owner_name in sorted(owner_names):
                bridge = str(networks[owner_name]["bridge"])
                ingress = "ibrname" if family == "bridge" else "iifname"
                egress = "obrname" if family == "bridge" else "oifname"
                lines.append(
                    f"    {egress} {_quoted(bridge)} jump {chain} comment "
                    + _quoted(_rule_marker(f"{owner_address}/dispatch/in"))
                )
                lines.append(
                    f"    {ingress} {_quoted(bridge)} jump {chain} comment "
                    + _quoted(_rule_marker(f"{owner_address}/dispatch/out"))
                )
    lines.extend(["  }", "}"])
    return lines


def _platform_index(
    policy: Mapping[str, object],
) -> dict[str, Mapping[str, object]]:
    anchors = policy["anchors"]
    assert isinstance(anchors, list)
    return {
        str(anchor["zone"]): anchor["workload"]
        for anchor in anchors
        if isinstance(anchor, dict) and isinstance(anchor["workload"], dict)
    }


def _workload_ipv4(workload: Mapping[str, object]) -> dict[str, str]:
    pairs = workload["ipv4_by_network"]
    assert isinstance(pairs, list)
    return {
        str(pair[0]): str(pair[1])
        for pair in pairs
        if isinstance(pair, list) and len(pair) == 2
    }


def _platform_table(
    policy: Mapping[str, object], family: str, table_name: str
) -> list[str]:
    owner = str(policy["owner"])
    digest = _digest(policy)
    anchors = _platform_index(policy)
    networks = _network_index(policy)
    lines = [
        f"table {family} {table_name} {{",
        (
            "  comment "
            + _quoted(
                f"aptl-owner={_owner_marker(owner)},authority=platform,digest={digest}"
            )
        ),
        "  chain forward {",
        "    type filter hook forward priority -300; policy accept;",
    ]
    crossings = policy["crossings"]
    assert isinstance(crossings, list)
    if family == "bridge":
        for bridge in sorted(str(item["bridge"]) for item in networks.values()):
            # Link-local address resolution is not an inter-zone grant. Without
            # these bounded L2 control frames, an otherwise-authorized IP flow
            # depends on a stale neighbor cache and fails after a clean boot.
            lines.append(
                f"    ibrname {_quoted(bridge)} obrname {_quoted(bridge)} "
                'ether type arp accept comment "platform/arp"'
            )
            lines.append(
                f"    ibrname {_quoted(bridge)} obrname {_quoted(bridge)} "
                "ether type ip6 meta l4proto ipv6-icmp "
                "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } "
                'accept comment "platform/nd"'
            )
    for crossing in crossings:
        if not isinstance(crossing, Mapping):
            continue
        source_addresses = _workload_ipv4(anchors[str(crossing["source"])])
        destination_addresses = _workload_ipv4(anchors[str(crossing["destination"])])
        ingress = "ibrname" if family == "bridge" else "iifname"
        egress = "obrname" if family == "bridge" else "oifname"
        ports = crossing["ports"]
        assert isinstance(ports, list)
        rendered_ports = (
            str(ports[0])
            if len(ports) == 1
            else "{ " + ", ".join(str(port) for port in ports) + " }"
        )
        identity = f"platform/{crossing['purpose']}"
        for network_name in sorted(set(source_addresses) & set(destination_addresses)):
            bridge = str(networks[network_name]["bridge"])
            source = source_addresses[network_name]
            destination = destination_addresses[network_name]
            lines.append(
                f"    {ingress} {_quoted(bridge)} {egress} {_quoted(bridge)} "
                f"ip saddr {source} ip daddr {destination} "
                f"{crossing['protocol']} dport {rendered_ports} accept "
                f"comment {_quoted(_rule_marker(identity))}"
            )
            lines.append(
                f"    {ingress} {_quoted(bridge)} {egress} {_quoted(bridge)} "
                f"ip saddr {destination} ip daddr {source} "
                f"ct state established,related accept "
                f"comment {_quoted(_rule_marker(identity + '/reply'))}"
            )
    if family == "inet":
        egress_anchor = anchors.get("egress")
        egress_ports = policy["egress_ports"]
        assert isinstance(egress_ports, list)
        if egress_anchor is not None and egress_ports:
            rendered_ports = (
                str(egress_ports[0])
                if len(egress_ports) == 1
                else "{ " + ", ".join(str(port) for port in egress_ports) + " }"
            )
            denied_ipv4 = (
                "{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, "
                "127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, "
                "192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, "
                "224.0.0.0/4, 240.0.0.0/4 }"
            )
            zone_networks = policy["zone_networks"]
            assert isinstance(zone_networks, list)
            egress_network = next(
                str(item["network"])
                for item in zone_networks
                if isinstance(item, Mapping) and item["zone"] == "egress"
            )
            egress_sources = _workload_ipv4(egress_anchor)
            for network_name, source in sorted(egress_sources.items()):
                if network_name != egress_network:
                    continue
                bridge = str(networks[network_name]["bridge"])
                lines.append(
                    f"    oifname {_quoted(bridge)} ip daddr {source} "
                    "ct state established,related accept comment "
                    + _quoted(
                        _rule_marker("platform/egress-broker-reply/" + network_name)
                    )
                )
                lines.append(
                    f"    iifname {_quoted(bridge)} ip saddr {source} "
                    f"ip daddr {denied_ipv4} drop "
                    f"comment {_quoted(_rule_marker('platform/egress-denied-range/' + network_name))}"
                )
                lines.append(
                    f"    iifname {_quoted(bridge)} ip saddr {source} "
                    f"tcp dport {rendered_ports} accept "
                    f"comment {_quoted(_rule_marker('platform/egress-broker/' + network_name))}"
                )
    for bridge in sorted(str(item["bridge"]) for item in networks.values()):
        ingress = "ibrname" if family == "bridge" else "iifname"
        egress = "obrname" if family == "bridge" else "oifname"
        lines.append(
            f"    {ingress} {_quoted(bridge)} drop comment "
            + _quoted(_rule_marker(f"platform/default-ingress/{bridge}"))
        )
        lines.append(
            f"    {egress} {_quoted(bridge)} drop comment "
            + _quoted(_rule_marker(f"platform/default-egress/{bridge}"))
        )
    lines.extend(["  }"])
    if family == "inet":
        for chain, hook, interface in (
            ("host_input", "input", "iifname"),
            ("host_output", "output", "oifname"),
        ):
            lines.extend(
                [
                    f"  chain {chain} {{",
                    f"    type filter hook {hook} priority -300; policy accept;",
                ]
            )
            for bridge in sorted(str(item["bridge"]) for item in networks.values()):
                lines.append(
                    f"    {interface} {_quoted(bridge)} drop comment "
                    + _quoted(_rule_marker(f"platform/{chain}/{bridge}"))
                )
            lines.append("  }")
    lines.append("}")
    return lines


def render_ruleset(
    raw_policy: object,
    *,
    existing_families: Sequence[str],
) -> str:
    """Render one atomic transaction for exactly one policy authority."""

    policy = validate_policy(raw_policy)
    authority = str(policy["authority"])
    table_name = _table_name(str(policy["owner"]), authority)
    lines: list[str] = []
    for family in ("inet", "bridge"):
        if family in existing_families:
            lines.append(f"delete table {family} {table_name}")
    renderer = _raes_table if authority == "raes" else _platform_table
    lines.extend(renderer(policy, "inet", table_name))
    lines.extend(renderer(policy, "bridge", table_name))
    return "\n".join(lines) + "\n"


def _nft_json(*args: str, input_text: str | None = None) -> dict[str, object]:
    result = subprocess.run(
        ["nft", "-j", *args],
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError("nft operation failed")
    if not result.stdout.strip():
        return {}
    parsed = json.loads(result.stdout)
    if not isinstance(parsed, dict):
        raise RuntimeError("nft observation was invalid")
    return parsed


def _table_comment(family: str, table_name: str) -> str | None:
    try:
        payload = _nft_json("list", "table", family, table_name)
    except RuntimeError:
        return None
    nftables = payload.get("nftables", [])
    if not isinstance(nftables, list):
        return None
    for item in nftables:
        if not isinstance(item, dict):
            continue
        table = item.get("table")
        if isinstance(table, dict) and isinstance(table.get("comment"), str):
            return table["comment"]
    return None


def _table_payload(family: str, table_name: str) -> dict[str, object]:
    try:
        return _nft_json("list", "table", family, table_name)
    except RuntimeError:
        return {}


def _expected_chains(
    policy: Mapping[str, object],
    family: str,
) -> dict[str, tuple[str | None, int | None, str | None]]:
    if policy["authority"] == "platform":
        expected = {"forward": ("forward", -300, "accept")}
        if family == "inet":
            expected.update(
                {
                    "host_input": ("input", -300, "accept"),
                    "host_output": ("output", -300, "accept"),
                }
            )
        return expected
    bindings = policy["owner_bindings"]
    assert isinstance(bindings, list)
    expected = {"forward": ("forward", -200, "accept")}
    for binding in bindings:
        if isinstance(binding, Mapping):
            address = str(binding["owner_address"])
            chain = "owner_" + hashlib.sha256(address.encode()).hexdigest()[:12]
            expected[chain] = (None, None, None)
    return expected


def _expected_rule_comments(
    policy: Mapping[str, object],
    family: str,
    table_name: str,
) -> list[str]:
    renderer = _raes_table if policy["authority"] == "raes" else _platform_table
    comments: list[str] = []
    for line in renderer(policy, family, table_name):
        if not line.startswith("    ") or " comment " not in line:
            continue
        raw = line.rsplit(" comment ", 1)[1]
        value = json.loads(raw)
        if not isinstance(value, str):
            raise RuntimeError("boundary expected rule identity was invalid")
        comments.append(value)
    return sorted(comments)


def _verify_observed_family(
    policy: Mapping[str, object],
    family: str,
) -> bool:
    table_name = _table_name(str(policy["owner"]), str(policy["authority"]))
    payload = _table_payload(family, table_name)
    nftables = payload.get("nftables", [])
    if not isinstance(nftables, list):
        return False
    chains: dict[str, tuple[str | None, int | None, str | None]] = {}
    comments: list[str] = []
    for item in nftables:
        if not isinstance(item, dict):
            continue
        chain = item.get("chain")
        if isinstance(chain, dict) and isinstance(chain.get("name"), str):
            chains[str(chain["name"])] = (
                chain.get("hook") if isinstance(chain.get("hook"), str) else None,
                chain.get("prio") if isinstance(chain.get("prio"), int) else None,
                chain.get("policy") if isinstance(chain.get("policy"), str) else None,
            )
        rule = item.get("rule")
        if isinstance(rule, dict) and isinstance(rule.get("comment"), str):
            comments.append(str(rule["comment"]))
        elif isinstance(rule, dict):
            return False
    return chains == _expected_chains(policy, family) and sorted(
        comments
    ) == _expected_rule_comments(policy, family, table_name)


def _owned_families(policy: Mapping[str, object]) -> tuple[str, ...]:
    owner = str(policy["owner"])
    authority = str(policy["authority"])
    table_name = _table_name(owner, authority)
    owned: list[str] = []
    prefix = f"aptl-owner={_owner_marker(owner)},authority={authority},"
    for family in ("bridge", "inet"):
        comment = _table_comment(family, table_name)
        if comment is None:
            continue
        if not comment.startswith(prefix):
            raise RuntimeError("boundary table ownership conflict")
        owned.append(family)
    return tuple(owned)


def _receipt(
    policy: Mapping[str, object],
    families: Sequence[str],
) -> dict[str, object]:
    return {
        "authority": policy["authority"],
        "owner": policy["owner"],
        "enforcement_digest": _digest(policy),
        "families": list(families),
        "default_deny": policy["authority"] == "platform",
    }


def _apply(policy: dict[str, object]) -> dict[str, object]:
    existing = _owned_families(policy)
    rendered = render_ruleset(policy, existing_families=existing)
    _nft_json("-f", "-", input_text=rendered)
    observed = _owned_families(policy)
    if observed != ("bridge", "inet"):
        raise RuntimeError("boundary tables were not observed")
    if not all(_verify_observed_family(policy, family) for family in observed):
        raise RuntimeError("boundary rule readback did not match")
    return _receipt(policy, observed)


def _cleanup(policy: dict[str, object]) -> dict[str, object]:
    existing = _owned_families(policy)
    table_name = _table_name(str(policy["owner"]), str(policy["authority"]))
    if existing:
        rendered = "\n".join(
            f"delete table {family} {table_name}" for family in existing
        )
        _nft_json("-f", "-", input_text=rendered + "\n")
    return _receipt(policy, ())


def _observe(policy: dict[str, object]) -> dict[str, object]:
    families = _owned_families(policy)
    if families != ("bridge", "inet"):
        raise RuntimeError("boundary tables are incomplete")
    digest = _digest(policy)
    table_name = _table_name(str(policy["owner"]), str(policy["authority"]))
    for family in families:
        comment = _table_comment(family, table_name) or ""
        if f"digest={digest}" not in comment:
            raise RuntimeError("boundary policy digest mismatch")
        if not _verify_observed_family(policy, family):
            raise RuntimeError("boundary rule readback did not match")
    return _receipt(policy, families)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("apply", "observe", "cleanup"))
    parser.add_argument("--stdin", action="store_true", required=True)
    args = parser.parse_args()
    try:
        policy = validate_policy(json.load(sys.stdin))
        action = {"apply": _apply, "observe": _observe, "cleanup": _cleanup}[
            args.action
        ]
        print(json.dumps(action(policy), sort_keys=True, separators=(",", ":")))
        return 0
    except (
        ValueError,
        RuntimeError,
        KeyError,
        TypeError,
        OSError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ):
        print("boundary helper failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
