"""Pure rendering checks for the authority-separated nftables helper."""

import importlib.util
from pathlib import Path

import pytest


HELPER = (
    Path(__file__).parents[1] / "containers" / "network-boundary-helper" / "helper.py"
)


@pytest.fixture(scope="module")
def helper():
    spec = importlib.util.spec_from_file_location("network_boundary_helper", HELPER)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _network(name: str, bridge: str, cidr: str) -> dict[str, object]:
    return {
        "name": name,
        "bridge": bridge,
        "ipv4_cidr": cidr,
        "ipv6_cidr": None,
        "labels": [],
    }


def _raes_policy() -> dict[str, object]:
    return {
        "authority": "raes",
        "owner": "seat-17",
        "networks": [
            _network("orchard", "br-orchard", "10.44.1.0/24"),
            _network("quartz", "br-quartz", "10.44.2.0/24"),
        ],
        "owner_bindings": [
            {
                "owner_address": "provision.node.sentinel",
                "owner_resource_type": "node",
                "ipv4_by_network": [["quartz", "10.44.2.10"]],
                "ipv6_by_network": [],
            }
        ],
        "rules": [
            {
                "owner_address": "provision.node.sentinel",
                "owner_resource_type": "node",
                "owner_name": "sentinel",
                "name": "allow-web",
                "order": 0,
                "direction": "in",
                "from_network": "orchard",
                "to_network": "quartz",
                "protocol": "tcp",
                "ports": [443],
                "action": "allow",
            }
        ],
    }


def _platform_policy() -> dict[str, object]:
    return {
        "authority": "platform",
        "owner": "seat-17",
        "policy_digest": "sha256:" + "a" * 64,
        "networks": [
            _network("participant-net", "br-part", "10.50.1.0/24"),
            _network("management-net", "br-mgmt", "10.50.2.0/24"),
            _network("egress-net", "br-egress", "10.50.3.0/24"),
        ],
        "zone_networks": [
            {"zone": "participant", "network": "participant-net"},
            {"zone": "management", "network": "management-net"},
            {"zone": "egress", "network": "egress-net"},
        ],
        "anchors": [
            {
                "zone": "participant",
                "workload": {
                    "identity": "participant-gateway",
                    "labels": [["org.aptl.zone", "participant"]],
                    "ipv4_by_network": [["participant-net", "10.50.1.10"]],
                    "ipv6_by_network": [],
                },
            },
            {
                "zone": "management",
                "workload": {
                    "identity": "management-agent",
                    "labels": [["org.aptl.zone", "management"]],
                    "ipv4_by_network": [["management-net", "10.50.2.10"]],
                    "ipv6_by_network": [],
                },
            },
            {
                "zone": "egress",
                "workload": {
                    "identity": "egress-proxy",
                    "labels": [["org.aptl.zone", "egress"]],
                    "ipv4_by_network": [
                        ["management-net", "10.50.2.20"],
                        ["egress-net", "10.50.3.20"],
                    ],
                    "ipv6_by_network": [],
                },
            },
        ],
        "crossings": [
            {
                "source": "management",
                "destination": "egress",
                "protocol": "tcp",
                "ports": [3128],
                "purpose": "model-proxy",
            }
        ],
        "egress_ports": [443],
        "default_deny": True,
    }


def test_raes_rules_remain_owner_anchored_and_separate(helper) -> None:
    rendered = helper.render_ruleset(_raes_policy(), existing_families=())

    assert "authority=raes" in rendered
    assert "policy-digest=" not in rendered
    assert "hook forward priority -200" in rendered
    assert 'iifname "br-orchard" oifname "br-quartz"' in rendered
    assert "ip daddr 10.44.2.10" in rendered
    assert "tcp dport 443 return" in rendered
    assert "ip daddr 10.44.2.10 jump owner_" in rendered


def test_platform_floor_covers_forward_and_guest_host_paths(helper) -> None:
    rendered = helper.render_ruleset(_platform_policy(), existing_families=())

    assert "authority=platform" in rendered
    assert "hook forward priority -300" in rendered
    assert "hook input priority -300" in rendered
    assert "hook output priority -300" in rendered
    assert 'iifname "br-mgmt" oifname "br-mgmt"' in rendered
    assert "ip saddr 10.50.2.10 ip daddr 10.50.2.20" in rendered
    assert "tcp dport 3128 accept" in rendered
    assert "tcp dport 443 accept" in rendered
    assert "ct state established,related accept" in rendered
    assert "ip daddr 10.50.3.20 ct state established,related accept" in rendered
    for bridge in ("br-part", "br-mgmt", "br-egress"):
        assert f'iifname "{bridge}" drop comment' in rendered
        assert f'oifname "{bridge}" drop comment' in rendered
    assert (
        "ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, "
        "127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, "
        "192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, "
        "224.0.0.0/4, 240.0.0.0/4 } drop"
    ) in rendered


def test_authorities_get_distinct_owned_tables(helper) -> None:
    raes = helper.render_ruleset(_raes_policy(), existing_families=())
    platform = helper.render_ruleset(_platform_policy(), existing_families=())

    raes_table = next(
        line for line in raes.splitlines() if line.startswith("table inet")
    )
    platform_table = next(
        line for line in platform.splitlines() if line.startswith("table inet")
    )
    assert raes_table != platform_table


def test_helper_rejects_cross_authority_fields(helper) -> None:
    policy = _raes_policy()
    policy["default_deny"] = True

    with pytest.raises(ValueError):
        helper.validate_policy(policy)


def test_multiple_acl_owners_remain_independent_intersecting_chains(helper) -> None:
    policy = _raes_policy()
    policy["owner_bindings"].append(
        {
            "owner_address": "provision.node.gateway",
            "owner_resource_type": "node",
            "ipv4_by_network": [["orchard", "10.44.1.10"]],
            "ipv6_by_network": [],
        }
    )
    policy["rules"].append(
        {
            "owner_address": "provision.node.gateway",
            "owner_resource_type": "node",
            "owner_name": "gateway",
            "name": "deny-other",
            "order": 0,
            "direction": "out",
            "from_network": "orchard",
            "to_network": "quartz",
            "protocol": "any",
            "ports": [],
            "action": "deny",
        }
    )
    policy["owner_bindings"].sort(key=lambda item: item["owner_address"])
    policy["rules"].sort(
        key=lambda item: (item["owner_address"], item["order"], item["name"])
    )

    rendered = helper.render_ruleset(policy, existing_families=())

    assert rendered.count("chain owner_") == 4
    assert "ip daddr 10.44.2.10 jump owner_" in rendered
    assert "ip saddr 10.44.1.10 jump owner_" in rendered
    assert "drop comment" in rendered


def test_helper_rejects_malformed_direct_acl_without_native_mutation(helper) -> None:
    policy = _raes_policy()
    policy["rules"][0]["from_network"] = ["orchard"]

    with pytest.raises(ValueError, match="endpoint"):
        helper.validate_policy(policy)


def test_authored_wildcard_endpoint_is_scoped_by_acl_owner(helper) -> None:
    policy = _raes_policy()
    policy["rules"][0]["from_network"] = None

    rendered = helper.render_ruleset(policy, existing_families=())

    assert "ip daddr 10.44.2.10 tcp dport 443 return" in rendered


@pytest.mark.parametrize(
    ("direction", "protocol", "needle"),
    [
        ("out", "udp", "udp dport 443 return"),
        ("inout", "icmp", "meta l4proto icmp return"),
        ("in", "any", "ip daddr 10.44.2.10 return"),
    ],
)
def test_supported_acl_direction_and_protocol_subset_is_rendered_exactly(
    helper,
    direction: str,
    protocol: str,
    needle: str,
) -> None:
    policy = _raes_policy()
    rule = policy["rules"][0]
    policy["owner_bindings"][0]["ipv4_by_network"].append(["orchard", "10.44.1.20"])
    rule["direction"] = direction
    rule["protocol"] = protocol
    rule["ports"] = [443] if protocol in {"tcp", "udp"} else []

    rendered = helper.render_ruleset(policy, existing_families=())

    assert needle in rendered
    if direction == "inout":
        assert rendered.count("meta l4proto icmp return") == 4


def test_ruleset_replacement_is_one_atomic_native_transaction(helper) -> None:
    rendered = helper.render_ruleset(
        _raes_policy(),
        existing_families=("bridge", "inet"),
    )

    assert rendered.startswith("delete table inet ")
    assert "\ndelete table bridge " in rendered
    assert rendered.count("table inet ") == 2
    assert rendered.count("table bridge ") == 2
