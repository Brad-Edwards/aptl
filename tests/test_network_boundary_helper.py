"""Pure rendering checks for the authority-separated nftables helper."""

import importlib.util
from pathlib import Path

import pytest


HELPER = (
    Path(__file__).parents[1]
    / "containers"
    / "network-boundary-helper"
    / "helper.py"
)


@pytest.fixture(scope="module")
def helper():
    spec = importlib.util.spec_from_file_location("network_boundary_helper", HELPER)
    assert spec is not None and spec.loader is not None
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


def _aces_policy() -> dict[str, object]:
    return {
        "authority": "aces",
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
            _network("transit", "br-transit", "10.50.2.0/24"),
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
                    "ipv4_by_network": [["transit", "10.50.2.10"]],
                    "ipv6_by_network": [],
                },
            },
            {
                "zone": "egress",
                "workload": {
                    "identity": "egress-proxy",
                    "labels": [["org.aptl.zone", "egress"]],
                    "ipv4_by_network": [["transit", "10.50.2.20"]],
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


def test_aces_rules_remain_owner_anchored_and_separate(helper) -> None:
    rendered = helper.render_ruleset(_aces_policy(), existing_families=())

    assert "authority=aces" in rendered
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
    assert 'iifname "br-transit" oifname "br-transit"' in rendered
    assert "ip saddr 10.50.2.10 ip daddr 10.50.2.20" in rendered
    assert "tcp dport 3128 accept" in rendered
    assert "tcp dport 443 accept" in rendered
    assert "ct state established,related accept" in rendered
    assert rendered.count("drop") >= 9


def test_authorities_get_distinct_owned_tables(helper) -> None:
    aces = helper.render_ruleset(_aces_policy(), existing_families=())
    platform = helper.render_ruleset(_platform_policy(), existing_families=())

    aces_table = next(line for line in aces.splitlines() if line.startswith("table inet"))
    platform_table = next(
        line for line in platform.splitlines() if line.startswith("table inet")
    )
    assert aces_table != platform_table


def test_helper_rejects_cross_authority_fields(helper) -> None:
    policy = _aces_policy()
    policy["default_deny"] = True

    with pytest.raises(ValueError):
        helper.validate_policy(policy)
