"""Binding tests for the separate RAES and platform authorities."""

import pytest

from aptl.core.appliance_boundary import ApplianceBoundaryPolicy
from aptl.core.deployment.boundary import BoundaryNetwork, BoundaryWorkload
from aptl.core.deployment.boundary_compiler import (
    BoundaryCompileError,
    compile_raes_boundary,
    compile_platform_boundary,
)
from aptl.core.deployment.realization import (
    DeploymentAclRealization,
    DeploymentNetworkAttachment,
    DeploymentNetworkRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)


def _realization(*, owner_ip: str | None = "10.44.2.10") -> DeploymentRealizationSpec:
    return DeploymentRealizationSpec(
        profiles=(),
        nodes=(
            DeploymentNodeRealization(
                address="provision.node.sentinel",
                name="sentinel",
                service_name=None,
                container_name="sentinel",
                networks=("quartz",),
                network_attachments=(
                    DeploymentNetworkAttachment(
                        network="quartz",
                        ipv4_address=owner_ip,
                    ),
                ),
            ),
        ),
        networks=(
            DeploymentNetworkRealization(name="orchard"),
            DeploymentNetworkRealization(name="quartz"),
        ),
        acls=(
            DeploymentAclRealization(
                owner_address="provision.node.sentinel",
                owner_resource_type="node",
                owner_name="sentinel",
                name="allow-web",
                order=0,
                direction="in",
                from_network="orchard",
                to_network="quartz",
                protocol="tcp",
                ports=(443,),
                action="allow",
            ),
        ),
    )


def _networks() -> tuple[BoundaryNetwork, ...]:
    return (
        BoundaryNetwork(
            name="orchard",
            bridge="br-orchard",
            ipv4_cidr="10.44.1.0/24",
        ),
        BoundaryNetwork(
            name="quartz",
            bridge="br-quartz",
            ipv4_cidr="10.44.2.0/24",
        ),
    )


def _policy() -> ApplianceBoundaryPolicy:
    return ApplianceBoundaryPolicy.model_validate(
        {
            "schema_version": "aptl.appliance-boundary/v1",
            "policy_id": "default",
            "generation": 1,
            "workbench_policy_version": "participant-workbench-profile/v1",
            "default_deny": True,
            "platform_networks": {
                "participant": "org.aptl.network=participant",
                "management": "org.aptl.network=management",
                "egress": "org.aptl.network=egress",
            },
            "platform_anchors": {
                "participant": "org.aptl.zone=participant",
                "management": "org.aptl.zone=management",
                "egress": "org.aptl.zone=egress",
            },
            "fixed_crossings": [
                {
                    "source": "management",
                    "destination": "egress",
                    "protocol": "tcp",
                    "ports": [3128],
                    "purpose": "model-proxy",
                }
            ],
            "egress_authorities": [],
            "egress_proxy_limits": {
                "max_connections": 32,
                "max_header_bytes": 4096,
                "header_timeout_seconds": 5,
                "connect_timeout_seconds": 10,
                "idle_timeout_seconds": 60,
            },
            "guest_publications": [],
            "docker_authority": {
                "allowed_holder_labels": [],
                "require_guest_daemon": True,
            },
        }
    )


def test_raes_binding_keeps_owner_address_and_platform_data_out() -> None:
    spec = compile_raes_boundary(_realization(), _networks(), owner="seat-17")

    assert spec.authority == "raes"
    assert spec.owner_bindings[0].ipv4_by_network == (("quartz", "10.44.2.10"),)
    assert spec.rules[0].details() == {
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


def test_raes_binding_refuses_to_widen_an_unaddressed_owner() -> None:
    realization = _realization(owner_ip=None)
    networks = _networks()

    with pytest.raises(BoundaryCompileError, match="exact admitted addresses"):
        compile_raes_boundary(realization, networks, owner="seat-17")


def test_raes_binding_rejects_dual_stack_until_acl_rules_are_dual_stack() -> None:
    dual_stack = (
        _networks()[0],
        BoundaryNetwork(
            name="quartz",
            bridge="br-quartz",
            ipv4_cidr="10.44.2.0/24",
            ipv6_cidr="2001:db8:44::/64",
        ),
    )
    realization = _realization()

    with pytest.raises(BoundaryCompileError, match="IPv4-only"):
        compile_raes_boundary(realization, dual_stack, owner="seat-17")


def test_platform_binding_uses_only_exact_labels() -> None:
    networks = tuple(
        BoundaryNetwork(
            name=zone,
            bridge=f"br-{zone[:7]}",
            labels=(("org.aptl.network", zone),),
        )
        for zone in ("participant", "management", "egress")
    )
    workloads = (
        BoundaryWorkload(
            identity="participant-gateway",
            labels=(("org.aptl.zone", "participant"),),
            ipv4_by_network=(("participant", "10.50.1.10"),),
        ),
        BoundaryWorkload(
            identity="management-agent",
            labels=(("org.aptl.zone", "management"),),
            ipv4_by_network=(
                ("management", "10.50.2.10"),
                ("egress", "10.50.3.10"),
            ),
        ),
        BoundaryWorkload(
            identity="egress-proxy",
            labels=(("org.aptl.zone", "egress"),),
            ipv4_by_network=(
                ("management", "10.50.2.20"),
                ("egress", "10.50.3.20"),
            ),
        ),
    )

    spec = compile_platform_boundary(
        _policy(),
        policy_digest="sha256:" + "a" * 64,
        networks=networks,
        workloads=workloads,
        owner="seat-17",
    )

    assert spec.authority == "platform"
    assert [zone for zone, _network in spec.anchors] == [
        "participant",
        "management",
        "egress",
    ]
    assert dict(spec.anchors)["management"].ipv4_by_network == (
        ("management", "10.50.2.10"),
        ("egress", "10.50.3.10"),
    )
    assert spec.crossings[0].details() == {
        "source": "management",
        "destination": "egress",
        "protocol": "tcp",
        "ports": [3128],
        "purpose": "model-proxy",
    }
    assert spec.egress_ports == ()


def test_platform_binding_rejects_ambiguous_anchor() -> None:
    duplicate = (
        BoundaryWorkload(
            identity="participant-a",
            labels=(("org.aptl.zone", "participant"),),
            ipv4_by_network=(("participant", "10.50.1.10"),),
        ),
        BoundaryWorkload(
            identity="participant-b",
            labels=(("org.aptl.zone", "participant"),),
            ipv4_by_network=(("participant", "10.50.1.11"),),
        ),
        BoundaryWorkload(
            identity="management",
            labels=(("org.aptl.zone", "management"),),
            ipv4_by_network=(("management", "10.50.2.10"),),
        ),
        BoundaryWorkload(
            identity="egress",
            labels=(("org.aptl.zone", "egress"),),
            ipv4_by_network=(
                ("management", "10.50.2.20"),
                ("egress", "10.50.3.20"),
            ),
        ),
    )

    policy = _policy()
    networks = (
        BoundaryNetwork(
            name="participant",
            bridge="br-part",
            labels=(("org.aptl.network", "participant"),),
        ),
        BoundaryNetwork(
            name="management",
            bridge="br-mgmt",
            labels=(("org.aptl.network", "management"),),
        ),
        BoundaryNetwork(
            name="egress",
            bridge="br-egress",
            labels=(("org.aptl.network", "egress"),),
        ),
    )

    with pytest.raises(BoundaryCompileError, match="exactly once"):
        compile_platform_boundary(
            policy,
            policy_digest="sha256:" + "a" * 64,
            networks=networks,
            workloads=duplicate,
            owner="seat-17",
        )


def test_platform_binding_rejects_ipv6_until_crossings_are_dual_stack() -> None:
    networks = (
        BoundaryNetwork(
            name="participant",
            bridge="br-part",
            ipv6_cidr="2001:db8:1::/64",
            labels=(("org.aptl.network", "participant"),),
        ),
        BoundaryNetwork(
            name="management",
            bridge="br-mgmt",
            labels=(("org.aptl.network", "management"),),
        ),
        BoundaryNetwork(
            name="egress",
            bridge="br-egress",
            labels=(("org.aptl.network", "egress"),),
        ),
    )
    policy = _policy()

    with pytest.raises(BoundaryCompileError, match="IPv6"):
        compile_platform_boundary(
            policy,
            policy_digest="sha256:" + "a" * 64,
            networks=networks,
            workloads=(),
            owner="seat-17",
        )
