"""Binding tests for the separate ACES and platform authorities."""

import pytest

from aptl.core.appliance_boundary import ApplianceBoundaryPolicy
from aptl.core.deployment.boundary import BoundaryNetwork, BoundaryWorkload
from aptl.core.deployment.boundary_compiler import (
    BoundaryCompileError,
    compile_aces_boundary,
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
            "default_deny": True,
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
            "guest_publications": [],
            "docker_authority": {
                "allowed_holder_labels": [],
                "require_guest_daemon": True,
            },
        }
    )


def test_aces_binding_keeps_owner_address_and_platform_data_out() -> None:
    spec = compile_aces_boundary(_realization(), _networks(), owner="seat-17")

    assert spec.authority == "aces"
    assert spec.owner_bindings[0].ipv4_by_network == (
        ("quartz", "10.44.2.10"),
    )
    assert "policy_digest" not in spec.details()


def test_aces_binding_refuses_to_widen_an_unaddressed_owner() -> None:
    with pytest.raises(BoundaryCompileError, match="exact admitted addresses"):
        compile_aces_boundary(_realization(owner_ip=None), _networks(), owner="seat-17")


def test_platform_binding_uses_only_exact_labels() -> None:
    networks = tuple(
        BoundaryNetwork(
            name=zone,
            bridge=f"br-{zone[:7]}",
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
            ipv4_by_network=(("egress", "10.50.3.20"),),
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
    assert "rules" not in spec.details()


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
            ipv4_by_network=(("management", "10.50.2.20"),),
        ),
    )

    with pytest.raises(BoundaryCompileError, match="exactly once"):
        compile_platform_boundary(
            _policy(),
            policy_digest="sha256:" + "a" * 64,
            networks=(
                BoundaryNetwork(name="participant", bridge="br-part"),
                BoundaryNetwork(name="management", bridge="br-mgmt"),
            ),
            workloads=duplicate,
            owner="seat-17",
        )
