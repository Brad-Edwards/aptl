"""Generic ACES ACL lowering for the APP-1 materialization surface."""

import json

from aces_contracts.planning import PlannedResource, ProvisioningPlan, RuntimeDomain

from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.config import AptlConfig


def _resource(
    name: str,
    resource_type: str,
    infrastructure: dict[str, object],
) -> PlannedResource:
    return PlannedResource(
        address=f"provision.{resource_type}.{name}",
        domain=RuntimeDomain.PROVISIONING,
        resource_type=resource_type,
        payload={
            "name": name,
            "spec": {
                "node": {"type": "switch" if resource_type == "network" else "vm"},
                "infrastructure": infrastructure,
            },
        },
    )


def _plan(*resources: PlannedResource) -> ProvisioningPlan:
    return ProvisioningPlan(
        resources={resource.address: resource for resource in resources},
        operations=(),
    )


def _project(tmp_path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        json.dumps(
            {
                "services": {
                    "sentinel": {
                        "container_name": "sentinel",
                        "profiles": ["victim"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )


def test_acl_lowering_preserves_aces_identity_order_and_semantics(tmp_path) -> None:
    _project(tmp_path)
    orchard = _resource(
        "orchard",
        "network",
        {"properties": {"cidr": "10.44.1.0/24", "gateway": "10.44.1.1"}},
    )
    quartz = _resource(
        "quartz",
        "network",
        {"properties": {"cidr": "10.44.2.0/24", "gateway": "10.44.2.1"}},
    )
    sentinel = _resource(
        "sentinel",
        "node",
        {
            "links": ["orchard", "quartz"],
            "properties": [
                {"orchard": "10.44.1.10"},
                {"quartz": "10.44.2.10"},
            ],
            "acls": [
                {
                    "name": "allow-web",
                    "direction": "in",
                    "from_net": "orchard",
                    "to_net": "quartz",
                    "protocol": "tcp",
                    "ports": [443, 8443],
                    "action": "allow",
                },
                {
                    "name": "deny-rest",
                    "direction": "inout",
                    "from_net": "orchard",
                    "to_net": "quartz",
                    "protocol": "any",
                    "ports": [],
                    "action": "deny",
                },
            ],
        },
    )

    realization = interpret_provisioning_plan(
        plan=_plan(orchard, quartz, sentinel),
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "synthetic"}, containers={"victim": True}),
    )

    assert [item.code for item in realization.diagnostics] == []
    spec = realization.deployment_spec(["victim"])
    assert [item.details() for item in spec.acls] == [
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
            "ports": [443, 8443],
            "action": "allow",
        },
        {
            "owner_address": "provision.node.sentinel",
            "owner_resource_type": "node",
            "owner_name": "sentinel",
            "name": "deny-rest",
            "order": 1,
            "direction": "inout",
            "from_network": "orchard",
            "to_network": "quartz",
            "protocol": "any",
            "ports": [],
            "action": "deny",
        },
    ]


def test_acl_lowering_rejects_unsupported_semantics_before_backend(tmp_path) -> None:
    _project(tmp_path)
    orchard = _resource(
        "orchard",
        "network",
        {"properties": {"cidr": "10.44.1.0/24", "gateway": "10.44.1.1"}},
    )
    sentinel = _resource(
        "sentinel",
        "node",
        {
            "links": ["orchard"],
            "properties": [{"orchard": "10.44.1.10"}],
            "acls": [
                {
                    "name": "unsupported",
                    "direction": "sideways",
                    "from_net": "missing",
                    "to_net": "orchard",
                    "protocol": "sctp",
                    "ports": [443],
                    "action": "permit",
                }
            ],
        },
    )

    realization = interpret_provisioning_plan(
        plan=_plan(orchard, sentinel),
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "synthetic"}, containers={"victim": True}),
    )

    assert {item.code for item in realization.diagnostics} == {
        "aptl.provisioner.acl-action-unsupported",
        "aptl.provisioner.acl-direction-unsupported",
        "aptl.provisioner.acl-endpoint-unresolved",
        "aptl.provisioner.acl-protocol-unsupported",
    }
    assert realization.deployment_spec(["victim"]).acls == ()
