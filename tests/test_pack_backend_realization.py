"""The interaction mapping labels a realized plan without changing its shape."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from raes_contracts.planning import PlannedResource, ProvisioningPlan
from raes_contracts.runtime_state import RuntimeDomain

from aptl.backends.pack_interaction import (
    ComponentGroupMembership,
    ResolvedPackBackendInteraction,
)
from aptl.core.config import AptlConfig
from aptl.core.scenario_bundle import (
    PackIdentity,
    ScenarioBundle,
    ScenarioSourceKind,
)


def _bundle(root: Path) -> ScenarioBundle:
    return ScenarioBundle(
        identity="demo",
        root=root,
        sdl_path=root / "sdl" / "demo.sdl.yaml",
        source_kind=ScenarioSourceKind.ENV_PACK,
        pack_identity=PackIdentity(
            pack_id="demo",
            pack_version="1.0.0",
            set_digest="sha256:" + "a" * 64,
        ),
    )


def _node(name: str, **payload_overrides: object) -> PlannedResource:
    payload: dict[str, object] = {
        "name": name,
        "spec": {"node": {"name": name}, "infrastructure": {}},
        **payload_overrides,
    }
    return PlannedResource(
        address=f"provision.node.{name}",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="node",
        payload=payload,
    )


def _plan(*nodes: PlannedResource) -> ProvisioningPlan:
    return ProvisioningPlan(
        resources={node.address: node for node in nodes},
        operations=[],
    )


def _resolved(*memberships: ComponentGroupMembership) -> ResolvedPackBackendInteraction:
    return ResolvedPackBackendInteraction(
        memberships=tuple(memberships),
        mapping_digest="sha256:" + "b" * 64,
        provider_id="test-provider",
        extension_api_version="1",
        distribution="test-dist",
        distribution_version="1.2.3",
        entry_point="demo.aptl",
    )


def test_pack_mapping_replaces_authored_hints_and_labels_exact_addresses(
    monkeypatch, tmp_path
) -> None:
    from aptl.backends.raes_realization import interpret_provisioning_plan

    monkeypatch.setattr(
        "aptl.backends.raes_pack_interaction.resolve_pack_backend_interaction",
        lambda context: _resolved(
            ComponentGroupMembership("provision.node.a", ("soc",)),
            ComponentGroupMembership("provision.node.b", ()),
        ),
    )
    plan = _plan(
        _node("a", compose_profile="enterprise"),
        _node("b", compose_profiles=["wazuh"]),
    )

    realization = interpret_provisioning_plan(
        plan=plan,
        config=AptlConfig(lab={"name": "test"}),
        bundle=_bundle(tmp_path),
    )

    assert {node.address: node.profiles for node in realization.nodes} == {
        "provision.node.a": ("soc",),
        "provision.node.b": (),
    }
    assert realization.profiles == frozenset({"soc"})
    assert "pack_interaction" not in realization.details()
    assert realization.pack_interaction_evidence(["soc", "otel"]) == {
        "pack": {
            "pack_id": "demo",
            "pack_version": "1.0.0",
            "set_digest": "sha256:" + "a" * 64,
        },
        "provider": {
            "provider_id": "test-provider",
            "extension_api_version": "1",
            "distribution": "test-dist",
            "distribution_version": "1.2.3",
            "entry_point": "demo.aptl",
            "mapping_digest": "sha256:" + "b" * 64,
        },
        "selected_profiles": ["soc", "otel"],
    }
    assert not any(
        diagnostic.code == "aptl.provisioner.node-profile-unresolved"
        for diagnostic in realization.diagnostics
    )


def test_provider_can_change_only_group_fields(monkeypatch, tmp_path) -> None:
    from aptl.backends.raes_realization import interpret_provisioning_plan

    plan = _plan(_node("a"), _node("b"))
    assignments = iter(
        (
            _resolved(
                ComponentGroupMembership("provision.node.a", ("soc",)),
                ComponentGroupMembership("provision.node.b", ()),
            ),
            _resolved(
                ComponentGroupMembership("provision.node.a", ()),
                ComponentGroupMembership("provision.node.b", ("enterprise",)),
            ),
        )
    )
    monkeypatch.setattr(
        "aptl.backends.raes_pack_interaction.resolve_pack_backend_interaction",
        lambda context: next(assignments),
    )

    first = interpret_provisioning_plan(
        plan=plan, config=AptlConfig(lab={"name": "test"}), bundle=_bundle(tmp_path)
    )
    second = interpret_provisioning_plan(
        plan=plan, config=AptlConfig(lab={"name": "test"}), bundle=_bundle(tmp_path)
    )

    def without_groups(realization):
        return (
            tuple(
                (node.address, node.name, node.backend_services, node.container_name)
                for node in realization.nodes
            ),
            realization.networks,
            realization.placements,
            realization.acls,
            realization.generated_artifacts,
            realization.persistent_volumes,
        )

    assert without_groups(first) == without_groups(second)
    assert first.profiles != second.profiles


def test_disabled_assigned_group_rejects_before_backend_mutation(monkeypatch, tmp_path) -> None:
    from raes_contracts.runtime_state import RuntimeSnapshot

    from aptl.backends.raes_provisioner import AptlProvisioner

    monkeypatch.setattr(
        "aptl.backends.raes_pack_interaction.resolve_pack_backend_interaction",
        lambda context: _resolved(
            ComponentGroupMembership("provision.node.a", ("soc",)),
        ),
    )
    backend = MagicMock()
    config = AptlConfig(
        lab={"name": "test"},
        containers={"soc": False},
    )
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=config,
        deployment_backend=backend,
        bundle=_bundle(tmp_path),
    )

    result = provisioner.apply(_plan(_node("a")), RuntimeSnapshot())

    assert result.success is False
    assert "aptl.provisioner.pack-interaction-group-disabled" in {
        diagnostic.code for diagnostic in result.diagnostics
    }
    backend.realize.assert_not_called()


def test_interaction_context_carries_the_selected_deployment_transport(
    monkeypatch, tmp_path
) -> None:
    from aptl.backends.raes_realization import interpret_provisioning_plan

    seen = []

    def resolve(context):
        seen.append(context.backend.transport)
        return _resolved(ComponentGroupMembership("provision.node.a", ()))

    monkeypatch.setattr(
        "aptl.backends.raes_pack_interaction.resolve_pack_backend_interaction", resolve
    )

    interpret_provisioning_plan(
        plan=_plan(_node("a")),
        config=AptlConfig(
            lab={"name": "test"},
            deployment={"provider": "ssh-compose", "ssh_host": "example.test"},
        ),
        bundle=_bundle(tmp_path),
    )

    assert seen == ["ssh-compose"]


def test_one_plan_resolves_the_provider_once_across_validate_and_apply(
    monkeypatch, tmp_path
) -> None:
    from aptl.backends.raes_provisioner import AptlProvisioner

    calls = 0

    def resolve(context):
        nonlocal calls
        calls += 1
        return _resolved(ComponentGroupMembership("provision.node.a", ()))

    monkeypatch.setattr(
        "aptl.backends.raes_pack_interaction.resolve_pack_backend_interaction", resolve
    )
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}),
        deployment_backend=MagicMock(),
        bundle=_bundle(tmp_path),
    )
    plan = _plan(_node("a"))

    provisioner.validate(plan)
    provisioner.realize_plan(plan)
    provisioner.realize_plan(plan)

    assert calls == 1


def test_generated_compose_uses_the_realized_membership_not_a_name_table() -> None:
    from aptl.core.deployment._compose_node_generation import render_realization_compose
    from aptl.core.deployment.realization import (
        DeploymentImageRealization,
        DeploymentNodeRealization,
        DeploymentRealizationSpec,
    )

    spec = DeploymentRealizationSpec(
        profiles=("enterprise",),
        networks=(),
        nodes=(
            DeploymentNodeRealization(
                address="provision.node.thehive",
                name="thehive",
                service_name="thehive",
                container_name="aptl-thehive",
                networks=(),
                profiles=("enterprise",),
            ),
        ),
        images=(
            DeploymentImageRealization(
                address="provision.node.thehive",
                service_name="thehive",
                source_name="thehive",
                source_version="1",
                image_ref="thehive:1",
                mode="pull",
                policy_rule="test",
            ),
        ),
    )

    service = render_realization_compose(spec)["services"]["thehive"]

    assert service["profiles"] == ["enterprise"]
