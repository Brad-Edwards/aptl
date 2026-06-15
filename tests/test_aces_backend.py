"""Tests for the APTL ACES runtime handoff."""

from pathlib import Path
from unittest.mock import MagicMock

from aces_contracts.planning import (
    ChangeAction,
    PlannedResource,
    ProvisioningPlan,
    ProvisionOp,
    RuntimeDomain,
)
from aces_contracts.runtime_state import RuntimeSnapshot

from aptl.core.config import AptlConfig
from aptl.core.lab_types import LabResult


def _write_compose(project_dir: Path, services: dict[str, list[str]]) -> None:
    lines = ["services:"]
    for service_name, profiles in services.items():
        rendered = ", ".join(f'"{profile}"' for profile in profiles)
        lines.extend(
            [
                f"  {service_name}:",
                f"    profiles: [{rendered}]",
                "    image: example:latest",
            ]
        )
    (project_dir / "docker-compose.yml").write_text("\n".join(lines))


def _node_resource(node_name: str) -> PlannedResource:
    address = f"provision.node.{node_name}"
    payload = {
        "name": node_name,
        "node_name": node_name,
        "node_type": "vm",
        "os_family": "linux",
        "spec": {"node": {"name": node_name}, "infrastructure": {}},
    }
    return PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="node",
        payload=payload,
    )


def _plan_for_resources(*resources: PlannedResource) -> ProvisioningPlan:
    mapped = {resource.address: resource for resource in resources}
    operations = [
        ProvisionOp(
            action=ChangeAction.CREATE,
            address=resource.address,
            resource_type=resource.resource_type,
            payload=resource.payload,
        )
        for resource in mapped.values()
    ]
    return ProvisioningPlan(resources=mapped, operations=operations)


def _plan_for_nodes(*node_names: str) -> ProvisioningPlan:
    return _plan_for_resources(*map(_node_resource, node_names))


def _plan_with_resource_type(resource_type: str) -> ProvisioningPlan:
    resource = PlannedResource(
        address=f"provision.{resource_type}.example",
        domain=RuntimeDomain.PROVISIONING,
        resource_type=resource_type,
        payload={"name": "example"},
    )
    return ProvisioningPlan(
        resources={resource.address: resource},
        operations=[
            ProvisionOp(
                action=ChangeAction.CREATE,
                address=resource.address,
                resource_type=resource.resource_type,
                payload=resource.payload,
            )
        ],
    )


def test_create_runtime_target_accepts_aptl_manifest_shape(tmp_path):
    from aptl.backends.aces import create_aptl_runtime_target

    backend = MagicMock()
    config = AptlConfig(lab={"name": "test"})

    target = create_aptl_runtime_target(
        project_dir=tmp_path,
        config=config,
        backend=backend,
    )

    assert target.name == "aptl"
    assert target.manifest.name == "aptl"


class _FakeExecutionPlan:
    """Minimal ExecutionPlan stand-in exposing the fields the handoff reads."""

    def __init__(self, provisioning, *, is_valid=True, diagnostics=None):
        self.provisioning = provisioning
        self.base_snapshot = RuntimeSnapshot()
        self.is_valid = is_valid
        self.diagnostics = diagnostics or []


def test_create_aptl_manifest_is_canonical_backend_manifest_v2():
    from aces_backend_protocols.capabilities import BackendManifest
    from aces_backend_protocols.manifest import backend_manifest_payload

    from aptl.backends.aces_manifest import create_aptl_manifest

    manifest = create_aptl_manifest()

    assert isinstance(manifest, BackendManifest)
    payload = backend_manifest_payload(manifest)
    assert payload["schema_version"] == "backend-manifest/v2"
    required = {
        "backend-manifest-v2",
        "operation-receipt-v1",
        "operation-status-v1",
        "runtime-snapshot-v1",
    }
    assert required <= set(payload["supported_contract_versions"])
    # provisioning-only: no orchestration / evaluation / participant surfaces.
    assert manifest.has_orchestrator is False
    assert manifest.has_evaluator is False
    assert manifest.has_participant_runtime is False


def test_aptl_target_passes_provisioning_only_conformance(tmp_path):
    from aces_conformance.conformance import run_target_conformance

    from aptl.backends.aces import create_aptl_runtime_target

    backend = MagicMock()
    config = AptlConfig(lab={"name": "test"})
    target = create_aptl_runtime_target(
        project_dir=tmp_path,
        config=config,
        backend=backend,
    )

    report = run_target_conformance(target, profile="provisioning-only")

    assert report.passed is True, [d.code for d in report.diagnostics]
    assert report.unsupported_contract_gaps == ()
    assert report.unsupported_capability_gaps == ()


def test_start_aces_scenario_uses_parser_runtime_manager_and_backend(
    mocker,
    tmp_path,
):
    from aptl.backends import aces

    _write_compose(
        tmp_path,
        {
            "wazuh.manager": ["wazuh"],
            "kali": ["kali"],
            "aptl-otel-collector": ["otel"],
        },
    )
    scenario = object()
    parser = mocker.patch("aptl.backends.aces.parse_sdl_file", return_value=scenario)
    calls: dict[str, object] = {}

    class FakeRuntimeManager:
        def __init__(self, target):
            self.target = target

        def plan(self, parsed_scenario):
            calls["planned_scenario"] = parsed_scenario
            return _FakeExecutionPlan(
                _plan_for_nodes("techvault.wazuh-manager", "techvault.kali")
            )

    mocker.patch("aptl.backends.aces.RuntimeManager", FakeRuntimeManager)
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(
        lab={"name": "test"},
        containers={"wazuh": True, "kali": True, "victim": False},
    )

    result = aces.start_aces_scenario(tmp_path, config, backend)

    assert result.success is True
    parser.assert_called_once_with(tmp_path / "scenarios" / "techvault.sdl.yaml")
    assert calls == {"planned_scenario": scenario}
    backend.start.assert_called_once_with(["wazuh", "kali", "otel"])


def test_start_aces_scenario_provisions_despite_evaluation_content(mocker, tmp_path):
    """A scenario carrying evaluation content (e.g. the `conditions` healthcheck
    section) must still provision. APTL is a provisioning-only ACES backend, so
    the planner's `evaluator.missing` error and the resulting invalid plan must
    not block lab standup."""
    from aces_contracts.diagnostics import Diagnostic, Severity

    from aptl.backends import aces

    _write_compose(tmp_path, {"victim": ["victim"]})
    mocker.patch("aptl.backends.aces.parse_sdl_file", return_value=object())

    evaluator_missing = Diagnostic(
        code="evaluator.missing",
        domain="evaluation",
        address="evaluation",
        message="Scenario requires evaluation support, but no evaluator is configured.",
        severity=Severity.ERROR,
    )

    class FakeRuntimeManager:
        def __init__(self, target):
            self.target = target

        def plan(self, parsed_scenario):
            return _FakeExecutionPlan(
                _plan_for_nodes("techvault.victim"),
                is_valid=False,
                diagnostics=[evaluator_missing],
            )

    mocker.patch("aptl.backends.aces.RuntimeManager", FakeRuntimeManager)
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(lab={"name": "test"}, containers={"victim": True})

    result = aces.start_aces_scenario(tmp_path, config, backend)

    assert result.success is True
    backend.start.assert_called_once_with(["victim", "otel"])


def test_start_aces_scenario_fails_closed_on_non_evaluator_plan_error(mocker, tmp_path):
    """A planner error that is NOT the expected evaluation-domain
    `evaluator.missing` (e.g. a provisioning ordering cycle) must fail closed:
    the provisioning-only handoff must refuse to start Compose on an otherwise
    invalid execution plan rather than bypass the gate for every plan."""
    from aces_contracts.diagnostics import Diagnostic, Severity

    from aptl.backends import aces

    _write_compose(tmp_path, {"victim": ["victim"]})
    mocker.patch("aptl.backends.aces.parse_sdl_file", return_value=object())

    provisioning_error = Diagnostic(
        code="provisioning.ordering.cycle",
        domain="provisioning",
        address="provision.node.techvault.victim",
        message="Provisioning ordering cycle detected.",
        severity=Severity.ERROR,
    )

    class FakeRuntimeManager:
        def __init__(self, target):
            self.target = target

        def plan(self, parsed_scenario):
            return _FakeExecutionPlan(
                _plan_for_nodes("techvault.victim"),
                is_valid=False,
                diagnostics=[provisioning_error],
            )

    mocker.patch("aptl.backends.aces.RuntimeManager", FakeRuntimeManager)
    backend = MagicMock()
    config = AptlConfig(lab={"name": "test"}, containers={"victim": True})

    result = aces.start_aces_scenario(tmp_path, config, backend)

    assert result.success is False
    assert result.error
    backend.start.assert_not_called()


def test_provisioner_profiles_are_derived_from_plan_content(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose(
        tmp_path,
        {
            "kali": ["kali"],
            "victim": ["victim"],
            "aptl-otel-collector": ["otel"],
        },
    )
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(
        lab={"name": "test"},
        containers={"kali": True, "victim": True, "wazuh": False},
    )
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=config,
        deployment_backend=backend,
    )

    first = provisioner.apply(_plan_for_nodes("scenario-a.kali"), RuntimeSnapshot())
    second = provisioner.apply(_plan_for_nodes("scenario-b.victim"), RuntimeSnapshot())

    assert first.success is True
    assert second.success is True
    assert backend.start.call_args_list[0].args == (["kali", "otel"],)
    assert backend.start.call_args_list[1].args == (["victim", "otel"],)


def test_provisioner_realization_details_follow_distinct_plan_content(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose(
        tmp_path,
        {
            "kali": ["kali"],
            "victim": ["victim"],
            "aptl-otel-collector": ["otel"],
        },
    )
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(
        lab={"name": "test"},
        containers={"kali": True, "victim": True, "wazuh": False},
    )
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=config,
        deployment_backend=backend,
    )
    attacker = _node_resource("exercise-a.kali")
    attacker.payload["spec"]["node"]["services"] = [
        {"name": "ssh-control", "port": 22, "protocol": "tcp"}
    ]
    attacker.payload["spec"]["runtime"] = {
        "rendered_configs": ["kali-operator.conf"],
        "evidence_paths": ["runs/exercise-a/kali"],
    }
    target = _node_resource("exercise-b.victim")
    target.payload["spec"]["node"]["services"] = [
        {"name": "web-target", "port": 8080, "protocol": "tcp"}
    ]
    target.payload["spec"]["runtime"] = {
        "rendered_configs": ["victim-web.conf"],
        "evidence_paths": ["runs/exercise-b/victim"],
    }

    first = provisioner.apply(_plan_for_resources(attacker), RuntimeSnapshot())
    second = provisioner.apply(_plan_for_resources(target), RuntimeSnapshot())

    assert first.success is True
    assert second.success is True
    assert (
        first.details["realization"]["nodes"] != second.details["realization"]["nodes"]
    )
    assert first.details["realization"]["nodes"][0]["services"] == ["ssh-control"]
    assert second.details["realization"]["nodes"][0]["services"] == ["web-target"]
    assert first.details["realization"]["nodes"][0]["rendered_configs"] == [
        "kali-operator.conf"
    ]
    assert second.details["realization"]["nodes"][0]["rendered_configs"] == [
        "victim-web.conf"
    ]


def test_provisioner_rejects_missing_node_realization_even_with_techvault_metadata(
    tmp_path,
):
    from aptl.backends.aces import AptlProvisioner

    _write_compose(tmp_path, {"kali": ["kali"]})
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}),
        deployment_backend=backend,
    )
    resource = PlannedResource(
        address="provision.node.techvault",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="node",
        payload={
            "name": "techvault",
            "metadata": {"scenario": "techvault"},
            "spec": {"node": {"description": "metadata-only node"}},
        },
    )

    result = provisioner.apply(_plan_for_resources(resource), RuntimeSnapshot())

    assert result.success is False
    assert any(
        diagnostic.code == "aptl.provisioner.node-profile-unresolved"
        and diagnostic.address == resource.address
        for diagnostic in result.diagnostics
    )
    backend.start.assert_not_called()


def test_provisioner_rejects_supported_placement_without_declared_target(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose(tmp_path, {"kali": ["kali"]})
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}),
        deployment_backend=backend,
    )
    node = _node_resource("scenario.kali")
    placement = PlannedResource(
        address="provision.content-placement.payload",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="content-placement",
        payload={
            "name": "payload",
            "content_name": "payload.exe",
            "target_node": "missing-node",
        },
    )

    result = provisioner.apply(_plan_for_resources(node, placement), RuntimeSnapshot())

    assert result.success is False
    assert any(
        diagnostic.code == "aptl.provisioner.binding-target-unresolved"
        and diagnostic.address == placement.address
        for diagnostic in result.diagnostics
    )
    backend.start.assert_not_called()


def test_provisioner_records_supported_placement_realizations(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose(
        tmp_path,
        {
            "kali": ["kali"],
            "aptl-otel-collector": ["otel"],
        },
    )
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}),
        deployment_backend=backend,
    )
    node = _node_resource("scenario.kali")
    feature = PlannedResource(
        address="provision.feature-binding.ssh",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="feature-binding",
        payload={
            "name": "ssh-feature",
            "feature_name": "ssh",
            "node_name": "scenario.kali",
        },
    )
    content = PlannedResource(
        address="provision.content-placement.payload",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="content-placement",
        payload={
            "name": "payload",
            "content_name": "payload.exe",
            "target_address": node.address,
        },
    )
    account = PlannedResource(
        address="provision.account-placement.operator",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="account-placement",
        payload={
            "name": "operator",
            "account_name": "operator",
            "node_name": "scenario.kali",
        },
    )

    result = provisioner.apply(
        _plan_for_resources(node, feature, content, account), RuntimeSnapshot()
    )

    assert result.success is True
    placements = result.details["realization"]["placements"]
    assert {placement["resource_type"] for placement in placements} == {
        "account-placement",
        "content-placement",
        "feature-binding",
    }
    assert {placement["target_address"] for placement in placements} == {node.address}
    assert result.details["realization"]["resource_counts"] == {
        "account-placement": 1,
        "content-placement": 1,
        "feature-binding": 1,
        "node": 1,
    }


def test_provisioner_rejects_unsupported_resource_type(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose(tmp_path, {"kali": ["kali"]})
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}),
        deployment_backend=backend,
    )

    result = provisioner.apply(
        _plan_with_resource_type("packet-capture"), RuntimeSnapshot()
    )

    assert result.success is False
    assert any(
        diagnostic.code == "aptl.provisioner.unsupported-resource-type"
        for diagnostic in result.diagnostics
    )
    backend.start.assert_not_called()


def test_aces_backend_does_not_import_legacy_sdl_parser():
    aces_module = Path(__file__).resolve().parents[1] / "src/aptl/backends/aces.py"
    source = aces_module.read_text()

    assert "aptl.core.sdl" not in source
    assert "ScenarioDefinition" not in source
