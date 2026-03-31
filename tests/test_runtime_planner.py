"""Planner tests for the SDL-native runtime layer."""

from __future__ import annotations

import textwrap
from pathlib import Path

from aptl.backends.stubs import create_stub_manifest
from aptl.core.runtime.capabilities import (
    BackendManifest,
    EvaluatorCapabilities,
    OrchestratorCapabilities,
    ProvisionerCapabilities,
)
from aptl.core.runtime.compiler import compile_runtime_model
from aptl.core.runtime.models import RuntimeDomain, RuntimeSnapshot, SnapshotEntry
from aptl.core.runtime.planner import plan
from aptl.core.sdl import parse_sdl


def _scenario(yaml_str: str):
    return parse_sdl(textwrap.dedent(yaml_str))


def _snapshot_from_plan(execution_plan) -> RuntimeSnapshot:
    entries: dict[str, SnapshotEntry] = {}
    for domain, operations in (
        (RuntimeDomain.PROVISIONING, execution_plan.provisioning.operations),
        (RuntimeDomain.ORCHESTRATION, execution_plan.orchestration.operations),
        (RuntimeDomain.EVALUATION, execution_plan.evaluation.operations),
    ):
        for op in operations:
            if op.action.value == "delete":
                continue
            entries[op.address] = SnapshotEntry(
                address=op.address,
                domain=domain,
                resource_type=op.resource_type,
                payload=op.payload,
                ordering_dependencies=op.ordering_dependencies,
                refresh_dependencies=op.refresh_dependencies,
                status="snapshot",
            )
    return RuntimeSnapshot(entries=entries)


def _plan_with_snapshot(yaml_str: str, snapshot: RuntimeSnapshot):
    return plan(compile_runtime_model(_scenario(yaml_str)), create_stub_manifest(), snapshot)


class TestRuntimePlanner:
    def test_plan_records_provenance(self):
        snapshot = RuntimeSnapshot(metadata={"seed": "planner"})
        manifest = create_stub_manifest()

        execution_plan = plan(
            compile_runtime_model(_scenario("""
name: provenance
nodes:
  vm: {type: vm, os: linux, resources: {ram: 1 gib, cpu: 1}}
""")),
            manifest,
            snapshot,
            target_name="custom-target",
        )

        assert execution_plan.target_name == "custom-target"
        assert execution_plan.manifest == manifest
        assert execution_plan.base_snapshot == snapshot

    def test_delete_operations_emitted_for_removed_resources(self):
        old_model = compile_runtime_model(_scenario("""
name: original
nodes:
  vm1: {type: vm, os: linux, resources: {ram: 1 gib, cpu: 1}}
  vm2: {type: vm, os: linux, resources: {ram: 1 gib, cpu: 1}}
"""))
        old_plan = plan(old_model, create_stub_manifest())
        snapshot = _snapshot_from_plan(old_plan)

        new_model = compile_runtime_model(_scenario("""
name: original
nodes:
  vm1: {type: vm, os: linux, resources: {ram: 1 gib, cpu: 1}}
"""))
        new_plan = plan(new_model, create_stub_manifest(), snapshot)

        delete_ops = {
            op.address: op.action.value
            for op in new_plan.provisioning.operations
            if op.action.value == "delete"
        }
        assert delete_ops == {"provision.node.vm2": "delete"}

    def test_dependency_changes_propagate_through_evaluation_graph(self):
        old_model = compile_runtime_model(_scenario("""
name: original
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    roles: {ops: operator}
conditions:
  health: {command: /bin/true, interval: 15}
metrics:
  uptime: {type: conditional, max-score: 100, condition: health}
"""))
        old_plan = plan(old_model, create_stub_manifest())
        snapshot = _snapshot_from_plan(old_plan)

        new_plan = _plan_with_snapshot("""
name: original
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    roles: {ops: operator}
conditions:
  health: {command: /bin/false, interval: 15}
metrics:
  uptime: {type: conditional, max-score: 100, condition: health}
""", snapshot)

        eval_actions = {op.address: op.action.value for op in new_plan.evaluation.operations}
        assert eval_actions["evaluation.condition.vm.health"] == "update"
        assert eval_actions["evaluation.metric.uptime"] == "update"

    def test_ambiguous_condition_refs_fail_closed(self):
        execution_plan = plan(
            compile_runtime_model(_scenario("""
name: ambiguous
nodes:
  a:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    roles: {ops: operator}
  b:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    roles: {ops: operator}
conditions:
  health: {command: /bin/true, interval: 15}
events:
  kickoff: {conditions: [health]}
""")),
            create_stub_manifest(),
        )

        codes = {diag.code for diag in execution_plan.diagnostics}
        assert "orchestration.condition-ref-ambiguous" in codes
        assert not execution_plan.is_valid

    def test_top_level_inject_refs_resolve_directly(self):
        execution_plan = plan(
            compile_runtime_model(_scenario("""
name: injects
nodes:
  web:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
injects:
  mail: {source: inbox}
events:
  kickoff: {injects: [mail]}
""")),
            create_stub_manifest(),
        )

        kickoff = execution_plan.model.events["orchestration.event.kickoff"]
        assert kickoff.inject_addresses == ("orchestration.inject.mail",)
        assert execution_plan.is_valid

    def test_unbound_condition_and_inject_refs_invalidate_plan(self):
        scenario = _scenario("""
name: unbound
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
conditions:
  health: {command: /bin/true, interval: 15}
injects:
  mail: {source: inbox}
metrics:
  uptime: {type: conditional, max-score: 100, condition: health}
events:
  kickoff: {conditions: [health], injects: [mail]}
""")
        scenario.injects = {}

        execution_plan = plan(
            compile_runtime_model(scenario),
            create_stub_manifest(),
        )

        codes = {diag.code for diag in execution_plan.diagnostics}
        assert "evaluation.condition-ref-unbound" in codes
        assert "orchestration.condition-ref-unbound" in codes
        assert "orchestration.inject-ref-unbound" in codes
        assert not execution_plan.is_valid

    def test_workflow_condition_refs_require_orchestrator_support(self):
        limited = BackendManifest(
            name="limited",
            provisioner=create_stub_manifest().provisioner,
            orchestrator=OrchestratorCapabilities(
                name="limited-orchestrator",
                supported_sections=frozenset({"workflows"}),
                supports_workflows=True,
                supports_condition_refs=False,
            ),
            evaluator=create_stub_manifest().evaluator,
        )

        execution_plan = plan(
            compile_runtime_model(_scenario("""
name: workflows
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    roles: {ops: operator}
conditions:
  health: {command: /bin/true, interval: 15}
workflows:
  flow:
    start: branch
    steps:
      branch:
        type: if
        when: {conditions: [health]}
        then: finish
        else: finish
      finish: {type: end}
""")),
            limited,
        )

        codes = {diag.code for diag in execution_plan.diagnostics}
        assert "orchestrator.condition-refs-unsupported" in codes
        assert not execution_plan.is_valid

    def test_workflow_condition_bindings_force_workflow_refresh(self):
        old_model = compile_runtime_model(_scenario("""
name: workflow
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    roles: {ops: operator}
conditions:
  health: {command: /bin/true, interval: 15}
objectives:
  initial:
    entity: blue
    success: {conditions: [health]}
entities:
  blue: {role: blue}
workflows:
  flow:
    start: branch
    steps:
      branch:
        type: if
        when: {conditions: [health]}
        then: finish
        else: finish
      finish: {type: end}
"""))
        old_plan = plan(old_model, create_stub_manifest())
        snapshot = _snapshot_from_plan(old_plan)

        new_plan = _plan_with_snapshot("""
name: workflow
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    roles: {ops: operator}
conditions:
  health: {command: /bin/false, interval: 15}
objectives:
  initial:
    entity: blue
    success: {conditions: [health]}
entities:
  blue: {role: blue}
workflows:
  flow:
    start: branch
    steps:
      branch:
        type: if
        when: {conditions: [health]}
        then: finish
        else: finish
      finish: {type: end}
""", snapshot)

        orchestration_actions = {
            op.address: op.action.value for op in new_plan.orchestration.operations
        }
        assert orchestration_actions["orchestration.workflow.flow"] == "update"

    def test_cross_domain_refresh_dependencies_do_not_drive_ordering(self):
        base = """
name: cross-domain
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    injects: {mail: ops}
    roles: {ops: operator}
conditions:
  health: {command: /bin/true, interval: 15}
injects:
  mail: {source: inbox}
events:
  kickoff: {conditions: [health], injects: [mail]}
"""
        old_model = compile_runtime_model(_scenario(base))
        kickoff = old_model.events["orchestration.event.kickoff"]
        assert "evaluation.condition.vm.health" not in kickoff.ordering_dependencies
        assert "evaluation.condition.vm.health" in kickoff.refresh_dependencies
        assert "orchestration.inject.mail" in kickoff.ordering_dependencies

        old_plan = plan(old_model, create_stub_manifest())
        snapshot = _snapshot_from_plan(old_plan)
        new_plan = _plan_with_snapshot(
            base.replace("/bin/true", "/bin/false"),
            snapshot,
        )

        orchestration_actions = {
            op.address: op.action.value for op in new_plan.orchestration.operations
        }
        assert orchestration_actions["orchestration.event.kickoff"] == "update"

    def test_objective_window_refs_are_refresh_only(self):
        model = compile_runtime_model(_scenario("""
name: objective-window
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    roles: {ops: operator}
conditions:
  health: {command: /bin/true, interval: 15}
metrics:
  uptime: {type: conditional, max-score: 100, condition: health}
objectives:
  initial:
    entity: blue
    success: {metrics: [uptime]}
    window:
      workflows: [flow]
      steps: [flow.branch]
entities:
  blue: {role: blue}
workflows:
  flow:
    start: branch
    steps:
      branch:
        type: if
        when: {conditions: [health]}
        then: finish
        else: finish
      finish: {type: end}
"""))

        objective = model.objectives["evaluation.objective.initial"]
        execution_plan = plan(model, create_stub_manifest())

        assert "orchestration.workflow.flow" not in objective.ordering_dependencies
        assert "orchestration.workflow.flow" in objective.refresh_dependencies
        assert execution_plan.evaluation.startup_order == [
            "evaluation.condition.vm.health",
            "evaluation.metric.uptime",
            "evaluation.objective.initial",
        ]

    def test_objective_updates_when_window_dependencies_change(self):
        base = """
name: windows
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    roles: {ops: operator}
conditions:
  health: {command: /bin/true, interval: 15}
metrics:
  uptime: {type: conditional, max-score: 100, condition: health}
objectives:
  initial:
    entity: blue
    success: {metrics: [uptime]}
    window:
      scripts: [timeline]
      events: [kickoff]
      workflows: [flow]
      steps: [flow.branch]
entities:
  blue: {role: blue}
events:
  kickoff: {conditions: [health], description: kickoff}
scripts:
  timeline: {start-time: 0, end-time: 60, speed: 1, events: {kickoff: 10}}
workflows:
  flow:
    description: primary
    start: branch
    steps:
      branch:
        type: if
        when: {conditions: [health]}
        then: finish
        else: finish
      finish: {type: end}
"""
        old_plan = plan(compile_runtime_model(_scenario(base)), create_stub_manifest())
        snapshot = _snapshot_from_plan(old_plan)

        changed_variants = [
            base.replace("end-time: 60", "end-time: 120"),
            base.replace("description: kickoff", "description: changed"),
            base.replace("description: primary", "description: updated"),
            base.replace("then: finish", "then: finish\n        description: changed"),
        ]
        for changed in changed_variants:
            new_plan = _plan_with_snapshot(changed, snapshot)
            actions = {op.address: op.action.value for op in new_plan.evaluation.operations}
            assert actions["evaluation.objective.initial"] == "update"

    def test_content_and_account_refresh_only_on_node_changes(self):
        old_model = compile_runtime_model(_scenario("""
name: provision
nodes:
  web:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    features: {nginx: web}
    roles: {web: appuser}
features:
  nginx: {type: service, source: nginx}
content:
  flag: {type: file, target: web, path: /tmp/flag.txt}
accounts:
  admin: {username: admin, node: web}
"""))
        old_plan = plan(old_model, create_stub_manifest())
        snapshot = _snapshot_from_plan(old_plan)

        feature_change_plan = _plan_with_snapshot("""
name: provision
nodes:
  web:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    features: {nginx: web}
    roles: {web: appuser}
features:
  nginx: {type: service, source: nginx-full}
content:
  flag: {type: file, target: web, path: /tmp/flag.txt}
accounts:
  admin: {username: admin, node: web}
""", snapshot)
        feature_actions = {
            op.address: op.action.value for op in feature_change_plan.provisioning.operations
        }
        assert feature_actions["provision.feature.web.nginx"] == "update"
        assert feature_actions["provision.content.flag"] == "unchanged"
        assert feature_actions["provision.account.admin"] == "unchanged"

        node_change_plan = _plan_with_snapshot("""
name: provision
nodes:
  web:
    type: vm
    os: windows
    resources: {ram: 1 gib, cpu: 1}
    features: {nginx: web}
    roles: {web: appuser}
features:
  nginx: {type: service, source: nginx}
content:
  flag: {type: file, target: web, path: /tmp/flag.txt}
accounts:
  admin: {username: admin, node: web}
""", snapshot)
        node_actions = {
            op.address: op.action.value for op in node_change_plan.provisioning.operations
        }
        assert node_actions["provision.node.web"] == "update"
        assert node_actions["provision.content.flag"] == "update"
        assert node_actions["provision.account.admin"] == "update"

    def test_semantic_capability_validation_catches_real_requirements(self):
        limited = BackendManifest(
            name="limited",
            provisioner=ProvisionerCapabilities(
                name="limited-provisioner",
                supported_node_types=frozenset({"vm", "switch"}),
                supported_os_families=frozenset({"linux"}),
                supported_content_types=frozenset({"file"}),
                supported_account_features=frozenset(),
                max_total_nodes=1,
                supports_acls=False,
                supports_accounts=True,
            ),
            orchestrator=OrchestratorCapabilities(
                name="limited-orchestrator",
                supported_sections=frozenset({"events", "scripts", "stories"}),
                supports_workflows=False,
            ),
            evaluator=EvaluatorCapabilities(
                name="limited-evaluator",
                supported_sections=frozenset({"conditions", "metrics"}),
                supports_scoring=True,
                supports_objectives=False,
            ),
        )

        model = compile_runtime_model(_scenario("""
name: limited
nodes:
  corp: {type: switch}
  dc:
    type: vm
    os: windows
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    roles: {ops: operator}
infrastructure:
  corp:
    count: 1
    properties: {cidr: 10.0.0.0/24, gateway: 10.0.0.1}
    acls:
      - {direction: in, from-net: corp, action: allow}
  dc: {count: 1, links: [corp]}
accounts:
  admin: {username: administrator, node: dc, spn: LDAP/dc.example.local}
conditions:
  health: {command: /bin/true, interval: 15}
metrics:
  uptime: {type: conditional, max-score: 100, condition: health}
objectives:
  defend:
    entity: blue
    success: {conditions: [health]}
entities:
  blue: {role: blue}
events:
  kickoff: {conditions: [health]}
scripts:
  timeline: {start-time: 0, end-time: 60, speed: 1, events: {kickoff: 10}}
stories:
  main: {scripts: [timeline]}
workflows:
  flow:
    start: start
    steps:
      start: {type: objective, objective: defend, next: end}
      end: {type: end}
"""))
        execution_plan = plan(model, limited)
        codes = {diag.code for diag in execution_plan.diagnostics}

        assert "provisioner.unsupported-os-family" in codes
        assert "provisioner.max-total-nodes-exceeded" in codes
        assert "provisioner.acls-unsupported" in codes
        assert "provisioner.unsupported-account-feature" in codes
        assert "orchestrator.unsupported-section" in codes
        assert "orchestrator.workflows-unsupported" in codes
        assert "evaluator.unsupported-section" in codes
        assert "evaluator.objectives-unsupported" in codes
        assert not execution_plan.is_valid

    def test_dependency_ordering_across_domain_plans(self):
        execution_plan = plan(
            compile_runtime_model(_scenario("""
name: ordering
nodes:
  corp: {type: switch}
  web:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    features: {nginx: web}
    conditions: {health: web}
    injects: {mail: web}
    roles: {web: appuser}
infrastructure:
  corp: {count: 1, properties: {cidr: 10.0.0.0/24, gateway: 10.0.0.1}}
  web: {count: 1, links: [corp]}
features:
  nginx: {type: service, source: nginx}
content:
  flag: {type: file, target: web, path: /tmp/flag.txt}
accounts:
  admin: {username: admin, node: web}
conditions:
  health: {command: /bin/true, interval: 15}
injects:
  mail: {source: inbox}
metrics:
  uptime: {type: conditional, max-score: 100, condition: health}
evaluations:
  overall: {metrics: [uptime], min-score: 50}
tlos:
  defend: {evaluation: overall}
goals:
  pass: {tlos: [defend]}
objectives:
  initial:
    entity: blue
    success: {metrics: [uptime], goals: [pass]}
entities:
  blue: {role: blue}
events:
  kickoff: {conditions: [health], injects: [mail]}
scripts:
  timeline: {start-time: 0, end-time: 60, speed: 1, events: {kickoff: 10}}
stories:
  main: {scripts: [timeline]}
workflows:
  flow:
    start: start
    steps:
      start: {type: objective, objective: initial, next: end}
      end: {type: end}
""")),
            create_stub_manifest(),
        )

        provision_order = [
            op.address
            for op in execution_plan.provisioning.operations
            if op.action.value != "delete"
        ]
        orchestration_order = execution_plan.orchestration.startup_order
        evaluation_order = execution_plan.evaluation.startup_order

        assert provision_order.index("provision.network.corp") < provision_order.index("provision.node.web")
        assert provision_order.index("provision.node.web") < provision_order.index("provision.feature.web.nginx")
        assert provision_order.index("provision.node.web") < provision_order.index("provision.content.flag")
        assert provision_order.index("provision.node.web") < provision_order.index("provision.account.admin")
        assert orchestration_order.index("orchestration.inject.mail") < orchestration_order.index("orchestration.inject-binding.web.mail")
        assert orchestration_order.index("orchestration.inject-binding.web.mail") < orchestration_order.index("orchestration.event.kickoff")
        assert orchestration_order.index("orchestration.event.kickoff") < orchestration_order.index("orchestration.script.timeline")
        assert orchestration_order.index("orchestration.script.timeline") < orchestration_order.index("orchestration.story.main")
        assert evaluation_order.index("evaluation.condition.web.health") < evaluation_order.index("evaluation.metric.uptime")
        assert evaluation_order.index("evaluation.metric.uptime") < evaluation_order.index("evaluation.evaluation.overall")
        assert evaluation_order.index("evaluation.evaluation.overall") < evaluation_order.index("evaluation.tlo.defend")
        assert evaluation_order.index("evaluation.tlo.defend") < evaluation_order.index("evaluation.goal.pass")
        assert evaluation_order.index("evaluation.goal.pass") < evaluation_order.index("evaluation.objective.initial")

    def test_satcom_release_poisoning_compiles_to_valid_execution_plan(self):
        content = Path("examples/satcom-release-poisoning.sdl.yaml").read_text(encoding="utf-8")
        model = compile_runtime_model(parse_sdl(content))
        execution_plan = plan(model, create_stub_manifest())

        assert execution_plan.is_valid
        assert len(model.node_deployments) > 5
        assert len(model.feature_bindings) > 5
        assert len(model.injects) > 0
        assert len(model.objectives) > 0
        assert len(model.workflows) > 0
        assert len(execution_plan.provisioning.operations) > 0
        assert len(execution_plan.orchestration.startup_order) > 0
        assert len(execution_plan.evaluation.startup_order) > 0
