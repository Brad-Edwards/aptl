"""Compiler and runtime model tests."""

from __future__ import annotations

import textwrap
from pathlib import Path

from aptl.core.runtime.capabilities import (
    WorkflowFeature,
    WorkflowStatePredicateFeature,
)
from aptl.core.runtime.compiler import compile_runtime_model
from aptl.core.sdl import parse_sdl, parse_sdl_file


def _scenario(yaml_str: str):
    return parse_sdl(textwrap.dedent(yaml_str))


class TestRuntimeModelCompilation:
    def test_feature_template_binds_to_multiple_nodes(self):
        model = compile_runtime_model(_scenario("""
name: bindings
nodes:
  vm1:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    features: {nginx: web}
    roles: {web: appuser}
  vm2:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    features: {nginx: web}
    roles: {web: appuser}
features:
  nginx: {type: service, source: nginx}
"""))

        assert set(model.feature_templates) == {"nginx"}
        assert set(model.feature_bindings) == {
            "provision.feature.vm1.nginx",
            "provision.feature.vm2.nginx",
        }
        assert model.feature_bindings["provision.feature.vm1.nginx"].node_name == "vm1"
        assert model.feature_bindings["provision.feature.vm2.nginx"].node_name == "vm2"

    def test_feature_binding_tracks_same_node_dependencies(self):
        model = compile_runtime_model(_scenario("""
name: feature-deps
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    features: {nginx: web, php-config: web}
    roles: {web: appuser}
features:
  nginx: {type: service, source: nginx}
  php-config: {type: configuration, source: php-config, dependencies: [nginx]}
"""))

        binding = model.feature_bindings["provision.feature.vm.php-config"]

        assert binding.ordering_dependencies == (
            "provision.node.vm",
            "provision.feature.vm.nginx",
        )
        assert binding.refresh_dependencies == (
            "provision.node.vm",
            "provision.feature.vm.nginx",
        )
        assert not model.diagnostics

    def test_missing_same_node_feature_dependency_emits_diagnostic(self):
        model = compile_runtime_model(_scenario("""
name: feature-deps
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    features: {php-config: web}
    roles: {web: appuser}
features:
  nginx: {type: service, source: nginx}
  php-config: {type: configuration, source: php-config, dependencies: [nginx]}
"""))

        binding = model.feature_bindings["provision.feature.vm.php-config"]
        diagnostics = {(diag.code, diag.address) for diag in model.diagnostics}

        assert (
            "provisioning.feature-dependency-binding-missing",
            "provision.feature.vm.php-config",
        ) in diagnostics
        assert binding.ordering_dependencies == ("provision.node.vm",)
        assert binding.refresh_dependencies == ("provision.node.vm",)

    def test_condition_and_inject_resources_preserve_context(self):
        model = compile_runtime_model(_scenario("""
name: bindings
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    injects: {phish: ops}
    roles: {ops: operator}
conditions:
  health: {command: /bin/true, interval: 10}
injects:
  phish: {source: phishing-bundle}
"""))

        condition = model.condition_bindings["evaluation.condition.vm.health"]
        inject = model.injects["orchestration.inject.phish"]
        inject_binding = model.inject_bindings["orchestration.inject-binding.vm.phish"]

        assert condition.node_name == "vm"
        assert condition.role_name == "ops"
        assert condition.template_address == "template.condition.health"
        assert inject.name == "phish"
        assert inject.spec["source"]["name"] == "phishing-bundle"
        assert inject_binding.node_name == "vm"
        assert inject_binding.role_name == "ops"
        assert inject_binding.template_address == "template.inject.phish"
        assert inject_binding.ordering_dependencies == (
            "orchestration.inject.phish",
        )
        assert inject_binding.refresh_dependencies == (
            "provision.node.vm",
            "orchestration.inject.phish",
        )
        assert condition.result_contract.resource_type == "condition-binding"
        assert condition.result_contract.supports_passed is True
        assert condition.execution_contract.requires_start_event is True

    def test_objective_windows_and_workflows_resolve_refresh_dependencies(self):
        model = compile_runtime_model(_scenario("""
name: orchestration
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
    success: {conditions: [health], metrics: [uptime]}
    window:
      stories: [main]
      scripts: [timeline]
      events: [kickoff]
      workflows: [flow]
      steps: [flow.branch]
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
      start: {type: objective, objective: initial, on-success: branch}
      branch:
        type: decision
        when: {conditions: [health]}
        then: end
        else: end
      end: {type: end}
"""))

        objective = model.objectives["evaluation.objective.initial"]
        workflow = model.workflows["orchestration.workflow.flow"]

        assert "evaluation.metric.uptime" in objective.success_addresses
        assert "evaluation.condition.vm.health" in objective.success_addresses
        assert objective.window_story_addresses == ("orchestration.story.main",)
        assert objective.window_script_addresses == ("orchestration.script.timeline",)
        assert objective.window_event_addresses == ("orchestration.event.kickoff",)
        assert objective.window_workflow_addresses == ("orchestration.workflow.flow",)
        assert objective.window_step_refs == ("flow.branch",)
        assert objective.window_step_workflow_addresses == ("orchestration.workflow.flow",)
        assert [ref.reference_kind for ref in objective.window_references] == [
            "story",
            "script",
            "event",
            "workflow",
            "workflow_step",
        ]
        assert objective.window_references[-1].workflow_name == "flow"
        assert objective.window_references[-1].step_name == "branch"
        assert "evaluation.metric.uptime" in objective.ordering_dependencies
        assert "orchestration.workflow.flow" in objective.refresh_dependencies
        assert workflow.referenced_objective_addresses == ("evaluation.objective.initial",)
        assert workflow.start_step == "start"
        assert workflow.control_steps["start"].on_success == "branch"
        assert workflow.result_contract.observable_steps["start"].observable_outcomes == (
            "succeeded",
            "failed",
        )
        assert workflow.control_steps["start"].state_contract.observable_outcomes == (
            "succeeded",
            "failed",
        )
        assert workflow.control_steps["branch"].step_type == "decision"
        assert not workflow.control_steps["branch"].state_contract.state_observable
        assert workflow.control_edges["start"] == ("branch",)
        assert workflow.control_edges["branch"] == ("end",)
        assert workflow.step_condition_addresses["branch"] == ("evaluation.condition.vm.health",)
        assert "evaluation.condition.vm.health" in workflow.step_predicate_addresses["branch"]
        assert workflow.ordering_dependencies == ()
        assert "evaluation.objective.initial" in workflow.refresh_dependencies
        assert model.metrics["evaluation.metric.uptime"].result_contract.supports_score is True
        assert model.metrics["evaluation.metric.uptime"].result_contract.fixed_max_score == 100
        assert model.objectives["evaluation.objective.initial"].result_contract.supports_passed is True

    def test_objective_window_step_outside_window_workflows_emits_diagnostic(self):
        model = compile_runtime_model(
            parse_sdl(
                textwrap.dedent("""
name: broken-window
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    roles: {ops: operator}
conditions:
  health: {command: /bin/true, interval: 15}
entities:
  blue: {role: blue}
objectives:
  initial:
    entity: blue
    success: {conditions: [health]}
    window:
      workflows: [flow]
      steps: [other.finish]
workflows:
  flow:
    start: finish
    steps:
      finish: {type: end}
  other:
    start: finish
    steps:
      finish: {type: end}
"""),
                skip_semantic_validation=True,
            )
        )

        diagnostics = {(diag.code, diag.address) for diag in model.diagnostics}
        assert (
            "evaluation.workflow-step-ref-workflow-outside-window",
            "evaluation.objective.initial",
        ) in diagnostics

    def test_missing_node_bindings_emit_diagnostics_without_crashing(self):
        model = compile_runtime_model(
            parse_sdl(
                textwrap.dedent("""
name: broken-bindings
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    features: {nginx: web}
    conditions: {health: web}
    injects: {phish: web}
    roles: {web: appuser}
"""),
                skip_semantic_validation=True,
            )
        )

        codes = {diag.code for diag in model.diagnostics}
        assert "provisioning.feature-template-ref-unbound" in codes
        assert "evaluation.condition-template-ref-unbound" in codes
        assert "orchestration.inject-template-ref-unbound" in codes
        assert model.feature_bindings == {}
        assert model.condition_bindings == {}
        assert model.inject_bindings == {}

    def test_missing_runtime_graph_refs_emit_partial_model_diagnostics(self):
        model = compile_runtime_model(
            parse_sdl(
                textwrap.dedent("""
name: broken-graph
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
evaluations:
  overall: {metrics: [uptime, missing-metric], min-score: 50}
tlos:
  defend: {evaluation: missing-evaluation}
goals:
  pass: {tlos: [missing-tlo]}
objectives:
  initial:
    entity: blue
    success:
      metrics: [missing-metric]
      goals: [missing-goal]
    window:
      workflows: [missing-workflow]
      steps: [missing-workflow.branch, badstep]
entities:
  blue: {role: blue}
scripts:
  timeline: {start-time: 0, end-time: 60, speed: 1, events: {missing-event: 10}}
stories:
  main: {scripts: [missing-script]}
workflows:
  flow:
    start: branch
    steps:
      branch:
        type: decision
        when: {metrics: [missing-metric], objectives: [missing-objective]}
        then: finish
        else: finish
      finish: {type: end}
"""),
                skip_semantic_validation=True,
            )
        )

        codes = {diag.code for diag in model.diagnostics}
        assert "orchestration.event-ref-unbound" in codes
        assert "orchestration.script-ref-unbound" in codes
        assert "evaluation.metric-ref-unbound" in codes
        assert "evaluation.evaluation-ref-unbound" in codes
        assert "evaluation.tlo-ref-unbound" in codes
        assert "evaluation.goal-ref-unbound" in codes
        assert "evaluation.workflow-ref-unbound" in codes
        assert "evaluation.workflow-step-ref-workflow-unbound" in codes
        assert "evaluation.workflow-step-ref-invalid-format" in codes
        assert "orchestration.metric-ref-unbound" in codes
        assert "orchestration.objective-ref-unbound" in codes

        assert model.scripts["orchestration.script.timeline"].event_addresses == ()
        assert model.stories["orchestration.story.main"].script_addresses == ()
        assert model.evaluations["evaluation.evaluation.overall"].metric_addresses == (
            "evaluation.metric.uptime",
        )
        assert model.tlos["evaluation.tlo.defend"].evaluation_address == ""
        assert model.goals["evaluation.goal.pass"].tlo_addresses == ()
        assert model.objectives["evaluation.objective.initial"].success_addresses == ()
        assert model.objectives["evaluation.objective.initial"].window_workflow_addresses == ()
        assert model.objectives["evaluation.objective.initial"].window_step_refs == ()
        assert model.workflows["orchestration.workflow.flow"].referenced_objective_addresses == ()

    def test_workflow_with_retry_and_step_state_compiles(self):
        model = compile_runtime_model(_scenario("""
name: retry-test
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    roles: {ops: operator}
conditions:
  health: {command: /bin/true, interval: 15}
entities:
  blue: {role: blue}
metrics:
  uptime: {type: conditional, max-score: 100, condition: health}
objectives:
  attempt:
    entity: blue
    success: {conditions: [health]}
  recover:
    entity: blue
    success: {metrics: [uptime]}
workflows:
  retry:
    start: attempt-loop
    steps:
      attempt-loop:
        type: retry
        objective: attempt
        on-success: branch
        max-attempts: 3
        on-exhausted: handle-error
      branch:
        type: decision
        when:
          conditions: [health]
          steps:
            - step: attempt-loop
              outcomes: [succeeded]
        then: done
        else: handle-error
      handle-error:
        type: objective
        objective: recover
        on-success: done
      done: {type: end}
"""))

        workflow = model.workflows["orchestration.workflow.retry"]
        assert workflow.control_steps["attempt-loop"].step_type == "retry"
        assert workflow.control_steps["attempt-loop"].objective_address == (
            "evaluation.objective.attempt"
        )
        assert workflow.control_steps["attempt-loop"].max_attempts == 3
        predicate = workflow.control_steps["branch"].predicate
        assert predicate is not None
        assert predicate.step_state_predicates[0].step_name == "attempt-loop"
        assert set(workflow.required_features) == {
            WorkflowFeature.DECISION,
            WorkflowFeature.RETRY,
            WorkflowFeature.FAILURE_TRANSITIONS,
        }
        assert set(workflow.required_state_predicate_features) == {
            WorkflowStatePredicateFeature.OUTCOME_MATCHING,
        }
        assert workflow.referenced_objective_addresses == (
            "evaluation.objective.attempt",
            "evaluation.objective.recover",
        )
        assert "evaluation.condition.vm.health" in workflow.step_predicate_addresses["branch"]

    def test_parallel_join_compiles_as_barrier_with_typed_predicate(self):
        model = compile_runtime_model(_scenario("""
name: parallel-join
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    roles: {ops: operator}
conditions:
  health: {command: /bin/true, interval: 15}
entities:
  blue: {role: blue}
objectives:
  left:
    entity: blue
    success: {conditions: [health]}
  right:
    entity: blue
    success: {conditions: [health]}
  recover:
    entity: blue
    success: {conditions: [health]}
workflows:
  flow:
    start: fanout
    steps:
      fanout:
        type: parallel
        branches: [left-branch, right-branch]
        join: joined
        on-failure: recover-step
      left-branch:
        type: objective
        objective: left
        on-success: joined
      right-branch:
        type: objective
        objective: right
        on-success: joined
      joined:
        type: join
        next: branch
      branch:
        type: decision
        when:
          steps:
            - step: left-branch
              outcomes: [succeeded]
              min-attempts: 2
        then: finish
        else: recover-step
      recover-step:
        type: objective
        objective: recover
        on-success: finish
      finish: {type: end}
"""))

        workflow = model.workflows["orchestration.workflow.flow"]
        assert workflow.control_edges["fanout"] == ("left-branch", "right-branch", "recover-step")
        assert workflow.join_owners == {"joined": "fanout"}
        assert workflow.control_steps["joined"].owning_parallel_step == "fanout"
        assert set(workflow.result_contract.observable_steps) == {
            "fanout",
            "left-branch",
            "right-branch",
            "recover-step",
        }
        assert workflow.control_steps["fanout"].state_contract.observable_outcomes == (
            "succeeded",
            "failed",
        )
        assert workflow.control_steps["fanout"].state_contract.fixed_attempts == 1
        assert not workflow.control_steps["joined"].state_contract.state_observable
        predicate = workflow.control_steps["branch"].predicate
        assert predicate is not None
        assert predicate.step_state_predicates == (
            predicate.step_state_predicates[0],
        )
        assert predicate.step_state_predicates[0].step_name == "left-branch"
        assert predicate.step_state_predicates[0].min_attempts == 2
        assert set(workflow.required_features) == {
            WorkflowFeature.DECISION,
            WorkflowFeature.PARALLEL_BARRIER,
            WorkflowFeature.FAILURE_TRANSITIONS,
        }
        assert set(workflow.required_state_predicate_features) == {
            WorkflowStatePredicateFeature.OUTCOME_MATCHING,
            WorkflowStatePredicateFeature.ATTEMPT_COUNTS,
        }

    def test_module_expansion_compiles_like_flat_scenario(self, tmp_path: Path):
        imported = tmp_path / "shared.yaml"
        imported.write_text(
            """
name: shared
version: 1.0.0
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    roles: {ops: operator}
conditions:
  health:
    command: /bin/true
    interval: 15
entities:
  blue:
    role: blue
objectives:
  validate:
    entity: blue
    success:
      conditions: [health]
workflows:
  response:
    start: run
    steps:
      run:
        type: objective
        objective: validate
        on-success: finish
      finish:
        type: end
""",
            encoding="utf-8",
        )
        root = tmp_path / "root.yaml"
        root.write_text(
            """
name: root
imports:
  - path: shared.yaml
    namespace: shared
    version: 1.0.0
""",
            encoding="utf-8",
        )
        flat = parse_sdl(
            textwrap.dedent(
                """
                name: root
                nodes:
                  shared.vm:
                    type: vm
                    os: linux
                    resources: {ram: 1 gib, cpu: 1}
                    conditions: {shared.health: ops}
                    roles: {ops: operator}
                conditions:
                  shared.health:
                    command: /bin/true
                    interval: 15
                entities:
                  shared.blue:
                    role: blue
                objectives:
                  shared.validate:
                    entity: shared.blue
                    success:
                      conditions: [shared.health]
                workflows:
                  shared.response:
                    start: run
                    steps:
                      run:
                        type: objective
                        objective: shared.validate
                        on-success: finish
                      finish:
                        type: end
                """
            )
        )

        expanded_model = compile_runtime_model(parse_sdl_file(root))
        flat_model = compile_runtime_model(flat)

        assert expanded_model.workflows.keys() == flat_model.workflows.keys()
        assert expanded_model.objectives.keys() == flat_model.objectives.keys()
        assert expanded_model.condition_bindings.keys() == flat_model.condition_bindings.keys()

    def test_workflow_switch_call_and_timeout_compile_to_explicit_contracts(self):
        model = compile_runtime_model(
            parse_sdl(
                textwrap.dedent(
                    """
                    name: advanced-workflow
                    nodes:
                      vm:
                        type: vm
                        os: linux
                        resources: {ram: 1 gib, cpu: 1}
                        conditions: {health: ops}
                        roles: {ops: operator}
                    conditions:
                      health: {command: /bin/true, interval: 15}
                    entities:
                      blue: {role: blue}
                    objectives:
                      validate:
                        entity: blue
                        success: {conditions: [health]}
                    workflows:
                      child:
                        start: run
                        steps:
                          run:
                            type: objective
                            objective: validate
                            on-success: finish
                          finish: {type: end}
                      parent:
                        start: route
                        timeout: 300
                        steps:
                          route:
                            type: switch
                            cases:
                              - when: {conditions: [health]}
                                next: delegate
                            default: finish
                          delegate:
                            type: call
                            workflow: child
                            on-success: finish
                          finish: {type: end}
                    """
                )
            )
        )

        workflow = model.workflows["orchestration.workflow.parent"]

        assert workflow.execution_contract.timeout_seconds == 300
        assert workflow.execution_contract.step_types["route"] == "switch"
        assert workflow.execution_contract.step_types["delegate"] == "call"
        assert workflow.execution_contract.call_steps["delegate"] == "orchestration.workflow.child"
        assert workflow.control_steps["route"].default_step == "finish"
        assert workflow.control_steps["route"].switch_cases[0].next_step == "delegate"
        assert workflow.control_steps["delegate"].called_workflow_address == "orchestration.workflow.child"
        assert workflow.result_contract.observable_steps["delegate"].observable_outcomes == (
            "succeeded",
            "failed",
        )
