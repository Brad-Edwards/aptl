"""Cross-stage FM2 semantic agreement tests."""

from __future__ import annotations

import textwrap

import pytest

from aptl.backends.stubs import create_stub_manifest
from aptl.core.runtime.compiler import compile_runtime_model
from aptl.core.runtime.models import RuntimeDomain, RuntimeSnapshot, SnapshotEntry
from aptl.core.runtime.planner import plan
from aptl.core.sdl import SDLValidationError, parse_sdl


def _scenario(yaml_str: str):
    return textwrap.dedent(yaml_str)


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


class TestObjectiveWindowAgreement:
    def test_validator_and_compiler_agree_on_window_errors(self):
        raw = _scenario("""
name: agreement
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
events:
  kickoff: {conditions: [health]}
  cleanup: {conditions: [health]}
scripts:
  timeline: {start-time: 0, end-time: 60, speed: 1, events: {kickoff: 10}}
  side: {start-time: 0, end-time: 60, speed: 1, events: {cleanup: 20}}
stories:
  main: {scripts: [timeline]}
objectives:
  initial:
    entity: blue
    success: {conditions: [health]}
    window:
      stories: [main]
      scripts: [side]
      events: [kickoff]
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
""")

        with pytest.raises(SDLValidationError) as exc_info:
            parse_sdl(raw)

        errors = exc_info.value.errors
        assert any("window script 'side' is not included by the referenced stories" in error for error in errors)
        assert any("window event 'kickoff' is not included by the referenced scripts" in error for error in errors)
        assert any("window step 'other.finish' is not part of the referenced workflows" in error for error in errors)

        model = compile_runtime_model(parse_sdl(raw, skip_semantic_validation=True))
        codes = {diag.code for diag in model.diagnostics}
        assert "evaluation.script-ref-outside-window-stories" in codes
        assert "evaluation.event-ref-outside-window-scripts" in codes
        assert "evaluation.workflow-step-ref-workflow-outside-window" in codes

    def test_compiler_and_planner_agree_on_window_refresh_semantics(self):
        raw = _scenario("""
name: refresh-agreement
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
      steps: [flow.branch]
workflows:
  flow:
    start: branch
    steps:
      branch:
        type: decision
        when: {conditions: [health]}
        then: finish
        else: finish
      finish: {type: end}
""")
        baseline = plan(
            compile_runtime_model(parse_sdl(raw)),
            create_stub_manifest(),
        )
        snapshot = _snapshot_from_plan(baseline)

        mutated = compile_runtime_model(
            parse_sdl(
                raw.replace("/bin/true", "/bin/false"),
                skip_semantic_validation=False,
            )
        )
        objective = mutated.objectives["evaluation.objective.initial"]
        assert "orchestration.workflow.flow" in objective.refresh_dependencies

        updated = plan(
            mutated,
            create_stub_manifest(),
            snapshot=snapshot,
        )

        actions = {
            op.address: op.action.value
            for op in updated.evaluation.operations
        }
        assert actions["evaluation.condition.vm.health"] == "update"
        assert actions["evaluation.objective.initial"] == "update"
