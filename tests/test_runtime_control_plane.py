"""Reference runtime control-plane tests."""

from __future__ import annotations

import textwrap

from aptl.backends.stubs import create_stub_target
from aptl.core.runtime.compiler import compile_runtime_model
from aptl.core.runtime.control_plane import RuntimeControlPlane
from aptl.core.runtime.models import OperationState, RuntimeDomain
from aptl.core.runtime.planner import plan
from aptl.core.sdl import parse_sdl


def _scenario(yaml_str: str):
    return parse_sdl(textwrap.dedent(yaml_str))


def test_control_plane_submits_provisioning_and_updates_snapshot():
    scenario = _scenario("""
name: provision
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
""")
    execution_plan = plan(compile_runtime_model(scenario), create_stub_target().manifest)
    control_plane = RuntimeControlPlane(create_stub_target())

    receipt = control_plane.submit_provisioning(execution_plan.provisioning)
    status = control_plane.get_operation(receipt.operation_id)
    snapshot = control_plane.get_snapshot()

    assert receipt.accepted is True
    assert receipt.domain == RuntimeDomain.PROVISIONING
    assert status is not None
    assert status.state == OperationState.SUCCEEDED
    assert snapshot.snapshot.entries


def test_control_plane_submits_orchestration_with_portable_workflow_state():
    scenario = _scenario("""
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
entities:
  blue: {role: blue}
objectives:
  validate:
    entity: blue
    success: {conditions: [health]}
workflows:
  response:
    start: run
    steps:
      run:
        type: objective
        objective: validate
        on-success: finish
      finish: {type: end}
""")
    target = create_stub_target()
    execution_plan = plan(compile_runtime_model(scenario), target.manifest)
    control_plane = RuntimeControlPlane(target)

    receipt = control_plane.submit_orchestration(execution_plan.orchestration)
    status = control_plane.get_operation(receipt.operation_id)
    snapshot = control_plane.get_snapshot()

    assert receipt.accepted is True
    assert status is not None
    assert status.state == OperationState.SUCCEEDED
    workflow_result = next(iter(snapshot.snapshot.orchestration_results.values()))
    assert workflow_result["workflow_status"] == "running"
    assert "run_id" in workflow_result
    assert snapshot.snapshot.orchestration_history
