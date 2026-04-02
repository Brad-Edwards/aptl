"""Reference HTTP/JSON control-plane API tests."""

from __future__ import annotations

import textwrap

from starlette.testclient import TestClient

from aptl.backends.stubs import create_stub_target
from aptl.core.runtime.compiler import compile_runtime_model
from aptl.core.runtime.control_plane import RuntimeControlPlane
from aptl.core.runtime.control_plane_api import create_control_plane_app
from aptl.core.runtime.planner import plan
from aptl.core.sdl import parse_sdl


def _scenario(yaml_str: str):
    return parse_sdl(textwrap.dedent(yaml_str))


def test_control_plane_api_accepts_orchestration_plan_and_exposes_snapshot():
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
    app = create_control_plane_app(control_plane)

    with TestClient(app) as client:
        response = client.post(
            "/operations/orchestration",
            json={
                "operations": [
                    {
                        "action": op.action.value,
                        "address": op.address,
                        "resource_type": op.resource_type,
                        "payload": op.payload,
                        "ordering_dependencies": list(op.ordering_dependencies),
                        "refresh_dependencies": list(op.refresh_dependencies),
                    }
                    for op in execution_plan.orchestration.operations
                ],
                "startup_order": execution_plan.orchestration.startup_order,
                "diagnostics": [],
            },
        )
        assert response.status_code == 200
        receipt = response.json()
        status_response = client.get(f"/operations/{receipt['operation_id']}")
        assert status_response.status_code == 200
        snapshot_response = client.get("/snapshot")
        assert snapshot_response.status_code == 200
        snapshot = snapshot_response.json()
        assert snapshot["orchestration_results"]
