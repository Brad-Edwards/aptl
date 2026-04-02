"""Reference HTTP/JSON control-plane API tests."""

from __future__ import annotations

import textwrap
from pathlib import Path

from starlette.testclient import TestClient

from aptl.backends.stubs import create_stub_target
from aptl.core.runtime.compiler import compile_runtime_model
from aptl.core.runtime.control_plane import RuntimeControlPlane
from aptl.core.runtime.control_plane_api import create_control_plane_app
from aptl.core.runtime.control_plane_security import ControlPlaneSecurityConfig
from aptl.core.runtime.control_plane_store import LocalControlPlaneStore
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
    app = create_control_plane_app(
        control_plane,
        security=ControlPlaneSecurityConfig.strict_defaults(target_name=target.name),
    )
    headers = {
        "x-aptl-client-verified": "true",
        "x-aptl-client-identity": "backend-service",
    }

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
            headers=headers,
        )
        assert response.status_code == 200
        receipt = response.json()
        status_response = client.get(
            f"/operations/{receipt['operation_id']}",
            headers=headers,
        )
        assert status_response.status_code == 200
        snapshot_response = client.get("/snapshot", headers=headers)
        assert snapshot_response.status_code == 200
        snapshot = snapshot_response.json()
        assert snapshot["orchestration_results"]


def test_control_plane_api_rejects_unauthenticated_mutations():
    target = create_stub_target()
    control_plane = RuntimeControlPlane(target)
    app = create_control_plane_app(
        control_plane,
        security=ControlPlaneSecurityConfig.strict_defaults(target_name=target.name),
    )

    with TestClient(app) as client:
        response = client.post(
            "/operations/provisioning",
            json={"operations": [], "diagnostics": []},
        )

    assert response.status_code == 401


def test_control_plane_api_supports_idempotent_retries():
    target = create_stub_target()
    control_plane = RuntimeControlPlane(target)
    app = create_control_plane_app(
        control_plane,
        security=ControlPlaneSecurityConfig.strict_defaults(target_name=target.name),
    )
    headers = {
        "x-aptl-client-verified": "true",
        "x-aptl-client-identity": "backend-service",
        "idempotency-key": "same-request",
    }

    with TestClient(app) as client:
        first = client.post(
            "/operations/provisioning",
            json={"operations": [], "diagnostics": []},
            headers=headers,
        )
        second = client.post(
            "/operations/provisioning",
            json={"operations": [], "diagnostics": []},
            headers=headers,
        )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["operation_id"] == second.json()["operation_id"]


def test_control_plane_api_persists_operations_and_snapshot(tmp_path: Path):
    scenario = _scenario("""
name: workflow
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
""")
    target = create_stub_target()
    execution_plan = plan(compile_runtime_model(scenario), target.manifest)
    store = LocalControlPlaneStore(tmp_path / "cp-store")
    control_plane = RuntimeControlPlane(target, store=store)
    app = create_control_plane_app(
        control_plane,
        security=ControlPlaneSecurityConfig.strict_defaults(target_name=target.name),
    )
    headers = {
        "x-aptl-client-verified": "true",
        "x-aptl-client-identity": "backend-service",
    }

    with TestClient(app) as client:
        receipt = client.post(
            "/operations/provisioning",
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
                    for op in execution_plan.provisioning.operations
                ],
                "diagnostics": [],
            },
            headers=headers,
        ).json()

    restarted = RuntimeControlPlane(target, store=store)
    assert restarted.get_operation(receipt["operation_id"]) is not None
    assert restarted.get_snapshot().snapshot.entries


def test_control_plane_api_records_audit_events_for_denials():
    target = create_stub_target()
    control_plane = RuntimeControlPlane(target)
    app = create_control_plane_app(
        control_plane,
        security=ControlPlaneSecurityConfig.strict_defaults(target_name=target.name),
    )

    with TestClient(app) as client:
        response = client.get("/snapshot")

    assert response.status_code == 401
    assert control_plane.audit_log()
    assert control_plane.audit_log()[-1].allowed is False


def test_control_plane_api_enforces_request_size_limit():
    target = create_stub_target()
    control_plane = RuntimeControlPlane(target)
    security = ControlPlaneSecurityConfig.strict_defaults(target_name=target.name)
    security = ControlPlaneSecurityConfig(
        require_verified_identity=security.require_verified_identity,
        verified_header=security.verified_header,
        identity_header=security.identity_header,
        max_request_bytes=32,
        trusted_identities=security.trusted_identities,
        bearer_tokens=security.bearer_tokens,
    )
    app = create_control_plane_app(control_plane, security=security)
    headers = {
        "x-aptl-client-verified": "true",
        "x-aptl-client-identity": "backend-service",
    }

    with TestClient(app) as client:
        response = client.post(
            "/operations/provisioning",
            json={"operations": [], "diagnostics": [], "padding": "x" * 100},
            headers=headers,
        )

    assert response.status_code == 413


def test_control_plane_api_cancels_workflow_runs():
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
    app = create_control_plane_app(
        control_plane,
        security=ControlPlaneSecurityConfig.strict_defaults(target_name=target.name),
    )
    headers = {
        "x-aptl-client-verified": "true",
        "x-aptl-client-identity": "backend-service",
    }

    with TestClient(app) as client:
        client.post(
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
            headers=headers,
        )
        cancel = client.post(
            "/workflows/orchestration.workflow.response/cancel",
            json={"reason": "operator requested stop"},
            headers=headers,
        )
        snapshot = client.get("/snapshot", headers=headers).json()

    assert cancel.status_code == 200
    result = snapshot["orchestration_results"]["orchestration.workflow.response"]
    assert result["workflow_status"] == "cancelled"
    assert result["terminal_reason"] == "operator requested stop"


def test_control_plane_api_reconciles_workflow_timeouts():
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
    timeout: 1
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
    app = create_control_plane_app(
        control_plane,
        security=ControlPlaneSecurityConfig.strict_defaults(target_name=target.name),
    )
    headers = {
        "x-aptl-client-verified": "true",
        "x-aptl-client-identity": "backend-service",
    }

    with TestClient(app) as client:
        client.post(
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
            headers=headers,
        )
        reconcile = client.post(
            "/workflows/reconcile-timeouts",
            headers=headers,
        )
        assert reconcile.status_code == 200
        control_plane.reconcile_workflow_timeouts(now="2099-01-01T00:00:00Z")
        snapshot = client.get("/snapshot", headers=headers).json()

    result = snapshot["orchestration_results"]["orchestration.workflow.response"]
    assert result["workflow_status"] == "timed_out"
    assert result["terminal_reason"] == "workflow timed out"
