"""Tests for RTE-001 workflow execution engine (issue #514)."""

from textwrap import dedent

from aces_contracts.workflow import (
    WorkflowExecutionState,
    WorkflowHistoryEventType,
    WorkflowStatus,
    WorkflowStepLifecycle,
    WorkflowStepOutcome,
)
from aces_runtime.workflow_result_contracts import workflow_result_contract_diagnostics
from aces_processor.compiler import compile_runtime_model
from aces_processor.planner import plan
from aces_sdl.parser import parse_sdl

from aptl.backends.aces_manifest import create_aptl_manifest
from aptl.core.runtime.workflow_engine import WorkflowEngine, WorkflowRunRecord


_WORKFLOW_SCENARIO = dedent(
    """
    name: workflow-engine-test
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
    """
)


def _workflow_payload():
    scenario = parse_sdl(_WORKFLOW_SCENARIO)
    execution_plan = plan(compile_runtime_model(scenario), create_aptl_manifest())
    workflow_op = next(
        op for op in execution_plan.orchestration.operations if op.resource_type == "workflow"
    )
    return workflow_op.address, workflow_op.payload


def test_drive_linear_objective_workflow_reports_succeeded():
    address, payload = _workflow_payload()
    engine = WorkflowEngine()
    registered_at = "2026-06-22T12:00:00Z"
    engine.register_pending(address, payload, registered_at)

    record = engine.drive(
        address,
        payload,
        objective_outcomes={"evaluation.objective.validate": WorkflowStepOutcome.SUCCEEDED},
    )

    state = WorkflowExecutionState.from_payload(record.result)
    assert state.workflow_status == WorkflowStatus.SUCCEEDED
    assert state.steps["run"].lifecycle == WorkflowStepLifecycle.COMPLETED
    assert state.steps["run"].outcome == WorkflowStepOutcome.SUCCEEDED
    assert state.steps["run"].attempts == 1
    assert record.history[0]["event_type"] == WorkflowHistoryEventType.WORKFLOW_STARTED.value
    assert any(event["event_type"] == WorkflowHistoryEventType.STEP_STARTED.value for event in record.history)
    assert any(event["event_type"] == WorkflowHistoryEventType.WORKFLOW_COMPLETED.value for event in record.history)


def test_drive_failed_objective_reports_workflow_failed():
    address, payload = _workflow_payload()
    engine = WorkflowEngine()
    engine.register_pending(address, payload, "2026-06-22T12:00:00Z")

    record = engine.drive(
        address,
        payload,
        objective_outcomes={"evaluation.objective.validate": WorkflowStepOutcome.FAILED},
    )

    state = WorkflowExecutionState.from_payload(record.result)
    assert state.workflow_status == WorkflowStatus.FAILED
    assert state.steps["run"].outcome == WorkflowStepOutcome.FAILED
    assert record.history[-1]["event_type"] == WorkflowHistoryEventType.WORKFLOW_FAILED.value


def test_driven_state_is_workflow_contract_clean():
    address, payload = _workflow_payload()
    engine = WorkflowEngine()
    engine.register_pending(address, payload, "2026-06-22T12:00:00Z")
    record = engine.drive(
        address,
        payload,
        objective_outcomes={"evaluation.objective.validate": WorkflowStepOutcome.SUCCEEDED},
    )

    from aces_contracts.runtime_state import RuntimeSnapshot, SnapshotEntry
    from aces_contracts.planning import RuntimeDomain

    snapshot = RuntimeSnapshot(
        entries={
            address: SnapshotEntry(
                address=address,
                domain=RuntimeDomain.ORCHESTRATION,
                resource_type="workflow",
                payload=payload,
            )
        },
        orchestration_results={address: record.result},
        orchestration_history={address: record.history},
    )
    diagnostics = workflow_result_contract_diagnostics(snapshot)
    assert diagnostics == [], [d.message for d in diagnostics]


def test_history_timestamps_are_monotonic():
    address, payload = _workflow_payload()
    engine = WorkflowEngine()
    engine.register_pending(address, payload, "2026-06-22T12:00:00Z")
    record = engine.drive(
        address,
        payload,
        objective_outcomes={"evaluation.objective.validate": WorkflowStepOutcome.SUCCEEDED},
    )
    timestamps = [event["timestamp"] for event in record.history]
    assert timestamps == sorted(timestamps)


def test_register_pending_starts_truthful():
    address, payload = _workflow_payload()
    engine = WorkflowEngine()
    record = engine.register_pending(address, payload, "2026-06-22T12:00:00Z")
    assert isinstance(record, WorkflowRunRecord)
    state = WorkflowExecutionState.from_payload(record.result)
    assert state.workflow_status == WorkflowStatus.PENDING
    assert record.history == []


def test_drive_leaves_pending_when_objective_outcomes_unavailable():
    address, payload = _workflow_payload()
    engine = WorkflowEngine()
    engine.register_pending(address, payload, "2026-06-22T12:00:00Z")

    record = engine.drive(address, payload, objective_outcomes={})

    state = WorkflowExecutionState.from_payload(record.result)
    assert state.workflow_status == WorkflowStatus.PENDING
    assert record.history == []


def test_drive_returns_existing_state_when_not_pending():
    address, payload = _workflow_payload()
    engine = WorkflowEngine()
    engine.register_pending(address, payload, "2026-06-22T12:00:00Z")
    driven = engine.drive(
        address,
        payload,
        objective_outcomes={"evaluation.objective.validate": WorkflowStepOutcome.SUCCEEDED},
    )

    again = engine.drive(
        address,
        payload,
        objective_outcomes={"evaluation.objective.validate": WorkflowStepOutcome.FAILED},
    )

    assert again.result == driven.result
    assert again.history == driven.history


def test_drive_failed_objective_with_on_failure_successor():
    scenario = parse_sdl(
        dedent(
            """
            name: workflow-on-failure
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
                    on-failure: recover
                  finish: {type: end}
                  recover: {type: end}
            """
        )
    )
    execution_plan = plan(compile_runtime_model(scenario), create_aptl_manifest())
    workflow_op = next(
        op for op in execution_plan.orchestration.operations if op.resource_type == "workflow"
    )
    engine = WorkflowEngine()
    engine.register_pending(workflow_op.address, workflow_op.payload, "2026-06-22T12:00:00Z")

    record = engine.drive(
        workflow_op.address,
        workflow_op.payload,
        objective_outcomes={"evaluation.objective.validate": WorkflowStepOutcome.FAILED},
    )

    state = WorkflowExecutionState.from_payload(record.result)
    assert state.workflow_status == WorkflowStatus.SUCCEEDED
    assert record.history[-1]["event_type"] == WorkflowHistoryEventType.WORKFLOW_COMPLETED.value


def test_drive_exhausted_objective_fails_workflow():
    address, payload = _workflow_payload()
    engine = WorkflowEngine()
    engine.register_pending(address, payload, "2026-06-22T12:00:00Z")

    record = engine.drive(
        address,
        payload,
        objective_outcomes={"evaluation.objective.validate": WorkflowStepOutcome.EXHAUSTED},
    )

    state = WorkflowExecutionState.from_payload(record.result)
    assert state.workflow_status == WorkflowStatus.FAILED
    assert record.history[-1]["event_type"] == WorkflowHistoryEventType.WORKFLOW_FAILED.value
