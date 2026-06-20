"""Tests for the APTL ACES orchestration adapter (issue #311)."""

from textwrap import dedent

from aces_contracts.runtime_state import ApplyResult, RuntimeSnapshot
from aces_contracts.workflow import WorkflowExecutionState, WorkflowStatus, WorkflowStepLifecycle
from aces_processor.compiler import compile_runtime_model
from aces_processor.planner import plan
from aces_runtime.workflow_result_contracts import workflow_result_contract_diagnostics
from aces_sdl.parser import parse_sdl

from aptl.backends.aces_manifest import create_aptl_manifest
from aptl.backends.aces_orchestrator import AptlOrchestrator

_WORKFLOW_SCENARIO = dedent(
    """
    name: orchestrator-test
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


def _orchestration_plan():
    scenario = parse_sdl(_WORKFLOW_SCENARIO)
    execution_plan = plan(compile_runtime_model(scenario), create_aptl_manifest())
    return execution_plan.orchestration


def test_start_registers_workflows_as_pending_with_pending_steps():
    orchestrator = AptlOrchestrator()
    result = orchestrator.start(_orchestration_plan(), RuntimeSnapshot())

    assert isinstance(result, ApplyResult)
    assert result.success is True
    assert result.snapshot.orchestration_results, "expected at least one workflow run recorded"

    for payload in result.snapshot.orchestration_results.values():
        state = WorkflowExecutionState.from_payload(payload)
        # PENDING, not RUNNING: the run is registered but no step has executed,
        # and the adapter never fabricates execution progress.
        assert state.workflow_status == WorkflowStatus.PENDING
        assert state.run_id
        assert state.steps, "workflow must report its observable steps"
        assert all(step.lifecycle == WorkflowStepLifecycle.PENDING for step in state.steps.values())
    # No history events are invented for a not-yet-executed workflow.
    assert result.snapshot.orchestration_history == {}


def test_start_output_is_workflow_contract_clean():
    orchestrator = AptlOrchestrator()
    result = orchestrator.start(_orchestration_plan(), RuntimeSnapshot())

    diagnostics = workflow_result_contract_diagnostics(result.snapshot)
    assert diagnostics == [], [d.message for d in diagnostics]


def test_results_and_status_reflect_registered_workflows():
    orchestrator = AptlOrchestrator()
    assert orchestrator.results() == {}
    assert orchestrator.history() == {}

    orchestrator.start(_orchestration_plan(), RuntimeSnapshot())

    assert orchestrator.results()
    # No history until real execution-state integration lands.
    assert orchestrator.history() == {}
    assert orchestrator.status()["registered_workflows"] == sorted(orchestrator.results())


def test_start_preserves_existing_provisioning_entries():
    from aces_contracts.planning import RuntimeDomain
    from aces_contracts.runtime_state import SnapshotEntry

    base = RuntimeSnapshot(
        entries={
            "provision.node.vm": SnapshotEntry(
                address="provision.node.vm",
                domain=RuntimeDomain.PROVISIONING,
                resource_type="node",
                payload={"name": "vm"},
            )
        }
    )
    orchestrator = AptlOrchestrator()
    result = orchestrator.start(_orchestration_plan(), base)

    assert "provision.node.vm" in result.snapshot.entries
    assert any(
        entry.domain == RuntimeDomain.ORCHESTRATION for entry in result.snapshot.entries.values()
    )


def test_stop_clears_orchestration_state():
    orchestrator = AptlOrchestrator()
    started = orchestrator.start(_orchestration_plan(), RuntimeSnapshot())

    stopped = orchestrator.stop(started.snapshot)

    assert stopped.success is True
    assert stopped.snapshot.orchestration_results == {}
    assert stopped.snapshot.orchestration_history == {}
    assert orchestrator.results() == {}
    assert orchestrator.history() == {}


def test_start_rejects_non_orchestration_plan():
    orchestrator = AptlOrchestrator()
    result = orchestrator.start(object(), RuntimeSnapshot())

    assert result.success is False
    assert any(d.code == "aptl.orchestrator.invalid-plan" for d in result.diagnostics)


def _workflow_op(address, payload, *, action=None):
    from aces_contracts.planning import ChangeAction, OrchestrationOp

    return OrchestrationOp(
        action=action or ChangeAction.CREATE,
        address=address,
        resource_type="workflow",
        payload=payload,
    )


def test_start_fails_closed_on_workflow_missing_result_contract():
    from aces_contracts.planning import OrchestrationPlan

    op = _workflow_op("orchestration.workflow.broken", {"name": "broken"})
    result = AptlOrchestrator().start(
        OrchestrationPlan(resources={}, operations=[op]), RuntimeSnapshot()
    )

    assert result.success is False
    assert any(d.code == "aptl.orchestrator.workflow-contract-missing" for d in result.diagnostics)


def test_start_fails_closed_on_invalid_result_contract():
    from aces_contracts.planning import OrchestrationPlan

    op = _workflow_op(
        "orchestration.workflow.broken",
        {"name": "broken", "result_contract": {"observable_steps": "not-a-dict"}},
    )
    result = AptlOrchestrator().start(
        OrchestrationPlan(resources={}, operations=[op]), RuntimeSnapshot()
    )

    assert result.success is False
    assert any(d.code == "aptl.orchestrator.workflow-contract-invalid" for d in result.diagnostics)


def test_start_handles_delete_operation():
    from aces_contracts.planning import ChangeAction, OrchestrationPlan, RuntimeDomain
    from aces_contracts.runtime_state import SnapshotEntry

    address = "orchestration.workflow.gone"
    base = RuntimeSnapshot(
        entries={
            address: SnapshotEntry(
                address=address,
                domain=RuntimeDomain.ORCHESTRATION,
                resource_type="workflow",
                payload={"name": "gone"},
            )
        },
        orchestration_results={address: {"workflow_status": "running"}},
        orchestration_history={address: [{"event_type": "workflow_started"}]},
    )
    op = _workflow_op(address, {"name": "gone"}, action=ChangeAction.DELETE)

    result = AptlOrchestrator().start(
        OrchestrationPlan(resources={}, operations=[op]), base
    )

    assert result.success is True
    assert address not in result.snapshot.entries
    assert address not in result.snapshot.orchestration_results
    assert address not in result.snapshot.orchestration_history
