"""Tests for the APTL ACES evaluation adapter (issue #312)."""

from pathlib import Path
from textwrap import dedent

from aces_contracts.evaluation import EvaluationExecutionState, EvaluationResultStatus
from aces_contracts.runtime_state import ApplyResult, RuntimeSnapshot
from aces_processor.compiler import compile_runtime_model
from aces_processor.planner import plan
from aces_runtime.evaluation_result_contracts import evaluation_result_contract_diagnostics
from aces_sdl import parse_sdl_file
from aces_sdl.parser import parse_sdl

from aptl.backends.aces_evaluator import AptlEvaluator
from aptl.backends.aces_manifest import create_aptl_manifest

PROJECT_ROOT = Path(__file__).resolve().parents[1]

_EVALUATION_SCENARIO = dedent(
    """
    name: evaluator-test
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


def _evaluation_plan():
    scenario = parse_sdl(_EVALUATION_SCENARIO)
    execution_plan = plan(compile_runtime_model(scenario), create_aptl_manifest())
    return execution_plan.evaluation


def test_start_registers_evaluations_as_pending_with_started_history():
    evaluator = AptlEvaluator()
    result = evaluator.start(_evaluation_plan(), RuntimeSnapshot())

    assert isinstance(result, ApplyResult)
    assert result.success is True
    assert result.snapshot.evaluation_results, "expected at least one evaluation run recorded"

    for address, payload in result.snapshot.evaluation_results.items():
        state = EvaluationExecutionState.from_payload(payload)
        assert state.status == EvaluationResultStatus.PENDING
        assert state.run_id
        history = result.snapshot.evaluation_history[address]
        assert history[0]["event_type"] == "evaluation_started"


def test_start_output_is_evaluation_contract_clean():
    evaluator = AptlEvaluator()
    result = evaluator.start(_evaluation_plan(), RuntimeSnapshot())

    diagnostics = evaluation_result_contract_diagnostics(result.snapshot)
    assert diagnostics == [], [d.message for d in diagnostics]


def test_results_and_status_reflect_registered_evaluations():
    evaluator = AptlEvaluator()
    assert evaluator.results() == {}
    assert evaluator.history() == {}

    evaluator.start(_evaluation_plan(), RuntimeSnapshot())

    assert evaluator.results()
    assert evaluator.history()
    assert evaluator.status()["registered_evaluations"] == sorted(evaluator.results())


def test_start_registers_paper_metric_and_tlo_resources():
    scenario = parse_sdl_file(PROJECT_ROOT / "scenarios" / "paper-agent-loop.sdl.yaml")
    evaluation = plan(
        compile_runtime_model(scenario),
        create_aptl_manifest(),
    ).evaluation

    result = AptlEvaluator().start(evaluation, RuntimeSnapshot())

    assert result.success is True
    assert (
        "evaluation.metric.participant-evidence-complete"
        in result.snapshot.evaluation_results
    )
    assert (
        "evaluation.tlo.authored-runtime-handoff"
        in result.snapshot.evaluation_results
    )


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
    evaluator = AptlEvaluator()
    result = evaluator.start(_evaluation_plan(), base)

    assert "provision.node.vm" in result.snapshot.entries
    assert any(
        entry.domain == RuntimeDomain.EVALUATION for entry in result.snapshot.entries.values()
    )


def test_stop_clears_evaluation_state():
    evaluator = AptlEvaluator()
    started = evaluator.start(_evaluation_plan(), RuntimeSnapshot())

    stopped = evaluator.stop(started.snapshot)

    assert stopped.success is True
    assert stopped.snapshot.evaluation_results == {}
    assert stopped.snapshot.evaluation_history == {}
    assert evaluator.results() == {}
    assert evaluator.history() == {}


def test_start_rejects_non_evaluation_plan():
    evaluator = AptlEvaluator()
    result = evaluator.start(object(), RuntimeSnapshot())

    assert result.success is False
    assert any(d.code == "aptl.evaluator.invalid-plan" for d in result.diagnostics)


def _evaluation_op(address, payload, *, action=None, resource_type="objective"):
    from aces_contracts.planning import ChangeAction, EvaluationOp

    return EvaluationOp(
        action=action or ChangeAction.CREATE,
        address=address,
        resource_type=resource_type,
        payload=payload,
    )


def test_start_fails_closed_on_evaluation_missing_result_contract():
    from aces_contracts.planning import EvaluationPlan

    op = _evaluation_op("evaluation.objective.broken", {"name": "broken"})
    result = AptlEvaluator().start(
        EvaluationPlan(resources={}, operations=[op]), RuntimeSnapshot()
    )

    assert result.success is False
    assert any(d.code == "aptl.evaluator.evaluation-contract-missing" for d in result.diagnostics)


def test_start_fails_closed_on_invalid_result_contract():
    from aces_contracts.planning import EvaluationPlan

    op = _evaluation_op(
        "evaluation.objective.broken",
        {"name": "broken", "result_contract": {"resource_type": ""}},
    )
    result = AptlEvaluator().start(
        EvaluationPlan(resources={}, operations=[op]), RuntimeSnapshot()
    )

    assert result.success is False
    assert any(d.code == "aptl.evaluator.evaluation-contract-invalid" for d in result.diagnostics)


def test_start_handles_delete_operation():
    from aces_contracts.planning import ChangeAction, EvaluationPlan, RuntimeDomain
    from aces_contracts.runtime_state import SnapshotEntry

    address = "evaluation.objective.gone"
    base = RuntimeSnapshot(
        entries={
            address: SnapshotEntry(
                address=address,
                domain=RuntimeDomain.EVALUATION,
                resource_type="objective",
                payload={"name": "gone"},
            )
        },
        evaluation_results={address: {"status": "ready"}},
        evaluation_history={address: [{"event_type": "evaluation_ready"}]},
    )
    op = _evaluation_op(address, {"name": "gone"}, action=ChangeAction.DELETE)

    result = AptlEvaluator().start(EvaluationPlan(resources={}, operations=[op]), base)

    assert result.success is True
    assert address not in result.snapshot.entries
    assert address not in result.snapshot.evaluation_results
    assert address not in result.snapshot.evaluation_history
