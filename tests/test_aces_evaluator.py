"""Tests for the APTL ACES evaluation adapter (issue #312)."""

from pathlib import Path
from textwrap import dedent

from aces_contracts.evaluation import (
    EvaluationExecutionState,
    EvaluationHistoryEventType,
    EvaluationResultStatus,
)
from aces_contracts.planning import RuntimeDomain
from aces_contracts.runtime_state import ApplyResult, RuntimeSnapshot, SnapshotEntry
from aces_processor.compiler import compile_runtime_model
from aces_processor.planner import plan
from aces_runtime.evaluation_result_contracts import evaluation_result_contract_diagnostics
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


def _snapshot_with_node_status(status: str) -> RuntimeSnapshot:
    return RuntimeSnapshot(
        entries={
            "provision.node.vm": SnapshotEntry(
                address="provision.node.vm",
                domain=RuntimeDomain.PROVISIONING,
                resource_type="node",
                payload={"name": "vm"},
                status=status,
            )
        }
    )


def _event_types(events: list[dict[str, object]]) -> list[str]:
    return [str(event["event_type"]) for event in events]


def test_start_reports_running_until_observed_state_is_available():
    evaluator = AptlEvaluator()
    result = evaluator.start(_evaluation_plan(), RuntimeSnapshot())

    assert isinstance(result, ApplyResult)
    assert result.success is True
    assert result.snapshot.evaluation_results, (
        "expected at least one evaluation run recorded"
    )

    for address, payload in result.snapshot.evaluation_results.items():
        state = EvaluationExecutionState.from_payload(payload)
        assert state.status == EvaluationResultStatus.RUNNING
        assert state.passed is None
        assert state.score is None
        assert state.run_id
        history = result.snapshot.evaluation_history[address]
        assert _event_types(history) == [
            EvaluationHistoryEventType.EVALUATION_STARTED.value,
            EvaluationHistoryEventType.EVALUATION_UPDATED.value,
        ]
        assert history[0]["status"] == EvaluationResultStatus.PENDING.value
        assert history[-1]["status"] == EvaluationResultStatus.RUNNING.value


def test_start_derives_condition_and_objective_pass_from_observed_state():
    result = AptlEvaluator().start(
        _evaluation_plan(),
        _snapshot_with_node_status("ready"),
    )

    assert result.success is True
    diagnostics = evaluation_result_contract_diagnostics(result.snapshot)
    assert diagnostics == [], [d.message for d in diagnostics]

    results = result.snapshot.evaluation_results
    assert sorted(results) == [
        "evaluation.condition.vm.health",
        "evaluation.objective.validate",
    ]
    condition = EvaluationExecutionState.from_payload(
        results["evaluation.condition.vm.health"]
    )
    objective = EvaluationExecutionState.from_payload(
        results["evaluation.objective.validate"]
    )

    assert condition.status == EvaluationResultStatus.READY
    assert condition.passed is True
    assert condition.score is None
    assert condition.max_score is None
    assert objective.status == EvaluationResultStatus.READY
    assert objective.passed is True
    assert objective.score is None
    assert objective.max_score is None

    objective_history = result.snapshot.evaluation_history[
        "evaluation.objective.validate"
    ]
    assert _event_types(objective_history) == [
        EvaluationHistoryEventType.EVALUATION_STARTED.value,
        EvaluationHistoryEventType.EVALUATION_UPDATED.value,
        EvaluationHistoryEventType.EVALUATION_READY.value,
    ]
    assert objective_history[1]["status"] == EvaluationResultStatus.RUNNING.value
    assert objective_history[-1]["passed"] is True
    assert objective_history[-1].get("score") is None
    assert objective_history[-1].get("max_score") is None


def test_start_keeps_unobserved_evaluations_running_without_placeholder_values():
    result = AptlEvaluator().start(_evaluation_plan(), RuntimeSnapshot())

    assert result.success is True
    diagnostics = evaluation_result_contract_diagnostics(result.snapshot)
    assert diagnostics == [], [d.message for d in diagnostics]

    results = result.snapshot.evaluation_results
    condition = EvaluationExecutionState.from_payload(
        results["evaluation.condition.vm.health"]
    )
    objective = EvaluationExecutionState.from_payload(
        results["evaluation.objective.validate"]
    )

    assert condition.status == EvaluationResultStatus.RUNNING
    assert condition.passed is None
    assert condition.score is None
    assert objective.status == EvaluationResultStatus.RUNNING
    assert objective.passed is None
    assert objective.score is None
    assert objective.max_score is None
    assert _event_types(
        result.snapshot.evaluation_history["evaluation.objective.validate"]
    ) == [
        EvaluationHistoryEventType.EVALUATION_STARTED.value,
        EvaluationHistoryEventType.EVALUATION_UPDATED.value,
    ]


def test_start_preserves_existing_run_history_when_observation_advances():
    evaluator = AptlEvaluator()
    initial = evaluator.start(_evaluation_plan(), RuntimeSnapshot())
    assert initial.success is True

    objective_address = "evaluation.objective.validate"
    initial_objective = EvaluationExecutionState.from_payload(
        initial.snapshot.evaluation_results[objective_address]
    )
    initial_history = list(initial.snapshot.evaluation_history[objective_address])
    ready_node = _snapshot_with_node_status("ready").entries["provision.node.vm"]
    observed_entries = dict(initial.snapshot.entries)
    observed_entries[ready_node.address] = ready_node

    advanced = evaluator.start(
        _evaluation_plan(),
        initial.snapshot.with_entries(
            observed_entries,
            evaluation_results=initial.snapshot.evaluation_results,
            evaluation_history=initial.snapshot.evaluation_history,
        ),
    )

    assert advanced.success is True
    advanced_objective = EvaluationExecutionState.from_payload(
        advanced.snapshot.evaluation_results[objective_address]
    )
    advanced_history = advanced.snapshot.evaluation_history[objective_address]
    assert advanced_objective.run_id == initial_objective.run_id
    assert advanced_history[: len(initial_history)] == initial_history
    assert _event_types(advanced_history) == [
        EvaluationHistoryEventType.EVALUATION_STARTED.value,
        EvaluationHistoryEventType.EVALUATION_UPDATED.value,
        EvaluationHistoryEventType.EVALUATION_READY.value,
    ]

    repeated = evaluator.start(_evaluation_plan(), advanced.snapshot)

    assert repeated.success is True
    repeated_objective = EvaluationExecutionState.from_payload(
        repeated.snapshot.evaluation_results[objective_address]
    )
    assert repeated_objective.run_id == initial_objective.run_id
    assert repeated.snapshot.evaluation_history[objective_address] == advanced_history


def test_start_marks_failed_condition_and_objective_failed():
    result = AptlEvaluator().start(
        _evaluation_plan(),
        _snapshot_with_node_status("failed"),
    )

    assert result.success is True
    diagnostics = evaluation_result_contract_diagnostics(result.snapshot)
    assert diagnostics == [], [d.message for d in diagnostics]

    results = result.snapshot.evaluation_results
    condition = EvaluationExecutionState.from_payload(
        results["evaluation.condition.vm.health"]
    )
    objective = EvaluationExecutionState.from_payload(
        results["evaluation.objective.validate"]
    )

    assert condition.status == EvaluationResultStatus.READY
    assert condition.passed is False
    assert condition.score is None
    assert objective.passed is False
    assert objective.score is None


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


def test_start_fails_closed_on_scoring_chain_resource():
    from aces_contracts.planning import EvaluationPlan

    op = _evaluation_op(
        "evaluation.metric.uptime",
        {
            "name": "uptime",
            "result_contract": {
                "state_schema_version": "evaluation-result-state/v1",
                "resource_type": "metric",
                "supports_passed": False,
                "supports_score": True,
                "fixed_max_score": 10,
            },
        },
        resource_type="metric",
    )

    result = AptlEvaluator().start(
        EvaluationPlan(resources={}, operations=[op]),
        RuntimeSnapshot(),
    )

    assert result.success is False
    assert result.snapshot.evaluation_results == {}
    assert any(
        d.code == "aptl.evaluator.unsupported-scoring-section"
        for d in result.diagnostics
    )


def test_start_fails_closed_on_score_bearing_condition_contract():
    from aces_contracts.planning import EvaluationPlan

    op = _evaluation_op(
        "evaluation.condition.vm.health",
        {
            "name": "health",
            "result_contract": {
                "state_schema_version": "evaluation-result-state/v1",
                "resource_type": "condition-binding",
                "supports_passed": True,
                "supports_score": True,
                "fixed_max_score": 10,
            },
        },
        resource_type="condition-binding",
    )

    result = AptlEvaluator().start(
        EvaluationPlan(resources={}, operations=[op]),
        RuntimeSnapshot(),
    )

    assert result.success is False
    assert any(
        d.code == "aptl.evaluator.unsupported-score-contract"
        for d in result.diagnostics
    )


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
