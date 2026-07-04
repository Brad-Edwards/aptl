"""Outcome resolution helpers for the APTL ACES evaluator adapter."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from aces_contracts.diagnostics import Diagnostic, Severity
from aces_contracts.evaluation import (
    EvaluationExecutionState,
    EvaluationHistoryEvent,
    EvaluationHistoryEventType,
    EvaluationResultContract,
    EvaluationResultStatus,
)
from aces_contracts.planning import EvaluationPlan, RuntimeDomain
from aces_contracts.runtime_state import RuntimeSnapshot

from aptl.backends._aces_evaluator_progress import append_progression
from aptl.utils.redaction import redact

EVALUATION_ADDRESS = "runtime.apply.evaluation"
OBSERVABLE_RESOURCE_TYPES = frozenset(
    {"condition-binding", "evaluation", "goal", "metric", "objective", "tlo"}
)
_FAILED_ENTRY_STATUSES = frozenset({"error", "failed", "unhealthy"})
_READY_ENTRY_STATUS = "ready"


@dataclass(frozen=True)
class _EvaluationOutcome(object):
    """Resolved evaluator state before it is rendered as ACES DTO payloads."""

    status: EvaluationResultStatus
    passed: bool | None = None
    score: float | int | None = None
    max_score: int | None = None
    detail: str | None = None


def evaluation_diagnostic(code: str, address: str, message: str) -> Diagnostic:
    """Build a redacted evaluation-domain ACES error diagnostic."""
    return Diagnostic(
        code=code,
        domain=RuntimeDomain.EVALUATION.value,
        address=address,
        message=redact(message),
        severity=Severity.ERROR,
    )


def utc_now() -> str:
    """Return the current UTC instant as an ISO-8601 ``...Z`` string."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _running(detail: str) -> _EvaluationOutcome:
    """Return a running outcome with an operator-facing wait reason."""
    return _EvaluationOutcome(status=EvaluationResultStatus.RUNNING, detail=detail)


def _ready_passed(passed: bool, detail: str) -> _EvaluationOutcome:
    """Return a ready pass/fail outcome."""
    return _EvaluationOutcome(
        status=EvaluationResultStatus.READY,
        passed=passed,
        detail=detail,
    )


def _ready_score(score: float | int, max_score: int, detail: str) -> _EvaluationOutcome:
    """Return a ready score outcome."""
    return _EvaluationOutcome(
        status=EvaluationResultStatus.READY,
        score=score,
        max_score=max_score,
        detail=detail,
    )


def _state_matches_contract(
    state: EvaluationExecutionState,
    contract: EvaluationResultContract,
) -> bool:
    """Return whether a prior state can continue under the compiled contract."""
    return (
        state.state_schema_version == contract.state_schema_version
        and state.resource_type == contract.resource_type
    )


def _load_result_contract(
    evaluation_address: str,
    payload: dict[str, object],
) -> tuple[EvaluationResultContract | None, list[Diagnostic]]:
    """Load a compiled result contract and return diagnostics on failure."""
    diagnostics: list[Diagnostic] = []
    result_contract: EvaluationResultContract | None = None
    result_contract_payload = payload.get("result_contract")
    if not isinstance(result_contract_payload, dict):
        diagnostics = [
            evaluation_diagnostic(
                "aptl.evaluator.evaluation-contract-missing",
                evaluation_address,
                "ACES evaluation resource is missing its compiled result_contract.",
            )
        ]
    else:
        try:
            result_contract = EvaluationResultContract.from_mapping(
                result_contract_payload
            )
        except (TypeError, ValueError) as exc:
            diagnostics = [
                evaluation_diagnostic(
                    "aptl.evaluator.evaluation-contract-invalid",
                    evaluation_address,
                    f"ACES evaluation result_contract is invalid: {exc}",
                )
            ]
    return result_contract, diagnostics


def _initialize_state(
    evaluation_address: str,
    registered_at: str,
    result_contract: EvaluationResultContract,
    states: dict[str, EvaluationExecutionState],
    history: dict[str, list[dict[str, object]]],
) -> None:
    """Initialize a new pending run and started event."""
    states[evaluation_address] = EvaluationExecutionState(
        state_schema_version=result_contract.state_schema_version,
        resource_type=result_contract.resource_type,
        run_id=uuid4().hex,
        status=EvaluationResultStatus.PENDING,
        observed_at=registered_at,
        updated_at=registered_at,
    )
    history[evaluation_address] = [
        EvaluationHistoryEvent(
            event_type=EvaluationHistoryEventType.EVALUATION_STARTED,
            timestamp=registered_at,
            status=EvaluationResultStatus.PENDING,
        ).to_payload()
    ]


def register_evaluation(
    evaluation_address: str,
    payload: dict[str, object],
    registered_at: str,
    states: dict[str, EvaluationExecutionState],
    history: dict[str, list[dict[str, object]]],
) -> tuple[EvaluationResultContract | None, list[Diagnostic]]:
    """Record a pending portable state only when the run is not already present."""
    result_contract, diagnostics = _load_result_contract(evaluation_address, payload)
    if result_contract is None:
        return None, diagnostics

    existing_state = states.get(evaluation_address)
    if existing_state is not None and _state_matches_contract(
        existing_state,
        result_contract,
    ):
        history.setdefault(evaluation_address, [])
        return result_contract, []

    _initialize_state(
        evaluation_address,
        registered_at,
        result_contract,
        states,
        history,
    )
    return result_contract, []


def existing_states(snapshot: RuntimeSnapshot) -> dict[str, EvaluationExecutionState]:
    """Load valid pre-existing evaluation results for untouched plan entries."""
    states: dict[str, EvaluationExecutionState] = {}
    for address, payload in snapshot.evaluation_results.items():
        if not isinstance(payload, dict):
            continue
        try:
            states[address] = EvaluationExecutionState.from_payload(payload)
        except (TypeError, ValueError):
            continue
    return states


def _evaluation_order(
    plan: EvaluationPlan,
    operation_payloads: dict[str, dict[str, object]],
) -> list[str]:
    """Return plan order with startup-order addresses first when available."""
    ordered: list[str] = []
    for address in plan.startup_order:
        if address in operation_payloads and address not in ordered:
            ordered.append(address)
    for address in operation_payloads:
        if address not in ordered:
            ordered.append(address)
    return ordered


def _string_values(raw: object) -> tuple[str, ...]:
    """Normalize compiled dependency fields into a tuple of non-empty strings."""
    if isinstance(raw, str):
        return (raw,) if raw else ()
    if not isinstance(raw, (list, tuple, set, frozenset)):
        return ()
    return tuple(str(value) for value in raw if str(value))


def _int_value(raw: object) -> int | None:
    """Return an integer value while excluding bools."""
    value = raw if not isinstance(raw, bool) and isinstance(raw, int) else None
    return value


def _number_value(raw: object) -> float | int | None:
    """Return a numeric value while excluding bools."""
    value = raw if not isinstance(raw, bool) and isinstance(raw, (int, float)) else None
    return value


def _metric_max_score(
    contract: EvaluationResultContract,
    payload: dict[str, object],
) -> int:
    """Resolve the compiled max score for a conditional metric."""
    max_score = contract.fixed_max_score
    spec = payload.get("spec")
    if max_score is None and isinstance(spec, dict):
        max_score = _int_value(spec.get("max_score"))
    return max_score if max_score is not None else 100


def _state_truth_value(state: EvaluationExecutionState | None) -> bool | None:
    """Return True/False for ready/failed dependency states; None means wait."""
    value: bool | None = None
    waiting_statuses = {
        EvaluationResultStatus.PENDING,
        EvaluationResultStatus.RUNNING,
    }
    if state is not None and state.status not in waiting_statuses:
        if state.status == EvaluationResultStatus.FAILED:
            value = False
        elif state.passed is not None:
            value = state.passed
        elif state.score is not None and state.max_score is None:
            value = bool(state.score)
        elif state.score is not None:
            value = float(state.score) >= float(state.max_score)
    return value


def _aggregate_dependency_outcome(
    states: dict[str, EvaluationExecutionState],
    dependencies: tuple[str, ...],
    *,
    ready_detail: str,
    waiting_detail: str,
) -> _EvaluationOutcome:
    """Aggregate dependency truth values into a running or pass/fail outcome."""
    values = [_state_truth_value(states.get(address)) for address in dependencies]
    waiting = not dependencies or any(value is None for value in values)
    outcome = (
        _running(waiting_detail)
        if waiting
        else _ready_passed(all(bool(value) for value in values), ready_detail)
    )
    return outcome


def _condition_outcome(
    payload: dict[str, object],
    snapshot: RuntimeSnapshot,
) -> _EvaluationOutcome:
    """Resolve a condition outcome from its observed provisioning node state."""
    node_address = str(payload.get("node_address") or "")
    node_entry = snapshot.entries.get(node_address) if node_address else None
    status = str(node_entry.status).lower() if node_entry is not None else ""
    if not node_address:
        outcome = _running("condition has no compiled node address")
    elif node_entry is None:
        outcome = _running(f"waiting for observed node state: {node_address}")
    elif status == _READY_ENTRY_STATUS:
        outcome = _ready_passed(True, f"observed ready node state: {node_address}")
    elif status in _FAILED_ENTRY_STATUSES:
        outcome = _ready_passed(False, f"observed failed node state: {node_address}")
    else:
        outcome = _running(f"waiting for ready node state: {node_address}")
    return outcome


def _metric_outcome(
    payload: dict[str, object],
    states: dict[str, EvaluationExecutionState],
    contract: EvaluationResultContract,
) -> _EvaluationOutcome:
    """Resolve a conditional metric score from observed condition states."""
    dependencies = _string_values(payload.get("condition_addresses"))
    values = [_state_truth_value(states.get(address)) for address in dependencies]
    if not dependencies:
        outcome = _running("metric has no observed condition dependencies")
    elif any(value is None for value in values):
        outcome = _running("waiting for metric condition dependencies")
    else:
        max_score = _metric_max_score(contract, payload)
        score = max_score if all(bool(value) for value in values) else 0
        outcome = _ready_score(score, max_score, "scored from observed condition state")
    return outcome


def _min_score_threshold(payload: dict[str, object], total_max_score: float) -> float:
    """Resolve the minimum score threshold for an evaluation resource."""
    spec = payload.get("spec")
    min_score = spec.get("min_score") if isinstance(spec, dict) else None
    threshold: float | None = None
    if isinstance(min_score, dict):
        absolute = _number_value(min_score.get("absolute"))
        percentage = _number_value(min_score.get("percentage"))
        if absolute is not None:
            threshold = float(absolute)
        elif percentage is not None:
            threshold = total_max_score * float(percentage) / 100
    else:
        direct = _number_value(min_score)
        threshold = float(direct) if direct is not None else None
    return total_max_score if threshold is None else threshold


def _evaluation_aggregate_outcome(
    payload: dict[str, object],
    states: dict[str, EvaluationExecutionState],
) -> _EvaluationOutcome:
    """Resolve an evaluation pass/fail outcome from metric scores."""
    dependencies = _string_values(payload.get("metric_addresses"))
    metric_states = [states.get(address) for address in dependencies]
    waiting = not dependencies or any(
        state is None
        or state.status in {EvaluationResultStatus.PENDING, EvaluationResultStatus.RUNNING}
        for state in metric_states
    )
    if waiting:
        outcome = _running("waiting for evaluation metric dependencies")
    else:
        total_score = sum(float(state.score or 0) for state in metric_states if state)
        total_max = sum(float(state.max_score or 0) for state in metric_states if state)
        threshold = _min_score_threshold(payload, total_max)
        outcome = _ready_passed(
            total_score >= threshold,
            "evaluated from observed metric scores",
        )
    return outcome


def _resolve_outcome(
    address: str,
    payload: dict[str, object],
    snapshot: RuntimeSnapshot,
    states: dict[str, EvaluationExecutionState],
    contracts: dict[str, EvaluationResultContract],
) -> _EvaluationOutcome:
    """Resolve an operation outcome according to its ACES resource type."""
    contract = contracts[address]
    resource_type = contract.resource_type
    outcome = _running(f"waiting for observed state for {address}")
    if resource_type == "condition-binding":
        outcome = _condition_outcome(payload, snapshot)
    elif resource_type == "metric":
        outcome = _metric_outcome(payload, states, contract)
    elif resource_type == "evaluation":
        outcome = _evaluation_aggregate_outcome(payload, states)
    elif resource_type == "tlo":
        outcome = _aggregate_dependency_outcome(
            states,
            _string_values(payload.get("evaluation_address")),
            ready_detail="TLO evaluated from observed evaluation state",
            waiting_detail="waiting for TLO evaluation dependency",
        )
    elif resource_type == "goal":
        outcome = _aggregate_dependency_outcome(
            states,
            _string_values(payload.get("tlo_addresses")),
            ready_detail="goal evaluated from observed TLO state",
            waiting_detail="waiting for goal TLO dependencies",
        )
    elif resource_type == "objective":
        outcome = _aggregate_dependency_outcome(
            states,
            _string_values(payload.get("success_addresses")),
            ready_detail="objective evaluated from observed success dependencies",
            waiting_detail="waiting for objective success dependencies",
        )
    return outcome


def _contract_score_fields(
    outcome: _EvaluationOutcome,
    contract: EvaluationResultContract,
) -> tuple[float | int | None, int | None]:
    """Return score fields allowed by the compiled result contract."""
    score = outcome.score if contract.supports_score else None
    max_score = outcome.max_score if contract.supports_score else None
    if contract.supports_score and contract.fixed_max_score is not None:
        max_score = contract.fixed_max_score
    if contract.supports_score and score is None and outcome.passed is not None:
        max_score = max_score if max_score is not None else 100
        score = max_score if outcome.passed else 0
    return score, max_score


def _contract_passed_field(
    outcome: _EvaluationOutcome,
    contract: EvaluationResultContract,
    score: float | int | None,
    max_score: int | None,
) -> bool | None:
    """Return the pass/fail field allowed by the compiled result contract."""
    passed = outcome.passed if contract.supports_passed else None
    if contract.supports_passed and passed is None and score is not None:
        threshold = max_score if max_score is not None else score
        passed = float(score) >= float(threshold)
    return passed


def _contractual_outcome(
    outcome: _EvaluationOutcome,
    contract: EvaluationResultContract,
) -> _EvaluationOutcome:
    """Strip or derive ready result values according to the compiled contract."""
    adjusted = _EvaluationOutcome(status=outcome.status, detail=outcome.detail)
    if outcome.status == EvaluationResultStatus.READY:
        score, max_score = _contract_score_fields(outcome, contract)
        passed = _contract_passed_field(outcome, contract, score, max_score)
        if contract.supports_score and score is None:
            adjusted = _running("waiting for contract-compatible score result")
        elif contract.supports_passed and passed is None:
            adjusted = _running("waiting for contract-compatible pass/fail result")
        else:
            adjusted = _EvaluationOutcome(
                status=EvaluationResultStatus.READY,
                passed=passed,
                score=score,
                max_score=max_score,
                detail=outcome.detail,
            )
    return adjusted


def drive_evaluations(
    plan: EvaluationPlan,
    snapshot: RuntimeSnapshot,
    operation_payloads: dict[str, dict[str, object]],
    states: dict[str, EvaluationExecutionState],
    history: dict[str, list[dict[str, object]]],
    contracts: dict[str, EvaluationResultContract],
) -> None:
    """Advance observable evaluation resources from current snapshot state."""
    for address in _evaluation_order(plan, operation_payloads):
        outcome = _resolve_outcome(
            address,
            operation_payloads[address],
            snapshot,
            states,
            contracts,
        )
        states[address] = append_progression(
            states[address],
            _contractual_outcome(outcome, contracts[address]),
            history[address],
        )
