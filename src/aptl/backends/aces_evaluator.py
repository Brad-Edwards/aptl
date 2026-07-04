"""APTL ACES evaluation adapter.

APTL's full remote-control-plane backend includes this evaluation component for
the objective/condition surface introduced by SCN-010 follow-on #312. APTL's
scenario runtime engine (RTE-001) already evaluates conditions and objectives;
this adapter exposes that surface through the *portable* ACES contracts
``evaluation-result-envelope-v1`` and ``evaluation-history-event-stream-v1``
rather than APTL-native scoring shapes.

The adapter is the ACES ``Evaluator`` component published on APTL's
``RuntimeTarget``. ``start()`` loads an ACES ``EvaluationPlan`` into runtime
state: it registers every evaluation resource as an ACES ``SnapshotEntry`` and,
for each observable evaluation resource, records a truthful
``EvaluationExecutionState`` and then advances observable resources from the
runtime snapshot supplied by the ACES control plane. Conditions observe
provisioning entries, conditional metrics score from those condition results,
and aggregate resources report pass/fail from their compiled dependency
addresses. The adapter never invents elapsed-time score curves; result values
are emitted only when the compiled ACES contract allows them. ``stop()`` clears
evaluation state.

This keeps the full remote-control-plane evaluation claim honest: APTL
publishes the evaluation result/history *contract* surface and the
observed run state behind it, not synthetic in-memory progress.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from aces_contracts.diagnostics import Diagnostic, Severity
from aces_contracts.evaluation import (
    EvaluationExecutionState,
    EvaluationHistoryEvent,
    EvaluationHistoryEventType,
    EvaluationResultContract,
    EvaluationResultStatus,
)
from aces_contracts.planning import ChangeAction, EvaluationPlan, RuntimeDomain
from aces_contracts.runtime_state import ApplyResult, RuntimeSnapshot, SnapshotEntry

from aptl.utils.redaction import redact

EVALUATION_ADDRESS = "runtime.apply.evaluation"
_ISO_UTC_OFFSET = "+00:00"
_OBSERVABLE_RESOURCE_TYPES = frozenset(
    {"condition-binding", "evaluation", "goal", "metric", "objective", "tlo"}
)
_FAILED_ENTRY_STATUSES = frozenset({"error", "failed", "unhealthy"})
_READY_ENTRY_STATUS = "ready"
_TERMINAL_RESULT_STATUSES = frozenset(
    {EvaluationResultStatus.FAILED, EvaluationResultStatus.READY}
)


def _evaluation_diagnostic(code: str, address: str, message: str) -> Diagnostic:
    """Build a redacted evaluation-domain ACES error diagnostic."""
    return Diagnostic(
        code=code,
        domain=RuntimeDomain.EVALUATION.value,
        address=address,
        message=redact(message),
        severity=Severity.ERROR,
    )


def _utc_now() -> str:
    """Return the current UTC instant as an ISO-8601 ``...Z`` string."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _next_timestamp(previous: str, *, offset_ms: int = 1) -> str:
    """Return an ISO timestamp strictly after ``previous``."""
    parsed = datetime.fromisoformat(previous.replace("Z", _ISO_UTC_OFFSET))
    return (parsed + timedelta(milliseconds=offset_ms)).isoformat().replace(
        _ISO_UTC_OFFSET,
        "Z",
    )


@dataclass(frozen=True)
class _EvaluationOutcome(object):
    """Resolved evaluator state before it is rendered as ACES DTO payloads."""

    status: EvaluationResultStatus
    passed: bool | None = None
    score: float | int | None = None
    max_score: int | None = None
    detail: str | None = None


def _running(detail: str) -> _EvaluationOutcome:
    return _EvaluationOutcome(status=EvaluationResultStatus.RUNNING, detail=detail)


def _ready_passed(passed: bool, detail: str) -> _EvaluationOutcome:
    return _EvaluationOutcome(
        status=EvaluationResultStatus.READY,
        passed=passed,
        detail=detail,
    )


def _ready_score(score: float | int, max_score: int, detail: str) -> _EvaluationOutcome:
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
    return (
        state.state_schema_version == contract.state_schema_version
        and state.resource_type == contract.resource_type
    )


def _register_evaluation(
    evaluation_address: str,
    payload: dict[str, object],
    registered_at: str,
    states: dict[str, EvaluationExecutionState],
    history: dict[str, list[dict[str, object]]],
) -> tuple[EvaluationResultContract | None, list[Diagnostic]]:
    """Record the truthful initial (``PENDING``) portable state for a run."""
    result_contract_payload = payload.get("result_contract")
    if not isinstance(result_contract_payload, dict):
        return None, [
            _evaluation_diagnostic(
                "aptl.evaluator.evaluation-contract-missing",
                evaluation_address,
                "ACES evaluation resource is missing its compiled result_contract.",
            )
        ]
    try:
        result_contract = EvaluationResultContract.from_mapping(result_contract_payload)
    except (TypeError, ValueError) as exc:
        return None, [
            _evaluation_diagnostic(
                "aptl.evaluator.evaluation-contract-invalid",
                evaluation_address,
                f"ACES evaluation result_contract is invalid: {exc}",
            )
        ]

    existing_state = states.get(evaluation_address)
    if existing_state is not None and _state_matches_contract(
        existing_state,
        result_contract,
    ):
        history.setdefault(evaluation_address, [])
        return result_contract, []

    state = EvaluationExecutionState(
        state_schema_version=result_contract.state_schema_version,
        resource_type=result_contract.resource_type,
        run_id=uuid4().hex,
        status=EvaluationResultStatus.PENDING,
        observed_at=registered_at,
        updated_at=registered_at,
    )
    states[evaluation_address] = state
    history[evaluation_address] = [
        EvaluationHistoryEvent(
            event_type=EvaluationHistoryEventType.EVALUATION_STARTED,
            timestamp=registered_at,
            status=EvaluationResultStatus.PENDING,
        ).to_payload()
    ]
    return result_contract, []


def _existing_states(snapshot: RuntimeSnapshot) -> dict[str, EvaluationExecutionState]:
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
    if isinstance(raw, bool) or not isinstance(raw, int):
        return None
    return raw


def _number_value(raw: object) -> float | int | None:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    return raw


def _metric_max_score(
    contract: EvaluationResultContract,
    payload: dict[str, object],
) -> int:
    if contract.fixed_max_score is not None:
        return contract.fixed_max_score
    spec = payload.get("spec")
    if isinstance(spec, dict):
        spec_max = _int_value(spec.get("max_score"))
        if spec_max is not None:
            return spec_max
    return 100


def _state_truth_value(state: EvaluationExecutionState | None) -> bool | None:
    """Return True/False for ready/failed dependency states; None means wait."""
    if state is None:
        return None
    if state.status in {EvaluationResultStatus.PENDING, EvaluationResultStatus.RUNNING}:
        return None
    if state.status == EvaluationResultStatus.FAILED:
        return False
    if state.passed is not None:
        return state.passed
    if state.score is None:
        return None
    if state.max_score is None:
        return bool(state.score)
    return float(state.score) >= float(state.max_score)


def _aggregate_dependency_outcome(
    states: dict[str, EvaluationExecutionState],
    dependencies: tuple[str, ...],
    *,
    ready_detail: str,
    waiting_detail: str,
) -> _EvaluationOutcome:
    if not dependencies:
        return _running(waiting_detail)
    values = [_state_truth_value(states.get(address)) for address in dependencies]
    if any(value is None for value in values):
        return _running(waiting_detail)
    return _ready_passed(all(bool(value) for value in values), ready_detail)


def _condition_outcome(
    payload: dict[str, object],
    snapshot: RuntimeSnapshot,
) -> _EvaluationOutcome:
    node_address = str(payload.get("node_address") or "")
    if not node_address:
        return _running("condition has no compiled node address")
    node_entry = snapshot.entries.get(node_address)
    if node_entry is None:
        return _running(f"waiting for observed node state: {node_address}")
    status = str(node_entry.status).lower()
    if status == _READY_ENTRY_STATUS:
        return _ready_passed(True, f"observed ready node state: {node_address}")
    if status in _FAILED_ENTRY_STATUSES:
        return _ready_passed(False, f"observed failed node state: {node_address}")
    return _running(f"waiting for ready node state: {node_address}")


def _metric_outcome(
    payload: dict[str, object],
    states: dict[str, EvaluationExecutionState],
    contract: EvaluationResultContract,
) -> _EvaluationOutcome:
    dependencies = _string_values(payload.get("condition_addresses"))
    if not dependencies:
        return _running("metric has no observed condition dependencies")
    values = [_state_truth_value(states.get(address)) for address in dependencies]
    if any(value is None for value in values):
        return _running("waiting for metric condition dependencies")
    max_score = _metric_max_score(contract, payload)
    score = max_score if all(bool(value) for value in values) else 0
    return _ready_score(score, max_score, "scored from observed condition state")


def _min_score_threshold(payload: dict[str, object], total_max_score: float) -> float:
    spec = payload.get("spec")
    min_score = spec.get("min_score") if isinstance(spec, dict) else None
    if isinstance(min_score, dict):
        absolute = _number_value(min_score.get("absolute"))
        if absolute is not None:
            return float(absolute)
        percentage = _number_value(min_score.get("percentage"))
        if percentage is not None:
            return total_max_score * float(percentage) / 100
    direct = _number_value(min_score)
    if direct is not None:
        return float(direct)
    return total_max_score


def _evaluation_aggregate_outcome(
    payload: dict[str, object],
    states: dict[str, EvaluationExecutionState],
) -> _EvaluationOutcome:
    dependencies = _string_values(payload.get("metric_addresses"))
    if not dependencies:
        return _running("evaluation has no observed metric dependencies")
    metric_states = [states.get(address) for address in dependencies]
    if any(
        state is None or state.status == EvaluationResultStatus.RUNNING
        for state in metric_states
    ):
        return _running("waiting for evaluation metric dependencies")
    if any(
        state.status == EvaluationResultStatus.PENDING
        for state in metric_states
        if state
    ):
        return _running("waiting for evaluation metric dependencies")
    total_score = sum(float(state.score or 0) for state in metric_states if state)
    total_max = sum(float(state.max_score or 0) for state in metric_states if state)
    threshold = _min_score_threshold(payload, total_max)
    return _ready_passed(
        total_score >= threshold,
        "evaluated from observed metric scores",
    )


def _resolve_outcome(
    address: str,
    payload: dict[str, object],
    snapshot: RuntimeSnapshot,
    states: dict[str, EvaluationExecutionState],
    contracts: dict[str, EvaluationResultContract],
) -> _EvaluationOutcome:
    contract = contracts[address]
    resource_type = contract.resource_type
    if resource_type == "condition-binding":
        return _condition_outcome(payload, snapshot)
    if resource_type == "metric":
        return _metric_outcome(payload, states, contract)
    if resource_type == "evaluation":
        return _evaluation_aggregate_outcome(payload, states)
    if resource_type == "tlo":
        return _aggregate_dependency_outcome(
            states,
            _string_values(payload.get("evaluation_address")),
            ready_detail="TLO evaluated from observed evaluation state",
            waiting_detail="waiting for TLO evaluation dependency",
        )
    if resource_type == "goal":
        return _aggregate_dependency_outcome(
            states,
            _string_values(payload.get("tlo_addresses")),
            ready_detail="goal evaluated from observed TLO state",
            waiting_detail="waiting for goal TLO dependencies",
        )
    if resource_type == "objective":
        return _aggregate_dependency_outcome(
            states,
            _string_values(payload.get("success_addresses")),
            ready_detail="objective evaluated from observed success dependencies",
            waiting_detail="waiting for objective success dependencies",
        )
    return _running(f"waiting for observed state for {address}")


def _terminal_event(status: EvaluationResultStatus) -> EvaluationHistoryEventType:
    if status == EvaluationResultStatus.READY:
        return EvaluationHistoryEventType.EVALUATION_READY
    if status == EvaluationResultStatus.FAILED:
        return EvaluationHistoryEventType.EVALUATION_FAILED
    return EvaluationHistoryEventType.EVALUATION_UPDATED


def _state_matches_outcome(
    state: EvaluationExecutionState,
    outcome: _EvaluationOutcome,
) -> bool:
    return (
        state.status == outcome.status
        and state.passed == outcome.passed
        and state.score == outcome.score
        and state.max_score == outcome.max_score
        and state.detail == outcome.detail
    )


def _contractual_outcome(
    outcome: _EvaluationOutcome,
    contract: EvaluationResultContract,
) -> _EvaluationOutcome:
    """Strip or derive ready result values according to the compiled contract."""
    if outcome.status != EvaluationResultStatus.READY:
        return _EvaluationOutcome(status=outcome.status, detail=outcome.detail)

    source_passed = outcome.passed
    passed = outcome.passed if contract.supports_passed else None
    score = outcome.score if contract.supports_score else None
    max_score = outcome.max_score if contract.supports_score else None

    if contract.supports_score:
        if contract.fixed_max_score is not None and score is not None:
            max_score = contract.fixed_max_score
        if score is None and source_passed is not None:
            max_score = (
                contract.fixed_max_score
                if contract.fixed_max_score is not None
                else 100
            )
            score = max_score if source_passed else 0
        if score is None:
            return _running("waiting for contract-compatible score result")

    if contract.supports_passed and passed is None and score is not None:
        threshold = max_score if max_score is not None else score
        passed = float(score) >= float(threshold)
    if contract.supports_passed and passed is None:
        return _running("waiting for contract-compatible pass/fail result")

    return _EvaluationOutcome(
        status=EvaluationResultStatus.READY,
        passed=passed,
        score=score,
        max_score=max_score,
        detail=outcome.detail,
    )


def _append_progression(
    state: EvaluationExecutionState,
    outcome: _EvaluationOutcome,
    events: list[dict[str, object]],
) -> EvaluationExecutionState:
    """Append running/terminal events and return the final result state."""
    last_timestamp = str(events[-1]["timestamp"]) if events else state.updated_at

    if state.status in _TERMINAL_RESULT_STATUSES:
        if outcome.status == EvaluationResultStatus.RUNNING:
            return state
        if _state_matches_outcome(state, outcome):
            return state

    if state.status in {
        EvaluationResultStatus.PENDING,
        EvaluationResultStatus.RUNNING,
    } and outcome.status == EvaluationResultStatus.RUNNING:
        running_at = _next_timestamp(last_timestamp)
        running_state = EvaluationExecutionState(
            state_schema_version=state.state_schema_version,
            resource_type=state.resource_type,
            run_id=state.run_id,
            status=EvaluationResultStatus.RUNNING,
            observed_at=state.observed_at,
            updated_at=running_at,
            detail=outcome.detail,
        )
        events.append(
            EvaluationHistoryEvent(
                event_type=EvaluationHistoryEventType.EVALUATION_UPDATED,
                timestamp=running_at,
                status=EvaluationResultStatus.RUNNING,
                detail=running_state.detail,
            ).to_payload()
        )
        return running_state

    if state.status == EvaluationResultStatus.PENDING:
        running_at = _next_timestamp(last_timestamp)
        running_state = EvaluationExecutionState(
            state_schema_version=state.state_schema_version,
            resource_type=state.resource_type,
            run_id=state.run_id,
            status=EvaluationResultStatus.RUNNING,
            observed_at=state.observed_at,
            updated_at=running_at,
        )
        events.append(
            EvaluationHistoryEvent(
                event_type=EvaluationHistoryEventType.EVALUATION_UPDATED,
                timestamp=running_at,
                status=EvaluationResultStatus.RUNNING,
            ).to_payload()
        )
        last_timestamp = running_state.updated_at

    terminal_at = _next_timestamp(last_timestamp)
    final_state = EvaluationExecutionState(
        state_schema_version=state.state_schema_version,
        resource_type=state.resource_type,
        run_id=state.run_id,
        status=outcome.status,
        observed_at=state.observed_at,
        updated_at=terminal_at,
        passed=outcome.passed,
        score=outcome.score,
        max_score=outcome.max_score,
        detail=outcome.detail,
    )
    events.append(
        EvaluationHistoryEvent(
            event_type=_terminal_event(outcome.status),
            timestamp=terminal_at,
            status=outcome.status,
            passed=outcome.passed,
            score=outcome.score,
            max_score=outcome.max_score,
            detail=outcome.detail,
        ).to_payload()
    )
    return final_state


def _drive_evaluations(
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
        outcome = _contractual_outcome(outcome, contracts[address])
        states[address] = _append_progression(
            states[address],
            outcome,
            history[address],
        )


@dataclass
class AptlEvaluator(object):
    """ACES evaluation adapter for APTL's full remote-control-plane target."""

    _results: dict[str, dict[str, object]] = field(default_factory=dict, init=False)
    _history: dict[str, list[dict[str, object]]] = field(default_factory=dict, init=False)

    def start(self, plan: object, snapshot: object) -> ApplyResult:
        """Load an ACES evaluation plan and register its observable resources."""
        working_snapshot = snapshot if isinstance(snapshot, RuntimeSnapshot) else RuntimeSnapshot()
        if not isinstance(plan, EvaluationPlan):
            return ApplyResult(
                success=False,
                snapshot=working_snapshot,
                diagnostics=[
                    _evaluation_diagnostic(
                        "aptl.evaluator.invalid-plan",
                        EVALUATION_ADDRESS,
                        "APTL evaluator expected an ACES EvaluationPlan.",
                    )
                ],
            )

        entries = dict(working_snapshot.entries)
        states = _existing_states(working_snapshot)
        history = {
            address: list(events)
            for address, events in working_snapshot.evaluation_history.items()
        }
        contracts: dict[str, EvaluationResultContract] = {}
        operation_payloads: dict[str, dict[str, object]] = {}
        diagnostics: list[Diagnostic] = []
        changed: list[str] = []
        registered_at = _utc_now()

        for op in plan.actionable_operations:
            if op.action == ChangeAction.DELETE:
                entries.pop(op.address, None)
                states.pop(op.address, None)
                history.pop(op.address, None)
                changed.append(op.address)
                continue
            entries[op.address] = SnapshotEntry(
                address=op.address,
                domain=RuntimeDomain.EVALUATION,
                resource_type=op.resource_type,
                payload=op.payload,
                ordering_dependencies=op.ordering_dependencies,
                refresh_dependencies=op.refresh_dependencies,
                status="ready",
            )
            changed.append(op.address)
            if op.resource_type in _OBSERVABLE_RESOURCE_TYPES:
                contract, evaluation_diagnostics = _register_evaluation(
                    op.address,
                    op.payload,
                    registered_at,
                    states,
                    history,
                )
                diagnostics.extend(evaluation_diagnostics)
                if contract is not None:
                    contracts[op.address] = contract
                    operation_payloads[op.address] = dict(op.payload)

        if diagnostics:
            return ApplyResult(
                success=False,
                snapshot=working_snapshot,
                diagnostics=diagnostics,
            )

        _drive_evaluations(
            plan,
            working_snapshot,
            operation_payloads,
            states,
            history,
            contracts,
        )
        results = {address: state.to_payload() for address, state in states.items()}
        self._results = {address: dict(result) for address, result in results.items()}
        self._history = {
            address: [dict(event) for event in events] for address, events in history.items()
        }
        return ApplyResult(
            success=True,
            snapshot=working_snapshot.with_entries(
                entries,
                evaluation_results=results,
                evaluation_history=history,
            ),
            changed_addresses=changed,
        )

    def status(self) -> dict[str, object]:
        """Return current evaluation status."""
        return {
            "backend": "aptl",
            "registered_evaluations": sorted(self._results),
        }

    def results(self) -> dict[str, dict[str, object]]:
        """Return the most recent evaluation result envelopes."""
        return {address: dict(result) for address, result in self._results.items()}

    def history(self) -> dict[str, list[dict[str, object]]]:
        """Return the evaluation history event streams."""
        return {
            address: [dict(event) for event in events]
            for address, events in self._history.items()
        }

    def stop(self, snapshot: object) -> ApplyResult:
        """Stop evaluation and clear evaluation state."""
        working_snapshot = snapshot if isinstance(snapshot, RuntimeSnapshot) else RuntimeSnapshot()
        retained_entries = {
            address: entry
            for address, entry in working_snapshot.entries.items()
            if entry.domain != RuntimeDomain.EVALUATION
        }
        changed = sorted(set(working_snapshot.entries) - set(retained_entries))
        self._results = {}
        self._history = {}
        return ApplyResult(
            success=True,
            snapshot=working_snapshot.with_entries(
                retained_entries,
                evaluation_results={},
                evaluation_history={},
            ),
            changed_addresses=changed,
        )
