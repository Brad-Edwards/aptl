"""RTE-001 workflow execution engine for APTL.

Drives compiled ACES workflow payloads through observable step lifecycles and
emits portable ``WorkflowExecutionState`` / ``WorkflowHistoryEvent`` records.
The ACES orchestrator adapter (``aptl.backends.aces_orchestrator``) registers
workflows and delegates execution here; observation surfaces read the stored
run records rather than seeding static ``PENDING`` state forever.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from aces_contracts.workflow import (
    WorkflowExecutionContract,
    WorkflowExecutionState,
    WorkflowHistoryEvent,
    WorkflowHistoryEventType,
    WorkflowResultContract,
    WorkflowStatus,
    WorkflowStepExecutionState,
    WorkflowStepLifecycle,
    WorkflowStepOutcome,
)

from aptl.utils.redaction import redact

_ISO_UTC_OFFSET = "+00:00"
_COMPLETED_TERMINAL_REASON = "completed"


def _utc_now() -> str:
    """Return the current UTC instant as an ISO-8601 ``...Z`` string."""
    return datetime.now(UTC).isoformat().replace(_ISO_UTC_OFFSET, "Z")


def _next_timestamp(previous: str, *, offset_ms: int = 1) -> str:
    """Return an ISO timestamp strictly after ``previous``."""
    parsed = datetime.fromisoformat(previous.replace("Z", _ISO_UTC_OFFSET))
    return (parsed + timedelta(milliseconds=offset_ms)).isoformat().replace(_ISO_UTC_OFFSET, "Z")


@dataclass
class WorkflowRunRecord(object):
    """Portable workflow result and history for one workflow address."""

    result: dict[str, object]
    history: list[dict[str, object]] = field(default_factory=list)


@dataclass
class WorkflowEngine(object):
    """In-memory RTE-001 workflow runtime keyed by workflow address."""

    _runs: dict[str, WorkflowRunRecord] = field(default_factory=dict, init=False)

    def register_pending(
        self,
        workflow_address: str,
        payload: dict[str, object],
        registered_at: str,
    ) -> WorkflowRunRecord:
        """Record truthful initial ``PENDING`` state for a workflow run."""
        result_contract = _load_result_contract(workflow_address, payload)
        steps = {
            step_name: WorkflowStepExecutionState(lifecycle=WorkflowStepLifecycle.PENDING)
            for step_name in result_contract.observable_steps
        }
        state = WorkflowExecutionState(
            state_schema_version=result_contract.state_schema_version,
            workflow_status=WorkflowStatus.PENDING,
            run_id=uuid4().hex,
            started_at=registered_at,
            updated_at=registered_at,
            steps=steps,
        )
        record = WorkflowRunRecord(result=state.to_payload(), history=[])
        self._runs[workflow_address] = record
        return record

    def get(self, workflow_address: str) -> WorkflowRunRecord | None:
        """Return a defensive copy of the stored run record, if present."""
        record = self._runs.get(workflow_address)
        if record is None:
            return None
        return WorkflowRunRecord(
            result=dict(record.result),
            history=[dict(event) for event in record.history],
        )

    def discard(self, workflow_address: str) -> None:
        """Drop any stored run record for ``workflow_address``."""
        self._runs.pop(workflow_address, None)

    def drive(
        self,
        workflow_address: str,
        payload: dict[str, object],
        *,
        objective_outcomes: dict[str, WorkflowStepOutcome],
    ) -> WorkflowRunRecord:
        """Execute a registered workflow using compiled control metadata."""
        record = self._runs.get(workflow_address)
        if record is None:
            record = self.register_pending(workflow_address, payload, _utc_now())

        current = WorkflowExecutionState.from_payload(record.result)
        if current.workflow_status != WorkflowStatus.PENDING:
            return WorkflowRunRecord(result=dict(record.result), history=list(record.history))

        execution_contract = _load_execution_contract(workflow_address, payload)
        if not _objective_outcomes_ready(execution_contract, payload, objective_outcomes):
            return WorkflowRunRecord(result=dict(record.result), history=list(record.history))
        control_steps = _load_control_steps(payload)
        result_contract = _load_result_contract(workflow_address, payload)

        history: list[dict[str, object]] = []
        timestamp = _next_timestamp(current.started_at, offset_ms=1)
        steps = {
            step_name: WorkflowStepExecutionState(lifecycle=WorkflowStepLifecycle.PENDING)
            for step_name in result_contract.observable_steps
        }

        history.append(
            WorkflowHistoryEvent(
                event_type=WorkflowHistoryEventType.WORKFLOW_STARTED,
                timestamp=timestamp,
                step_name=execution_contract.start_step,
            ).to_payload()
        )

        terminal_status, terminal_event, terminal_reason = _walk_control_flow(
            execution_contract=execution_contract,
            control_steps=control_steps,
            steps=steps,
            history=history,
            timestamp=timestamp,
            objective_outcomes=objective_outcomes,
        )

        final_timestamp = _next_timestamp(str(history[-1]["timestamp"]), offset_ms=1)
        final_steps = {
            name: WorkflowStepExecutionState(
                lifecycle=step.lifecycle,
                outcome=step.outcome,
                attempts=step.attempts,
            )
            for name, step in steps.items()
        }
        final_state = WorkflowExecutionState(
            state_schema_version=current.state_schema_version,
            workflow_status=terminal_status,
            run_id=current.run_id,
            started_at=current.started_at,
            updated_at=str(final_timestamp),
            terminal_reason=terminal_reason,
            steps=final_steps,
        )
        history.append(
            WorkflowHistoryEvent(
                event_type=terminal_event,
                timestamp=str(final_timestamp),
                details={"reason": terminal_reason} if terminal_reason else {},
            ).to_payload()
        )

        driven = WorkflowRunRecord(result=final_state.to_payload(), history=history)
        self._runs[workflow_address] = driven
        return WorkflowRunRecord(result=dict(driven.result), history=[dict(event) for event in driven.history])

    def export(self) -> tuple[dict[str, dict[str, object]], dict[str, list[dict[str, object]]]]:
        """Return portable orchestration result and history maps."""
        results = {address: dict(record.result) for address, record in self._runs.items()}
        history = {
            address: [dict(event) for event in record.history]
            for address, record in self._runs.items()
            if record.history
        }
        return results, history


@dataclass(frozen=True)
class _ControlFlowTerminal(object):
    """Terminal workflow status produced while walking compiled control flow."""

    status: WorkflowStatus
    event: WorkflowHistoryEventType
    reason: str | None


def _load_result_contract(workflow_address: str, payload: dict[str, object]) -> WorkflowResultContract:
    """Load and validate the compiled workflow result contract."""
    result_contract_payload = payload.get("result_contract")
    if not isinstance(result_contract_payload, dict):
        raise ValueError(
            redact(
                f"Workflow '{workflow_address}' is missing compiled result_contract."
            )
        )
    return WorkflowResultContract.from_mapping(result_contract_payload)


def _load_execution_contract(
    workflow_address: str,
    payload: dict[str, object],
) -> WorkflowExecutionContract:
    """Load and validate the compiled workflow execution contract."""
    execution_contract_payload = payload.get("execution_contract")
    if not isinstance(execution_contract_payload, dict):
        raise ValueError(
            redact(
                f"Workflow '{workflow_address}' is missing compiled execution_contract."
            )
        )
    return WorkflowExecutionContract.from_mapping(execution_contract_payload)


def _load_control_steps(payload: dict[str, object]) -> dict[str, dict[str, Any]]:
    """Load compiled workflow control-step metadata keyed by step name."""
    control_steps = payload.get("control_steps")
    if not isinstance(control_steps, dict):
        raise ValueError("Workflow payload is missing compiled control_steps.")
    return {str(name): step for name, step in control_steps.items() if isinstance(step, dict)}


def _resolve_outcome_check_successor(
    step_meta: dict[str, Any],
    outcome: WorkflowStepOutcome,
) -> str | None:
    """Return the next step for readiness checks, or ``None`` when complete."""
    if outcome == WorkflowStepOutcome.SUCCEEDED:
        return str(step_meta.get("on_success") or "")
    if outcome == WorkflowStepOutcome.FAILED:
        on_failure = str(step_meta.get("on_failure") or "")
        return on_failure if on_failure else None
    return None


def _objective_outcomes_ready(
    execution_contract: WorkflowExecutionContract,
    payload: dict[str, object],
    objective_outcomes: dict[str, WorkflowStepOutcome],
) -> bool:
    """Return whether objective outcomes cover the executable control path."""
    control_steps = _load_control_steps(payload)
    current_step = execution_contract.start_step
    visited: set[str] = set()

    while current_step and current_step not in visited:
        visited.add(current_step)
        step_meta = control_steps.get(current_step)
        if step_meta is None:
            return False

        step_type = str(step_meta.get("step_type", ""))
        if step_type == "end":
            return True
        if step_type != "objective":
            return False

        objective_address = str(step_meta.get("objective_address", ""))
        if objective_address not in objective_outcomes:
            return False

        next_step = _resolve_outcome_check_successor(
            step_meta,
            objective_outcomes[objective_address],
        )
        if next_step is None:
            return True
        current_step = next_step

    return True


def _require_step_meta(
    control_steps: dict[str, dict[str, Any]],
    current_step: str,
) -> dict[str, Any]:
    """Return compiled metadata for ``current_step`` or raise."""
    step_meta = control_steps.get(current_step)
    if step_meta is None:
        raise ValueError(f"Workflow references unknown step '{current_step}'.")
    return step_meta


def _terminal_for_failed_objective(current_step: str) -> _ControlFlowTerminal:
    """Build the terminal state for a failed objective with no recovery step."""
    return _ControlFlowTerminal(
        status=WorkflowStatus.FAILED,
        event=WorkflowHistoryEventType.WORKFLOW_FAILED,
        reason=f"objective step '{current_step}' failed",
    )


def _terminal_for_unsupported_outcome(
    current_step: str,
    outcome: WorkflowStepOutcome,
) -> _ControlFlowTerminal:
    """Build the terminal state for an unsupported objective outcome."""
    return _ControlFlowTerminal(
        status=WorkflowStatus.FAILED,
        event=WorkflowHistoryEventType.WORKFLOW_FAILED,
        reason=(
            f"objective step '{current_step}' returned unsupported outcome "
            f"'{outcome.value}'"
        ),
    )


def _terminal_for_missing_successor(step_meta: dict[str, Any], current_step: str) -> _ControlFlowTerminal:
    """Build the terminal state when an objective step lacks a successor."""
    step_name = str(step_meta.get("name", current_step))
    return _ControlFlowTerminal(
        status=WorkflowStatus.FAILED,
        event=WorkflowHistoryEventType.WORKFLOW_FAILED,
        reason=f"objective step '{step_name}' has no successor",
    )


def _execute_objective_step(
    *,
    current_step: str,
    step_meta: dict[str, Any],
    steps: dict[str, WorkflowStepExecutionState],
    history: list[dict[str, object]],
    timestamp: str,
    objective_outcomes: dict[str, WorkflowStepOutcome],
) -> tuple[str, str, _ControlFlowTerminal | None]:
    """Record one objective step and return the next step or a terminal state."""
    timestamp = _next_timestamp(timestamp)
    history.append(
        WorkflowHistoryEvent(
            event_type=WorkflowHistoryEventType.STEP_STARTED,
            timestamp=timestamp,
            step_name=current_step,
        ).to_payload()
    )
    objective_address = str(step_meta.get("objective_address", ""))
    outcome = objective_outcomes.get(objective_address)
    if outcome is None:
        raise ValueError(
            redact(
                f"No objective outcome available for workflow step '{current_step}' "
                f"({objective_address})."
            )
        )

    steps[current_step] = WorkflowStepExecutionState(
        lifecycle=WorkflowStepLifecycle.COMPLETED,
        outcome=outcome,
        attempts=1,
    )
    timestamp = _next_timestamp(timestamp)
    history.append(
        WorkflowHistoryEvent(
            event_type=WorkflowHistoryEventType.STEP_COMPLETED,
            timestamp=timestamp,
            step_name=current_step,
            outcome=outcome,
        ).to_payload()
    )

    if outcome == WorkflowStepOutcome.SUCCEEDED:
        next_step = str(step_meta.get("on_success") or "")
        terminal = None
    elif outcome == WorkflowStepOutcome.FAILED:
        on_failure = str(step_meta.get("on_failure") or "")
        if on_failure:
            next_step = on_failure
            terminal = None
        else:
            next_step = ""
            terminal = _terminal_for_failed_objective(current_step)
    else:
        next_step = ""
        terminal = _terminal_for_unsupported_outcome(current_step, outcome)

    return next_step, timestamp, terminal


def _walk_control_flow(
    *,
    execution_contract: WorkflowExecutionContract,
    control_steps: dict[str, dict[str, Any]],
    steps: dict[str, WorkflowStepExecutionState],
    history: list[dict[str, object]],
    timestamp: str,
    objective_outcomes: dict[str, WorkflowStepOutcome],
) -> tuple[WorkflowStatus, WorkflowHistoryEventType, str | None]:
    """Walk compiled workflow control flow and emit step history events."""
    terminal = _ControlFlowTerminal(
        status=WorkflowStatus.FAILED,
        event=WorkflowHistoryEventType.WORKFLOW_FAILED,
        reason="workflow control flow ended abruptly",
    )
    current_step = execution_contract.start_step

    while current_step:
        step_meta = _require_step_meta(control_steps, current_step)
        step_type = str(step_meta.get("step_type", ""))
        if step_type == "end":
            terminal = _ControlFlowTerminal(
                status=WorkflowStatus.SUCCEEDED,
                event=WorkflowHistoryEventType.WORKFLOW_COMPLETED,
                reason=_COMPLETED_TERMINAL_REASON,
            )
            break

        if step_type != "objective":
            raise ValueError(
                f"RTE-001 workflow engine does not yet drive step type '{step_type}'."
            )

        current_step, timestamp, step_terminal = _execute_objective_step(
            current_step=current_step,
            step_meta=step_meta,
            steps=steps,
            history=history,
            timestamp=timestamp,
            objective_outcomes=objective_outcomes,
        )
        if step_terminal is not None:
            terminal = step_terminal
            break
        if not current_step:
            terminal = _terminal_for_missing_successor(step_meta, current_step)
            break

    return terminal.status, terminal.event, terminal.reason
