"""History progression helpers for ACES evaluator result streams."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Protocol

from aces_contracts.evaluation import (
    EvaluationExecutionState,
    EvaluationHistoryEvent,
    EvaluationHistoryEventType,
    EvaluationResultStatus,
)

_ISO_UTC_OFFSET = "+00:00"
_TERMINAL_RESULT_STATUSES = frozenset(
    {EvaluationResultStatus.FAILED, EvaluationResultStatus.READY}
)


class _OutcomeLike(Protocol):
    """Subset of outcome fields needed to append evaluator history."""

    status: EvaluationResultStatus
    passed: bool | None
    score: float | int | None
    max_score: int | None
    detail: str | None


def _next_timestamp(previous: str, *, offset_ms: int = 1) -> str:
    """Return an ISO timestamp strictly after ``previous``."""
    parsed = datetime.fromisoformat(previous.replace("Z", _ISO_UTC_OFFSET))
    return (parsed + timedelta(milliseconds=offset_ms)).isoformat().replace(
        _ISO_UTC_OFFSET,
        "Z",
    )


def _terminal_event(status: EvaluationResultStatus) -> EvaluationHistoryEventType:
    """Map a terminal result status to the portable history event type."""
    event_type = EvaluationHistoryEventType.EVALUATION_UPDATED
    if status == EvaluationResultStatus.READY:
        event_type = EvaluationHistoryEventType.EVALUATION_READY
    elif status == EvaluationResultStatus.FAILED:
        event_type = EvaluationHistoryEventType.EVALUATION_FAILED
    return event_type


def _state_matches_outcome(
    state: EvaluationExecutionState,
    outcome: _OutcomeLike,
) -> bool:
    """Return whether a terminal state already represents the resolved outcome."""
    return (
        state.status == outcome.status
        and state.passed == outcome.passed
        and state.score == outcome.score
        and state.max_score == outcome.max_score
        and state.detail == outcome.detail
    )


def _append_running_state(
    state: EvaluationExecutionState,
    events: list[dict[str, object]],
    timestamp: str,
    detail: str | None,
) -> EvaluationExecutionState:
    """Append a running event and return the corresponding state."""
    running_state = EvaluationExecutionState(
        state_schema_version=state.state_schema_version,
        resource_type=state.resource_type,
        run_id=state.run_id,
        status=EvaluationResultStatus.RUNNING,
        observed_at=state.observed_at,
        updated_at=timestamp,
        detail=detail,
    )
    events.append(
        EvaluationHistoryEvent(
            event_type=EvaluationHistoryEventType.EVALUATION_UPDATED,
            timestamp=timestamp,
            status=EvaluationResultStatus.RUNNING,
            detail=detail,
        ).to_payload()
    )
    return running_state


def _append_terminal_state(
    state: EvaluationExecutionState,
    outcome: _OutcomeLike,
    events: list[dict[str, object]],
    timestamp: str,
) -> EvaluationExecutionState:
    """Append a terminal event and return the corresponding final state."""
    final_state = EvaluationExecutionState(
        state_schema_version=state.state_schema_version,
        resource_type=state.resource_type,
        run_id=state.run_id,
        status=outcome.status,
        observed_at=state.observed_at,
        updated_at=timestamp,
        passed=outcome.passed,
        score=outcome.score,
        max_score=outcome.max_score,
        detail=outcome.detail,
    )
    events.append(
        EvaluationHistoryEvent(
            event_type=_terminal_event(outcome.status),
            timestamp=timestamp,
            status=outcome.status,
            passed=outcome.passed,
            score=outcome.score,
            max_score=outcome.max_score,
            detail=outcome.detail,
        ).to_payload()
    )
    return final_state


def _should_keep_terminal_state(
    state: EvaluationExecutionState,
    outcome: _OutcomeLike,
) -> bool:
    """Return whether a terminal run should remain unchanged for this observation."""
    return state.status in _TERMINAL_RESULT_STATUSES and (
        outcome.status == EvaluationResultStatus.RUNNING
        or _state_matches_outcome(state, outcome)
    )


def append_progression(
    state: EvaluationExecutionState,
    outcome: _OutcomeLike,
    events: list[dict[str, object]],
) -> EvaluationExecutionState:
    """Append running/terminal events and return the final result state."""
    result = state
    last_timestamp = str(events[-1]["timestamp"]) if events else state.updated_at
    can_run = state.status in {
        EvaluationResultStatus.PENDING,
        EvaluationResultStatus.RUNNING,
    }
    if _should_keep_terminal_state(state, outcome):
        pass
    elif can_run and outcome.status == EvaluationResultStatus.RUNNING:
        result = _append_running_state(
            state,
            events,
            _next_timestamp(last_timestamp),
            outcome.detail,
        )
    else:
        if state.status == EvaluationResultStatus.PENDING:
            result = _append_running_state(
                state,
                events,
                _next_timestamp(last_timestamp),
                None,
            )
            last_timestamp = result.updated_at
        result = _append_terminal_state(
            state,
            outcome,
            events,
            _next_timestamp(last_timestamp),
        )
    return result
