"""Terminal-cause -> RAES run/outcome status mapping (EXP-009 / ADR-050).

The mapping is the single code-owned policy every archival caller shares. It
must cover every terminal cause the execution controller can hand off, force
closed on an unknown cause, and never erase the real execution outcome by
defaulting every record to ``run_status="sealed"`` (ADR-050: the seal marker,
not ``run_status``, is the archive commit state).
"""

from __future__ import annotations

import pytest
from raes_contracts.contracts import ExperimentRunModel

from aptl.core.archival.status import (
    TerminalCause,
    TerminalStatus,
    map_terminal_cause,
)


def _run_status_literals() -> frozenset[str]:
    return frozenset(
        ExperimentRunModel.model_fields["run_status"].annotation.__args__
    )


def _outcome_status_literals() -> frozenset[str]:
    return frozenset(
        ExperimentRunModel.model_fields["outcome_status"].annotation.__args__
    )


def test_every_terminal_cause_maps_to_valid_literals() -> None:
    """Every cause maps to run/outcome status literals the RAES model accepts."""
    run_literals = _run_status_literals()
    outcome_literals = _outcome_status_literals()
    for cause in TerminalCause:
        evaluator_outcome = "succeeded" if cause is TerminalCause.COMPLETED else None
        status = map_terminal_cause(cause, evaluator_outcome=evaluator_outcome)
        assert status.run_status in run_literals
        assert status.outcome_status in outcome_literals


def test_completed_uses_evaluator_outcome() -> None:
    """A completed attempt records the evaluator's outcome verbatim."""
    for outcome in ("succeeded", "failed", "partial", "inconclusive", "not-evaluated"):
        status = map_terminal_cause(
            TerminalCause.COMPLETED, evaluator_outcome=outcome
        )
        assert status == TerminalStatus(
            run_status="completed", outcome_status=outcome, requires_invalidation=False
        )


def test_completed_requires_evaluator_outcome() -> None:
    """Completed without an evaluator outcome is a programming error, not a guess."""
    with pytest.raises(ValueError, match="evaluator outcome"):
        map_terminal_cause(TerminalCause.COMPLETED, evaluator_outcome=None)


def test_completed_rejects_unknown_evaluator_outcome() -> None:
    with pytest.raises(ValueError, match="outcome"):
        map_terminal_cause(TerminalCause.COMPLETED, evaluator_outcome="totally-made-up")


def test_scenario_and_evaluator_failure_map_to_failed() -> None:
    for cause in (TerminalCause.SCENARIO_FAILURE, TerminalCause.EVALUATOR_FAILURE):
        status = map_terminal_cause(cause, evaluator_outcome=None)
        assert status.run_status == "failed"
        assert status.outcome_status == "failed"
        assert status.requires_invalidation is False


def test_abort_causes_map_to_aborted_not_evaluated() -> None:
    """Cancellation, policy stop, and infrastructure interruption abort the run."""
    for cause in (
        TerminalCause.CANCELLATION,
        TerminalCause.POLICY_STOP,
        TerminalCause.INFRASTRUCTURE_INTERRUPTION,
    ):
        status = map_terminal_cause(cause, evaluator_outcome=None)
        assert status.run_status == "aborted"
        assert status.outcome_status == "not-evaluated"
        assert status.requires_invalidation is False


def test_capture_loss_and_validity_failure_invalidate() -> None:
    for cause in (TerminalCause.CAPTURE_LOSS, TerminalCause.VALIDITY_FAILURE):
        status = map_terminal_cause(cause, evaluator_outcome=None)
        assert status.run_status == "invalidated"
        assert status.requires_invalidation is True


def test_superseded_maps_to_superseded() -> None:
    status = map_terminal_cause(TerminalCause.SUPERSEDED, evaluator_outcome=None)
    assert status.run_status == "superseded"
    assert status.requires_invalidation is False


def test_no_cause_maps_to_sealed_run_status() -> None:
    """The seal state belongs to the commit marker, never to run_status."""
    for cause in TerminalCause:
        evaluator_outcome = "succeeded" if cause is TerminalCause.COMPLETED else None
        status = map_terminal_cause(cause, evaluator_outcome=evaluator_outcome)
        assert status.run_status != "sealed"


def test_unknown_cause_fails_closed() -> None:
    """A non-member cause is a hard failure, never a silent success."""
    with pytest.raises((ValueError, TypeError)):
        map_terminal_cause("not-a-cause", evaluator_outcome=None)  # type: ignore[arg-type]
