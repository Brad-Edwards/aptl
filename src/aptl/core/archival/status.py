"""The code-owned terminal-cause -> RAES run/outcome status mapping (EXP-009 /
ADR-050 "One terminal-attempt coordinator owns finalization").

The execution controller (issues #437/#459) normalizes every way an attempt can
end into a :class:`TerminalCause`. This module is the *single* policy that turns
that typed cause into the portable ``ExperimentRunModel`` ``run_status`` and
``outcome_status``. Every archival caller shares it, so a completed run never
loses its evaluator outcome, an aborted run never masquerades as a failure, and
no record is forced to ``run_status="sealed"`` — the seal state is the ADR-050
commit marker, not a run-record field.

The mapping fails closed: an unknown cause raises rather than defaulting to a
success or an omission.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from raes_contracts.contracts import ExperimentRunModel

#: The ``outcome_status`` values the installed RAES model accepts, read from the
#: model itself so this policy can never drift from the contract it targets.
_VALID_OUTCOME_STATUSES: frozenset[str] = frozenset(
    ExperimentRunModel.model_fields["outcome_status"].annotation.__args__
)


class TerminalCause(str, Enum):
    """The normalized cause an execution attempt reached a terminal state.

    The execution controller owns normalization (ADR-050); the archive
    coordinator consumes the typed cause and never infers cancellation from a
    missing file or a timeout from the wall clock.
    """

    #: Execution ran to completion and the evaluator produced a verdict.
    COMPLETED = "completed"
    #: The scenario itself failed (participant/range fault during execution).
    SCENARIO_FAILURE = "scenario-failure"
    #: The evaluator failed to produce a usable verdict.
    EVALUATOR_FAILURE = "evaluator-failure"
    #: Infrastructure interruption (host restart, backend loss) aborted the run.
    INFRASTRUCTURE_INTERRUPTION = "infrastructure-interruption"
    #: A policy stop halted the run before completion.
    POLICY_STOP = "policy-stop"
    #: Cooperative cancellation halted the run before completion.
    CANCELLATION = "cancellation"
    #: Required evidence was lost mid-run (capture loss), invalidating the run.
    CAPTURE_LOSS = "capture-loss"
    #: Another validity failure (clock uncertainty, unacceptable truncation)
    #: invalidated the run.
    VALIDITY_FAILURE = "validity-failure"
    #: This record version was replaced by a newer sealed version (repair).
    SUPERSEDED = "superseded"


@dataclass(frozen=True)
class TerminalStatus:
    """The portable run/outcome status a terminal cause resolves to.

    ``requires_invalidation`` tells the run-record composer whether the RAES
    model demands an :class:`ExperimentInvalidationModel` for this status
    (``run_status="invalidated"``).
    """

    run_status: str
    outcome_status: str
    requires_invalidation: bool


#: Fixed run/outcome status for every non-completed cause. ``COMPLETED`` is not
#: here because its ``outcome_status`` is the evaluator's, supplied per call.
_FIXED_STATUS: dict[TerminalCause, tuple[str, str, bool]] = {
    TerminalCause.SCENARIO_FAILURE: ("failed", "failed", False),
    TerminalCause.EVALUATOR_FAILURE: ("failed", "failed", False),
    TerminalCause.INFRASTRUCTURE_INTERRUPTION: ("aborted", "not-evaluated", False),
    TerminalCause.POLICY_STOP: ("aborted", "not-evaluated", False),
    TerminalCause.CANCELLATION: ("aborted", "not-evaluated", False),
    TerminalCause.CAPTURE_LOSS: ("invalidated", "inconclusive", True),
    TerminalCause.VALIDITY_FAILURE: ("invalidated", "inconclusive", True),
    TerminalCause.SUPERSEDED: ("superseded", "inconclusive", False),
}


def map_terminal_cause(
    cause: TerminalCause, *, evaluator_outcome: str | None
) -> TerminalStatus:
    """Return the portable status for ``cause``.

    For :attr:`TerminalCause.COMPLETED` the ``outcome_status`` is the evaluator's
    verdict and must be supplied as a valid RAES ``outcome_status`` literal — the
    archival layer never derives an outcome. For every other cause the outcome is
    fixed by policy and ``evaluator_outcome`` is ignored.

    Raises :class:`ValueError` for a completed run with a missing/invalid
    evaluator outcome and :class:`TypeError` for a non-:class:`TerminalCause`
    argument (fail closed).
    """
    if not isinstance(cause, TerminalCause):
        raise TypeError(f"cause must be a TerminalCause, got {type(cause)!r}")

    if cause is TerminalCause.COMPLETED:
        if evaluator_outcome is None:
            raise ValueError(
                "a completed attempt requires the evaluator outcome; the archival "
                "layer never derives one"
            )
        if evaluator_outcome not in _VALID_OUTCOME_STATUSES:
            raise ValueError(
                f"invalid evaluator outcome {evaluator_outcome!r}; expected one of "
                f"{sorted(_VALID_OUTCOME_STATUSES)}"
            )
        return TerminalStatus(
            run_status="completed",
            outcome_status=evaluator_outcome,
            requires_invalidation=False,
        )

    # Every non-completed TerminalCause member is present in _FIXED_STATUS, so a
    # missing key is a programmer error (KeyError), not a runtime condition.
    run_status, outcome_status, requires_invalidation = _FIXED_STATUS[cause]
    return TerminalStatus(
        run_status=run_status,
        outcome_status=outcome_status,
        requires_invalidation=requires_invalidation,
    )
