"""The live execution controller (#437/#459) that drives admitted trials to a
sealed terminal record (EXP-009 / ADR-050).

:class:`ExperimentExecutor` is the production terminal-attempt authority ADR-050
reserves for #437/#459. For each planned trial it:

1. allocates a distinct ``attempt_id`` (the portable ``run_id``);
2. runs the injected workload (participant actions + evaluation) as the evidence
   coordinator's ``trial_body``, so collectors are live during the trial;
3. normalizes the terminal cause from the workload signal and the acquisition
   disposition (a ``finally`` boundary maps an exception/cancellation to an
   interruption);
4. always records the attempt's own terminal attestation as lifecycle evidence,
   so the RAES run's mandatory evidence/traceability/result fields are satisfied
   even when an authored collector never started;
5. assembles the owner-native :class:`TerminalAttemptContext` and calls
   :func:`finalize_terminal_attempt` exactly once.

The workload and collectors are injected — participant execution and evaluation
are lab/RAES-runtime concerns, the same seam ``acquire_evidence`` already uses
for ``trial_body``. The executor itself does the real archival work; it defines
no metrics and derives no results.

The terminal-attempt value types and the context-assembly builders live in
:mod:`aptl.core.execution.assembly`; they are re-exported here for the
controller's public API.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from aptl.core.archival.coordinator import SealResult, finalize_terminal_attempt
from aptl.core.archival.status import TerminalCause
from aptl.core.correlation.clock import ClockProvider
from aptl.core.evidence.coordinator import AcquisitionResult, acquire_evidence
from aptl.core.evidence.outcomes import AcquisitionDisposition
from aptl.core.evidence.protocol import Collector, RunScope
from aptl.core.execution.assembly import (
    _SIGNAL_CAUSE_MAP,
    LIFECYCLE_OBSERVATION_REF,
    AdmittedExperiment,
    AssemblyInputs,
    TerminalCauseResolution,
    TrialExecutionContext,
    TrialOutcome,
    TrialTerminalSignal,
    Workload,
    assemble_context,
)
from aptl.core.experiment.trial_plan_models import PlannedTrial
from aptl.core.runstore import LocalRunStore
from aptl.utils.logging import get_logger

log = get_logger("execution.executor")

#: Run-relative path of the durable attempt-intent journal, written create-once
#: before the workload so an interrupted attempt is recoverable.
_ATTEMPT_INTENT_RELPATH = "attempt-intent.json"

__all__ = [
    "AdmittedExperiment",
    "ExperimentExecutor",
    "LIFECYCLE_OBSERVATION_REF",
    "TrialExecutionContext",
    "TrialOutcome",
    "TrialTerminalSignal",
    "Workload",
    "normalize_terminal_cause",
]


def normalize_terminal_cause(
    outcome: TrialOutcome | None, disposition: AcquisitionDisposition
) -> TerminalCauseResolution:
    """Resolve the terminal cause from the workload signal and evidence disposition.

    Evidence invalidation dominates (a lost required capture invalidates the run
    regardless of the workload); otherwise a workload failure/abort wins; an
    inconclusive acquisition (a required source never started) is an
    infrastructure interruption; a clean completion with intact evidence is a
    completion. A missing outcome (the workload raised or was cancelled before
    reporting) is an infrastructure interruption.
    """
    if disposition is AcquisitionDisposition.INVALIDATED:
        reason = (outcome.invalidation_reason if outcome else None) or (
            "required evidence was lost during the run"
        )
        return TerminalCauseResolution(TerminalCause.CAPTURE_LOSS, invalidation_reason=reason)
    cause = _resolve_non_invalidated_cause(outcome, disposition)
    evaluator_outcome = (
        outcome.evaluator_outcome
        if outcome is not None and cause is TerminalCause.COMPLETED
        else None
    )
    return TerminalCauseResolution(cause, evaluator_outcome=evaluator_outcome)


def _resolve_non_invalidated_cause(
    outcome: TrialOutcome | None, disposition: AcquisitionDisposition
) -> TerminalCause:
    """Resolve the terminal cause when evidence was not invalidated."""
    if outcome is None:
        return TerminalCause.INFRASTRUCTURE_INTERRUPTION
    mapped = _SIGNAL_CAUSE_MAP.get(outcome.signal)
    if mapped is not None:
        return mapped
    # A completed workload: an inconclusive acquisition (a required source never
    # started) is an interruption; intact evidence is a completion.
    return (
        TerminalCause.INFRASTRUCTURE_INTERRUPTION
        if disposition is AcquisitionDisposition.INCONCLUSIVE
        else TerminalCause.COMPLETED
    )


@dataclass
class ExperimentExecutor:
    """Drives an :class:`AdmittedExperiment` to sealed terminal records."""

    store: LocalRunStore
    clock: ClockProvider
    collectors: Mapping[str, Collector]
    workload: Workload
    attempt_id_factory: Callable[[PlannedTrial, int], str] = (
        lambda trial, ordinal: f"{trial.planned_trial_id}-attempt-{ordinal}"
    )

    def execute(self, admitted: AdmittedExperiment) -> list[SealResult]:
        """Execute every planned trial once, returning one seal result per attempt."""
        return [self.execute_trial(admitted, trial) for trial in admitted.plan.trials]

    def execute_trial(
        self, admitted: AdmittedExperiment, planned_trial: PlannedTrial, *, attempt_ordinal: int = 1
    ) -> SealResult:
        """Execute one planned trial once and seal its terminal record."""
        attempt_id = self.attempt_id_factory(planned_trial, attempt_ordinal)
        scope = RunScope(
            run_id=attempt_id,
            planned_trial_id=planned_trial.planned_trial_id,
            attempt_id=attempt_id,
        )
        self.store.create_run(attempt_id)
        started_at = self.clock.now()
        # Durably bind the attempt to its admitted trial BEFORE running the
        # workload, so a crash / host restart / non-returning cancellation leaves
        # a recoverable intent (recover_interrupted_attempt) rather than an
        # untracked run.
        self._write_attempt_intent(admitted, planned_trial, attempt_id, started_at)

        trial_context = TrialExecutionContext(attempt_id, planned_trial, scope)
        holder: dict[str, TrialOutcome] = {}
        ran: dict[str, bool] = {"done": False}

        def trial_body() -> None:
            """Run the injected workload and record its outcome for the attempt."""
            holder["outcome"] = self.workload(trial_context)
            ran["done"] = True

        acquisition = acquire_evidence(
            bindings=admitted.plan.capture_bindings,
            collectors=self.collectors,
            run_store=self.store,
            scope=scope,
            clock=self.clock,
            trial_body=trial_body,
        )
        # ``acquire_evidence`` runs the trial body only while collectors are live.
        # When the plan declares no captures there is nothing to capture, so the
        # trial still runs — here, outside a (non-existent) capture window. A
        # plan that DID declare captures but whose collectors never started is a
        # genuine infrastructure interruption; the trial body correctly did not
        # run and ``outcome`` stays ``None``.
        if not ran["done"] and not admitted.plan.capture_bindings:
            # A crashed trial is a terminal cause, not a bug: capture the raise
            # and let terminal-cause normalization classify the interruption.
            try:
                holder["outcome"] = self.workload(trial_context)
            except Exception:  # noqa: BLE001
                log.warning("trial workload raised for attempt %s", attempt_id)
        ended_at = self.clock.now()
        outcome = holder.get("outcome")
        resolution = normalize_terminal_cause(outcome, acquisition.disposition)

        context = assemble_context(
            self.store,
            self.clock,
            AssemblyInputs(
                admitted=admitted,
                planned_trial=planned_trial,
                attempt_id=attempt_id,
                scope=scope,
                acquisition=acquisition,
                outcome=outcome,
                resolution=resolution,
                started_at=started_at,
                ended_at=ended_at,
            ),
        )
        result = finalize_terminal_attempt(context, store=self.store)
        log.info(
            "executed and sealed attempt %s (cause=%s, run_status=%s)",
            attempt_id,
            resolution.cause,
            result.run.run_status,
        )
        return result

    def _write_attempt_intent(
        self,
        admitted: AdmittedExperiment,
        planned_trial: PlannedTrial,
        attempt_id: str,
        started_at: str,
    ) -> None:
        """Persist the bounded, immutable attempt intent create-once."""
        self.store.create_run_json_once(
            attempt_id,
            _ATTEMPT_INTENT_RELPATH,
            {
                "schema_version": "aptl.attempt-intent/v1",
                "attempt_id": attempt_id,
                "planned_trial_id": planned_trial.planned_trial_id,
                "plan_id": admitted.plan.plan_id,
                "plan_digest": admitted.plan.plan_digest,
                "started_at": started_at,
            },
        )

    def recover_interrupted_attempt(
        self, admitted: AdmittedExperiment, planned_trial: PlannedTrial, attempt_id: str
    ) -> SealResult | None:
        """Convert an unfinished attempt into a sealed interruption record.

        Returns ``None`` when the attempt has no intent (never started) or is
        already sealed (nothing to recover). Otherwise it seals an
        infrastructure-interruption terminal record for the attempt from its
        durable admitted inputs — the restart path a crash requires.
        """
        if self.store.is_sealed(attempt_id):
            return None
        if self.store.read_run_json(attempt_id, _ATTEMPT_INTENT_RELPATH) is None:
            return None
        scope = RunScope(
            run_id=attempt_id,
            planned_trial_id=planned_trial.planned_trial_id,
            attempt_id=attempt_id,
        )
        now = self.clock.now()
        context = assemble_context(
            self.store,
            self.clock,
            AssemblyInputs(
                admitted=admitted,
                planned_trial=planned_trial,
                attempt_id=attempt_id,
                scope=scope,
                acquisition=AcquisitionResult(
                    disposition=AcquisitionDisposition.INCONCLUSIVE,
                    records=(),
                    refs=(),
                    reports=(),
                    diagnostics=(),
                ),
                outcome=None,
                resolution=normalize_terminal_cause(None, AcquisitionDisposition.INCONCLUSIVE),
                started_at=now,
                ended_at=now,
            ),
        )
        return finalize_terminal_attempt(context, store=self.store)
