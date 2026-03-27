"""Scenario runtime engine with async evaluation loop.

Drives a scenario through periodic objective evaluation cycles,
updating session state and scores incrementally. Emits OTel spans
for each evaluation event.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone

from aptl.core.evaluators import EvaluationResult, evaluate_objective
from aptl.core.scenarios import ObjectiveType, ScenarioDefinition
from aptl.core.scoring import ScoreReport, compute_score
from aptl.core.session import ScenarioSession
from aptl.core.telemetry import (
    SPAN_EVALUATION,
    create_child_span,
    get_tracer,
    init_tracing,
    make_parent_context,
    shutdown_tracing,
)
from aptl.utils.logging import get_logger

log = get_logger("engine")


@dataclass
class EngineResult:
    """Final result from the engine after it stops."""

    completed_objectives: list[str] = field(default_factory=list)
    score: ScoreReport | None = None
    elapsed_seconds: float = 0.0
    timed_out: bool = False
    evaluation_cycles: int = 0


ProgressCallback = None  # Type alias placeholder


class ScenarioEngine:
    """Async engine that evaluates scenario objectives in real time.

    The engine periodically checks all non-manual, non-completed
    objectives against live infrastructure and updates session state
    as objectives are completed.

    Args:
        scenario: The scenario definition to evaluate.
        session_mgr: Session manager for state persistence.
        poll_interval: Seconds between evaluation cycles.
        timeout_minutes: Max runtime in minutes (None = no timeout).
        on_progress: Optional callback invoked after each cycle with
            (cycle_number, results, score).
    """

    def __init__(
        self,
        scenario: ScenarioDefinition,
        session_mgr: ScenarioSession,
        poll_interval: float = 10.0,
        timeout_minutes: float | None = None,
        on_progress: object = None,
    ) -> None:
        self._scenario = scenario
        self._session_mgr = session_mgr
        self._poll_interval = poll_interval
        self._timeout_minutes = timeout_minutes
        self._on_progress = on_progress
        self._all_objectives = scenario.objectives.all_objectives()
        self._evaluable_ids = {
            o.id
            for o in self._all_objectives
            if o.type != ObjectiveType.MANUAL
        }

    async def run(self, shutdown_event: asyncio.Event) -> EngineResult:
        """Main evaluation loop.

        Runs until all evaluable objectives are complete, the timeout
        is reached, or the shutdown event is set.
        """
        session = self._session_mgr.get_active()
        if session is None:
            log.error("No active session to run engine against")
            return EngineResult()

        started_at = datetime.fromisoformat(session.started_at)
        if not started_at.tzinfo:
            started_at = started_at.replace(tzinfo=timezone.utc)

        init_tracing()
        tracer = get_tracer()
        parent_ctx = make_parent_context(session.trace_id, session.span_id)

        result = EngineResult()
        cycle = 0

        try:
            while not shutdown_event.is_set():
                cycle += 1
                now = datetime.now(timezone.utc)
                elapsed = (now - started_at).total_seconds()

                # Check timeout
                if self._timeout_minutes is not None:
                    if elapsed >= self._timeout_minutes * 60:
                        log.info("Engine timeout reached after %.0fs", elapsed)
                        result.timed_out = True
                        break

                # Reload session to get latest completed_objectives
                session = self._session_mgr.get_active()
                if session is None:
                    log.warning("Session disappeared during engine run")
                    break

                completed_set = set(session.completed_objectives)
                pending = [
                    o
                    for o in self._all_objectives
                    if o.id in self._evaluable_ids and o.id not in completed_set
                ]

                if not pending:
                    log.info("All evaluable objectives complete")
                    break

                # Transition to EVALUATING
                try:
                    self._session_mgr.set_evaluating()
                except Exception:
                    pass  # May already be evaluating or race condition

                # Evaluate all pending objectives concurrently
                eval_results = await asyncio.gather(
                    *[
                        evaluate_objective(o, session.started_at)
                        for o in pending
                    ],
                    return_exceptions=True,
                )

                # Process results
                cycle_results: list[EvaluationResult] = []
                for i, er in enumerate(eval_results):
                    if isinstance(er, Exception):
                        log.warning(
                            "Evaluation exception for %s: %s",
                            pending[i].id,
                            er,
                        )
                        continue

                    cycle_results.append(er)

                    if er.passed and er.objective_id not in completed_set:
                        self._session_mgr.record_objective_complete(er.objective_id)
                        completed_set.add(er.objective_id)
                        log.info("Objective completed: %s", er.objective_id)

                    # Emit OTel evaluation span
                    span = create_child_span(
                        tracer,
                        parent_ctx,
                        SPAN_EVALUATION,
                        {
                            "aptl.objective.id": er.objective_id,
                            "aptl.evaluation.passed": er.passed,
                            "aptl.evaluation.detail": er.detail,
                            "aptl.evaluation.cycle": cycle,
                        },
                    )
                    span.end()

                # Transition back to ACTIVE
                try:
                    self._session_mgr.set_active_from_evaluating()
                except Exception:
                    pass

                # Compute score
                session = self._session_mgr.get_active()
                if session is not None:
                    score = compute_score(
                        self._scenario,
                        session.completed_objectives,
                        session.hints_used,
                        elapsed,
                    )
                    result.score = score
                    result.completed_objectives = list(session.completed_objectives)

                    # Invoke progress callback
                    if self._on_progress is not None:
                        try:
                            self._on_progress(cycle, cycle_results, score)
                        except Exception as e:
                            log.warning("Progress callback error: %s", e)

                result.evaluation_cycles = cycle

                # Wait for next cycle (interruptible by shutdown_event)
                try:
                    await asyncio.wait_for(
                        shutdown_event.wait(),
                        timeout=self._poll_interval,
                    )
                    # If we get here, shutdown was signaled
                    break
                except asyncio.TimeoutError:
                    # Normal timeout, continue to next cycle
                    pass

        finally:
            now = datetime.now(timezone.utc)
            result.elapsed_seconds = (now - started_at).total_seconds()
            result.evaluation_cycles = cycle
            shutdown_tracing()

        return result

    async def evaluate_once(self) -> list[EvaluationResult]:
        """Run a single evaluation pass and return results.

        Does not loop. Updates session state for completed objectives.
        """
        session = self._session_mgr.get_active()
        if session is None:
            return []

        completed_set = set(session.completed_objectives)
        pending = [
            o
            for o in self._all_objectives
            if o.id in self._evaluable_ids and o.id not in completed_set
        ]

        if not pending:
            return []

        eval_results = await asyncio.gather(
            *[evaluate_objective(o, session.started_at) for o in pending],
            return_exceptions=True,
        )

        results: list[EvaluationResult] = []
        for i, er in enumerate(eval_results):
            if isinstance(er, Exception):
                log.warning(
                    "Evaluation exception for %s: %s",
                    pending[i].id,
                    er,
                )
                continue

            results.append(er)

            if er.passed and er.objective_id not in completed_set:
                self._session_mgr.record_objective_complete(er.objective_id)
                completed_set.add(er.objective_id)
                log.info("Objective completed: %s", er.objective_id)

        return results

    def get_score(self) -> ScoreReport | None:
        """Compute current score snapshot."""
        session = self._session_mgr.get_active()
        if session is None:
            return None

        started_at = datetime.fromisoformat(session.started_at)
        if not started_at.tzinfo:
            started_at = started_at.replace(tzinfo=timezone.utc)
        elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()

        return compute_score(
            self._scenario,
            session.completed_objectives,
            session.hints_used,
            elapsed,
        )
