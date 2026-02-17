"""Scoring and report generation for scenario evaluations.

Calculates scores from objective results applying time bonuses and hint
penalties, and generates structured after-action reports for serialization.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from aptl.core.events import Event
from aptl.core.objectives import ObjectiveResult, ObjectiveStatus
from aptl.core.scenarios import Objective, ScoringConfig, ScenarioDefinition
from aptl.core.session import ActiveSession
from aptl.utils.logging import get_logger

log = get_logger("scoring")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class ScoreBreakdown:
    """Detailed breakdown of a scenario score.

    Attributes:
        objective_scores: Map of objective_id to points awarded.
        time_bonus: Bonus points for fast completion.
        hint_penalties: Total points deducted for hints used.
        total: Final score (objectives + bonus - penalties, floor 0).
        max_possible: Maximum achievable score.
        passing: Whether the score meets the passing threshold.
    """

    objective_scores: dict[str, int] = field(default_factory=dict)
    time_bonus: int = 0
    hint_penalties: int = 0
    total: int = 0
    max_possible: int = 0
    passing: bool = False


@dataclass
class ScenarioReport:
    """Structured after-action report for a completed scenario.

    Attributes:
        scenario_id: ID of the scenario.
        scenario_name: Human-readable scenario name.
        difficulty: Difficulty level.
        mode: Scenario mode (red/blue/purple).
        started_at: ISO 8601 timestamp of session start.
        finished_at: ISO 8601 timestamp of session finish.
        duration_seconds: Total elapsed time.
        score: Full score breakdown.
        objective_results: Serialized per-objective results.
        events: Serialized event timeline.
        hints_used: Map of objective_id to highest hint level used.
    """

    scenario_id: str
    scenario_name: str
    difficulty: str
    mode: str
    started_at: str
    finished_at: str
    duration_seconds: float
    score: ScoreBreakdown
    objective_results: list[dict] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    hints_used: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _compute_time_bonus(
    scoring_config: ScoringConfig,
    elapsed_seconds: float,
    all_complete: bool,
) -> int:
    """Calculate time bonus points.

    The bonus is only awarded when all objectives are complete and the
    time bonus feature is enabled. The bonus decays linearly from
    max_bonus to 0 over decay_after_minutes.

    Args:
        scoring_config: Scenario scoring configuration.
        elapsed_seconds: Seconds elapsed since scenario start.
        all_complete: Whether all objectives are completed.

    Returns:
        Time bonus points (0 if not applicable).
    """
    tb = scoring_config.time_bonus
    if not tb.enabled or not all_complete:
        return 0

    decay_seconds = tb.decay_after_minutes * 60
    if elapsed_seconds >= decay_seconds:
        return 0

    remaining = 1.0 - (elapsed_seconds / decay_seconds)
    return int(tb.max_bonus * remaining)


def _compute_hint_penalties(
    objectives: list[Objective],
    hints_used: dict[str, int],
) -> tuple[int, dict[str, int]]:
    """Calculate total hint penalties and per-objective penalty breakdown.

    For each objective, the penalty is the sum of point_penalty for each
    hint level up to and including the level used. The objective's score
    is floored at 0 (penalties cannot make it negative).

    Args:
        objectives: All scenario objectives.
        hints_used: Map of objective_id to highest hint level used.

    Returns:
        Tuple of (total_penalties, per_objective_penalty_map).
    """
    total = 0
    per_objective: dict[str, int] = {}

    for obj in objectives:
        level_used = hints_used.get(obj.id, 0)
        if level_used == 0 or not obj.hints:
            continue

        penalty = 0
        for hint in obj.hints:
            if hint.level <= level_used:
                penalty += hint.point_penalty

        # Cap penalty at the objective's point value
        penalty = min(penalty, obj.points)
        per_objective[obj.id] = penalty
        total += penalty

    return total, per_objective


def calculate_score(
    objectives: list[Objective],
    results: list[ObjectiveResult],
    scoring_config: ScoringConfig,
    elapsed_seconds: float,
    hints_used: dict[str, int],
) -> ScoreBreakdown:
    """Calculate the scenario score.

    Scoring rules:
    1. Each completed objective awards its defined points.
    2. Time bonus: if enabled and all objectives complete, awards
       (max_bonus * remaining_fraction) where remaining_fraction
       decreases linearly from 1.0 to 0.0 over decay_after_minutes.
    3. Hint penalties: each hint used deducts its point_penalty from
       the total (floor at 0 per objective).
    4. Total = sum(objective_scores) + time_bonus - hint_penalties.
    5. Passing = total >= scoring_config.passing_score.

    Args:
        objectives: All scenario objectives.
        results: Evaluation results for each objective.
        scoring_config: Scoring configuration from the scenario.
        elapsed_seconds: Time elapsed since scenario start.
        hints_used: Map of objective_id -> highest hint level used.

    Returns:
        ScoreBreakdown with full details.
    """
    # Build results lookup
    result_by_id = {r.objective_id: r for r in results}

    # 1. Objective scores
    objective_scores: dict[str, int] = {}
    all_complete = True
    for obj in objectives:
        result = result_by_id.get(obj.id)
        if result and result.status == ObjectiveStatus.COMPLETED:
            objective_scores[obj.id] = obj.points
        else:
            objective_scores[obj.id] = 0
            all_complete = False

    raw_objective_total = sum(objective_scores.values())

    # 2. Time bonus
    time_bonus = _compute_time_bonus(scoring_config, elapsed_seconds, all_complete)

    # 3. Hint penalties
    total_penalties, _ = _compute_hint_penalties(objectives, hints_used)

    # 4. Total (floor at 0)
    total = max(0, raw_objective_total + time_bonus - total_penalties)

    # 5. Max possible
    max_possible = sum(obj.points for obj in objectives)
    if scoring_config.time_bonus.enabled:
        max_possible += scoring_config.time_bonus.max_bonus
    if scoring_config.max_score > 0:
        max_possible = scoring_config.max_score

    # 6. Passing
    passing = total >= scoring_config.passing_score

    breakdown = ScoreBreakdown(
        objective_scores=objective_scores,
        time_bonus=time_bonus,
        hint_penalties=total_penalties,
        total=total,
        max_possible=max_possible,
        passing=passing,
    )

    log.info(
        "Score calculated: %d/%d (%s)",
        total,
        max_possible,
        "PASS" if passing else "FAIL",
    )
    return breakdown


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def _serialize_objective_result(result: ObjectiveResult) -> dict:
    """Convert an ObjectiveResult to a JSON-serializable dict."""
    d = asdict(result)
    d["status"] = result.status.value
    return d


def _serialize_event(event: Event) -> dict:
    """Convert an Event to a JSON-serializable dict."""
    d = asdict(event)
    d["event_type"] = event.event_type.value
    return d


def generate_report(
    scenario: ScenarioDefinition,
    session: ActiveSession,
    results: list[ObjectiveResult],
    events: list[Event],
    score: ScoreBreakdown,
) -> ScenarioReport:
    """Generate a structured after-action report.

    Args:
        scenario: The scenario definition.
        session: The completed session.
        results: Final objective results.
        events: Full event timeline.
        score: Calculated score.

    Returns:
        ScenarioReport ready for serialization.
    """
    finished_at = datetime.now(timezone.utc).isoformat()

    # Calculate duration from session start
    start = datetime.fromisoformat(session.started_at)
    end = datetime.fromisoformat(finished_at)
    duration = (end - start).total_seconds()

    report = ScenarioReport(
        scenario_id=scenario.metadata.id,
        scenario_name=scenario.metadata.name,
        difficulty=scenario.metadata.difficulty.value,
        mode=scenario.mode.value,
        started_at=session.started_at,
        finished_at=finished_at,
        duration_seconds=duration,
        score=score,
        objective_results=[_serialize_objective_result(r) for r in results],
        events=[_serialize_event(e) for e in events],
        hints_used=dict(session.hints_used),
    )

    log.info(
        "Generated report for scenario '%s': %d/%d in %.0fs",
        scenario.metadata.id,
        score.total,
        score.max_possible,
        duration,
    )
    return report


def write_report(report: ScenarioReport, path: Path) -> None:
    """Write a report to a JSON file.

    Creates parent directories if they do not exist.

    Args:
        report: The report to write.
        path: Output file path.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    data = asdict(report)
    path.write_text(
        json.dumps(data, indent=2) + "\n",
        encoding="utf-8",
    )
    log.info("Wrote report to %s", path)
