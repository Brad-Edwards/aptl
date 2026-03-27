"""Scenario scoring computation.

Pure-function score calculation based on completed objectives, hint
usage, and elapsed time. Consumes existing Pydantic models from
``scenarios.py`` and returns structured score reports.
"""

from dataclasses import dataclass, field

from aptl.core.scenarios import Objective, ScenarioDefinition


@dataclass
class ObjectiveScore:
    """Score breakdown for a single objective."""

    objective_id: str
    base_points: int
    hint_penalty: int
    earned: int
    completed: bool


@dataclass
class ScoreReport:
    """Complete score report for a scenario run."""

    total_score: int
    max_score: int
    passing_score: int
    passed: bool
    time_bonus: int
    hint_penalties: int
    objective_scores: list[ObjectiveScore] = field(default_factory=list)


def _hint_penalty(objective: Objective, max_hint_level: int) -> int:
    """Compute total hint penalty for an objective.

    Sums point_penalty for all hints at or below the used level.
    """
    penalty = 0
    for hint in objective.hints:
        if hint.level <= max_hint_level:
            penalty += hint.point_penalty
    return penalty


def _time_bonus(
    max_bonus: int,
    decay_after_minutes: int,
    estimated_minutes: int,
    elapsed_seconds: float,
) -> int:
    """Compute time bonus with linear decay.

    Full bonus is awarded if the scenario is completed before
    ``decay_after_minutes``. After that, bonus decays linearly
    to zero at ``estimated_minutes``.
    """
    if max_bonus <= 0:
        return 0

    elapsed_minutes = elapsed_seconds / 60.0

    if elapsed_minutes <= decay_after_minutes:
        return max_bonus

    decay_window = estimated_minutes - decay_after_minutes
    if decay_window <= 0:
        return 0

    elapsed_in_decay = elapsed_minutes - decay_after_minutes
    if elapsed_in_decay >= decay_window:
        return 0

    fraction_remaining = 1.0 - (elapsed_in_decay / decay_window)
    return int(max_bonus * fraction_remaining)


def compute_score(
    scenario: ScenarioDefinition,
    completed_objectives: list[str],
    hints_used: dict[str, int],
    elapsed_seconds: float,
) -> ScoreReport:
    """Compute the current score for a scenario run.

    Args:
        scenario: The scenario definition with objectives and scoring config.
        completed_objectives: List of objective IDs that have been completed.
        hints_used: Map of objective_id to highest hint level revealed.
        elapsed_seconds: Time elapsed since scenario start.

    Returns:
        Complete score report with per-objective breakdown.
    """
    all_objectives = scenario.objectives.all_objectives()
    completed_set = set(completed_objectives)
    scoring = scenario.scoring

    objective_scores: list[ObjectiveScore] = []
    total_hint_penalties = 0

    for obj in all_objectives:
        is_completed = obj.id in completed_set
        penalty = _hint_penalty(obj, hints_used.get(obj.id, 0))
        total_hint_penalties += penalty

        if is_completed:
            earned = max(0, obj.points - penalty)
        else:
            earned = 0

        objective_scores.append(
            ObjectiveScore(
                objective_id=obj.id,
                base_points=obj.points,
                hint_penalty=penalty,
                earned=earned,
                completed=is_completed,
            )
        )

    base_total = sum(os.earned for os in objective_scores)

    bonus = 0
    if scoring.time_bonus.enabled:
        bonus = _time_bonus(
            max_bonus=scoring.time_bonus.max_bonus,
            decay_after_minutes=scoring.time_bonus.decay_after_minutes,
            estimated_minutes=scenario.metadata.estimated_minutes,
            elapsed_seconds=elapsed_seconds,
        )

    total = base_total + bonus

    return ScoreReport(
        total_score=total,
        max_score=scoring.max_score,
        passing_score=scoring.passing_score,
        passed=total >= scoring.passing_score,
        time_bonus=bonus,
        hint_penalties=total_hint_penalties,
        objective_scores=objective_scores,
    )
