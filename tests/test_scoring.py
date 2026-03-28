"""Tests for scenario scoring computation."""

import pytest

from aptl.core.scenarios import (
    ContainerRequirements,
    Hint,
    Objective,
    ObjectiveSet,
    ObjectiveType,
    ScenarioDefinition,
    ScenarioMetadata,
    ScenarioMode,
    ScoringConfig,
    TimeBonusConfig,
)
from aptl.core.scoring import ObjectiveScore, ScoreReport, compute_score


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_scenario(
    objectives_red: list[Objective] | None = None,
    objectives_blue: list[Objective] | None = None,
    scoring: ScoringConfig | None = None,
    estimated_minutes: int = 30,
) -> ScenarioDefinition:
    """Build a minimal scenario for score testing."""
    red = objectives_red or []
    blue = objectives_blue or []
    return ScenarioDefinition(
        metadata=ScenarioMetadata(
            id="score-test",
            name="Score Test",
            description="A scoring test scenario",
            difficulty="beginner",
            estimated_minutes=estimated_minutes,
        ),
        mode=ScenarioMode.RED if red else ScenarioMode.BLUE,
        containers=ContainerRequirements(required=["kali"]),
        objectives=ObjectiveSet(red=red, blue=blue),
        scoring=scoring or ScoringConfig(),
    )


@pytest.fixture
def simple_objectives() -> list[Objective]:
    return [
        Objective(
            id="obj-a",
            description="First objective",
            type=ObjectiveType.MANUAL,
            points=100,
            hints=[
                Hint(level=1, text="Hint 1", point_penalty=10),
                Hint(level=2, text="Hint 2", point_penalty=25),
            ],
        ),
        Objective(
            id="obj-b",
            description="Second objective",
            type=ObjectiveType.MANUAL,
            points=50,
            hints=[
                Hint(level=1, text="Hint 1", point_penalty=5),
            ],
        ),
    ]


# ---------------------------------------------------------------------------
# Base score tests
# ---------------------------------------------------------------------------


def test_no_objectives_completed(simple_objectives):
    """Score is 0 when nothing is completed."""
    scenario = _make_scenario(
        objectives_red=simple_objectives,
        scoring=ScoringConfig(passing_score=100, max_score=150),
    )
    score = compute_score(scenario, [], {}, 0)
    assert score.total_score == 0
    assert not score.passed


def test_all_objectives_completed_no_hints(simple_objectives):
    """Full base score when all completed with no hints."""
    scenario = _make_scenario(
        objectives_red=simple_objectives,
        scoring=ScoringConfig(passing_score=100, max_score=150),
    )
    score = compute_score(scenario, ["obj-a", "obj-b"], {}, 0)
    assert score.total_score == 150  # 100 + 50
    assert score.passed is True
    assert score.hint_penalties == 0


def test_partial_completion(simple_objectives):
    """Only completed objectives earn points."""
    scenario = _make_scenario(
        objectives_red=simple_objectives,
        scoring=ScoringConfig(passing_score=100, max_score=150),
    )
    score = compute_score(scenario, ["obj-a"], {}, 0)
    assert score.total_score == 100
    assert score.passed is True


# ---------------------------------------------------------------------------
# Hint penalty tests
# ---------------------------------------------------------------------------


def test_hint_penalty_level_1(simple_objectives):
    """Level 1 hint penalizes only that hint's penalty."""
    scenario = _make_scenario(objectives_red=simple_objectives)
    score = compute_score(scenario, ["obj-a"], {"obj-a": 1}, 0)
    # 100 base - 10 penalty for level 1
    assert score.objective_scores[0].hint_penalty == 10
    assert score.objective_scores[0].earned == 90
    assert score.total_score == 90


def test_hint_penalty_level_2(simple_objectives):
    """Level 2 hint includes penalties for level 1 and 2."""
    scenario = _make_scenario(objectives_red=simple_objectives)
    score = compute_score(scenario, ["obj-a"], {"obj-a": 2}, 0)
    # 100 base - 10 (lvl 1) - 25 (lvl 2) = 65
    assert score.objective_scores[0].hint_penalty == 35
    assert score.objective_scores[0].earned == 65


def test_hint_penalty_on_incomplete_objective(simple_objectives):
    """Hint penalty on incomplete objective doesn't subtract (earned=0)."""
    scenario = _make_scenario(objectives_red=simple_objectives)
    score = compute_score(scenario, [], {"obj-a": 2}, 0)
    assert score.objective_scores[0].earned == 0
    # But penalties are still counted in total
    assert score.hint_penalties == 35


def test_hint_penalty_capped_at_zero(simple_objectives):
    """Score per objective never goes below 0."""
    obj = Objective(
        id="low-pts",
        description="Low points",
        type=ObjectiveType.MANUAL,
        points=5,
        hints=[Hint(level=1, text="Big hint", point_penalty=100)],
    )
    scenario = _make_scenario(objectives_red=[obj])
    score = compute_score(scenario, ["low-pts"], {"low-pts": 1}, 0)
    assert score.objective_scores[0].earned == 0  # max(0, 5-100)


# ---------------------------------------------------------------------------
# Time bonus tests
# ---------------------------------------------------------------------------


def test_time_bonus_full():
    """Full bonus awarded when completed before decay starts."""
    obj = Objective(
        id="obj-a", description="Test", type=ObjectiveType.MANUAL, points=100
    )
    scenario = _make_scenario(
        objectives_red=[obj],
        scoring=ScoringConfig(
            time_bonus=TimeBonusConfig(
                enabled=True, max_bonus=50, decay_after_minutes=10
            ),
            max_score=150,
        ),
        estimated_minutes=30,
    )
    score = compute_score(scenario, ["obj-a"], {}, elapsed_seconds=300)  # 5 min
    assert score.time_bonus == 50
    assert score.total_score == 150


def test_time_bonus_partial_decay():
    """Partial bonus during decay window."""
    obj = Objective(
        id="obj-a", description="Test", type=ObjectiveType.MANUAL, points=100
    )
    scenario = _make_scenario(
        objectives_red=[obj],
        scoring=ScoringConfig(
            time_bonus=TimeBonusConfig(
                enabled=True, max_bonus=50, decay_after_minutes=10
            ),
            max_score=200,
        ),
        estimated_minutes=30,
    )
    # 20 minutes = 10 min in decay window. Decay window = 30-10 = 20 min total.
    # 10/20 = 0.5 remaining => 50 * 0.5 = 25
    score = compute_score(scenario, ["obj-a"], {}, elapsed_seconds=1200)
    assert score.time_bonus == 25


def test_time_bonus_zero_after_timeout():
    """No bonus after estimated time expires."""
    obj = Objective(
        id="obj-a", description="Test", type=ObjectiveType.MANUAL, points=100
    )
    scenario = _make_scenario(
        objectives_red=[obj],
        scoring=ScoringConfig(
            time_bonus=TimeBonusConfig(
                enabled=True, max_bonus=50, decay_after_minutes=10
            ),
            max_score=150,
        ),
        estimated_minutes=30,
    )
    score = compute_score(scenario, ["obj-a"], {}, elapsed_seconds=1800)  # 30 min
    assert score.time_bonus == 0
    assert score.total_score == 100


def test_time_bonus_disabled():
    """No bonus when time_bonus is disabled."""
    obj = Objective(
        id="obj-a", description="Test", type=ObjectiveType.MANUAL, points=100
    )
    scenario = _make_scenario(
        objectives_red=[obj],
        scoring=ScoringConfig(
            time_bonus=TimeBonusConfig(enabled=False, max_bonus=50),
        ),
    )
    score = compute_score(scenario, ["obj-a"], {}, elapsed_seconds=60)
    assert score.time_bonus == 0


# ---------------------------------------------------------------------------
# Pass/fail threshold tests
# ---------------------------------------------------------------------------


def test_passing_score_met():
    """Passes when total meets or exceeds passing_score."""
    obj = Objective(
        id="obj-a", description="Test", type=ObjectiveType.MANUAL, points=100
    )
    scenario = _make_scenario(
        objectives_red=[obj],
        scoring=ScoringConfig(passing_score=100, max_score=100),
    )
    score = compute_score(scenario, ["obj-a"], {}, 0)
    assert score.passed is True


def test_passing_score_not_met():
    """Fails when total is below passing_score."""
    obj = Objective(
        id="obj-a", description="Test", type=ObjectiveType.MANUAL, points=50
    )
    scenario = _make_scenario(
        objectives_red=[obj],
        scoring=ScoringConfig(passing_score=100, max_score=100),
    )
    score = compute_score(scenario, ["obj-a"], {}, 0)
    assert score.passed is False


def test_zero_passing_score_always_passes():
    """Zero passing score means any result passes."""
    obj = Objective(
        id="obj-a", description="Test", type=ObjectiveType.MANUAL, points=100
    )
    scenario = _make_scenario(
        objectives_red=[obj],
        scoring=ScoringConfig(passing_score=0, max_score=100),
    )
    score = compute_score(scenario, [], {}, 0)
    assert score.passed is True


# ---------------------------------------------------------------------------
# Score report structure
# ---------------------------------------------------------------------------


def test_score_report_structure(simple_objectives):
    """Score report contains per-objective breakdowns."""
    scenario = _make_scenario(
        objectives_red=simple_objectives,
        scoring=ScoringConfig(passing_score=50, max_score=150),
    )
    score = compute_score(scenario, ["obj-a"], {"obj-b": 1}, 0)

    assert len(score.objective_scores) == 2
    assert score.objective_scores[0].objective_id == "obj-a"
    assert score.objective_scores[0].completed is True
    assert score.objective_scores[1].objective_id == "obj-b"
    assert score.objective_scores[1].completed is False
    assert score.max_score == 150
    assert score.passing_score == 50
