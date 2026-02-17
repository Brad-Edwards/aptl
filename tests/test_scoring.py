"""Tests for scoring and report generation.

Tests cover objective scoring, time bonus calculation, hint penalty
calculation, the combined calculate_score function, report generation,
and report serialization to disk.
"""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from aptl.core.events import Event, EventType
from aptl.core.objectives import ObjectiveResult, ObjectiveStatus
from aptl.core.scenarios import (
    Hint,
    Objective,
    ObjectiveType,
    ScoringConfig,
    TimeBonusConfig,
)
from aptl.core.scoring import (
    ScenarioReport,
    ScoreBreakdown,
    _compute_hint_penalties,
    _compute_time_bonus,
    calculate_score,
    generate_report,
    write_report,
)
from aptl.core.session import ActiveSession, SessionState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _obj(
    obj_id: str = "obj-a",
    points: int = 100,
    hints: list | None = None,
) -> Objective:
    """Create a minimal manual Objective."""
    return Objective(
        id=obj_id,
        description=f"Objective {obj_id}",
        type=ObjectiveType.MANUAL,
        points=points,
        hints=hints or [],
    )


def _result(
    obj_id: str = "obj-a",
    status: ObjectiveStatus = ObjectiveStatus.COMPLETED,
    points: int = 0,
) -> ObjectiveResult:
    """Create an ObjectiveResult."""
    return ObjectiveResult(
        objective_id=obj_id,
        status=status,
        points_awarded=points,
    )


def _scoring_config(
    passing_score: int = 50,
    max_score: int = 0,
    time_bonus_enabled: bool = False,
    max_bonus: int = 0,
    decay_minutes: int = 10,
) -> ScoringConfig:
    """Create a ScoringConfig."""
    return ScoringConfig(
        passing_score=passing_score,
        max_score=max_score,
        time_bonus=TimeBonusConfig(
            enabled=time_bonus_enabled,
            max_bonus=max_bonus,
            decay_after_minutes=decay_minutes,
        ),
    )


def _session(
    scenario_id: str = "test-scenario",
    started_at: str | None = None,
    hints_used: dict | None = None,
    completed_objectives: list | None = None,
) -> ActiveSession:
    """Create an ActiveSession."""
    return ActiveSession(
        scenario_id=scenario_id,
        state=SessionState.COMPLETED,
        started_at=started_at or datetime.now(timezone.utc).isoformat(),
        events_file="events/test.jsonl",
        hints_used=hints_used or {},
        completed_objectives=completed_objectives or [],
    )


# ---------------------------------------------------------------------------
# ScoreBreakdown dataclass
# ---------------------------------------------------------------------------


class TestScoreBreakdown:
    """Tests for the ScoreBreakdown dataclass."""

    def test_defaults(self):
        sb = ScoreBreakdown()
        assert sb.objective_scores == {}
        assert sb.time_bonus == 0
        assert sb.hint_penalties == 0
        assert sb.total == 0
        assert sb.max_possible == 0
        assert sb.passing is False

    def test_creation_with_values(self):
        sb = ScoreBreakdown(
            objective_scores={"a": 50, "b": 50},
            time_bonus=10,
            hint_penalties=5,
            total=105,
            max_possible=110,
            passing=True,
        )
        assert sb.total == 105
        assert sb.passing is True


# ---------------------------------------------------------------------------
# _compute_time_bonus
# ---------------------------------------------------------------------------


class TestComputeTimeBonus:
    """Tests for the time bonus calculation."""

    def test_disabled_returns_zero(self):
        config = _scoring_config(time_bonus_enabled=False, max_bonus=100)
        assert _compute_time_bonus(config, 0.0, True) == 0

    def test_not_all_complete_returns_zero(self):
        config = _scoring_config(time_bonus_enabled=True, max_bonus=100)
        assert _compute_time_bonus(config, 0.0, False) == 0

    def test_full_bonus_at_zero_elapsed(self):
        config = _scoring_config(
            time_bonus_enabled=True,
            max_bonus=100,
            decay_minutes=10,
        )
        assert _compute_time_bonus(config, 0.0, True) == 100

    def test_half_bonus_at_half_time(self):
        config = _scoring_config(
            time_bonus_enabled=True,
            max_bonus=100,
            decay_minutes=10,
        )
        # 5 minutes = 300 seconds, half of 600
        assert _compute_time_bonus(config, 300.0, True) == 50

    def test_zero_bonus_at_decay_time(self):
        config = _scoring_config(
            time_bonus_enabled=True,
            max_bonus=100,
            decay_minutes=10,
        )
        assert _compute_time_bonus(config, 600.0, True) == 0

    def test_zero_bonus_after_decay_time(self):
        config = _scoring_config(
            time_bonus_enabled=True,
            max_bonus=100,
            decay_minutes=10,
        )
        assert _compute_time_bonus(config, 900.0, True) == 0

    def test_linear_decay(self):
        config = _scoring_config(
            time_bonus_enabled=True,
            max_bonus=200,
            decay_minutes=10,
        )
        # At 25% of time (150s), should be 75% remaining = 150
        assert _compute_time_bonus(config, 150.0, True) == 150

    def test_truncates_to_int(self):
        config = _scoring_config(
            time_bonus_enabled=True,
            max_bonus=100,
            decay_minutes=3,  # 180 seconds
        )
        # At 60 seconds: remaining = 1 - 60/180 = 0.6667, bonus = 66.67 -> 66
        assert _compute_time_bonus(config, 60.0, True) == 66


# ---------------------------------------------------------------------------
# _compute_hint_penalties
# ---------------------------------------------------------------------------


class TestComputeHintPenalties:
    """Tests for hint penalty calculation."""

    def test_no_hints_used(self):
        objectives = [_obj("a", 100)]
        total, per_obj = _compute_hint_penalties(objectives, {})
        assert total == 0
        assert per_obj == {}

    def test_single_hint_penalty(self):
        objectives = [
            _obj("a", 100, hints=[
                Hint(level=1, text="Hint 1", point_penalty=10),
            ]),
        ]
        total, per_obj = _compute_hint_penalties(objectives, {"a": 1})
        assert total == 10
        assert per_obj == {"a": 10}

    def test_cumulative_hint_penalties(self):
        """Using hint level 2 should accumulate penalties for levels 1 and 2."""
        objectives = [
            _obj("a", 100, hints=[
                Hint(level=1, text="Hint 1", point_penalty=10),
                Hint(level=2, text="Hint 2", point_penalty=15),
            ]),
        ]
        total, per_obj = _compute_hint_penalties(objectives, {"a": 2})
        assert total == 25
        assert per_obj == {"a": 25}

    def test_penalty_capped_at_objective_points(self):
        """Penalty should not exceed the objective's point value."""
        objectives = [
            _obj("a", 20, hints=[
                Hint(level=1, text="Hint 1", point_penalty=15),
                Hint(level=2, text="Hint 2", point_penalty=15),
            ]),
        ]
        total, per_obj = _compute_hint_penalties(objectives, {"a": 2})
        assert total == 20  # capped at 20, not 30
        assert per_obj == {"a": 20}

    def test_multiple_objectives_with_hints(self):
        objectives = [
            _obj("a", 100, hints=[
                Hint(level=1, text="Hint 1", point_penalty=10),
            ]),
            _obj("b", 100, hints=[
                Hint(level=1, text="Hint 1", point_penalty=5),
                Hint(level=2, text="Hint 2", point_penalty=10),
            ]),
        ]
        total, per_obj = _compute_hint_penalties(objectives, {"a": 1, "b": 2})
        assert per_obj == {"a": 10, "b": 15}
        assert total == 25

    def test_no_hints_defined_on_objective(self):
        """Using hints for an objective with no hints defined is a no-op."""
        objectives = [_obj("a", 100)]
        total, per_obj = _compute_hint_penalties(objectives, {"a": 1})
        assert total == 0
        assert per_obj == {}

    def test_zero_penalty_hints(self):
        """Hints with zero penalty should not add any deduction."""
        objectives = [
            _obj("a", 100, hints=[
                Hint(level=1, text="Free hint", point_penalty=0),
            ]),
        ]
        total, per_obj = _compute_hint_penalties(objectives, {"a": 1})
        assert total == 0
        assert per_obj == {"a": 0}


# ---------------------------------------------------------------------------
# calculate_score
# ---------------------------------------------------------------------------


class TestCalculateScore:
    """Tests for the combined calculate_score function."""

    def test_all_completed_no_bonus(self):
        objectives = [_obj("a", 50), _obj("b", 50)]
        results = [
            _result("a", ObjectiveStatus.COMPLETED),
            _result("b", ObjectiveStatus.COMPLETED),
        ]
        config = _scoring_config(passing_score=50)

        score = calculate_score(objectives, results, config, 300.0, {})

        assert score.objective_scores == {"a": 50, "b": 50}
        assert score.total == 100
        assert score.passing is True

    def test_partial_completion(self):
        objectives = [_obj("a", 50), _obj("b", 50)]
        results = [
            _result("a", ObjectiveStatus.COMPLETED),
            _result("b", ObjectiveStatus.PENDING),
        ]
        config = _scoring_config(passing_score=60)

        score = calculate_score(objectives, results, config, 300.0, {})

        assert score.objective_scores == {"a": 50, "b": 0}
        assert score.total == 50
        assert score.passing is False

    def test_no_objectives_completed(self):
        objectives = [_obj("a", 100)]
        results = [_result("a", ObjectiveStatus.PENDING)]
        config = _scoring_config(passing_score=50)

        score = calculate_score(objectives, results, config, 300.0, {})

        assert score.total == 0
        assert score.passing is False

    def test_time_bonus_included(self):
        objectives = [_obj("a", 100)]
        results = [_result("a", ObjectiveStatus.COMPLETED)]
        config = _scoring_config(
            passing_score=50,
            time_bonus_enabled=True,
            max_bonus=50,
            decay_minutes=10,
        )

        score = calculate_score(objectives, results, config, 0.0, {})

        assert score.time_bonus == 50
        assert score.total == 150  # 100 + 50

    def test_hint_penalties_deducted(self):
        objectives = [
            _obj("a", 100, hints=[
                Hint(level=1, text="Hint", point_penalty=20),
            ]),
        ]
        results = [_result("a", ObjectiveStatus.COMPLETED)]
        config = _scoring_config(passing_score=50)

        score = calculate_score(objectives, results, config, 300.0, {"a": 1})

        assert score.hint_penalties == 20
        assert score.total == 80  # 100 - 20

    def test_total_floored_at_zero(self):
        """Total score should never go below zero."""
        objectives = [
            _obj("a", 10, hints=[
                Hint(level=1, text="Hint 1", point_penalty=5),
                Hint(level=2, text="Hint 2", point_penalty=5),
                Hint(level=3, text="Hint 3", point_penalty=5),
            ]),
        ]
        results = [_result("a", ObjectiveStatus.PENDING)]  # 0 points
        config = _scoring_config(passing_score=0)

        score = calculate_score(objectives, results, config, 300.0, {"a": 3})

        assert score.total == 0  # 0 - penalties, floored at 0

    def test_max_possible_from_objectives(self):
        objectives = [_obj("a", 50), _obj("b", 75)]
        results = [
            _result("a", ObjectiveStatus.COMPLETED),
            _result("b", ObjectiveStatus.COMPLETED),
        ]
        config = _scoring_config(passing_score=50)

        score = calculate_score(objectives, results, config, 300.0, {})

        assert score.max_possible == 125

    def test_max_possible_with_time_bonus(self):
        objectives = [_obj("a", 100)]
        results = [_result("a", ObjectiveStatus.COMPLETED)]
        config = _scoring_config(
            time_bonus_enabled=True,
            max_bonus=50,
        )

        score = calculate_score(objectives, results, config, 0.0, {})

        assert score.max_possible == 150  # 100 + 50

    def test_max_possible_overridden_by_config(self):
        """When max_score is set in config, it overrides calculated max."""
        objectives = [_obj("a", 100)]
        results = [_result("a", ObjectiveStatus.COMPLETED)]
        config = _scoring_config(max_score=200)

        score = calculate_score(objectives, results, config, 300.0, {})

        assert score.max_possible == 200

    def test_passing_threshold_zero(self):
        """With passing_score=0, any score (including 0) should pass."""
        objectives = [_obj("a", 100)]
        results = [_result("a", ObjectiveStatus.PENDING)]
        config = _scoring_config(passing_score=0)

        score = calculate_score(objectives, results, config, 300.0, {})

        assert score.total == 0
        assert score.passing is True

    def test_passing_at_exact_threshold(self):
        objectives = [_obj("a", 50)]
        results = [_result("a", ObjectiveStatus.COMPLETED)]
        config = _scoring_config(passing_score=50)

        score = calculate_score(objectives, results, config, 300.0, {})

        assert score.total == 50
        assert score.passing is True

    def test_failed_objectives_score_zero(self):
        objectives = [_obj("a", 100)]
        results = [_result("a", ObjectiveStatus.FAILED)]
        config = _scoring_config(passing_score=50)

        score = calculate_score(objectives, results, config, 300.0, {})

        assert score.objective_scores == {"a": 0}
        assert score.total == 0

    def test_missing_result_for_objective(self):
        """Objectives without results should score 0."""
        objectives = [_obj("a", 100), _obj("b", 100)]
        results = [_result("a", ObjectiveStatus.COMPLETED)]  # b missing
        config = _scoring_config(passing_score=50)

        score = calculate_score(objectives, results, config, 300.0, {})

        assert score.objective_scores["b"] == 0

    def test_combined_bonus_and_penalties(self):
        objectives = [
            _obj("a", 100, hints=[
                Hint(level=1, text="H1", point_penalty=10),
            ]),
        ]
        results = [_result("a", ObjectiveStatus.COMPLETED)]
        config = _scoring_config(
            passing_score=50,
            time_bonus_enabled=True,
            max_bonus=30,
            decay_minutes=10,
        )

        # At 0 elapsed, full bonus
        score = calculate_score(objectives, results, config, 0.0, {"a": 1})

        assert score.time_bonus == 30
        assert score.hint_penalties == 10
        assert score.total == 120  # 100 + 30 - 10


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------


class TestGenerateReport:
    """Tests for report generation."""

    def _make_scenario(self):
        from aptl.core.scenarios import ScenarioDefinition

        return ScenarioDefinition(
            metadata={
                "id": "test-scenario",
                "name": "Test Scenario",
                "description": "A test scenario",
                "difficulty": "beginner",
                "estimated_minutes": 10,
            },
            mode="red",
            containers={"required": ["kali"]},
            objectives={
                "red": [
                    {"id": "obj-a", "description": "Do A", "type": "manual", "points": 100},
                ],
                "blue": [],
            },
        )

    def test_report_has_correct_metadata(self):
        scenario = self._make_scenario()
        session = _session(started_at=datetime.now(timezone.utc).isoformat())
        results = [_result("obj-a", ObjectiveStatus.COMPLETED)]
        events = []
        score = ScoreBreakdown(total=100, max_possible=100, passing=True)

        report = generate_report(scenario, session, results, events, score)

        assert report.scenario_id == "test-scenario"
        assert report.scenario_name == "Test Scenario"
        assert report.difficulty == "beginner"
        assert report.mode == "red"

    def test_report_has_duration(self):
        started = datetime.now(timezone.utc) - timedelta(minutes=5)
        session = _session(started_at=started.isoformat())
        scenario = self._make_scenario()
        results = []
        events = []
        score = ScoreBreakdown()

        report = generate_report(scenario, session, results, events, score)

        # Duration should be approximately 5 minutes
        assert report.duration_seconds >= 299.0  # Allow slight timing variance

    def test_report_includes_objective_results(self):
        scenario = self._make_scenario()
        session = _session()
        results = [_result("obj-a", ObjectiveStatus.COMPLETED)]
        events = []
        score = ScoreBreakdown()

        report = generate_report(scenario, session, results, events, score)

        assert len(report.objective_results) == 1
        assert report.objective_results[0]["objective_id"] == "obj-a"
        assert report.objective_results[0]["status"] == "completed"

    def test_report_includes_events(self):
        scenario = self._make_scenario()
        session = _session()
        results = []
        events = [
            Event(
                event_type=EventType.SCENARIO_STARTED,
                scenario_id="test-scenario",
                timestamp=datetime.now(timezone.utc).isoformat(),
                data={"mode": "red"},
            ),
        ]
        score = ScoreBreakdown()

        report = generate_report(scenario, session, results, events, score)

        assert len(report.events) == 1
        assert report.events[0]["event_type"] == "scenario_started"

    def test_report_includes_hints_used(self):
        scenario = self._make_scenario()
        session = _session(hints_used={"obj-a": 2})
        results = []
        events = []
        score = ScoreBreakdown()

        report = generate_report(scenario, session, results, events, score)

        assert report.hints_used == {"obj-a": 2}

    def test_report_has_timestamps(self):
        scenario = self._make_scenario()
        session = _session(started_at="2026-02-16T14:30:00+00:00")
        results = []
        events = []
        score = ScoreBreakdown()

        report = generate_report(scenario, session, results, events, score)

        assert report.started_at == "2026-02-16T14:30:00+00:00"
        assert report.finished_at  # Should be set


# ---------------------------------------------------------------------------
# write_report
# ---------------------------------------------------------------------------


class TestWriteReport:
    """Tests for writing reports to disk."""

    def test_write_creates_file(self, tmp_path):
        report = ScenarioReport(
            scenario_id="test",
            scenario_name="Test",
            difficulty="beginner",
            mode="red",
            started_at="2026-02-16T14:30:00+00:00",
            finished_at="2026-02-16T14:45:00+00:00",
            duration_seconds=900.0,
            score=ScoreBreakdown(total=100, max_possible=100, passing=True),
        )

        path = tmp_path / "report.json"
        write_report(report, path)

        assert path.exists()

    def test_write_creates_parent_dirs(self, tmp_path):
        report = ScenarioReport(
            scenario_id="test",
            scenario_name="Test",
            difficulty="beginner",
            mode="red",
            started_at="2026-02-16T14:30:00+00:00",
            finished_at="2026-02-16T14:45:00+00:00",
            duration_seconds=900.0,
            score=ScoreBreakdown(),
        )

        path = tmp_path / "deep" / "nested" / "report.json"
        write_report(report, path)

        assert path.exists()

    def test_write_produces_valid_json(self, tmp_path):
        report = ScenarioReport(
            scenario_id="test",
            scenario_name="Test",
            difficulty="beginner",
            mode="red",
            started_at="2026-02-16T14:30:00+00:00",
            finished_at="2026-02-16T14:45:00+00:00",
            duration_seconds=900.0,
            score=ScoreBreakdown(
                objective_scores={"a": 50},
                total=50,
                max_possible=100,
                passing=True,
            ),
        )

        path = tmp_path / "report.json"
        write_report(report, path)

        data = json.loads(path.read_text())
        assert data["scenario_id"] == "test"
        assert data["score"]["total"] == 50
        assert data["score"]["passing"] is True

    def test_write_includes_all_fields(self, tmp_path):
        report = ScenarioReport(
            scenario_id="test",
            scenario_name="Test",
            difficulty="beginner",
            mode="red",
            started_at="2026-02-16T14:30:00+00:00",
            finished_at="2026-02-16T14:45:00+00:00",
            duration_seconds=900.0,
            score=ScoreBreakdown(),
            objective_results=[{"id": "a", "status": "completed"}],
            events=[{"event_type": "scenario_started"}],
            hints_used={"a": 1},
        )

        path = tmp_path / "report.json"
        write_report(report, path)

        data = json.loads(path.read_text())
        assert "objective_results" in data
        assert "events" in data
        assert "hints_used" in data
        assert data["hints_used"] == {"a": 1}


# ---------------------------------------------------------------------------
# ScenarioReport dataclass
# ---------------------------------------------------------------------------


class TestScenarioReport:
    """Tests for the ScenarioReport dataclass."""

    def test_defaults(self):
        report = ScenarioReport(
            scenario_id="test",
            scenario_name="Test",
            difficulty="beginner",
            mode="red",
            started_at="2026-02-16T14:30:00+00:00",
            finished_at="2026-02-16T14:45:00+00:00",
            duration_seconds=900.0,
            score=ScoreBreakdown(),
        )
        assert report.objective_results == []
        assert report.events == []
        assert report.hints_used == {}
