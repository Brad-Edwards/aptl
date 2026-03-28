"""Tests for CLI evaluate, run, status scoring, and _print_score_summary."""

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from typer.testing import CliRunner

from aptl.cli.scenario import app
from aptl.core.engine import EngineResult
from aptl.core.evaluators import EvaluationResult
from aptl.core.scoring import ObjectiveScore, ScoreReport


runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_scenario_yaml(
    scenario_id: str = "eval-test",
    mode: str = "red",
    objectives_red: list | None = None,
    scoring: dict | None = None,
    estimated_minutes: int = 10,
) -> dict:
    """Build a scenario dict for YAML serialization."""
    if objectives_red is None:
        objectives_red = [
            {
                "id": "cmd-check",
                "description": "Check command output",
                "type": "command_output",
                "points": 100,
                "command_output": {
                    "container": "kali",
                    "command": "echo FLAG",
                    "contains": ["FLAG"],
                },
            },
        ]
    return {
        "metadata": {
            "id": scenario_id,
            "name": "Evaluate Test",
            "description": "Test scenario for evaluate command",
            "difficulty": "beginner",
            "estimated_minutes": estimated_minutes,
        },
        "mode": mode,
        "containers": {"required": ["kali"]},
        "objectives": {
            "red": objectives_red,
            "blue": [],
        },
        "scoring": scoring or {"passing_score": 50, "max_score": 100},
    }


@pytest.fixture
def scenario_dir(tmp_path: Path) -> Path:
    """Create a scenario file with evaluable objectives."""
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    path = scenarios / "eval-test.yaml"
    path.write_text(yaml.dump(_make_scenario_yaml(), default_flow_style=False))
    return tmp_path


@pytest.fixture
def manual_only_scenario_dir(tmp_path: Path) -> Path:
    """Create a scenario file with only manual objectives (no auto-evaluable)."""
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    scenario = _make_scenario_yaml(
        objectives_red=[
            {
                "id": "manual-obj",
                "description": "Do something manually",
                "type": "manual",
                "points": 100,
            },
        ],
    )
    path = scenarios / "eval-test.yaml"
    path.write_text(yaml.dump(scenario, default_flow_style=False))
    return tmp_path


@pytest.fixture
def active_scenario(scenario_dir: Path):
    """Start a session for the test scenario."""
    from aptl.core.scenarios import load_scenario
    from aptl.core.session import ScenarioSession

    scenario = load_scenario(scenario_dir / "scenarios" / "eval-test.yaml")
    session_mgr = ScenarioSession(scenario_dir / ".aptl")
    session = session_mgr.start(scenario)
    return scenario_dir, session_mgr, session


# ---------------------------------------------------------------------------
# _print_score_summary coverage
# ---------------------------------------------------------------------------


def test_status_shows_time_bonus_and_penalties(scenario_dir: Path, mocker):
    """Status displays time bonus and hint penalty lines when present."""
    from aptl.core.scenarios import load_scenario
    from aptl.core.session import ScenarioSession

    scenario = load_scenario(scenario_dir / "scenarios" / "eval-test.yaml")
    session_mgr = ScenarioSession(scenario_dir / ".aptl")
    session = session_mgr.start(scenario)

    mocker.patch(
        "aptl.cli.scenario.compute_score",
        return_value=ScoreReport(
            total_score=120,
            max_score=150,
            passing_score=100,
            passed=True,
            time_bonus=30,
            hint_penalties=10,
            objective_scores=[
                ObjectiveScore(
                    objective_id="cmd-check",
                    base_points=100,
                    hint_penalty=10,
                    earned=90,
                    completed=True,
                )
            ],
        ),
    )

    result = runner.invoke(
        app,
        ["status", "--project-dir", str(scenario_dir)],
    )
    assert result.exit_code == 0
    assert "+30" in result.output  # time bonus line
    assert "-10" in result.output  # penalties line
    assert "PASS" in result.output


def test_status_scoring_error_is_silent(tmp_path: Path):
    """Status still works when scenario file can't be loaded for scoring."""
    from aptl.core.session import ScenarioSession

    # Create a session pointing to a scenario that doesn't have a YAML file
    session_mgr = ScenarioSession(tmp_path / ".aptl")
    from aptl.core.session import ActiveSession, SessionState

    session = ActiveSession(
        scenario_id="missing-scenario",
        state=SessionState.ACTIVE,
        started_at="2026-03-26T10:00:00+00:00",
    )
    session_mgr._write(session)

    result = runner.invoke(
        app,
        ["status", "--project-dir", str(tmp_path)],
    )
    # Should show basic status without crashing, even without scoring
    assert result.exit_code == 0 or result.exit_code == 1
    assert "missing-scenario" in result.output


# ---------------------------------------------------------------------------
# Evaluate command
# ---------------------------------------------------------------------------


def test_evaluate_command_runs(active_scenario, mocker):
    """aptl scenario evaluate runs a single pass and shows results."""
    project_dir, session_mgr, session = active_scenario

    async def mock_evaluate_once(self):
        return [
            EvaluationResult(
                objective_id="cmd-check",
                passed=True,
                detail="All checks passed",
                checked_at="2026-03-26T10:01:00+00:00",
            )
        ]

    mocker.patch(
        "aptl.core.engine.ScenarioEngine.evaluate_once",
        mock_evaluate_once,
    )
    mocker.patch("aptl.core.engine.ScenarioEngine.get_score", return_value=ScoreReport(
        total_score=100,
        max_score=100,
        passing_score=50,
        passed=True,
        time_bonus=0,
        hint_penalties=0,
        objective_scores=[
            ObjectiveScore(
                objective_id="cmd-check",
                base_points=100,
                hint_penalty=0,
                earned=100,
                completed=True,
            )
        ],
    ))

    result = runner.invoke(
        app,
        ["evaluate", "--project-dir", str(project_dir)],
    )
    assert result.exit_code == 0
    assert "PASS" in result.output
    assert "cmd-check" in result.output


def test_evaluate_no_pending_objectives(active_scenario, mocker):
    """Evaluate reports 'no pending' when all evaluable objectives are done."""
    project_dir, session_mgr, session = active_scenario
    session_mgr.record_objective_complete("cmd-check")

    async def mock_evaluate_once(self):
        return []

    mocker.patch(
        "aptl.core.engine.ScenarioEngine.evaluate_once",
        mock_evaluate_once,
    )

    result = runner.invoke(
        app,
        ["evaluate", "--project-dir", str(project_dir)],
    )
    assert result.exit_code == 0
    assert "No evaluable objectives pending" in result.output


def test_evaluate_no_active_session(tmp_path: Path):
    """aptl scenario evaluate exits when no session is active."""
    result = runner.invoke(
        app,
        ["evaluate", "--project-dir", str(tmp_path)],
    )
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Run command
# ---------------------------------------------------------------------------


def test_run_command_full_lifecycle(scenario_dir: Path, mocker):
    """aptl scenario run starts, evaluates, reports, and stops."""
    mocker.patch("aptl.cli.scenario.collect_flags", return_value={})
    mocker.patch("aptl.cli.scenario.init_tracing")
    mocker.patch("aptl.cli.scenario.shutdown_tracing")
    mocker.patch("aptl.cli.scenario.get_tracer", return_value=MagicMock())
    mocker.patch("aptl.cli.scenario.make_parent_context", return_value=MagicMock())
    mocker.patch("aptl.cli.scenario.create_child_span", return_value=MagicMock())
    mocker.patch("aptl.cli.scenario.write_trace_context")
    mocker.patch("aptl.cli.scenario.create_root_span")
    mocker.patch("aptl.cli.scenario._load_env")
    mocker.patch("aptl.cli.scenario.assemble_run", return_value=None)

    # Mock the engine to complete immediately
    mock_result = EngineResult(
        completed_objectives=["cmd-check"],
        score=ScoreReport(
            total_score=100,
            max_score=100,
            passing_score=50,
            passed=True,
            time_bonus=0,
            hint_penalties=0,
            objective_scores=[
                ObjectiveScore(
                    objective_id="cmd-check",
                    base_points=100,
                    hint_penalty=0,
                    earned=100,
                    completed=True,
                )
            ],
        ),
        elapsed_seconds=15.0,
        timed_out=False,
        evaluation_cycles=2,
    )

    async def mock_engine_run(self, shutdown_event):
        return mock_result

    mocker.patch(
        "aptl.core.engine.ScenarioEngine.run",
        mock_engine_run,
    )

    result = runner.invoke(
        app,
        ["run", "--project-dir", str(scenario_dir), "eval-test",
         "--poll-interval", "0.1", "--timeout", "1"],
    )
    assert result.exit_code == 0
    assert "Started scenario" in result.output
    assert "Evaluable:" in result.output
    assert "Evaluation engine started" in result.output
    assert "evaluation complete" in result.output
    assert "Cycles:" in result.output
    assert "PASS" in result.output


def test_run_command_timeout_report(scenario_dir: Path, mocker):
    """aptl scenario run reports timeout when engine times out."""
    mocker.patch("aptl.cli.scenario.collect_flags", return_value={})
    mocker.patch("aptl.cli.scenario.init_tracing")
    mocker.patch("aptl.cli.scenario.shutdown_tracing")
    mocker.patch("aptl.cli.scenario.get_tracer", return_value=MagicMock())
    mocker.patch("aptl.cli.scenario.make_parent_context", return_value=MagicMock())
    mocker.patch("aptl.cli.scenario.create_child_span", return_value=MagicMock())
    mocker.patch("aptl.cli.scenario.write_trace_context")
    mocker.patch("aptl.cli.scenario.create_root_span")
    mocker.patch("aptl.cli.scenario._load_env")
    mocker.patch("aptl.cli.scenario.assemble_run", return_value=None)

    mock_result = EngineResult(
        completed_objectives=[],
        score=ScoreReport(
            total_score=0,
            max_score=100,
            passing_score=50,
            passed=False,
            time_bonus=0,
            hint_penalties=0,
            objective_scores=[],
        ),
        elapsed_seconds=600.0,
        timed_out=True,
        evaluation_cycles=5,
    )

    async def mock_engine_run(self, shutdown_event):
        return mock_result

    mocker.patch("aptl.core.engine.ScenarioEngine.run", mock_engine_run)

    result = runner.invoke(
        app,
        ["run", "--project-dir", str(scenario_dir), "eval-test", "--timeout", "1"],
    )
    assert result.exit_code == 0
    assert "timeout reached" in result.output


def test_run_command_manual_only_exits_early(manual_only_scenario_dir: Path, mocker):
    """aptl scenario run exits early when no auto-evaluable objectives exist."""
    mocker.patch("aptl.cli.scenario.collect_flags", return_value={})
    mocker.patch("aptl.cli.scenario.init_tracing")
    mocker.patch("aptl.cli.scenario.shutdown_tracing")
    mocker.patch("aptl.cli.scenario.get_tracer", return_value=MagicMock())
    mocker.patch("aptl.cli.scenario.make_parent_context", return_value=MagicMock())
    mocker.patch("aptl.cli.scenario.create_child_span", return_value=MagicMock())
    mocker.patch("aptl.cli.scenario.write_trace_context")

    result = runner.invoke(
        app,
        ["run", "--project-dir", str(manual_only_scenario_dir), "eval-test"],
    )
    assert result.exit_code == 0
    assert "No auto-evaluable objectives" in result.output


def test_run_command_missing_scenario(tmp_path: Path):
    """aptl scenario run fails when scenario doesn't exist."""
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()

    result = runner.invoke(
        app,
        ["run", "--project-dir", str(tmp_path), "nonexistent"],
    )
    assert result.exit_code == 1


def test_run_command_double_start_fails(active_scenario, mocker):
    """aptl scenario run fails if a session is already active."""
    project_dir, _, _ = active_scenario

    result = runner.invoke(
        app,
        ["run", "--project-dir", str(project_dir), "eval-test"],
    )
    assert result.exit_code == 1
    assert "already active" in result.output


def test_run_progress_callback_output(scenario_dir: Path, mocker):
    """Run command progress callback prints newly-passed objectives and cycle summary."""
    mocker.patch("aptl.cli.scenario.collect_flags", return_value={})
    mocker.patch("aptl.cli.scenario.init_tracing")
    mocker.patch("aptl.cli.scenario.shutdown_tracing")
    mocker.patch("aptl.cli.scenario.get_tracer", return_value=MagicMock())
    mocker.patch("aptl.cli.scenario.make_parent_context", return_value=MagicMock())
    mocker.patch("aptl.cli.scenario.create_child_span", return_value=MagicMock())
    mocker.patch("aptl.cli.scenario.write_trace_context")
    mocker.patch("aptl.cli.scenario.create_root_span")
    mocker.patch("aptl.cli.scenario._load_env")
    mocker.patch("aptl.cli.scenario.assemble_run", return_value=None)

    # Engine that captures and invokes the progress callback
    async def mock_engine_run(self, shutdown_event):
        if self._on_progress:
            self._on_progress(
                1,
                [EvaluationResult("cmd-check", True, "Pass", "2026-03-26T10:01:00+00:00")],
                ScoreReport(
                    total_score=100, max_score=100, passing_score=50,
                    passed=True, time_bonus=0, hint_penalties=0,
                    objective_scores=[
                        ObjectiveScore("cmd-check", 100, 0, 100, True),
                    ],
                ),
            )
        return EngineResult(
            completed_objectives=["cmd-check"],
            score=ScoreReport(
                total_score=100, max_score=100, passing_score=50,
                passed=True, time_bonus=0, hint_penalties=0,
                objective_scores=[ObjectiveScore("cmd-check", 100, 0, 100, True)],
            ),
            elapsed_seconds=10.0,
            timed_out=False,
            evaluation_cycles=1,
        )

    mocker.patch("aptl.core.engine.ScenarioEngine.run", mock_engine_run)

    result = runner.invoke(
        app,
        ["run", "--project-dir", str(scenario_dir), "eval-test",
         "--poll-interval", "0.1", "--timeout", "1"],
    )
    assert result.exit_code == 0
    assert "[PASS] cmd-check" in result.output
    assert "Cycle 1:" in result.output


# ---------------------------------------------------------------------------
# Status command with scoring
# ---------------------------------------------------------------------------


def test_status_shows_score(active_scenario, mocker):
    """aptl scenario status shows score information."""
    project_dir, session_mgr, session = active_scenario

    result = runner.invoke(
        app,
        ["status", "--project-dir", str(project_dir)],
    )
    assert result.exit_code == 0
    assert "eval-test" in result.output
    assert "active" in result.output.lower()
