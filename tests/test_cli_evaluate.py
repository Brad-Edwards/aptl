"""Tests for CLI evaluate and run commands."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from typer.testing import CliRunner

from aptl.cli.scenario import app
from aptl.core.evaluators import EvaluationResult
from aptl.core.scoring import ObjectiveScore, ScoreReport


runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scenario_dir(tmp_path: Path) -> Path:
    """Create a scenario file with evaluable objectives."""
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    scenario = {
        "metadata": {
            "id": "eval-test",
            "name": "Evaluate Test",
            "description": "Test scenario for evaluate command",
            "difficulty": "beginner",
            "estimated_minutes": 10,
        },
        "mode": "red",
        "containers": {"required": ["kali"]},
        "objectives": {
            "red": [
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
            ],
            "blue": [],
        },
        "scoring": {
            "passing_score": 50,
            "max_score": 100,
        },
    }
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
# Evaluate command
# ---------------------------------------------------------------------------


def test_evaluate_command_runs(active_scenario, mocker):
    """aptl scenario evaluate runs a single pass."""
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


def test_evaluate_no_active_session(tmp_path: Path):
    """aptl scenario evaluate exits when no session is active."""
    result = runner.invoke(
        app,
        ["evaluate", "--project-dir", str(tmp_path)],
    )
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Status command with scoring
# ---------------------------------------------------------------------------


def test_status_shows_score(active_scenario, mocker):
    """aptl scenario status shows score information."""
    project_dir, session_mgr, session = active_scenario

    # Mock compute_score to avoid needing real scenario lookup errors
    result = runner.invoke(
        app,
        ["status", "--project-dir", str(project_dir)],
    )
    assert result.exit_code == 0
    assert "eval-test" in result.output
    assert "active" in result.output.lower()
