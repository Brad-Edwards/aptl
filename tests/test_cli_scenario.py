"""Tests for CLI scenario commands.

Tests exercise the typer CLI commands using CliRunner, with mocked
core modules to avoid requiring a running lab environment.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from typer.testing import CliRunner

from aptl.cli.scenario import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_scenario(tmp_path: Path, scenario_id: str = "test-scenario") -> Path:
    """Write a valid scenario YAML file and return the parent dir."""
    scenarios_dir = tmp_path / "scenarios"
    scenarios_dir.mkdir(exist_ok=True)
    data = {
        "metadata": {
            "id": scenario_id,
            "name": "Test Scenario",
            "description": "A test scenario for CLI tests",
            "difficulty": "beginner",
            "estimated_minutes": 10,
        },
        "mode": "red",
        "containers": {"required": ["kali"]},
        "objectives": {
            "red": [
                {
                    "id": "obj-a",
                    "description": "Do something",
                    "type": "manual",
                    "points": 50,
                    "hints": [
                        {"level": 1, "text": "First hint", "point_penalty": 5},
                        {"level": 2, "text": "Second hint", "point_penalty": 10},
                    ],
                },
                {
                    "id": "obj-b",
                    "description": "Do another thing",
                    "type": "manual",
                    "points": 50,
                },
            ],
            "blue": [],
        },
        "scoring": {
            "passing_score": 50,
            "max_score": 100,
            "time_bonus": {
                "enabled": False,
                "max_bonus": 0,
                "decay_after_minutes": 10,
            },
        },
    }
    path = scenarios_dir / f"{scenario_id}.yaml"
    path.write_text(yaml.dump(data, default_flow_style=False))
    return tmp_path


def _start_session(project_dir: Path, scenario_id: str = "test-scenario") -> None:
    """Start a scenario session via the CLI."""
    result = runner.invoke(app, [
        "start", scenario_id,
        "--project-dir", str(project_dir),
    ])
    assert result.exit_code == 0, f"start failed: {result.output}"


# ---------------------------------------------------------------------------
# list command
# ---------------------------------------------------------------------------


class TestListCommand:
    """Tests for 'aptl scenario list'."""

    def test_no_scenarios(self, tmp_path):
        result = runner.invoke(app, [
            "list",
            "--project-dir", str(tmp_path),
        ])
        assert result.exit_code == 0
        assert "No scenarios" in result.output

    def test_lists_scenario(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        result = runner.invoke(app, [
            "list",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "test-scenario" in result.output

    def test_custom_scenarios_dir(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        result = runner.invoke(app, [
            "list",
            "--scenarios-dir", str(project_dir / "scenarios"),
        ])
        assert result.exit_code == 0
        assert "test-scenario" in result.output


# ---------------------------------------------------------------------------
# show command
# ---------------------------------------------------------------------------


class TestShowCommand:
    """Tests for 'aptl scenario show'."""

    def test_show_scenario(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        result = runner.invoke(app, [
            "show", "test-scenario",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "Test Scenario" in result.output
        assert "beginner" in result.output

    def test_show_not_found(self, tmp_path):
        result = runner.invoke(app, [
            "show", "nonexistent",
            "--project-dir", str(tmp_path),
        ])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# validate command
# ---------------------------------------------------------------------------


class TestValidateCommand:
    """Tests for 'aptl scenario validate'."""

    def test_valid_file(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        result = runner.invoke(app, [
            "validate",
            str(project_dir / "scenarios" / "test-scenario.yaml"),
        ])
        assert result.exit_code == 0
        assert "Valid" in result.output

    def test_invalid_file(self, tmp_path):
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("not a scenario")
        result = runner.invoke(app, ["validate", str(bad_file)])
        assert result.exit_code == 1

    def test_missing_file(self, tmp_path):
        result = runner.invoke(app, [
            "validate",
            str(tmp_path / "missing.yaml"),
        ])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# start command
# ---------------------------------------------------------------------------


class TestStartCommand:
    """Tests for 'aptl scenario start'."""

    def test_start_scenario(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        result = runner.invoke(app, [
            "start", "test-scenario",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "Started scenario" in result.output
        assert "Test Scenario" in result.output

    def test_start_creates_session_file(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        runner.invoke(app, [
            "start", "test-scenario",
            "--project-dir", str(project_dir),
        ])
        session_file = project_dir / ".aptl" / "session.json"
        assert session_file.exists()
        data = json.loads(session_file.read_text())
        assert data["scenario_id"] == "test-scenario"
        assert data["state"] == "active"

    def test_start_creates_events_file(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        runner.invoke(app, [
            "start", "test-scenario",
            "--project-dir", str(project_dir),
        ])
        events_dir = project_dir / ".aptl" / "events"
        assert events_dir.exists()
        event_files = list(events_dir.glob("*.jsonl"))
        assert len(event_files) == 1

    def test_start_rejects_double_start(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        runner.invoke(app, [
            "start", "test-scenario",
            "--project-dir", str(project_dir),
        ])
        result = runner.invoke(app, [
            "start", "test-scenario",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 1
        assert "already active" in result.output

    def test_start_not_found(self, tmp_path):
        result = runner.invoke(app, [
            "start", "nonexistent",
            "--project-dir", str(tmp_path),
        ])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# status command
# ---------------------------------------------------------------------------


class TestStatusCommand:
    """Tests for 'aptl scenario status'."""

    def test_no_active_scenario(self, tmp_path):
        result = runner.invoke(app, [
            "status",
            "--project-dir", str(tmp_path),
        ])
        assert result.exit_code == 0
        assert "No active scenario" in result.output

    def test_active_scenario_status(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        result = runner.invoke(app, [
            "status",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "test-scenario" in result.output
        assert "active" in result.output
        assert "Elapsed" in result.output


# ---------------------------------------------------------------------------
# evaluate command
# ---------------------------------------------------------------------------


class TestEvaluateCommand:
    """Tests for 'aptl scenario evaluate'."""

    def test_no_active_scenario(self, tmp_path):
        result = runner.invoke(app, [
            "evaluate",
            "--project-dir", str(tmp_path),
        ])
        assert result.exit_code == 1
        assert "No active scenario" in result.output

    def test_evaluate_manual_objectives(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        result = runner.invoke(app, [
            "evaluate",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        # Manual objectives should show as pending
        assert "pending" in result.output
        assert "0/2" in result.output


# ---------------------------------------------------------------------------
# hint command
# ---------------------------------------------------------------------------


class TestHintCommand:
    """Tests for 'aptl scenario hint'."""

    def test_no_active_scenario(self, tmp_path):
        result = runner.invoke(app, [
            "hint", "obj-a",
            "--project-dir", str(tmp_path),
        ])
        assert result.exit_code == 1

    def test_reveal_first_hint(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        result = runner.invoke(app, [
            "hint", "obj-a",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "First hint" in result.output
        assert "level 1" in result.output

    def test_reveal_second_hint(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        # First hint
        runner.invoke(app, [
            "hint", "obj-a",
            "--project-dir", str(project_dir),
        ])
        # Second hint
        result = runner.invoke(app, [
            "hint", "obj-a",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "Second hint" in result.output
        assert "level 2" in result.output

    def test_all_hints_exhausted(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        runner.invoke(app, ["hint", "obj-a", "--project-dir", str(project_dir)])
        runner.invoke(app, ["hint", "obj-a", "--project-dir", str(project_dir)])
        result = runner.invoke(app, [
            "hint", "obj-a",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "All hints already revealed" in result.output

    def test_no_hints_available(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        result = runner.invoke(app, [
            "hint", "obj-b",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "No hints available" in result.output

    def test_objective_not_found(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        result = runner.invoke(app, [
            "hint", "nonexistent",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_hint_shows_penalty(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        result = runner.invoke(app, [
            "hint", "obj-a",
            "--project-dir", str(project_dir),
        ])
        assert "-5 pts" in result.output

    def test_hint_recorded_in_session(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        runner.invoke(app, [
            "hint", "obj-a",
            "--project-dir", str(project_dir),
        ])

        session_data = json.loads(
            (project_dir / ".aptl" / "session.json").read_text()
        )
        assert session_data["hints_used"]["obj-a"] == 1


# ---------------------------------------------------------------------------
# complete command
# ---------------------------------------------------------------------------


class TestCompleteCommand:
    """Tests for 'aptl scenario complete'."""

    def test_no_active_scenario(self, tmp_path):
        result = runner.invoke(app, [
            "complete", "obj-a",
            "--project-dir", str(tmp_path),
        ])
        assert result.exit_code == 1

    def test_complete_manual_objective(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        result = runner.invoke(app, [
            "complete", "obj-a",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "marked as complete" in result.output

    def test_complete_updates_session(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        runner.invoke(app, [
            "complete", "obj-a",
            "--project-dir", str(project_dir),
        ])

        session_data = json.loads(
            (project_dir / ".aptl" / "session.json").read_text()
        )
        assert "obj-a" in session_data["completed_objectives"]

    def test_complete_already_done(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        runner.invoke(app, [
            "complete", "obj-a",
            "--project-dir", str(project_dir),
        ])
        result = runner.invoke(app, [
            "complete", "obj-a",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "already completed" in result.output

    def test_complete_objective_not_found(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        result = runner.invoke(app, [
            "complete", "nonexistent",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 1
        assert "not found" in result.output


# ---------------------------------------------------------------------------
# stop command
# ---------------------------------------------------------------------------


class TestStopCommand:
    """Tests for 'aptl scenario stop'."""

    def test_no_active_scenario(self, tmp_path):
        result = runner.invoke(app, [
            "stop",
            "--project-dir", str(tmp_path),
        ])
        assert result.exit_code == 1
        assert "No active scenario" in result.output

    def test_stop_generates_report(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        result = runner.invoke(app, [
            "stop",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "Scenario stopped" in result.output
        assert "Report:" in result.output

        # Verify report file exists
        reports_dir = project_dir / ".aptl" / "reports"
        assert reports_dir.exists()
        report_files = list(reports_dir.glob("*.json"))
        assert len(report_files) == 1

    def test_stop_clears_session(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        runner.invoke(app, [
            "stop",
            "--project-dir", str(project_dir),
        ])

        session_file = project_dir / ".aptl" / "session.json"
        assert not session_file.exists()

    def test_stop_shows_score(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        result = runner.invoke(app, [
            "stop",
            "--project-dir", str(project_dir),
        ])
        assert "Score:" in result.output

    def test_stop_with_completed_objectives(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        # Complete one objective
        runner.invoke(app, [
            "complete", "obj-a",
            "--project-dir", str(project_dir),
        ])

        result = runner.invoke(app, [
            "stop",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        # Score should reflect 50 points from obj-a
        assert "50/" in result.output

    def test_stop_report_contents(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        # Complete an objective and use a hint
        runner.invoke(app, [
            "hint", "obj-a",
            "--project-dir", str(project_dir),
        ])
        runner.invoke(app, [
            "complete", "obj-a",
            "--project-dir", str(project_dir),
        ])

        runner.invoke(app, [
            "stop",
            "--project-dir", str(project_dir),
        ])

        reports_dir = project_dir / ".aptl" / "reports"
        report_files = list(reports_dir.glob("*.json"))
        report = json.loads(report_files[0].read_text())

        assert report["scenario_id"] == "test-scenario"
        assert report["score"]["total"] == 45  # 50 - 5 hint penalty
        assert report["hints_used"] == {"obj-a": 1}

    def test_full_lifecycle(self, tmp_path):
        """Test the complete start -> hint -> complete -> evaluate -> stop flow."""
        project_dir = _write_scenario(tmp_path)

        # Start
        result = runner.invoke(app, [
            "start", "test-scenario",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0

        # Status
        result = runner.invoke(app, [
            "status",
            "--project-dir", str(project_dir),
        ])
        assert "test-scenario" in result.output

        # Hint
        result = runner.invoke(app, [
            "hint", "obj-a",
            "--project-dir", str(project_dir),
        ])
        assert "First hint" in result.output

        # Complete both objectives
        runner.invoke(app, [
            "complete", "obj-a",
            "--project-dir", str(project_dir),
        ])
        runner.invoke(app, [
            "complete", "obj-b",
            "--project-dir", str(project_dir),
        ])

        # Evaluate
        result = runner.invoke(app, [
            "evaluate",
            "--project-dir", str(project_dir),
        ])
        assert "2/2" in result.output

        # Stop
        result = runner.invoke(app, [
            "stop",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "95/" in result.output  # 100 - 5 hint penalty

        # Verify no active session
        result = runner.invoke(app, [
            "status",
            "--project-dir", str(project_dir),
        ])
        assert "No active scenario" in result.output
