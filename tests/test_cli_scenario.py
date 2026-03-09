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
    scenarios_dir.mkdir(parents=True, exist_ok=True)
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



def _write_config(project_dir: Path, containers: dict | None = None) -> Path:
    """Write an aptl.json config file and return the path."""
    config = {"lab": {"name": "aptl"}}
    if containers is not None:
        config["containers"] = containers
    config_path = project_dir / "aptl.json"
    config_path.write_text(json.dumps(config))
    return config_path


def _write_scenario_with_containers(
    tmp_path: Path,
    scenario_id: str = "test-scenario",
    required: list[str] | None = None,
) -> Path:
    """Write a scenario YAML with specific required containers."""
    scenarios_dir = tmp_path / "scenarios"
    scenarios_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "metadata": {
            "id": scenario_id,
            "name": "Test Scenario",
            "description": "A test scenario for CLI tests",
            "difficulty": "beginner",
            "estimated_minutes": 10,
        },
        "mode": "red",
        "containers": {"required": required or ["kali"]},
        "objectives": {
            "red": [
                {
                    "id": "obj-a",
                    "description": "Do something",
                    "type": "manual",
                    "points": 50,
                },
            ],
            "blue": [],
        },
        "scoring": {
            "passing_score": 50,
            "max_score": 50,
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
# start command — container validation
# ---------------------------------------------------------------------------


class TestStartContainerValidation:
    """Tests for container profile validation when starting a scenario."""

    def test_start_fails_when_required_profile_disabled(self, tmp_path):
        """Scenario requiring soc should fail when soc is disabled."""
        project_dir = _write_scenario_with_containers(
            tmp_path, required=["kali", "soc"]
        )
        _write_config(project_dir, containers={"kali": True, "soc": False})
        result = runner.invoke(app, [
            "start", "test-scenario",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 1
        assert "soc" in result.output
        assert "disabled profiles" in result.output

    def test_start_succeeds_when_all_profiles_enabled(self, tmp_path):
        """Scenario requiring kali should succeed when kali is enabled."""
        project_dir = _write_scenario_with_containers(
            tmp_path, required=["kali"]
        )
        _write_config(project_dir, containers={"kali": True})
        result = runner.invoke(app, [
            "start", "test-scenario",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "Started scenario" in result.output

    def test_start_succeeds_with_no_config_file(self, tmp_path):
        """Scenario requiring kali (on by default) works without aptl.json."""
        project_dir = _write_scenario_with_containers(
            tmp_path, required=["kali"]
        )
        # No aptl.json — defaults apply (kali=True)
        result = runner.invoke(app, [
            "start", "test-scenario",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "Started scenario" in result.output

    def test_error_lists_all_missing_profiles(self, tmp_path):
        """Error message should list every disabled profile."""
        project_dir = _write_scenario_with_containers(
            tmp_path, required=["kali", "soc", "enterprise"]
        )
        # Default config: soc=False, enterprise=False
        result = runner.invoke(app, [
            "start", "test-scenario",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 1
        assert "soc" in result.output
        assert "enterprise" in result.output


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

    def test_stop_scenario(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        result = runner.invoke(app, [
            "stop",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "Scenario stopped" in result.output

    def test_stop_clears_session(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        runner.invoke(app, [
            "stop",
            "--project-dir", str(project_dir),
        ])

        session_file = project_dir / ".aptl" / "session.json"
        assert not session_file.exists()

    def test_stop_shows_duration(self, tmp_path):
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        result = runner.invoke(app, [
            "stop",
            "--project-dir", str(project_dir),
        ])
        assert "Duration:" in result.output

    def test_full_lifecycle(self, tmp_path):
        """Test the complete start -> status -> stop flow."""
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

        # Stop
        result = runner.invoke(app, [
            "stop",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "Scenario stopped" in result.output

        # Verify no active session
        result = runner.invoke(app, [
            "status",
            "--project-dir", str(project_dir),
        ])
        assert "No active scenario" in result.output

    def test_stop_loads_dotenv_before_assembly(self, tmp_path):
        """Verify .env is loaded into os.environ before assemble_run()."""
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        # Write a .env file with known values
        env_file = project_dir / ".env"
        env_file.write_text(
            "INDEXER_USERNAME=admin\n"
            "INDEXER_PASSWORD=secret123\n"
            "THEHIVE_API_KEY=hive-key-abc\n"
        )

        captured_env = {}

        original_assemble = None

        def _spy_assemble(**kwargs):
            """Capture os.environ at the moment assemble_run is called."""
            import os as _os
            captured_env["INDEXER_USERNAME"] = _os.environ.get("INDEXER_USERNAME")
            captured_env["INDEXER_PASSWORD"] = _os.environ.get("INDEXER_PASSWORD")
            captured_env["THEHIVE_API_KEY"] = _os.environ.get("THEHIVE_API_KEY")
            return tmp_path / "runs" / "fake-run"

        with patch("aptl.cli.scenario.assemble_run", side_effect=_spy_assemble):
            result = runner.invoke(app, [
                "stop",
                "--project-dir", str(project_dir),
            ])

        assert result.exit_code == 0
        assert captured_env["INDEXER_USERNAME"] == "admin"
        assert captured_env["INDEXER_PASSWORD"] == "secret123"
        assert captured_env["THEHIVE_API_KEY"] == "hive-key-abc"

    def test_stop_warns_on_missing_dotenv(self, tmp_path, caplog):
        """Verify graceful handling when .env doesn't exist."""
        project_dir = _write_scenario(tmp_path)
        _start_session(project_dir)

        # Do NOT create a .env file
        assert not (project_dir / ".env").exists()

        result = runner.invoke(app, [
            "stop",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "Scenario stopped" in result.output


# ---------------------------------------------------------------------------
# Attack step display tests
# ---------------------------------------------------------------------------


def _write_step_scenario(tmp_path: Path) -> Path:
    """Write a unified scenario with attack steps and return project dir."""
    scenarios_dir = tmp_path / "scenarios"
    scenarios_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "metadata": {
            "id": "step-scenario",
            "name": "Step Scenario",
            "description": "A scenario with attack steps",
            "difficulty": "intermediate",
            "estimated_minutes": 20,
            "tags": ["test"],
            "mitre_attack": {
                "tactics": ["Reconnaissance"],
                "techniques": ["T1595.002"],
            },
        },
        "mode": "purple",
        "containers": {"required": ["kali"]},
        "attack_chain": "Recon -> Exploit",
        "steps": [
            {
                "step_number": 1,
                "technique_id": "T1595.002",
                "technique_name": "Active Scanning",
                "tactic": "Reconnaissance",
                "description": "Scan the target",
                "target": "victim",
                "commands": ["nmap -sV 172.20.0.20"],
                "expected_detections": [
                    {
                        "product_name": "wazuh",
                        "analytic_uid": "1000001",
                        "severity_id": 3,
                        "description": "Port scan detected",
                    }
                ],
                "investigation_hints": ["Check Suricata alerts"],
            },
        ],
    }
    path = scenarios_dir / "step-scenario.yaml"
    path.write_text(yaml.dump(data, default_flow_style=False))
    return tmp_path


class TestStepDisplay:
    """Tests for attack step display in scenario CLI commands."""

    def test_list_shows_step_count(self, tmp_path):
        project_dir = _write_step_scenario(tmp_path)
        result = runner.invoke(app, [
            "list",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "step-scenario" in result.output
        assert "1" in result.output  # step count

    def test_show_displays_attack_steps(self, tmp_path):
        project_dir = _write_step_scenario(tmp_path)
        result = runner.invoke(app, [
            "show", "step-scenario",
            "--project-dir", str(project_dir),
        ])
        assert result.exit_code == 0
        assert "Attack Chain: Recon -> Exploit" in result.output
        assert "Attack Steps:" in result.output
        assert "Step 1" in result.output
        assert "T1595.002" in result.output
        assert "Active Scanning" in result.output
        assert "Reconnaissance" in result.output
        assert "nmap -sV 172.20.0.20" in result.output
        assert "Expected Detections:" in result.output
        assert "Port scan detected" in result.output
        assert "Investigation Hints:" in result.output

    def test_validate_shows_step_count(self, tmp_path):
        project_dir = _write_step_scenario(tmp_path)
        result = runner.invoke(app, [
            "validate",
            str(project_dir / "scenarios" / "step-scenario.yaml"),
        ])
        assert result.exit_code == 0
        assert "0 objectives" in result.output
        assert "1 steps" in result.output
