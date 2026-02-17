"""Integration tests for the SOC scenario feature.

Validates example scenario files, tests CLI commands against real
scenarios, and verifies the end-to-end lifecycle matches acceptance
criteria from the spec.
"""

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from aptl.cli.scenario import app
from aptl.core.events import EventLog, EventType
from aptl.core.objectives import ObjectiveStatus
from aptl.core.scenarios import (
    ScenarioDefinition,
    ScenarioMode,
    find_scenarios,
    load_scenario,
)
from aptl.core.scoring import ScoreBreakdown, calculate_score
from aptl.core.session import ScenarioSession, SessionState

runner = CliRunner()

SCENARIOS_DIR = Path(__file__).parent.parent / "scenarios"


# ---------------------------------------------------------------------------
# Example scenario file validation
# ---------------------------------------------------------------------------


class TestExampleScenarios:
    """Validate that the bundled example scenario files load correctly."""

    def test_recon_nmap_scan_loads(self):
        """AC-2: recon-nmap-scan.yaml validates without errors."""
        path = SCENARIOS_DIR / "recon-nmap-scan.yaml"
        if not path.exists():
            pytest.skip("Example scenario file not found")

        scenario = load_scenario(path)
        assert scenario.metadata.id == "recon-nmap-scan"
        assert scenario.mode == ScenarioMode.RED
        assert scenario.metadata.difficulty.value == "beginner"

    def test_recon_nmap_scan_objectives(self):
        """recon-nmap-scan should have 3 red objectives, 0 blue."""
        path = SCENARIOS_DIR / "recon-nmap-scan.yaml"
        if not path.exists():
            pytest.skip("Example scenario file not found")

        scenario = load_scenario(path)
        assert len(scenario.objectives.red) == 3
        assert len(scenario.objectives.blue) == 0

        ids = [o.id for o in scenario.objectives.red]
        assert "port-scan" in ids
        assert "service-identification" in ids
        assert "find-flag" in ids

    def test_recon_nmap_scan_scoring(self):
        """recon-nmap-scan should have time bonus and passing score."""
        path = SCENARIOS_DIR / "recon-nmap-scan.yaml"
        if not path.exists():
            pytest.skip("Example scenario file not found")

        scenario = load_scenario(path)
        assert scenario.scoring.time_bonus.enabled is True
        assert scenario.scoring.time_bonus.max_bonus == 50
        assert scenario.scoring.passing_score == 100
        assert scenario.scoring.max_score == 250

    def test_recon_nmap_scan_preconditions(self):
        """recon-nmap-scan should have one file precondition."""
        path = SCENARIOS_DIR / "recon-nmap-scan.yaml"
        if not path.exists():
            pytest.skip("Example scenario file not found")

        scenario = load_scenario(path)
        assert len(scenario.preconditions) == 1
        assert scenario.preconditions[0].type.value == "file"
        assert scenario.preconditions[0].container == "victim"

    def test_recon_nmap_scan_hints(self):
        """recon-nmap-scan objectives should have correct hint counts."""
        path = SCENARIOS_DIR / "recon-nmap-scan.yaml"
        if not path.exists():
            pytest.skip("Example scenario file not found")

        scenario = load_scenario(path)
        obj_by_id = {o.id: o for o in scenario.objectives.red}

        assert len(obj_by_id["port-scan"].hints) == 2
        assert len(obj_by_id["service-identification"].hints) == 1
        assert len(obj_by_id["find-flag"].hints) == 2

    def test_detect_brute_force_loads(self):
        """AC-2: detect-brute-force.yaml validates without errors."""
        path = SCENARIOS_DIR / "detect-brute-force.yaml"
        if not path.exists():
            pytest.skip("Example scenario file not found")

        scenario = load_scenario(path)
        assert scenario.metadata.id == "detect-brute-force"
        assert scenario.mode == ScenarioMode.PURPLE
        assert scenario.metadata.difficulty.value == "intermediate"

    def test_detect_brute_force_objectives(self):
        """detect-brute-force should have 1 red and 2 blue objectives."""
        path = SCENARIOS_DIR / "detect-brute-force.yaml"
        if not path.exists():
            pytest.skip("Example scenario file not found")

        scenario = load_scenario(path)
        assert len(scenario.objectives.red) == 1
        assert len(scenario.objectives.blue) == 2

        blue_ids = [o.id for o in scenario.objectives.blue]
        assert "detect-auth-failures" in blue_ids
        assert "identify-attacker-ip" in blue_ids

    def test_detect_brute_force_wazuh_alert_type(self):
        """detect-brute-force should have a wazuh_alert objective."""
        path = SCENARIOS_DIR / "detect-brute-force.yaml"
        if not path.exists():
            pytest.skip("Example scenario file not found")

        scenario = load_scenario(path)
        alert_obj = next(
            o for o in scenario.objectives.blue if o.id == "detect-auth-failures"
        )
        assert alert_obj.type.value == "wazuh_alert"
        assert alert_obj.wazuh_alert is not None
        assert alert_obj.wazuh_alert.min_matches == 5

    def test_find_scenarios_discovers_both(self):
        """AC-1: find_scenarios should discover both example files."""
        if not SCENARIOS_DIR.exists():
            pytest.skip("Scenarios directory not found")

        paths = find_scenarios(SCENARIOS_DIR)
        names = [p.stem for p in paths]
        assert "recon-nmap-scan" in names
        assert "detect-brute-force" in names

    def test_total_points_recon_nmap_scan(self):
        """Total objective points should be 200 (50+50+100)."""
        path = SCENARIOS_DIR / "recon-nmap-scan.yaml"
        if not path.exists():
            pytest.skip("Example scenario file not found")

        scenario = load_scenario(path)
        total = sum(o.points for o in scenario.objectives.all_objectives())
        assert total == 200

    def test_total_points_detect_brute_force(self):
        """Total objective points should be 200 (50+75+75)."""
        path = SCENARIOS_DIR / "detect-brute-force.yaml"
        if not path.exists():
            pytest.skip("Example scenario file not found")

        scenario = load_scenario(path)
        total = sum(o.points for o in scenario.objectives.all_objectives())
        assert total == 200


# ---------------------------------------------------------------------------
# CLI integration with real scenario files
# ---------------------------------------------------------------------------


class TestCLIWithExampleScenarios:
    """Test CLI commands against the bundled example scenario files."""

    def _project_dir(self, tmp_path: Path) -> Path:
        """Set up a project dir that uses the real scenarios directory."""
        return tmp_path

    def test_list_shows_examples(self, tmp_path):
        """AC-1: list should show both example scenarios."""
        if not SCENARIOS_DIR.exists():
            pytest.skip("Scenarios directory not found")

        result = runner.invoke(app, [
            "list",
            "--scenarios-dir", str(SCENARIOS_DIR),
        ])
        assert result.exit_code == 0
        assert "recon-nmap-scan" in result.output
        assert "detect-brute-f" in result.output  # Rich may truncate the ID
        assert "beginner" in result.output
        assert "intermediate" in result.output

    def test_show_recon_scenario(self, tmp_path):
        """AC-1: show should display full scenario details."""
        if not SCENARIOS_DIR.exists():
            pytest.skip("Scenarios directory not found")

        result = runner.invoke(app, [
            "show", "recon-nmap-scan",
            "--scenarios-dir", str(SCENARIOS_DIR),
        ])
        assert result.exit_code == 0
        assert "Network Reconnaissance" in result.output
        assert "port-scan" in result.output
        assert "find-flag" in result.output

    def test_validate_recon_scenario(self, tmp_path):
        """AC-2: validate should succeed for the example file."""
        path = SCENARIOS_DIR / "recon-nmap-scan.yaml"
        if not path.exists():
            pytest.skip("Example scenario file not found")

        result = runner.invoke(app, ["validate", str(path)])
        assert result.exit_code == 0
        assert "Valid" in result.output

    def test_validate_brute_force_scenario(self, tmp_path):
        """AC-2: validate should succeed for the brute force example."""
        path = SCENARIOS_DIR / "detect-brute-force.yaml"
        if not path.exists():
            pytest.skip("Example scenario file not found")

        result = runner.invoke(app, ["validate", str(path)])
        assert result.exit_code == 0
        assert "Valid" in result.output


# ---------------------------------------------------------------------------
# Full lifecycle integration test
# ---------------------------------------------------------------------------


class TestFullLifecycle:
    """End-to-end test of the complete scenario lifecycle.

    Uses a purpose-built scenario with manual objectives to test:
    start -> status -> hint -> complete -> evaluate -> stop
    without requiring Docker or Wazuh.
    """

    @staticmethod
    def _setup_project(tmp_path: Path) -> Path:
        """Create a project dir with a test scenario."""
        scenarios_dir = tmp_path / "scenarios"
        scenarios_dir.mkdir()

        data = {
            "metadata": {
                "id": "integration-test",
                "name": "Integration Test Scenario",
                "description": "Full lifecycle integration test",
                "difficulty": "beginner",
                "estimated_minutes": 5,
            },
            "mode": "red",
            "containers": {"required": ["kali"]},
            "objectives": {
                "red": [
                    {
                        "id": "obj-one",
                        "description": "First objective",
                        "type": "manual",
                        "points": 60,
                        "hints": [
                            {"level": 1, "text": "Hint one", "point_penalty": 5},
                            {"level": 2, "text": "Hint two", "point_penalty": 10},
                        ],
                    },
                    {
                        "id": "obj-two",
                        "description": "Second objective",
                        "type": "manual",
                        "points": 40,
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

        (scenarios_dir / "integration-test.yaml").write_text(
            yaml.dump(data, default_flow_style=False)
        )
        return tmp_path

    def test_start_creates_session_and_events(self, tmp_path):
        """AC-3: start creates session.json and initializes event log."""
        project = self._setup_project(tmp_path)

        result = runner.invoke(app, [
            "start", "integration-test",
            "--project-dir", str(project),
        ])
        assert result.exit_code == 0
        assert "Started scenario" in result.output

        # Session file
        session_path = project / ".aptl" / "session.json"
        assert session_path.exists()
        session_data = json.loads(session_path.read_text())
        assert session_data["scenario_id"] == "integration-test"
        assert session_data["state"] == "active"

        # Events file
        events_dir = project / ".aptl" / "events"
        event_files = list(events_dir.glob("*.jsonl"))
        assert len(event_files) == 1
        content = event_files[0].read_text()
        assert "scenario_started" in content

    def test_status_shows_progress(self, tmp_path):
        """AC-4: status shows elapsed time and completion state."""
        project = self._setup_project(tmp_path)
        runner.invoke(app, [
            "start", "integration-test",
            "--project-dir", str(project),
        ])

        result = runner.invoke(app, [
            "status", "--project-dir", str(project),
        ])
        assert result.exit_code == 0
        assert "integration-test" in result.output
        assert "active" in result.output
        assert "Elapsed" in result.output
        assert "Completed:   0" in result.output

    def test_hint_reveals_progressively(self, tmp_path):
        """AC-6: hints reveal progressively and record penalties."""
        project = self._setup_project(tmp_path)
        runner.invoke(app, [
            "start", "integration-test",
            "--project-dir", str(project),
        ])

        # First hint
        result = runner.invoke(app, [
            "hint", "obj-one", "--project-dir", str(project),
        ])
        assert "Hint one" in result.output
        assert "level 1/2" in result.output
        assert "-5 pts" in result.output

        # Second hint
        result = runner.invoke(app, [
            "hint", "obj-one", "--project-dir", str(project),
        ])
        assert "Hint two" in result.output
        assert "level 2/2" in result.output

        # No more hints
        result = runner.invoke(app, [
            "hint", "obj-one", "--project-dir", str(project),
        ])
        assert "All hints already revealed" in result.output

        # Session records hint level
        session_data = json.loads(
            (project / ".aptl" / "session.json").read_text()
        )
        assert session_data["hints_used"]["obj-one"] == 2

    def test_complete_and_evaluate(self, tmp_path):
        """AC-5: evaluate updates session state with completions."""
        project = self._setup_project(tmp_path)
        runner.invoke(app, [
            "start", "integration-test",
            "--project-dir", str(project),
        ])

        # Complete first objective
        result = runner.invoke(app, [
            "complete", "obj-one", "--project-dir", str(project),
        ])
        assert "marked as complete" in result.output

        # Evaluate shows 1/2
        result = runner.invoke(app, [
            "evaluate", "--project-dir", str(project),
        ])
        assert "1/2" in result.output

        # Status shows 1 completed
        result = runner.invoke(app, [
            "status", "--project-dir", str(project),
        ])
        assert "Completed:   1" in result.output

    def test_stop_generates_report_with_score(self, tmp_path):
        """AC-7: stop generates report with score, time bonus, penalties."""
        project = self._setup_project(tmp_path)
        runner.invoke(app, [
            "start", "integration-test",
            "--project-dir", str(project),
        ])

        # Use a hint and complete both objectives
        runner.invoke(app, [
            "hint", "obj-one", "--project-dir", str(project),
        ])
        runner.invoke(app, [
            "complete", "obj-one", "--project-dir", str(project),
        ])
        runner.invoke(app, [
            "complete", "obj-two", "--project-dir", str(project),
        ])

        result = runner.invoke(app, [
            "stop", "--project-dir", str(project),
        ])
        assert result.exit_code == 0
        assert "Scenario stopped" in result.output
        assert "Score: 95/100" in result.output  # 100 - 5 hint penalty
        assert "Report:" in result.output

        # Report file exists and has correct contents
        reports = list((project / ".aptl" / "reports").glob("*.json"))
        assert len(reports) == 1
        report = json.loads(reports[0].read_text())

        assert report["scenario_id"] == "integration-test"
        assert report["score"]["total"] == 95
        assert report["score"]["hint_penalties"] == 5
        assert report["score"]["passing"] is True
        assert report["hints_used"] == {"obj-one": 1}
        assert len(report["objective_results"]) == 2
        assert len(report["events"]) > 0

    def test_session_cleared_after_stop(self, tmp_path):
        """After stop, session should be cleared for a new scenario."""
        project = self._setup_project(tmp_path)
        runner.invoke(app, [
            "start", "integration-test",
            "--project-dir", str(project),
        ])
        runner.invoke(app, [
            "stop", "--project-dir", str(project),
        ])

        # No active scenario
        result = runner.invoke(app, [
            "status", "--project-dir", str(project),
        ])
        assert "No active scenario" in result.output

        # Can start a new scenario
        result = runner.invoke(app, [
            "start", "integration-test",
            "--project-dir", str(project),
        ])
        assert result.exit_code == 0

    def test_event_log_records_full_timeline(self, tmp_path):
        """Events log should capture the full scenario timeline."""
        project = self._setup_project(tmp_path)
        runner.invoke(app, [
            "start", "integration-test",
            "--project-dir", str(project),
        ])

        # Capture the events file path before stop clears session
        session_data = json.loads(
            (project / ".aptl" / "session.json").read_text()
        )
        events_path = project / ".aptl" / session_data["events_file"]

        runner.invoke(app, [
            "hint", "obj-one", "--project-dir", str(project),
        ])
        runner.invoke(app, [
            "complete", "obj-one", "--project-dir", str(project),
        ])
        runner.invoke(app, [
            "evaluate", "--project-dir", str(project),
        ])
        runner.invoke(app, [
            "stop", "--project-dir", str(project),
        ])

        # Read events
        event_log = EventLog(events_path)
        events = event_log.read_all()
        event_types = [e.event_type for e in events]

        assert EventType.SCENARIO_STARTED in event_types
        assert EventType.HINT_REQUESTED in event_types
        assert EventType.OBJECTIVE_COMPLETED in event_types
        assert EventType.EVALUATION_RUN in event_types
        assert EventType.SCENARIO_STOPPED in event_types

    def test_fail_scenario_below_passing_score(self, tmp_path):
        """Stopping with insufficient points should show FAIL."""
        project = self._setup_project(tmp_path)
        runner.invoke(app, [
            "start", "integration-test",
            "--project-dir", str(project),
        ])

        # Complete only obj-two (40 points) - below passing_score of 50
        runner.invoke(app, [
            "complete", "obj-two", "--project-dir", str(project),
        ])

        result = runner.invoke(app, [
            "stop", "--project-dir", str(project),
        ])
        assert "Score: 40/100" in result.output
        assert "FAIL" in result.output

    def test_pass_scenario_at_threshold(self, tmp_path):
        """Completing enough points to meet passing_score shows PASS."""
        project = self._setup_project(tmp_path)
        runner.invoke(app, [
            "start", "integration-test",
            "--project-dir", str(project),
        ])

        # Complete obj-one (60 points) - meets passing_score of 50
        runner.invoke(app, [
            "complete", "obj-one", "--project-dir", str(project),
        ])

        result = runner.invoke(app, [
            "stop", "--project-dir", str(project),
        ])
        assert "Score: 60/100" in result.output
        assert "PASS" in result.output
