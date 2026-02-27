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
from aptl.core.scenarios import (
    ScenarioDefinition,
    ScenarioMode,
    find_scenarios,
    load_scenario,
)
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

    def test_webapp_compromise_loads(self):
        """Converted webapp-compromise.yaml should load as unified scenario."""
        path = SCENARIOS_DIR / "webapp-compromise.yaml"
        if not path.exists():
            pytest.skip("Converted playbook not present")
        scenario = load_scenario(path)
        assert scenario.metadata.id == "webapp-compromise"
        assert len(scenario.steps) == 6
        assert scenario.attack_chain == "Recon -> SQLi -> DB Access -> Privesc -> Data Exfil"
        assert scenario.steps[0].technique_id == "T1595.002"

    def test_ad_domain_compromise_loads(self):
        """Converted ad-domain-compromise.yaml should load as unified scenario."""
        path = SCENARIOS_DIR / "ad-domain-compromise.yaml"
        if not path.exists():
            pytest.skip("Converted playbook not present")
        scenario = load_scenario(path)
        assert scenario.metadata.id == "ad-domain-compromise"
        assert len(scenario.steps) == 5
        assert scenario.steps[0].expected_detections[0].product_name == "wazuh"

    def test_lateral_movement_loads(self):
        """Converted lateral-movement-data-theft.yaml should load as unified scenario."""
        path = SCENARIOS_DIR / "lateral-movement-data-theft.yaml"
        if not path.exists():
            pytest.skip("Converted playbook not present")
        scenario = load_scenario(path)
        assert scenario.metadata.id == "lateral-movement-data-theft"
        assert len(scenario.steps) == 5

    def test_find_scenarios_discovers_all(self):
        """find_scenarios should discover all 5 scenario files."""
        if not SCENARIOS_DIR.exists():
            pytest.skip("Scenarios directory not found")
        paths = find_scenarios(SCENARIOS_DIR)
        names = [p.stem for p in paths]
        assert "recon-nmap-scan" in names
        assert "detect-brute-force" in names
        assert "webapp-compromise" in names
        assert "ad-domain-compromise" in names
        assert "lateral-movement-data-theft" in names


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

        wide_runner = CliRunner(env={"COLUMNS": "200"})
        result = wide_runner.invoke(app, [
            "list",
            "--scenarios-dir", str(SCENARIOS_DIR),
        ])
        assert result.exit_code == 0
        assert "recon-nmap-scan" in result.output
        assert "detect-brute-force" in result.output
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

    Uses a purpose-built scenario to test:
    start -> status -> stop
    without requiring Docker or Wazuh.
    """

    @staticmethod
    def _setup_project(tmp_path: Path) -> Path:
        """Create a project dir with a test scenario."""
        scenarios_dir = tmp_path / "scenarios"
        scenarios_dir.mkdir(parents=True)

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
            "steps": [
                {
                    "step_number": 1,
                    "technique_id": "T1595.002",
                    "technique_name": "Active Scanning",
                    "tactic": "Reconnaissance",
                    "description": "Scan the target",
                    "target": "victim",
                },
            ],
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
        """AC-4: status shows elapsed time."""
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

    def test_stop_scenario(self, tmp_path):
        """AC-7: stop ends the scenario and assembles run archive."""
        project = self._setup_project(tmp_path)
        runner.invoke(app, [
            "start", "integration-test",
            "--project-dir", str(project),
        ])

        result = runner.invoke(app, [
            "stop", "--project-dir", str(project),
        ])
        assert result.exit_code == 0
        assert "Scenario stopped" in result.output
        assert "Duration:" in result.output

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

    def test_event_log_records_timeline(self, tmp_path):
        """Events log should capture the scenario timeline."""
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
            "stop", "--project-dir", str(project),
        ])

        # Read events
        event_log = EventLog(events_path)
        events = event_log.read_all()
        event_types = [e.event_type for e in events]

        assert EventType.SCENARIO_STARTED in event_types
        assert EventType.SCENARIO_STOPPED in event_types
