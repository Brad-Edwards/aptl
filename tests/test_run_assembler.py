"""Integration tests for run assembly."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from aptl.core.config import AptlConfig
from aptl.core.run_assembler import assemble_run
from aptl.core.runstore import LocalRunStore
from aptl.core.scenarios import ScenarioDefinition, load_scenario
from aptl.core.session import ActiveSession, SessionState


def _make_session(run_id: str = "test-run-id") -> ActiveSession:
    return ActiveSession(
        scenario_id="test-scenario",
        state=SessionState.COMPLETED,
        started_at="2025-01-01T00:00:00+00:00",
        trace_id="a" * 32,
        span_id="b" * 16,
        flags={
            "aptl-victim": {
                "user": {
                    "flag": "APTL{test}",
                    "token": "aptl:v1:victim:user:abc:def",
                    "path": "/home/labadmin/user.txt",
                    "description": "Test flag",
                }
            }
        },
        run_id=run_id,
    )



def _make_scenario_yaml(path: Path) -> Path:
    """Create a minimal scenario YAML file for testing."""
    yaml_content = """metadata:
  id: test-scenario
  name: Test Scenario
  description: A test scenario for unit tests.
  version: "1.0"
  difficulty: beginner
  estimated_minutes: 60
  tags: [test]
  mitre_attack:
    tactics: []
    techniques: []

mode: red

containers:
  required: [victim, kali]

objectives:
  red:
    - id: obj-1
      description: Test objective
      type: manual
      points: 100

scoring:
  max_score: 150
  passing_score: 50
  time_bonus:
    enabled: true
    max_bonus: 50
    decay_after_minutes: 30
"""
    scenario_dir = path / "scenarios"
    scenario_dir.mkdir(parents=True, exist_ok=True)
    scenario_path = scenario_dir / "test-scenario.yaml"
    scenario_path.write_text(yaml_content)
    return scenario_path


class TestAssembleRun:
    """Tests for the run assembly orchestrator."""

    @patch("aptl.core.run_assembler._active_containers")
    @patch("aptl.core.run_assembler.collect_wazuh_alerts")
    @patch("aptl.core.run_assembler.collect_suricata_eve")
    @patch("aptl.core.run_assembler.collect_thehive_cases")
    @patch("aptl.core.run_assembler.collect_misp_events")
    @patch("aptl.core.run_assembler.collect_shuffle_executions")
    @patch("aptl.core.run_assembler.collect_container_logs")
    @patch("aptl.core.run_assembler.collect_traces")
    def test_assembles_complete_run(
        self,
        mock_traces,
        mock_container_logs,
        mock_shuffle,
        mock_misp,
        mock_thehive,
        mock_suricata,
        mock_wazuh,
        mock_containers,
        tmp_path,
    ):
        # Setup mocks
        mock_containers.return_value = ["aptl-victim", "aptl-kali"]
        mock_wazuh.return_value = [
            {"rule": {"id": "1"}, "@timestamp": "2025-01-01T00:30:00"},
        ]
        mock_suricata.return_value = []
        mock_thehive.return_value = []
        mock_misp.return_value = []
        mock_shuffle.return_value = []
        mock_container_logs.return_value = {
            "aptl-victim": "victim log output\n",
        }
        mock_traces.return_value = [
            {"name": "aptl.scenario.run", "traceId": "a" * 32},
            {"name": "execute_tool", "traceId": "a" * 32},
        ]

        # Create scenario file
        scenario_path = _make_scenario_yaml(tmp_path)
        scenario = load_scenario(scenario_path)

        store = LocalRunStore(tmp_path / "runs")
        session = _make_session()
        config = AptlConfig()

        run_dir = assemble_run(
            store=store,
            run_id="test-run-id",
            session=session,
            scenario=scenario,
            scenario_path=scenario_path,
            config=config,
        )

        # Verify run directory structure
        assert run_dir.exists()
        assert (run_dir / "manifest.json").exists()
        assert (run_dir / "flags.json").exists()
        assert (run_dir / "scenario" / "definition.yaml").exists()
        assert (run_dir / "wazuh" / "alerts.jsonl").exists()
        assert (run_dir / "containers" / "aptl-victim.log").exists()
        assert (run_dir / "traces" / "spans.json").exists()

        # Verify manifest content
        manifest = json.loads((run_dir / "manifest.json").read_text())
        assert manifest["run_id"] == "test-run-id"
        assert manifest["scenario_id"] == "test-scenario"
        assert manifest["scenario_name"] == "Test Scenario"
        assert manifest["flags_captured"] == 1
        assert manifest["trace_id"] == "a" * 32

        # Verify flags
        flags = json.loads((run_dir / "flags.json").read_text())
        assert "aptl-victim" in flags

        # Verify container logs
        assert "victim log output" in (run_dir / "containers" / "aptl-victim.log").read_text()

        # Verify traces
        spans = json.loads((run_dir / "traces" / "spans.json").read_text())
        assert len(spans) == 2
        assert spans[0]["name"] == "aptl.scenario.run"

    @patch("aptl.core.run_assembler._active_containers")
    @patch("aptl.core.run_assembler.collect_wazuh_alerts")
    @patch("aptl.core.run_assembler.collect_suricata_eve")
    @patch("aptl.core.run_assembler.collect_thehive_cases")
    @patch("aptl.core.run_assembler.collect_misp_events")
    @patch("aptl.core.run_assembler.collect_shuffle_executions")
    @patch("aptl.core.run_assembler.collect_container_logs")
    @patch("aptl.core.run_assembler.collect_traces")
    def test_handles_no_optional_data(
        self,
        mock_traces,
        mock_container_logs,
        mock_shuffle,
        mock_misp,
        mock_thehive,
        mock_suricata,
        mock_wazuh,
        mock_containers,
        tmp_path,
    ):
        """Run assembly works even when all optional collectors return empty."""
        mock_containers.return_value = []
        mock_wazuh.return_value = []
        mock_suricata.return_value = []
        mock_thehive.return_value = []
        mock_misp.return_value = []
        mock_shuffle.return_value = []
        mock_container_logs.return_value = {}
        mock_traces.return_value = []

        scenario_path = _make_scenario_yaml(tmp_path)
        scenario = load_scenario(scenario_path)

        store = LocalRunStore(tmp_path / "runs")
        session = _make_session()
        config = AptlConfig()

        run_dir = assemble_run(
            store=store,
            run_id="minimal-run",
            session=session,
            scenario=scenario,
            scenario_path=scenario_path,
            config=config,
        )

        # Core files should always exist
        assert (run_dir / "manifest.json").exists()
        assert (run_dir / "flags.json").exists()

        # No traces when Tempo returns empty
        assert not (run_dir / "traces" / "spans.json").exists()
        assert not (run_dir / "soc" / "thehive-cases.json").exists()


class TestRunManifest:
    """Tests for manifest structure."""

    @patch("aptl.core.run_assembler._active_containers", return_value=[])
    @patch("aptl.core.run_assembler.collect_wazuh_alerts", return_value=[])
    @patch("aptl.core.run_assembler.collect_suricata_eve", return_value=[])
    @patch("aptl.core.run_assembler.collect_thehive_cases", return_value=[])
    @patch("aptl.core.run_assembler.collect_misp_events", return_value=[])
    @patch("aptl.core.run_assembler.collect_shuffle_executions", return_value=[])
    @patch("aptl.core.run_assembler.collect_container_logs", return_value={})
    @patch("aptl.core.run_assembler.collect_traces", return_value=[])
    def test_manifest_has_required_fields(
        self, m1, m2, m3, m4, m5, m6, m7, m8, tmp_path
    ):

        scenario_path = _make_scenario_yaml(tmp_path)
        scenario = load_scenario(scenario_path)

        store = LocalRunStore(tmp_path / "runs")
        run_dir = assemble_run(
            store=store,
            run_id="manifest-test",
            session=_make_session("manifest-test"),
            scenario=scenario,
            scenario_path=scenario_path,
            config=AptlConfig(),
        )

        manifest = json.loads((run_dir / "manifest.json").read_text())

        required_keys = [
            "run_id",
            "scenario_id",
            "scenario_name",
            "started_at",
            "finished_at",
            "duration_seconds",
            "trace_id",
            "config_snapshot",
            "containers",
            "flags_captured",
        ]
        for key in required_keys:
            assert key in manifest, f"Missing manifest key: {key}"

        assert manifest["run_id"] == "manifest-test"
        assert manifest["trace_id"] == "a" * 32
        assert isinstance(manifest["duration_seconds"], (int, float))
        assert isinstance(manifest["config_snapshot"], dict)
        assert "lab" in manifest["config_snapshot"]
        assert "containers" in manifest["config_snapshot"]
