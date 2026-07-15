"""Tests for the CLI command structure.

Smoke tests that verify CLI commands exist and produce expected output.
Integration tests verify CLI commands call the correct core functions.
We test our CLI wiring, not typer internals.
"""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, MagicMock

import pytest
from typer.testing import CliRunner


@pytest.fixture
def runner():
    return CliRunner()


class TestMainApp:
    """Tests for the top-level aptl CLI."""

    def test_version_flag(self, runner):
        """--version should print the package version."""
        from aptl.cli.main import app

        import aptl

        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert aptl.__version__ in result.stdout

    def test_help_shows_subcommands(self, runner):
        """Help output should list the major subcommands."""
        from aptl.cli.main import app

        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "lab" in result.stdout
        assert "config" in result.stdout
        assert "scenario" not in result.stdout

    def test_removed_scenario_subcommand_is_not_available(self, runner):
        """The legacy scenario command group should not be exposed."""
        from aptl.cli.main import app

        result = runner.invoke(app, ["scenario", "--help"])
        assert result.exit_code != 0
        assert "No such command" in result.output


class TestLabCommands:
    """Tests for aptl lab subcommands."""

    def test_lab_start_exists(self, runner):
        """aptl lab start should be a valid command."""
        from aptl.cli.main import app

        result = runner.invoke(app, ["lab", "start", "--help"])
        assert result.exit_code == 0

    def test_lab_stop_exists(self, runner):
        """aptl lab stop should be a valid command."""
        from aptl.cli.main import app

        result = runner.invoke(app, ["lab", "stop", "--help"])
        assert result.exit_code == 0

    def test_lab_status_exists(self, runner):
        """aptl lab status should be a valid command."""
        from aptl.cli.main import app

        result = runner.invoke(app, ["lab", "status", "--help"])
        assert result.exit_code == 0

    def test_lab_info_exists(self, runner):
        """aptl lab info should be a valid command."""
        from aptl.cli.main import app

        result = runner.invoke(app, ["lab", "info", "--help"])
        assert result.exit_code == 0

    def test_lab_continuity_audit_exists(self, runner):
        """aptl lab continuity-audit should be a valid command."""
        from aptl.cli.main import app

        result = runner.invoke(app, ["lab", "continuity-audit", "--help"])
        assert result.exit_code == 0

    def test_lab_scenarios_exists(self, runner):
        """aptl lab scenarios should list curated startup scenarios."""
        from aptl.cli.main import app

        result = runner.invoke(app, ["lab", "scenarios", "--help"])
        assert result.exit_code == 0


class TestConfigCommands:
    """Tests for aptl config subcommands."""

    def test_config_show_exists(self, runner):
        """aptl config show should be a valid command."""
        from aptl.cli.main import app

        result = runner.invoke(app, ["config", "show", "--help"])
        assert result.exit_code == 0

    def test_config_validate_exists(self, runner):
        """aptl config validate should be a valid command."""
        from aptl.cli.main import app

        result = runner.invoke(app, ["config", "validate", "--help"])
        assert result.exit_code == 0


class TestContainerCommands:
    """Tests for aptl container subcommands."""

    def test_container_list_exists(self, runner):
        """aptl container list should be a valid command."""
        from aptl.cli.main import app

        result = runner.invoke(app, ["container", "list", "--help"])
        assert result.exit_code == 0

    def test_container_logs_exists(self, runner):
        """aptl container logs should be a valid command."""
        from aptl.cli.main import app

        result = runner.invoke(app, ["container", "logs", "--help"])
        assert result.exit_code == 0


class TestLabStartCommand:
    """Tests for the aptl lab start CLI command."""

    def test_start_calls_orchestrate_lab_start(self, runner, mocker):
        """start command should call orchestrate_lab_start."""
        from aptl.cli.main import app
        from aptl.core.lab import LabResult

        mock_orchestrate = mocker.patch(
            "aptl.cli.lab.orchestrate_lab_start",
            return_value=LabResult(success=True, message="Lab started"),
        )

        result = runner.invoke(app, ["lab", "start"])

        assert result.exit_code == 0
        mock_orchestrate.assert_called_once()
        assert "Credentials file: .env" in result.stdout
        assert "Wazuh Dashboard: https://localhost:443" in result.stdout
        assert "see INDEXER_PASSWORD in .env" in result.stdout

    def test_lab_info_prints_access_summary(self, runner, tmp_path):
        """lab info should reprint access URLs and credential locations."""
        from aptl.cli.main import app

        (tmp_path / ".env").touch()

        result = runner.invoke(app, ["lab", "info", "--project-dir", str(tmp_path)])

        assert result.exit_code == 0
        assert f"Credentials file: {tmp_path / '.env'}" in result.stdout
        assert "Grafana: http://localhost:3100" in result.stdout

    def test_lab_info_omits_reverse_access_when_service_is_not_running(
        self, runner, tmp_path, mocker
    ):
        """The default TechVault scenario does not realize reverse."""
        from aptl.cli.main import app

        (tmp_path / ".env").touch()
        mocker.patch("aptl.cli.lab_render.live_services", return_value=set())

        result = runner.invoke(app, ["lab", "info", "--project-dir", str(tmp_path)])

        assert result.exit_code == 0
        assert "Reverse engineering SSH" not in result.stdout
        assert "aptl_lab_key" not in result.stdout

    def test_lab_info_prints_reverse_access_when_service_is_running(
        self, runner, tmp_path, mocker
    ):
        """An explicitly realized reverse service remains discoverable."""
        from aptl.cli.main import app
        from aptl.core.host_ports import ResolvedPort

        (tmp_path / ".env").touch()
        mocker.patch(
            "aptl.cli.lab.live_resolved_ports",
            return_value=[
                ResolvedPort(
                    service="reverse",
                    env_var="REVERSE_SSH_PORT",
                    default_port=2027,
                    resolved_port=20027,
                    protos=("tcp",),
                    host_ip="127.0.0.1",
                    remapped=True,
                )
            ],
        )
        mocker.patch(
            "aptl.cli.lab_render.live_services", return_value={"reverse"}
        )

        result = runner.invoke(app, ["lab", "info", "--project-dir", str(tmp_path)])

        assert result.exit_code == 0
        assert "Reverse engineering SSH" in result.stdout
        assert "localhost -p 20027" in result.stdout

    def test_lab_info_fails_without_env(self, runner, tmp_path):
        """lab info should tell users to start the lab before .env exists."""
        from aptl.cli.main import app

        result = runner.invoke(app, ["lab", "info", "--project-dir", str(tmp_path)])

        assert result.exit_code == 1
        assert "run `aptl lab start` first" in result.stderr

    def test_lab_info_reflects_remapped_ports_from_live_docker_state(
        self, runner, tmp_path, mocker
    ):
        """When docker has published Grafana on a remapped host port
        (default 3100 was already in use), `aptl lab info` must print the
        remapped port so students don't paste a URL that goes to whatever
        is on 3100 (#737)."""
        from aptl.cli.main import app
        from aptl.core.host_ports import ResolvedPort

        (tmp_path / ".env").touch()

        # Bypass config load — return a stub list directly.
        mocker.patch(
            "aptl.cli.lab.live_resolved_ports",
            return_value=[
                ResolvedPort(
                    service="aptl-grafana-otel",
                    env_var=None,
                    default_port=3100,
                    resolved_port=20005,
                    protos=("tcp",),
                    host_ip="127.0.0.1",
                    remapped=True,
                ),
            ],
        )

        result = runner.invoke(
            app, ["lab", "info", "--project-dir", str(tmp_path)]
        )

        assert result.exit_code == 0
        assert "Grafana: http://localhost:20005" in result.stdout
        assert "Grafana: http://localhost:3100" not in result.stdout
        # The remap block also appears now (aids reconciliation vs walkthrough).
        assert "3100 -> 20005" in result.stdout

    def test_live_resolved_ports_returns_empty_when_config_missing(self, tmp_path):
        """Best-effort: no aptl.json / no backend / any error path just
        returns []; info falls back to compile-time defaults."""
        from aptl.cli.lab_render import live_resolved_ports

        # tmp_path has neither aptl.json nor a running lab, so
        # resolve_config_for_cli raises and the helper swallows it.
        assert live_resolved_ports(tmp_path) == []

    def test_live_resolved_ports_extracts_binding_from_docker_inspect(
        self, tmp_path, mocker
    ):
        """Walks compose ps + docker inspect and builds a ResolvedPort
        entry for each published port."""
        from aptl.cli.lab_render import live_resolved_ports
        from aptl.core.host_ports import ResolvedPort

        backend = mocker.MagicMock()
        backend.container_list.return_value = [
            {"Name": "aptl-wazuh-indexer", "Service": "wazuh.indexer"},
        ]
        backend.container_inspect.return_value = {
            "NetworkSettings": {
                "Ports": {
                    "9200/tcp": [{"HostIp": "127.0.0.1", "HostPort": "20015"}],
                },
            },
        }
        mocker.patch(
            "aptl.cli._common.resolve_config_for_cli",
            return_value=(mocker.MagicMock(), tmp_path),
        )
        mocker.patch(
            "aptl.core.deployment.get_backend", return_value=backend
        )

        result = live_resolved_ports(tmp_path)

        assert len(result) == 1
        entry = result[0]
        assert isinstance(entry, ResolvedPort)
        assert entry.service == "wazuh.indexer"
        assert entry.default_port == 9200
        assert entry.resolved_port == 20015
        assert entry.remapped is True
        assert entry.host_ip == "127.0.0.1"

    def test_start_handles_failure_gracefully(self, runner, mocker):
        """start command should exit 1 and show error on failure.

        Under ADR-030, a fatal orchestrator result carries
        ``outcome=FAILED`` alongside ``success=False`` (the orchestrator
        wraps short-circuits this way); the mock matches that contract.
        """
        from aptl.cli.main import app
        from aptl.core.lab import LabResult
        from aptl.core.lab_types import StartupOutcome

        mocker.patch(
            "aptl.cli.lab.orchestrate_lab_start",
            return_value=LabResult(
                success=False,
                error="vm.max_map_count too low",
                outcome=StartupOutcome.FAILED,
            ),
        )

        result = runner.invoke(app, ["lab", "start"])

        assert result.exit_code == 1
        assert "vm.max_map_count" in result.stdout or "failed" in result.stdout.lower()

    def test_start_uses_project_dir_option(self, runner, mocker, tmp_path):
        """start command should pass --project-dir to orchestrate."""
        from aptl.cli.main import app
        from aptl.core.lab import LabResult

        mock_orchestrate = mocker.patch(
            "aptl.cli.lab.orchestrate_lab_start",
            return_value=LabResult(success=True, message="Lab started"),
        )

        result = runner.invoke(app, ["lab", "start", "--project-dir", str(tmp_path)])

        assert result.exit_code == 0
        mock_orchestrate.assert_called_once_with(
            tmp_path,
            skip_seed=False,
            scenario_path=None,
            progress=ANY,
        )

    def test_start_accepts_catalog_scenario_id(self, runner, mocker, tmp_path):
        """--scenario should resolve a catalog id and pass its SDL path."""
        from aptl.cli.main import app
        from aptl.core.lab import LabResult

        selected = tmp_path / "scenarios" / "custom.sdl.yaml"
        resolver = mocker.patch(
            "aptl.cli.lab.resolve_scenario_selection",
            return_value=selected,
        )
        mock_orchestrate = mocker.patch(
            "aptl.cli.lab.orchestrate_lab_start",
            return_value=LabResult(success=True, message="Lab started"),
        )

        result = runner.invoke(
            app,
            ["lab", "start", "--project-dir", str(tmp_path), "--scenario", "custom"],
        )

        assert result.exit_code == 0
        resolver.assert_called_once_with(
            tmp_path,
            scenario_id="custom",
            scenario_path=None,
        )
        mock_orchestrate.assert_called_once_with(
            tmp_path,
            skip_seed=False,
            scenario_path=selected,
            progress=ANY,
        )

    def test_start_accepts_explicit_scenario_path(self, runner, mocker, tmp_path):
        """--scenario-path should resolve and pass an explicit ACES SDL path."""
        from aptl.cli.main import app
        from aptl.core.lab import LabResult

        selected = tmp_path / "scenarios" / "custom.sdl.yaml"
        resolver = mocker.patch(
            "aptl.cli.lab.resolve_scenario_selection",
            return_value=selected,
        )
        mock_orchestrate = mocker.patch(
            "aptl.cli.lab.orchestrate_lab_start",
            return_value=LabResult(success=True, message="Lab started"),
        )

        result = runner.invoke(
            app,
            [
                "lab",
                "start",
                "--project-dir",
                str(tmp_path),
                "--scenario-path",
                "scenarios/custom.sdl.yaml",
            ],
        )

        assert result.exit_code == 0
        resolver.assert_called_once_with(
            tmp_path,
            scenario_id=None,
            scenario_path=Path("scenarios/custom.sdl.yaml"),
        )
        mock_orchestrate.assert_called_once_with(
            tmp_path,
            skip_seed=False,
            scenario_path=selected,
            progress=ANY,
        )

    def test_start_prints_progress_updates(self, runner, mocker):
        """The CLI should surface progress emitted by the startup path."""
        from aptl.cli.main import app
        from aptl.core.lab import LabResult
        from aptl.core.lab_types import StartupOutcome

        def fake_orchestrate(_project_dir, **kwargs):
            kwargs["progress"]("Starting containers with Docker Compose.")
            return LabResult(success=True, outcome=StartupOutcome.READY)

        mocker.patch(
            "aptl.cli.lab.orchestrate_lab_start",
            side_effect=fake_orchestrate,
        )

        result = runner.invoke(app, ["lab", "start"])

        assert result.exit_code == 0
        assert "[lab start] Starting containers with Docker Compose." in result.stdout

    def test_start_rejects_both_scenario_selectors(self, runner, mocker, tmp_path):
        """Catalog id and explicit path selectors are mutually exclusive."""
        from aptl.cli.main import app

        mocker.patch(
            "aptl.cli.lab.resolve_scenario_selection",
            side_effect=ValueError("scenario selectors are mutually exclusive"),
        )
        result = runner.invoke(
            app,
            [
                "lab",
                "start",
                "--project-dir",
                str(tmp_path),
                "--scenario",
                "custom",
                "--scenario-path",
                "scenarios/custom.sdl.yaml",
            ],
        )

        assert result.exit_code == 2
        assert "mutually exclusive" in result.stderr

    def test_start_clean_calls_clean_boot_lab(self, runner, mocker, tmp_path):
        """--clean routes through clean_boot_lab, not the plain start path."""
        from aptl.cli.main import app
        from aptl.core.lab import LabResult

        mock_clean = mocker.patch(
            "aptl.cli.lab.clean_boot_lab",
            return_value=LabResult(success=True, message="Lab started"),
        )
        mock_orchestrate = mocker.patch("aptl.cli.lab.orchestrate_lab_start")

        result = runner.invoke(
            app,
            ["lab", "start", "--project-dir", str(tmp_path), "--clean", "--yes"],
        )

        assert result.exit_code == 0
        mock_orchestrate.assert_not_called()
        mock_clean.assert_called_once_with(
            tmp_path,
            remove_volumes=True,
            skip_seed=False,
            scenario_path=None,
            progress=ANY,
        )

    def test_start_clean_aborts_without_confirmation(self, runner, mocker, tmp_path):
        """--clean is destructive: declining the prompt aborts before any boot."""
        from aptl.cli.main import app

        mock_clean = mocker.patch("aptl.cli.lab.clean_boot_lab")

        result = runner.invoke(
            app,
            ["lab", "start", "--project-dir", str(tmp_path), "--clean"],
            input="n\n",
        )

        assert result.exit_code == 0
        mock_clean.assert_not_called()
        assert "Aborted" in result.stdout

    def test_start_clean_yes_bypasses_prompt(self, runner, mocker, tmp_path):
        """--yes skips the destructive confirmation prompt."""
        from aptl.cli.main import app
        from aptl.core.lab import LabResult

        mock_clean = mocker.patch(
            "aptl.cli.lab.clean_boot_lab",
            return_value=LabResult(success=True, message="Lab started"),
        )

        result = runner.invoke(
            app,
            ["lab", "start", "--project-dir", str(tmp_path), "--clean", "--yes"],
        )

        assert result.exit_code == 0
        mock_clean.assert_called_once()

    def test_start_clean_flag_listed_in_help(self, runner):
        """The --clean flag is discoverable from start --help.

        Strip ANSI escapes first: when color is forced on (CI sets
        ``FORCE_COLOR``), Rich styles the option name and injects escape
        sequences inside the ``--clean`` token, so the raw stdout has no
        literal ``--clean`` substring even though the flag is rendered.
        """
        import re

        from aptl.cli.main import app

        result = runner.invoke(app, ["lab", "start", "--help"])

        assert result.exit_code == 0
        plain = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
        assert "--clean" in plain

    def test_lab_scenarios_lists_catalog_entries(self, runner, mocker, tmp_path):
        """The list command should read catalog rows dynamically."""
        from aptl.cli.main import app

        mocker.patch(
            "aptl.cli.lab.load_scenario_catalog",
            return_value=SimpleNamespace(
                scenarios=[
                    SimpleNamespace(
                        id="techvault-operational",
                        name="TechVault Operational",
                        path="scenarios/techvault-operational.sdl.yaml",
                        description="Default public startup scenario.",
                    )
                ]
            ),
        )

        result = runner.invoke(
            app,
            ["lab", "scenarios", "--project-dir", str(tmp_path)],
        )

        assert result.exit_code == 0
        assert "techvault-operational" in result.stdout
        assert "scenarios/techvault-operational.sdl.yaml" in result.stdout

    def test_start_ready_outcome_prints_ready(self, runner, mocker):
        """A clean start prints the ready outcome (ADR-030)."""
        from aptl.cli.main import app
        from aptl.core.lab import LabResult
        from aptl.core.lab_types import StartupOutcome

        mocker.patch(
            "aptl.cli.lab.orchestrate_lab_start",
            return_value=LabResult(
                success=True,
                message="Lab started successfully",
                outcome=StartupOutcome.READY,
            ),
        )

        result = runner.invoke(app, ["lab", "start"])

        assert result.exit_code == 0
        assert "ready" in result.stdout.lower()

    def test_start_degraded_usable_lists_diagnostics(self, runner, mocker):
        """A telemetry warning produces degraded_usable + a one-line entry."""
        from aptl.cli.main import app
        from aptl.core.lab import LabResult
        from aptl.core.lab_types import (
            DiagnosticImpact,
            DiagnosticSeverity,
            StartupDiagnostic,
            StartupOutcome,
        )

        mocker.patch(
            "aptl.cli.lab.orchestrate_lab_start",
            return_value=LabResult(
                success=True,
                message="Lab started with outcome=degraded_usable",
                outcome=StartupOutcome.DEGRADED_USABLE,
                diagnostics=[
                    StartupDiagnostic(
                        step="wait_for_services",
                        component="wazuh_indexer",
                        impact=DiagnosticImpact.TELEMETRY,
                        severity=DiagnosticSeverity.WARNING,
                        message="Wazuh Indexer did not become ready within 300s",
                    ),
                ],
            ),
        )

        result = runner.invoke(app, ["lab", "start"])

        assert result.exit_code == 0
        assert "degraded_usable" in result.stdout
        assert "wazuh_indexer" in result.stdout
        assert "telemetry" in result.stdout
        # Non-fatal: should still print partial readiness lead-in.
        assert "warning" in result.stdout.lower()

    def test_start_degraded_unusable_groups_by_impact(self, runner, mocker):
        """Multiple diagnostics surface per impact bucket."""
        from aptl.cli.main import app
        from aptl.core.lab import LabResult
        from aptl.core.lab_types import (
            DiagnosticImpact,
            DiagnosticSeverity,
            StartupDiagnostic,
            StartupOutcome,
        )

        mocker.patch(
            "aptl.cli.lab.orchestrate_lab_start",
            return_value=LabResult(
                success=True,
                message="Lab started with outcome=degraded_unusable",
                outcome=StartupOutcome.DEGRADED_UNUSABLE,
                diagnostics=[
                    StartupDiagnostic(
                        step="test_ssh",
                        component="ssh:kali",
                        impact=DiagnosticImpact.READINESS,
                        severity=DiagnosticSeverity.WARNING,
                        message="SSH to kali not ready after 60s",
                    ),
                    StartupDiagnostic(
                        step="build_mcps",
                        impact=DiagnosticImpact.CAPABILITY,
                        severity=DiagnosticSeverity.WARNING,
                        message="MCP build returned non-zero exit; see lab logs",
                    ),
                ],
            ),
        )

        result = runner.invoke(app, ["lab", "start"])

        # Non-fatal exit, but operator must see what's degraded.
        assert result.exit_code == 0
        assert "degraded_unusable" in result.stdout
        assert "ssh:kali" in result.stdout
        assert "build_mcps" in result.stdout
        # Both impact labels should appear.
        assert "readiness" in result.stdout
        assert "capability" in result.stdout

    def test_start_failed_outcome_exits_nonzero(self, runner, mocker):
        from aptl.cli.main import app
        from aptl.core.lab import LabResult
        from aptl.core.lab_types import StartupOutcome

        mocker.patch(
            "aptl.cli.lab.orchestrate_lab_start",
            return_value=LabResult(
                success=False,
                error="vm.max_map_count too low",
                outcome=StartupOutcome.FAILED,
            ),
        )

        result = runner.invoke(app, ["lab", "start"])

        assert result.exit_code == 1
        assert "vm.max_map_count" in result.stdout
        assert "failed" in result.stdout.lower()


class TestLabStopCommand:
    """Tests for the aptl lab stop CLI command."""

    def test_stop_calls_stop_lab(self, runner, mocker):
        """stop command should call stop_lab."""
        from aptl.cli.main import app
        from aptl.core.lab import LabResult

        mock_stop = mocker.patch(
            "aptl.cli.lab.stop_lab",
            return_value=LabResult(success=True, message="Lab stopped"),
        )

        result = runner.invoke(app, ["lab", "stop"])

        assert result.exit_code == 0
        mock_stop.assert_called_once()

    def test_stop_handles_failure(self, runner, mocker):
        """stop command should exit 1 on failure."""
        from aptl.cli.main import app
        from aptl.core.lab import LabResult

        mocker.patch(
            "aptl.cli.lab.stop_lab",
            return_value=LabResult(success=False, error="docker not found"),
        )

        result = runner.invoke(app, ["lab", "stop"])

        assert result.exit_code == 1

    def test_stop_with_volumes_flag(self, runner, mocker):
        """stop --volumes should pass remove_volumes=True."""
        from aptl.cli.main import app
        from aptl.core.lab import LabResult

        mock_stop = mocker.patch(
            "aptl.cli.lab.stop_lab",
            return_value=LabResult(success=True, message="Lab stopped"),
        )

        result = runner.invoke(app, ["lab", "stop", "--volumes", "--yes"])

        assert result.exit_code == 0
        mock_stop.assert_called_once_with(remove_volumes=True, project_dir=Path("."))

    def test_stop_volumes_shows_warning(self, runner, mocker):
        """stop --volumes without --yes should show data loss warning."""
        from aptl.cli.main import app

        mocker.patch("aptl.cli.lab.stop_lab")

        result = runner.invoke(app, ["lab", "stop", "--volumes"], input="n\n")

        assert "WARNING" in result.output
        assert "Aborted" in result.output

    def test_stop_volumes_confirm_proceeds(self, runner, mocker):
        """stop --volumes with confirmation should proceed."""
        from aptl.cli.main import app
        from aptl.core.lab import LabResult

        mocker.patch(
            "aptl.cli.lab.stop_lab",
            return_value=LabResult(success=True, message="Lab stopped"),
        )

        result = runner.invoke(app, ["lab", "stop", "--volumes"], input="y\n")

        assert result.exit_code == 0


class TestLabStatusCommand:
    """Tests for the aptl lab status CLI command."""

    def test_status_calls_lab_status(self, runner, mocker):
        """status command should call lab_status."""
        from aptl.cli.main import app
        from aptl.core.lab import LabStatus

        mock_status = mocker.patch(
            "aptl.cli.lab.lab_status",
            return_value=LabStatus(
                running=True,
                containers=[{"Name": "aptl-victim", "State": "running"}],
            ),
        )

        result = runner.invoke(app, ["lab", "status"])

        assert result.exit_code == 0
        mock_status.assert_called_once()

    def test_status_shows_not_running(self, runner, mocker):
        """status command should indicate when lab is not running."""
        from aptl.cli.main import app
        from aptl.core.lab import LabStatus

        mocker.patch(
            "aptl.cli.lab.lab_status",
            return_value=LabStatus(running=False, containers=[]),
        )

        result = runner.invoke(app, ["lab", "status"])

        assert result.exit_code == 0
        assert "not running" in result.stdout.lower()

    def test_status_shows_container_health(self, runner, mocker):
        """status should display container health when available."""
        from aptl.cli.main import app
        from aptl.core.lab import LabStatus

        mocker.patch(
            "aptl.cli.lab.lab_status",
            return_value=LabStatus(
                running=True,
                containers=[
                    {"Name": "aptl-victim", "State": "running", "Health": "healthy"},
                ],
            ),
        )

        result = runner.invoke(app, ["lab", "status"])

        assert result.exit_code == 0
        assert "aptl-victim" in result.output
        assert "healthy" in result.output

    def test_status_shows_error_when_not_running(self, runner, mocker):
        """status should display error message when not running."""
        from aptl.cli.main import app
        from aptl.core.lab import LabStatus

        mocker.patch(
            "aptl.cli.lab.lab_status",
            return_value=LabStatus(
                running=False,
                containers=[],
                error="docker daemon not running",
            ),
        )

        result = runner.invoke(app, ["lab", "status"])

        assert "not running" in result.stdout.lower()
        assert "docker daemon not running" in result.output


def _continuity_result(events):
    """Helper: wrap an event list in a ContinuityAuditResult for mocks."""
    from aptl.core.continuity import ContinuityAuditResult

    return ContinuityAuditResult(events=list(events), archive_error=None)


class TestLabContinuityAuditCommand:
    """Tests for the aptl lab continuity-audit CLI command (issue #252)."""

    def _stub_cli_plumbing(self, mocker, project_dir: Path):
        """Stub the CLI helpers so the command runs without a real lab.

        ``continuity-audit`` lazily imports its dependencies inside the
        command body (a CLI-startup-cost optimization), so tests must
        patch the *source* module names — not ``aptl.cli.lab.<name>``,
        which never has the attributes attached.
        """
        from aptl.core.config import AptlConfig
        from aptl.core.session import ScenarioSession

        mocker.patch(
            "aptl.cli.continuity.resolve_config_for_cli",
            return_value=(AptlConfig(), project_dir),
        )
        mocker.patch(
            "aptl.cli.continuity.get_backend",
            return_value=mocker.MagicMock(),
        )
        get_active = mocker.patch.object(
            ScenarioSession, "get_active", return_value=None,
        )
        return get_active

    def test_calls_audit_and_revert_with_default_targets(
        self, runner, mocker, tmp_path
    ):
        from aptl.cli.main import app
        from aptl.core.continuity import default_targets

        self._stub_cli_plumbing(mocker, tmp_path)
        mocker.patch(
            "aptl.cli.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        mock_audit = mocker.patch(
            "aptl.cli.continuity.audit_and_revert",
            return_value=_continuity_result([]),
        )

        result = runner.invoke(
            app, ["lab", "continuity-audit", "--project-dir", str(tmp_path)],
        )

        assert result.exit_code == 0
        mock_audit.assert_called_once()
        # First positional arg is the backend stub, second is the targets
        # list. Confirm targets default to default_targets().
        kwargs = mock_audit.call_args.kwargs
        positional = mock_audit.call_args.args
        targets_arg = positional[1] if len(positional) > 1 else kwargs["targets"]
        assert targets_arg == default_targets()

    def test_no_findings_prints_clean_summary(
        self, runner, mocker, tmp_path
    ):
        from aptl.cli.main import app

        self._stub_cli_plumbing(mocker, tmp_path)
        mocker.patch(
            "aptl.cli.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        mocker.patch(
            "aptl.cli.continuity.audit_and_revert",
            return_value=_continuity_result([]),
        )

        result = runner.invoke(
            app, ["lab", "continuity-audit", "--project-dir", str(tmp_path)],
        )

        assert result.exit_code == 0
        assert "no blanket kali source-IP rules" in result.stdout

    def test_reports_reverted_events(self, runner, mocker, tmp_path):
        from aptl.cli.main import app
        from aptl.core.continuity import KaliCarveOutEvent

        self._stub_cli_plumbing(mocker, tmp_path)
        mocker.patch(
            "aptl.cli.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        event = KaliCarveOutEvent(
            timestamp="2026-05-03T12:00:00+00:00",
            target="aptl-victim",
            source_ip="172.20.4.30/32",
            rule_text="-A INPUT -s 172.20.4.30/32 -j DROP",
            action="REVERTED",
            error=None,
        )
        mocker.patch(
            "aptl.cli.continuity.audit_and_revert",
            return_value=_continuity_result([event]),
        )

        result = runner.invoke(
            app, ["lab", "continuity-audit", "--project-dir", str(tmp_path)],
        )

        assert result.exit_code == 0
        assert "1 reverted" in result.stdout
        assert "aptl-victim" in result.stdout
        assert "REVERTED" in result.stdout

    def test_json_output(self, runner, mocker, tmp_path):
        import json as json_mod
        from aptl.cli.main import app
        from aptl.core.continuity import KaliCarveOutEvent

        self._stub_cli_plumbing(mocker, tmp_path)
        mocker.patch(
            "aptl.cli.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        event = KaliCarveOutEvent(
            timestamp="2026-05-03T12:00:00+00:00",
            target="aptl-victim",
            source_ip="172.20.4.30/32",
            rule_text="-A INPUT -s 172.20.4.30/32 -j DROP",
            action="REVERTED",
            error=None,
        )
        mocker.patch(
            "aptl.cli.continuity.audit_and_revert",
            return_value=_continuity_result([event]),
        )

        result = runner.invoke(
            app,
            ["lab", "continuity-audit", "--project-dir", str(tmp_path), "--json"],
        )

        assert result.exit_code == 0
        parsed = json_mod.loads(result.stdout)
        assert isinstance(parsed, list) and len(parsed) == 1
        assert parsed[0]["target"] == "aptl-victim"
        assert parsed[0]["action"] == "REVERTED"

    def test_target_option_overrides_defaults(
        self, runner, mocker, tmp_path
    ):
        from aptl.cli.main import app

        self._stub_cli_plumbing(mocker, tmp_path)
        mocker.patch(
            "aptl.cli.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        mock_audit = mocker.patch(
            "aptl.cli.continuity.audit_and_revert",
            return_value=_continuity_result([]),
        )

        result = runner.invoke(
            app,
            [
                "lab", "continuity-audit",
                "--project-dir", str(tmp_path),
                "--target", "aptl-victim",
            ],
        )

        assert result.exit_code == 0
        positional = mock_audit.call_args.args
        kwargs = mock_audit.call_args.kwargs
        targets_arg = positional[1] if len(positional) > 1 else kwargs["targets"]
        assert targets_arg == ["aptl-victim"]

    def test_fails_hard_when_whitelist_empty(self, runner, mocker, tmp_path):
        # Codex finding C7 (cycle 2): a silent zero-exit on empty
        # whitelist let automation believe the carve-out was clean
        # while it was actually disabled. Treat empty/missing
        # whitelist as a hard error.
        from aptl.cli.main import app

        self._stub_cli_plumbing(mocker, tmp_path)
        mocker.patch("aptl.cli.continuity.kali_source_ips", return_value=[])
        # The audit should not even be reached.
        mock_audit = mocker.patch(
            "aptl.cli.continuity.audit_and_revert",
            return_value=_continuity_result([]),
        )

        result = runner.invoke(
            app, ["lab", "continuity-audit", "--project-dir", str(tmp_path)],
        )

        assert result.exit_code != 0
        assert "no kali IPs found" in result.output
        mock_audit.assert_not_called()

    def test_rejects_explicit_target_not_in_compose_project(
        self, runner, mocker, tmp_path
    ):
        # Codex security finding S1 (cycle 1): without project-ownership
        # validation, --target accepts any container name on the daemon.
        # The CLI must reject targets that backend.container_exists()
        # rules out, before they reach container_exec.
        from aptl.cli.main import app
        from aptl.core.config import AptlConfig
        from aptl.core.session import ScenarioSession

        mocker.patch(
            "aptl.cli.continuity.resolve_config_for_cli",
            return_value=(AptlConfig(), tmp_path),
        )
        backend = mocker.MagicMock()
        backend.container_exists.return_value = False
        mocker.patch("aptl.cli.continuity.get_backend", return_value=backend)
        mocker.patch.object(ScenarioSession, "get_active", return_value=None)
        # Make sure the audit isn't reached.
        mock_audit = mocker.patch("aptl.cli.continuity.audit_and_revert")

        result = runner.invoke(
            app,
            [
                "lab", "continuity-audit",
                "--project-dir", str(tmp_path),
                "--target", "foreign-container",
            ],
        )

        assert result.exit_code != 0
        assert "foreign-container" in result.output
        mock_audit.assert_not_called()

    def test_default_targets_filtered_to_present_subset(
        self, runner, mocker, tmp_path,
    ):
        # Codex finding C8 (cycle 2): when using defaults (no --target),
        # a missing default in the active compose profile must NOT
        # reject the entire command. Instead, filter to the present
        # subset, warn about the skipped names, and audit the rest.
        from aptl.cli.main import app
        from aptl.core.config import AptlConfig
        from aptl.core.session import ScenarioSession

        mocker.patch(
            "aptl.cli.continuity.resolve_config_for_cli",
            return_value=(AptlConfig(), tmp_path),
        )

        # Simulate a profile where only aptl-webapp is up.
        backend = mocker.MagicMock()
        backend.container_exists.side_effect = lambda name: name == "aptl-webapp"
        mocker.patch("aptl.cli.continuity.get_backend", return_value=backend)
        mocker.patch.object(ScenarioSession, "get_active", return_value=None)
        mocker.patch(
            "aptl.cli.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        mock_audit = mocker.patch(
            "aptl.cli.continuity.audit_and_revert",
            return_value=_continuity_result([]),
        )

        result = runner.invoke(
            app, ["lab", "continuity-audit", "--project-dir", str(tmp_path)],
        )

        assert result.exit_code == 0
        # Audit was called with only the present default.
        positional = mock_audit.call_args.args
        kwargs = mock_audit.call_args.kwargs
        targets_arg = positional[1] if len(positional) > 1 else kwargs["targets"]
        assert targets_arg == ["aptl-webapp"]
        assert "skipping defaults not in active profile" in result.output

    def test_run_id_override_wires_archive(self, runner, mocker, tmp_path):
        # Without --run-id, the archival path is unreachable today
        # (ScenarioSession.start() doesn't populate run_id). Explicit
        # --run-id makes the archive reachable; full session wiring
        # lands with #263/RTE-001.
        from aptl.cli.main import app
        from aptl.core.continuity import KaliCarveOutEvent

        # Pre-create the run directory + manifest so --run-id passes
        # the existence validation.
        runs_dir = tmp_path / "runs"
        run_id = "explicit-run-7f3"
        run_dir = runs_dir / run_id
        run_dir.mkdir(parents=True)
        (run_dir / "manifest.json").write_text("{}")

        self._stub_cli_plumbing(mocker, tmp_path)
        mocker.patch(
            "aptl.cli.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        mock_audit = mocker.patch(
            "aptl.cli.continuity.audit_and_revert",
            return_value=_continuity_result([
                KaliCarveOutEvent(
                    timestamp="2026-05-03T12:00:00+00:00",
                    target="aptl-webapp",
                    source_ip="172.20.4.30/32",
                    rule_text="-A INPUT -s 172.20.4.30/32 -j DROP",
                    action="REVERTED",
                    error=None,
                ),
            ]),
        )

        result = runner.invoke(
            app,
            [
                "lab", "continuity-audit",
                "--project-dir", str(tmp_path),
                "--run-id", run_id,
            ],
        )

        assert result.exit_code == 0
        kwargs = mock_audit.call_args.kwargs
        assert kwargs.get("run_id") == run_id
        assert kwargs.get("run_store") is not None

    def test_run_id_traversal_rejected(self, runner, mocker, tmp_path):
        # Path-traversal in --run-id would let LocalRunStore.append_jsonl
        # write outside the run-storage base directory. Reject.
        from aptl.cli.main import app

        self._stub_cli_plumbing(mocker, tmp_path)
        mocker.patch(
            "aptl.cli.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        mock_audit = mocker.patch("aptl.cli.continuity.audit_and_revert")

        result = runner.invoke(
            app,
            [
                "lab", "continuity-audit",
                "--project-dir", str(tmp_path),
                "--run-id", "../../escape",
            ],
        )

        assert result.exit_code != 0
        mock_audit.assert_not_called()

    def test_run_id_must_exist_in_store(self, runner, mocker, tmp_path):
        # A typo in --run-id would otherwise create an orphan archive
        # directory that ``aptl runs list/show`` cannot discover. Fail
        # loudly when the referenced run has no manifest.
        from aptl.cli.main import app

        self._stub_cli_plumbing(mocker, tmp_path)
        mocker.patch(
            "aptl.cli.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        mock_audit = mocker.patch("aptl.cli.continuity.audit_and_revert")

        result = runner.invoke(
            app,
            [
                "lab", "continuity-audit",
                "--project-dir", str(tmp_path),
                "--run-id", "typo-not-a-real-run",
            ],
        )

        assert result.exit_code != 0
        assert "does not exist" in result.output
        mock_audit.assert_not_called()

    def test_corrupt_session_does_not_block_audit(self, runner, mocker, tmp_path):
        # A corrupt .aptl/session.json must degrade to "no archive",
        # not block the audit. The firewall repair is more important
        # than archive discovery.
        from aptl.cli.main import app
        from aptl.cli._common import resolve_config_for_cli  # noqa: F401
        from aptl.core.config import AptlConfig
        from aptl.core.scenarios import ScenarioStateError
        from aptl.core.session import ScenarioSession

        mocker.patch(
            "aptl.cli.continuity.resolve_config_for_cli",
            return_value=(AptlConfig(), tmp_path),
        )
        backend = mocker.MagicMock()
        backend.container_exists.return_value = True
        mocker.patch("aptl.cli.continuity.get_backend", return_value=backend)
        mocker.patch.object(
            ScenarioSession, "get_active",
            side_effect=ScenarioStateError("corrupt session"),
        )
        mocker.patch(
            "aptl.cli.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        mock_audit = mocker.patch(
            "aptl.cli.continuity.audit_and_revert",
            return_value=_continuity_result([]),
        )

        result = runner.invoke(
            app, ["lab", "continuity-audit", "--project-dir", str(tmp_path)],
        )

        # Audit ran; no archive was wired.
        assert result.exit_code == 0
        mock_audit.assert_called_once()
        kwargs = mock_audit.call_args.kwargs
        assert kwargs.get("run_id") is None
        assert kwargs.get("run_store") is None

    def test_fails_when_no_default_targets_present(
        self, runner, mocker, tmp_path,
    ):
        # If *none* of the defaults are running, there's nothing to
        # audit and the CLI must fail loudly so automation notices.
        from aptl.cli.main import app
        from aptl.core.config import AptlConfig
        from aptl.core.session import ScenarioSession

        mocker.patch(
            "aptl.cli.continuity.resolve_config_for_cli",
            return_value=(AptlConfig(), tmp_path),
        )
        backend = mocker.MagicMock()
        backend.container_exists.return_value = False
        mocker.patch("aptl.cli.continuity.get_backend", return_value=backend)
        mocker.patch.object(ScenarioSession, "get_active", return_value=None)
        mock_audit = mocker.patch("aptl.cli.continuity.audit_and_revert")

        result = runner.invoke(
            app, ["lab", "continuity-audit", "--project-dir", str(tmp_path)],
        )

        assert result.exit_code != 0
        assert "none of the default targets" in result.output
        mock_audit.assert_not_called()

    def test_exits_nonzero_on_revert_failed(self, runner, mocker, tmp_path):
        # Codex finding C5 (cycle 1): a REVERT_FAILED event must surface
        # as a non-zero exit code so automation sees the signal.
        from aptl.cli.main import app
        from aptl.core.continuity import KaliCarveOutEvent

        self._stub_cli_plumbing(mocker, tmp_path)
        mocker.patch(
            "aptl.cli.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        mocker.patch(
            "aptl.cli.continuity.audit_and_revert",
            return_value=_continuity_result([
                KaliCarveOutEvent(
                    timestamp="2026-05-03T12:00:00+00:00",
                    target="aptl-webapp",
                    source_ip="172.20.4.30/32",
                    rule_text="-A INPUT -s 172.20.4.30/32 -j DROP",
                    action="REVERT_FAILED",
                    error="iptables: bad rule",
                ),
            ]),
        )

        result = runner.invoke(
            app, ["lab", "continuity-audit", "--project-dir", str(tmp_path)],
        )

        assert result.exit_code != 0

    def test_exits_nonzero_on_audit_failed(self, runner, mocker, tmp_path):
        # AUDIT_FAILED (backend inspection failure) must also surface as
        # a non-zero exit. Silent zero-exit on inspection failure was
        # the precondition for codex finding C3.
        from aptl.cli.main import app
        from aptl.core.continuity import KaliCarveOutEvent

        self._stub_cli_plumbing(mocker, tmp_path)
        mocker.patch(
            "aptl.cli.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        mocker.patch(
            "aptl.cli.continuity.audit_and_revert",
            return_value=_continuity_result([
                KaliCarveOutEvent(
                    timestamp="2026-05-03T12:00:00+00:00",
                    target="aptl-webapp",
                    source_ip="",
                    rule_text="",
                    action="AUDIT_FAILED",
                    error="iptables -S on aptl-webapp failed: ...",
                ),
            ]),
        )

        result = runner.invoke(
            app, ["lab", "continuity-audit", "--project-dir", str(tmp_path)],
        )

        assert result.exit_code != 0
