"""Tests for the CLI command structure.

Smoke tests that verify CLI commands exist and produce expected output.
Integration tests verify CLI commands call the correct core functions.
We test our CLI wiring, not typer internals.
"""

from pathlib import Path
from unittest.mock import MagicMock

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

        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.stdout

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

    def test_lab_continuity_audit_exists(self, runner):
        """aptl lab continuity-audit should be a valid command."""
        from aptl.cli.main import app

        result = runner.invoke(app, ["lab", "continuity-audit", "--help"])
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

    def test_start_handles_failure_gracefully(self, runner, mocker):
        """start command should exit 1 and show error on failure."""
        from aptl.cli.main import app
        from aptl.core.lab import LabResult

        mocker.patch(
            "aptl.cli.lab.orchestrate_lab_start",
            return_value=LabResult(
                success=False, error="vm.max_map_count too low"
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
        mock_orchestrate.assert_called_once_with(tmp_path, skip_seed=False)


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
            "aptl.cli._common.resolve_config_for_cli",
            return_value=(AptlConfig(), project_dir),
        )
        mocker.patch(
            "aptl.core.deployment.get_backend",
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
            "aptl.core.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        mock_audit = mocker.patch(
            "aptl.core.continuity.audit_and_revert", return_value=[],
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
            "aptl.core.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        mocker.patch("aptl.core.continuity.audit_and_revert", return_value=[])

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
            "aptl.core.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        event = KaliCarveOutEvent(
            timestamp="2026-05-03T12:00:00+00:00",
            target="aptl-victim",
            source_ip="172.20.4.30/32",
            rule_text="-A INPUT -s 172.20.4.30/32 -j DROP",
            action="REVERTED",
            error=None,
        )
        mocker.patch("aptl.core.continuity.audit_and_revert", return_value=[event])

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
            "aptl.core.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        event = KaliCarveOutEvent(
            timestamp="2026-05-03T12:00:00+00:00",
            target="aptl-victim",
            source_ip="172.20.4.30/32",
            rule_text="-A INPUT -s 172.20.4.30/32 -j DROP",
            action="REVERTED",
            error=None,
        )
        mocker.patch("aptl.core.continuity.audit_and_revert", return_value=[event])

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
            "aptl.core.continuity.kali_source_ips", return_value=["172.20.4.30"],
        )
        mock_audit = mocker.patch(
            "aptl.core.continuity.audit_and_revert", return_value=[],
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

    def test_warns_when_whitelist_empty(self, runner, mocker, tmp_path):
        from aptl.cli.main import app

        self._stub_cli_plumbing(mocker, tmp_path)
        mocker.patch("aptl.core.continuity.kali_source_ips", return_value=[])
        mocker.patch("aptl.core.continuity.audit_and_revert", return_value=[])

        result = runner.invoke(
            app, ["lab", "continuity-audit", "--project-dir", str(tmp_path)],
        )

        assert result.exit_code == 0
        # Stderr is captured via result.stderr in CliRunner when
        # mix_stderr=False; the runner mixes by default so the warning
        # ends up in result.output.
        assert "no kali IPs found" in result.output
