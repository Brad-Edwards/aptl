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
        mock_orchestrate.assert_called_once_with(tmp_path)


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

        result = runner.invoke(app, ["lab", "stop", "--volumes"])

        assert result.exit_code == 0
        mock_stop.assert_called_once_with(remove_volumes=True, project_dir=Path("."))


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
