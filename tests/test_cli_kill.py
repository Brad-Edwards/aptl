"""Tests for the kill switch CLI command.

Verifies command registration, argument handling, and output formatting.
Core kill logic is mocked.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner


@pytest.fixture
def runner():
    return CliRunner()


class TestKillCommand:
    """Tests for aptl kill."""

    def test_kill_help_exists(self, runner):
        """aptl kill --help should return 0."""
        from aptl.cli.main import app

        result = runner.invoke(app, ["kill", "--help"])
        assert result.exit_code == 0
        assert "kill" in result.stdout.lower()

    @patch("aptl.cli.kill.execute_kill")
    def test_kill_calls_execute_kill(self, mock_execute, runner):
        """aptl kill should call execute_kill with default args."""
        from aptl.core.kill import KillResult
        from aptl.cli.main import app

        mock_execute.return_value = KillResult(success=True, mcp_processes_killed=2)

        result = runner.invoke(app, ["kill"])

        assert result.exit_code == 0
        mock_execute.assert_called_once()
        call_kwargs = mock_execute.call_args
        assert call_kwargs.kwargs.get("containers") is False or not call_kwargs[1].get("containers", True)

    @patch("aptl.cli.kill.execute_kill")
    def test_kill_with_containers_flag(self, mock_execute, runner):
        """aptl kill --containers should pass containers=True."""
        from aptl.core.kill import KillResult
        from aptl.cli.main import app

        mock_execute.return_value = KillResult(
            success=True, mcp_processes_killed=1, containers_stopped=True,
        )

        result = runner.invoke(app, ["kill", "--containers"])

        assert result.exit_code == 0
        mock_execute.assert_called_once()
        assert mock_execute.call_args.kwargs["containers"] is True

    @patch("aptl.cli.kill.execute_kill")
    def test_kill_short_flag(self, mock_execute, runner):
        """aptl kill -c should work as short form for --containers."""
        from aptl.core.kill import KillResult
        from aptl.cli.main import app

        mock_execute.return_value = KillResult(
            success=True, mcp_processes_killed=0, containers_stopped=True,
        )

        result = runner.invoke(app, ["kill", "-c"])

        assert result.exit_code == 0
        assert mock_execute.call_args.kwargs["containers"] is True

    @patch("aptl.cli.kill.execute_kill")
    def test_kill_no_confirmation_prompt(self, mock_execute, runner):
        """Kill should not prompt for confirmation (emergency action)."""
        from aptl.core.kill import KillResult
        from aptl.cli.main import app

        mock_execute.return_value = KillResult(
            success=True, mcp_processes_killed=0, containers_stopped=True,
        )

        # If there were a prompt, runner.invoke without input would fail
        result = runner.invoke(app, ["kill", "--containers"])

        assert result.exit_code == 0

    @patch("aptl.cli.kill.execute_kill")
    def test_kill_displays_process_count(self, mock_execute, runner):
        """Output should report how many processes were killed."""
        from aptl.core.kill import KillResult
        from aptl.cli.main import app

        mock_execute.return_value = KillResult(
            success=True, mcp_processes_killed=3,
        )

        result = runner.invoke(app, ["kill"])

        assert "3" in result.stdout
        assert "MCP" in result.stdout

    @patch("aptl.cli.kill.execute_kill")
    def test_kill_displays_no_processes_found(self, mock_execute, runner):
        """Output should report when no MCP processes were found."""
        from aptl.core.kill import KillResult
        from aptl.cli.main import app

        mock_execute.return_value = KillResult(
            success=True, mcp_processes_killed=0,
        )

        result = runner.invoke(app, ["kill"])

        assert "No MCP server processes found" in result.stdout

    @patch("aptl.cli.kill.execute_kill")
    def test_kill_exit_0_on_success(self, mock_execute, runner):
        """Exit code 0 when kill succeeds."""
        from aptl.core.kill import KillResult
        from aptl.cli.main import app

        mock_execute.return_value = KillResult(success=True)

        result = runner.invoke(app, ["kill"])

        assert result.exit_code == 0

    @patch("aptl.cli.kill.execute_kill")
    def test_kill_exit_1_on_total_failure(self, mock_execute, runner):
        """Exit code 1 when all kill steps fail."""
        from aptl.core.kill import KillResult
        from aptl.cli.main import app

        mock_execute.return_value = KillResult(
            success=False,
            errors=["everything failed"],
        )

        result = runner.invoke(app, ["kill"])

        assert result.exit_code == 1

    @patch("aptl.cli.kill.execute_kill")
    def test_kill_shows_warnings(self, mock_execute, runner):
        """Errors should be displayed as warnings."""
        from aptl.core.kill import KillResult
        from aptl.cli.main import app

        mock_execute.return_value = KillResult(
            success=True,
            mcp_processes_killed=1,
            errors=["Permission denied killing mcp-red (pid=200)"],
        )

        result = runner.invoke(app, ["kill"])

        assert result.exit_code == 0
        assert "Permission denied" in result.stdout

    @patch("aptl.cli.kill.execute_kill")
    def test_kill_shows_session_cleared(self, mock_execute, runner):
        """Output should report when a session was cleared."""
        from aptl.core.kill import KillResult
        from aptl.cli.main import app

        mock_execute.return_value = KillResult(
            success=True,
            mcp_processes_killed=0,
            session_cleared=True,
        )

        result = runner.invoke(app, ["kill"])

        assert "session cleared" in result.stdout.lower()
