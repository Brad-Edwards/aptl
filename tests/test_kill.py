"""Tests for the emergency kill switch core logic.

All process discovery, signal sending, and Docker Compose interactions
are mocked. No real processes are killed or containers stopped.
"""

import json
import os
import signal
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest


class TestFindMcpProcesses:
    """Tests for MCP server process discovery."""

    @patch("aptl.core.kill.sys")
    @patch("aptl.core.kill.os.listdir")
    @patch("builtins.open", create=True)
    def test_finds_running_mcp_processes(self, mock_open, mock_listdir, mock_sys):
        from aptl.core.kill import find_mcp_processes

        mock_sys.platform = "linux"
        mock_listdir.return_value = ["1", "100", "200", "self", "cpuinfo"]

        # PID 100 is an MCP server, PID 200 is not, PID 1 is init
        def open_side_effect(path, mode="r"):
            m = MagicMock()
            if path == "/proc/100/cmdline":
                m.__enter__ = lambda s: s
                m.__exit__ = MagicMock(return_value=False)
                m.read.return_value = b"node\x00/home/user/aptl/mcp/mcp-wazuh/build/index.js\x00"
            elif path == "/proc/200/cmdline":
                m.__enter__ = lambda s: s
                m.__exit__ = MagicMock(return_value=False)
                m.read.return_value = b"node\x00/home/user/other-app/server.js\x00"
            elif path == "/proc/1/cmdline":
                m.__enter__ = lambda s: s
                m.__exit__ = MagicMock(return_value=False)
                m.read.return_value = b"/sbin/init\x00"
            else:
                raise FileNotFoundError(path)
            return m

        mock_open.side_effect = open_side_effect

        result = find_mcp_processes()

        assert len(result) == 1
        assert result[0]["pid"] == 100
        assert result[0]["name"] == "mcp-wazuh"
        assert "mcp-wazuh/build/index.js" in result[0]["cmdline"]

    @patch("aptl.core.kill.sys")
    @patch("aptl.core.kill.os.listdir")
    def test_returns_empty_when_no_mcp_processes(self, mock_listdir, mock_sys):
        from aptl.core.kill import find_mcp_processes

        mock_sys.platform = "linux"
        mock_listdir.return_value = ["1"]

        with patch("builtins.open", create=True) as mock_open:
            m = MagicMock()
            m.__enter__ = lambda s: s
            m.__exit__ = MagicMock(return_value=False)
            m.read.return_value = b"/sbin/init\x00"
            mock_open.return_value = m

            result = find_mcp_processes()

        assert result == []

    @patch("aptl.core.kill.sys")
    @patch("aptl.core.kill.os.listdir")
    @patch("builtins.open", create=True)
    def test_finds_multiple_mcp_servers(self, mock_open, mock_listdir, mock_sys):
        from aptl.core.kill import find_mcp_processes

        mock_sys.platform = "linux"
        mock_listdir.return_value = ["100", "200"]

        def open_side_effect(path, mode="r"):
            m = MagicMock()
            m.__enter__ = lambda s: s
            m.__exit__ = MagicMock(return_value=False)
            if path == "/proc/100/cmdline":
                m.read.return_value = b"node\x00mcp/mcp-wazuh/build/index.js\x00"
            elif path == "/proc/200/cmdline":
                m.read.return_value = b"node\x00mcp/mcp-red/build/index.js\x00"
            else:
                raise FileNotFoundError(path)
            return m

        mock_open.side_effect = open_side_effect

        result = find_mcp_processes()

        assert len(result) == 2
        names = {p["name"] for p in result}
        assert names == {"mcp-wazuh", "mcp-red"}

    @patch("aptl.core.kill.sys")
    @patch("aptl.core.kill.os.listdir")
    @patch("builtins.open", create=True)
    def test_handles_permission_errors(self, mock_open, mock_listdir, mock_sys):
        from aptl.core.kill import find_mcp_processes

        mock_sys.platform = "linux"
        mock_listdir.return_value = ["100"]

        mock_open.side_effect = PermissionError("Permission denied")

        result = find_mcp_processes()

        assert result == []

    @patch("aptl.core.kill.sys")
    @patch("aptl.core.kill.os.listdir")
    @patch("builtins.open", create=True)
    def test_handles_vanishing_processes(self, mock_open, mock_listdir, mock_sys):
        from aptl.core.kill import find_mcp_processes

        mock_sys.platform = "linux"
        mock_listdir.return_value = ["100"]

        mock_open.side_effect = FileNotFoundError("No such file")

        result = find_mcp_processes()

        assert result == []

    @patch("aptl.core.kill.sys")
    @patch("aptl.core.kill.os.getpid", return_value=999)
    @patch("aptl.core.kill.os.listdir")
    @patch("builtins.open", create=True)
    def test_skips_own_process(self, mock_open, mock_listdir, mock_getpid, mock_sys):
        from aptl.core.kill import find_mcp_processes

        mock_sys.platform = "linux"
        # PID 999 is our own process, PID 100 is a real MCP server
        mock_listdir.return_value = ["999", "100"]

        def open_side_effect(path, mode="r"):
            m = MagicMock()
            m.__enter__ = lambda s: s
            m.__exit__ = MagicMock(return_value=False)
            if path == "/proc/100/cmdline":
                m.read.return_value = b"node\x00mcp/mcp-wazuh/build/index.js\x00"
            elif path == "/proc/999/cmdline":
                # Own process cmdline might match if running aptl kill
                m.read.return_value = b"python\x00aptl\x00kill\x00mcp-wazuh/build/index.js\x00"
            else:
                raise FileNotFoundError(path)
            return m

        mock_open.side_effect = open_side_effect

        result = find_mcp_processes()

        assert len(result) == 1
        assert result[0]["pid"] == 100

    @patch("aptl.core.kill.sys")
    @patch("aptl.core.kill.subprocess.run")
    def test_pgrep_fallback_on_non_linux(self, mock_run, mock_sys):
        from aptl.core.kill import find_mcp_processes

        mock_sys.platform = "darwin"

        def run_side_effect(cmd, **kwargs):
            m = MagicMock()
            if "mcp-wazuh" in cmd[2]:
                m.returncode = 0
                m.stdout = "12345\n"
            else:
                m.returncode = 1
                m.stdout = ""
            return m

        mock_run.side_effect = run_side_effect

        result = find_mcp_processes()

        assert len(result) == 1
        assert result[0]["pid"] == 12345
        assert result[0]["name"] == "mcp-wazuh"


class TestKillMcpProcesses:
    """Tests for SIGTERM/SIGKILL process termination."""

    @patch("aptl.core.kill.find_mcp_processes")
    @patch("aptl.core.kill.os.kill")
    @patch("aptl.core.kill._process_exited")
    def test_kills_all_found_processes(self, mock_alive, mock_kill, mock_find):
        from aptl.core.kill import kill_mcp_processes

        mock_find.return_value = [
            {"pid": 100, "cmdline": "node mcp-wazuh/build/index.js", "name": "mcp-wazuh"},
        ]
        # Process exits after SIGTERM
        mock_alive.return_value = True

        killed, errors = kill_mcp_processes(timeout=1.0)

        mock_kill.assert_called_once_with(100, signal.SIGTERM)
        assert killed == 1
        assert errors == []

    @patch("aptl.core.kill.find_mcp_processes")
    @patch("aptl.core.kill.os.kill")
    @patch("aptl.core.kill._process_exited")
    @patch("aptl.core.kill.time.sleep")
    @patch("aptl.core.kill.time.monotonic")
    def test_sigkill_fallback_after_timeout(
        self, mock_monotonic, mock_sleep, mock_alive, mock_kill, mock_find
    ):
        from aptl.core.kill import kill_mcp_processes

        mock_find.return_value = [
            {"pid": 100, "cmdline": "node mcp-wazuh/build/index.js", "name": "mcp-wazuh"},
        ]
        # Process stays alive throughout timeout (_process_exited returns False)
        mock_alive.return_value = False
        # Simulate time progression past deadline
        mock_monotonic.side_effect = [0.0, 0.0, 6.0]

        killed, errors = kill_mcp_processes(timeout=5.0)

        # SIGTERM first, then SIGKILL
        calls = mock_kill.call_args_list
        assert call(100, signal.SIGTERM) in calls
        assert call(100, signal.SIGKILL) in calls
        assert killed == 1

    @patch("aptl.core.kill.find_mcp_processes")
    @patch("aptl.core.kill.os.kill")
    def test_handles_already_dead_process(self, mock_kill, mock_find):
        from aptl.core.kill import kill_mcp_processes

        mock_find.return_value = [
            {"pid": 100, "cmdline": "node mcp-wazuh/build/index.js", "name": "mcp-wazuh"},
        ]
        mock_kill.side_effect = ProcessLookupError("No such process")

        killed, errors = kill_mcp_processes(timeout=1.0)

        assert killed == 1
        assert errors == []

    @patch("aptl.core.kill.find_mcp_processes")
    @patch("aptl.core.kill.os.kill")
    def test_handles_permission_error(self, mock_kill, mock_find):
        from aptl.core.kill import kill_mcp_processes

        mock_find.return_value = [
            {"pid": 100, "cmdline": "node mcp-wazuh/build/index.js", "name": "mcp-wazuh"},
        ]
        mock_kill.side_effect = PermissionError("Operation not permitted")

        killed, errors = kill_mcp_processes(timeout=1.0)

        assert killed == 0
        assert len(errors) == 1
        assert "Permission denied" in errors[0]

    @patch("aptl.core.kill.find_mcp_processes")
    def test_returns_zero_when_no_processes(self, mock_find):
        from aptl.core.kill import kill_mcp_processes

        mock_find.return_value = []

        killed, errors = kill_mcp_processes()

        assert killed == 0
        assert errors == []


class TestKillLabContainers:
    """Tests for emergency container stop."""

    @patch("aptl.core.kill.subprocess.run")
    def test_runs_docker_compose_kill_and_down(self, mock_run):
        from aptl.core.kill import kill_lab_containers

        mock_run.return_value = MagicMock(returncode=0, stderr="")

        success, error = kill_lab_containers(project_dir=Path("/tmp/aptl"))

        assert success is True
        assert error == ""
        assert mock_run.call_count == 2

        # First call: docker compose kill
        first_cmd = mock_run.call_args_list[0][0][0]
        assert "kill" in first_cmd
        assert "--profile" in first_cmd

        # Second call: docker compose down
        second_cmd = mock_run.call_args_list[1][0][0]
        assert "down" in second_cmd

    @patch("aptl.core.kill.subprocess.run")
    def test_includes_all_profiles(self, mock_run):
        from aptl.core.kill import kill_lab_containers
        from aptl.core.lab import ALL_KNOWN_PROFILES

        mock_run.return_value = MagicMock(returncode=0, stderr="")

        kill_lab_containers()

        first_cmd = mock_run.call_args_list[0][0][0]
        for profile in ALL_KNOWN_PROFILES:
            assert profile in first_cmd

    @patch("aptl.core.kill.subprocess.run")
    def test_handles_docker_failure(self, mock_run):
        from aptl.core.kill import kill_lab_containers

        mock_run.side_effect = FileNotFoundError("docker not found")

        success, error = kill_lab_containers()

        assert success is False
        assert "docker compose kill failed" in error

    @patch("aptl.core.kill.subprocess.run")
    def test_uses_project_dir_as_cwd(self, mock_run):
        from aptl.core.kill import kill_lab_containers

        mock_run.return_value = MagicMock(returncode=0, stderr="")
        project = Path("/my/project")

        kill_lab_containers(project_dir=project)

        for c in mock_run.call_args_list:
            assert c[1]["cwd"] == project

    @patch("aptl.core.kill.subprocess.run")
    def test_subprocess_calls_have_timeout(self, mock_run):
        from aptl.core.kill import _DOCKER_TIMEOUT, kill_lab_containers

        mock_run.return_value = MagicMock(returncode=0, stderr="")

        kill_lab_containers()

        for c in mock_run.call_args_list:
            assert c[1]["timeout"] == _DOCKER_TIMEOUT

    @patch("aptl.core.kill.subprocess.run")
    def test_handles_timeout_expired(self, mock_run):
        from aptl.core.kill import kill_lab_containers

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=30)

        success, error = kill_lab_containers()

        assert success is False

    @patch("aptl.core.kill.subprocess.run")
    def test_down_failure_is_non_fatal_when_kill_succeeded(self, mock_run):
        from aptl.core.kill import kill_lab_containers

        def run_side_effect(cmd, **kwargs):
            m = MagicMock()
            if "kill" in cmd:
                m.returncode = 0
                m.stderr = ""
            else:
                # docker compose down fails
                m.returncode = 1
                m.stderr = "network not found"
            return m

        mock_run.side_effect = run_side_effect

        success, error = kill_lab_containers()

        # kill succeeded, down failure is just a warning
        assert success is True
        assert error == ""


class TestClearSession:
    """Tests for scenario session cleanup."""

    def test_clears_active_session(self, tmp_path):
        from aptl.core.kill import clear_session

        state_dir = tmp_path / ".aptl"
        state_dir.mkdir()
        session_file = state_dir / "session.json"
        session_file.write_text(json.dumps({
            "scenario_id": "test-scenario",
            "state": "active",
            "started_at": "2026-03-22T00:00:00+00:00",
        }))

        result = clear_session(state_dir)

        assert result is True
        assert not session_file.exists()

    def test_safe_when_no_session(self, tmp_path):
        from aptl.core.kill import clear_session

        state_dir = tmp_path / ".aptl"
        state_dir.mkdir()

        result = clear_session(state_dir)

        assert result is False

    def test_safe_when_state_dir_missing(self, tmp_path):
        from aptl.core.kill import clear_session

        state_dir = tmp_path / ".aptl"
        # Don't create it

        result = clear_session(state_dir)

        assert result is False


class TestCleanTraceContext:
    """Tests for trace context file cleanup."""

    def test_removes_trace_context_file(self, tmp_path):
        from aptl.core.kill import clean_trace_context

        state_dir = tmp_path / ".aptl"
        state_dir.mkdir()
        trace_file = state_dir / "trace-context.json"
        trace_file.write_text('{"trace_id": "abc", "span_id": "def"}')

        result = clean_trace_context(state_dir)

        assert result is True
        assert not trace_file.exists()

    def test_safe_when_no_file(self, tmp_path):
        from aptl.core.kill import clean_trace_context

        state_dir = tmp_path / ".aptl"
        state_dir.mkdir()

        result = clean_trace_context(state_dir)

        assert result is False


class TestExecuteKill:
    """Integration tests for the kill switch orchestrator."""

    @patch("aptl.core.kill.kill_mcp_processes")
    @patch("aptl.core.kill.kill_lab_containers")
    @patch("aptl.core.kill.clear_session")
    @patch("aptl.core.kill.clean_trace_context")
    def test_kills_mcp_only_by_default(
        self, mock_trace, mock_session, mock_containers, mock_mcp
    ):
        from aptl.core.kill import execute_kill

        mock_mcp.return_value = (3, [])
        mock_session.return_value = False
        mock_trace.return_value = False

        result = execute_kill(containers=False)

        assert result.success is True
        assert result.mcp_processes_killed == 3
        assert result.containers_stopped is False
        mock_containers.assert_not_called()

    @patch("aptl.core.kill.kill_mcp_processes")
    @patch("aptl.core.kill.kill_lab_containers")
    @patch("aptl.core.kill.clear_session")
    @patch("aptl.core.kill.clean_trace_context")
    def test_kills_mcp_and_containers(
        self, mock_trace, mock_session, mock_containers, mock_mcp
    ):
        from aptl.core.kill import execute_kill

        mock_mcp.return_value = (2, [])
        mock_containers.return_value = (True, "")
        mock_session.return_value = True
        mock_trace.return_value = True

        result = execute_kill(containers=True)

        assert result.success is True
        assert result.mcp_processes_killed == 2
        assert result.containers_stopped is True
        assert result.session_cleared is True
        assert result.trace_context_cleaned is True
        mock_containers.assert_called_once()

    @patch("aptl.core.kill.kill_mcp_processes")
    @patch("aptl.core.kill.kill_lab_containers")
    @patch("aptl.core.kill.clear_session")
    @patch("aptl.core.kill.clean_trace_context")
    def test_continues_on_partial_failure(
        self, mock_trace, mock_session, mock_containers, mock_mcp
    ):
        from aptl.core.kill import execute_kill

        mock_mcp.side_effect = RuntimeError("proc failed")
        mock_containers.return_value = (True, "")
        mock_session.return_value = True
        mock_trace.return_value = True

        result = execute_kill(containers=True)

        # MCP failed but containers + session + trace succeeded
        assert result.success is True
        assert result.mcp_processes_killed == 0
        assert result.containers_stopped is True
        assert len(result.errors) == 1
        assert "MCP process kill failed" in result.errors[0]

    @patch("aptl.core.kill.kill_mcp_processes")
    @patch("aptl.core.kill.clear_session")
    @patch("aptl.core.kill.clean_trace_context")
    def test_reports_all_errors(self, mock_trace, mock_session, mock_mcp):
        from aptl.core.kill import execute_kill

        mock_mcp.return_value = (0, ["perm denied pid=100"])
        mock_session.side_effect = RuntimeError("session broken")
        mock_trace.return_value = False

        result = execute_kill(containers=False)

        assert result.success is False
        assert len(result.errors) == 2

    @patch("aptl.core.kill.kill_mcp_processes")
    @patch("aptl.core.kill.clear_session")
    @patch("aptl.core.kill.clean_trace_context")
    def test_success_when_nothing_to_kill(self, mock_trace, mock_session, mock_mcp):
        from aptl.core.kill import execute_kill

        mock_mcp.return_value = (0, [])
        mock_session.return_value = False
        mock_trace.return_value = False

        result = execute_kill(containers=False)

        # No actions taken but no errors either = success
        assert result.success is True
        assert result.mcp_processes_killed == 0

    @patch("aptl.core.kill.kill_mcp_processes")
    @patch("aptl.core.kill.clear_session")
    @patch("aptl.core.kill.clean_trace_context")
    def test_cleans_session_and_trace_context(self, mock_trace, mock_session, mock_mcp):
        from aptl.core.kill import execute_kill

        mock_mcp.return_value = (0, [])
        mock_session.return_value = True
        mock_trace.return_value = True

        result = execute_kill(containers=False)

        assert result.session_cleared is True
        assert result.trace_context_cleaned is True
        mock_session.assert_called_once()
        mock_trace.assert_called_once()
