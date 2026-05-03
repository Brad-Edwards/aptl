"""Tests for the deployment backend abstraction layer.

Tests cover the DeploymentBackend Protocol, DockerComposeBackend,
SSHComposeBackend, config model, and factory function.
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aptl.core.config import AptlConfig, DeploymentConfig
from aptl.core.deployment import (
    DockerComposeBackend,
    SSHComposeBackend,
    get_backend,
)
from aptl.core.lab import LabResult, LabStatus


# ---------------------------------------------------------------------------
# DeploymentConfig model tests
# ---------------------------------------------------------------------------


class TestDeploymentConfig:
    """Tests for the DeploymentConfig Pydantic model."""

    def test_default_provider_is_docker_compose(self):
        cfg = DeploymentConfig()
        assert cfg.provider == "docker-compose"
        assert cfg.project_name == "aptl"

    def test_accepts_docker_compose(self):
        cfg = DeploymentConfig(provider="docker-compose")
        assert cfg.provider == "docker-compose"

    def test_accepts_ssh_compose(self):
        cfg = DeploymentConfig(provider="ssh-compose")
        assert cfg.provider == "ssh-compose"

    def test_rejects_unknown_provider(self):
        with pytest.raises(ValueError, match="Unknown deployment provider"):
            DeploymentConfig(provider="kubernetes")

    def test_ssh_fields_default_to_none(self):
        cfg = DeploymentConfig()
        assert cfg.ssh_host is None
        assert cfg.ssh_user is None
        assert cfg.ssh_key is None
        assert cfg.ssh_port == 22
        assert cfg.remote_dir is None

    def test_ssh_fields_populated(self):
        cfg = DeploymentConfig(
            provider="ssh-compose",
            ssh_host="lab.example.com",
            ssh_user="admin",
            ssh_key="~/.ssh/lab_key",
            ssh_port=2222,
            remote_dir="/opt/aptl",
        )
        assert cfg.ssh_host == "lab.example.com"
        assert cfg.ssh_user == "admin"
        assert cfg.ssh_key == "~/.ssh/lab_key"
        assert cfg.ssh_port == 2222
        assert cfg.remote_dir == "/opt/aptl"


class TestAptlConfigDeployment:
    """Tests for DeploymentConfig in AptlConfig."""

    def test_default_config_has_deployment(self):
        cfg = AptlConfig(lab={"name": "test"})
        assert cfg.deployment.provider == "docker-compose"

    def test_config_with_explicit_deployment(self):
        cfg = AptlConfig(
            lab={"name": "test"},
            deployment={"provider": "ssh-compose", "ssh_host": "server"},
        )
        assert cfg.deployment.provider == "ssh-compose"
        assert cfg.deployment.ssh_host == "server"

    def test_config_without_deployment_key(self):
        """Config JSON without deployment key uses defaults."""
        cfg = AptlConfig(
            lab={"name": "test"},
            containers={"wazuh": True, "kali": False},
        )
        assert cfg.deployment.provider == "docker-compose"

    def test_load_config_with_deployment(self, tmp_path):
        from aptl.core.config import load_config

        config_file = tmp_path / "aptl.json"
        config_file.write_text(json.dumps({
            "lab": {"name": "test"},
            "deployment": {"provider": "docker-compose", "project_name": "mylab"},
        }))

        cfg = load_config(config_file)
        assert cfg.deployment.project_name == "mylab"


# ---------------------------------------------------------------------------
# DockerComposeBackend tests
# ---------------------------------------------------------------------------


class TestDockerComposeBackend:
    """Tests for the Docker Compose deployment backend."""

    def _make_backend(self, tmp_path: Path) -> DockerComposeBackend:
        return DockerComposeBackend(project_dir=tmp_path, project_name="test")

    def test_start_calls_compose_up(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = backend.start(["wazuh", "kali"])

        assert result.success is True
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "docker"
        assert cmd[1] == "compose"
        assert "--profile" in cmd
        assert "wazuh" in cmd
        assert "kali" in cmd
        assert "up" in cmd
        assert "--build" in cmd
        assert "-d" in cmd
        assert mock_run.call_args[1]["cwd"] == tmp_path

    def test_start_without_build(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = backend.start(["wazuh"], build=False)

        assert result.success is True
        cmd = mock_run.call_args[0][0]
        assert "--build" not in cmd

    def test_start_returns_failure_on_error(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="compose up failed"
            )
            result = backend.start(["wazuh"])

        assert result.success is False
        assert "compose up failed" in result.error

    def test_stop_calls_compose_down(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = backend.stop(["wazuh"])

        assert result.success is True
        cmd = mock_run.call_args[0][0]
        assert "down" in cmd
        assert "-v" not in cmd

    def test_stop_with_volumes(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = backend.stop(["wazuh"], remove_volumes=True)

        assert result.success is True
        cmd = mock_run.call_args[0][0]
        assert "-v" in cmd

    def test_stop_returns_failure(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="network error"
            )
            result = backend.stop([])

        assert result.success is False

    def test_status_parses_json_array(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[{"Name":"aptl-victim","State":"running"}]',
                stderr="",
            )
            status = backend.status()

        assert status.running is True
        assert len(status.containers) == 1

    def test_status_parses_ndjson(self, tmp_path):
        backend = self._make_backend(tmp_path)
        ndjson = (
            '{"Name":"aptl-victim","State":"running"}\n'
            '{"Name":"aptl-kali","State":"running"}'
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=ndjson, stderr=""
            )
            status = backend.status()

        assert status.running is True
        assert len(status.containers) == 2

    def test_status_handles_empty_output(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr=""
            )
            status = backend.status()

        assert status.running is False
        assert status.containers == []

    def test_status_handles_compose_failure(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="docker not found"
            )
            status = backend.status()

        assert status.running is False
        assert "docker not found" in status.error

    def test_status_handles_invalid_json(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="not json", stderr=""
            )
            status = backend.status()

        assert status.running is False
        assert "parse" in status.error.lower()

    def test_kill_runs_compose_kill_then_down(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            success, error = backend.kill(["wazuh", "kali"])

        assert success is True
        assert error == ""
        assert mock_run.call_count == 2

        first_cmd = mock_run.call_args_list[0][0][0]
        assert "kill" in first_cmd
        second_cmd = mock_run.call_args_list[1][0][0]
        assert "down" in second_cmd

    def test_kill_handles_timeout(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(
                cmd="docker", timeout=30
            )
            success, error = backend.kill(["wazuh"])

        assert success is False

    def test_kill_handles_file_not_found(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("docker not found")
            success, error = backend.kill(["wazuh"])

        assert success is False
        assert "docker compose kill failed" in error

    def test_pull_images_success(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            warnings = backend.pull_images(["wazuh/wazuh-manager:4.12.0"])

        assert warnings == []
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "pull", "wazuh/wazuh-manager:4.12.0"]

    def test_pull_images_returns_warnings(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="not found"
            )
            warnings = backend.pull_images(["bad:image"])

        assert len(warnings) == 1
        assert "bad:image" in warnings[0]

    def test_pull_images_handles_oserror(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = OSError("docker binary not found")
            warnings = backend.pull_images(["some:image"])

        assert len(warnings) == 1

    def test_project_dir_property(self, tmp_path):
        backend = self._make_backend(tmp_path)
        assert backend.project_dir == tmp_path

    def test_project_name_property(self, tmp_path):
        backend = DockerComposeBackend(
            project_dir=tmp_path, project_name="mylab"
        )
        assert backend.project_name == "mylab"


# ---------------------------------------------------------------------------
# DockerComposeBackend container interaction tests (CLI-004)
# ---------------------------------------------------------------------------


class TestDockerComposeBackendContainerInteraction:
    """Tests for the 6 container-interaction methods added under CLI-004."""

    def _make_backend(self, tmp_path: Path) -> DockerComposeBackend:
        return DockerComposeBackend(project_dir=tmp_path, project_name="test")

    # container_list -------------------------------------------------------

    def test_container_list_uses_compose_ps_with_all_flag(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.container_list()
        cmd = mock_run.call_args[0][0]
        assert cmd[:3] == ["docker", "compose", "ps"]
        assert "-a" in cmd
        assert "--format" in cmd
        assert "json" in cmd
        assert mock_run.call_args[1]["cwd"] == tmp_path

    def test_container_list_omits_all_when_requested(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.container_list(all_containers=False)
        cmd = mock_run.call_args[0][0]
        assert "-a" not in cmd

    def test_container_list_parses_ndjson(self, tmp_path):
        backend = self._make_backend(tmp_path)
        ndjson = (
            '{"Name":"aptl-victim","State":"running"}\n'
            '{"Name":"aptl-kali","State":"exited"}'
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=ndjson, stderr="")
            containers = backend.container_list()
        assert len(containers) == 2
        assert containers[0]["Name"] == "aptl-victim"
        assert containers[1]["State"] == "exited"

    def test_container_list_parses_json_array(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[{"Name":"aptl-victim","State":"running"}]',
                stderr="",
            )
            containers = backend.container_list()
        assert len(containers) == 1

    def test_container_list_empty_when_no_output(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            containers = backend.container_list()
        assert containers == []

    def test_container_list_empty_on_compose_failure(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="not running"
            )
            containers = backend.container_list()
        assert containers == []

    def test_container_list_empty_on_invalid_json(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="not-json", stderr=""
            )
            containers = backend.container_list()
        assert containers == []

    # container_logs (streaming) -------------------------------------------

    def test_container_logs_streams_without_capture(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            exit_code = backend.container_logs("aptl-victim")
        assert exit_code == 0
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "logs", "aptl-victim"]
        # Streaming: no capture_output kwarg
        assert "capture_output" not in mock_run.call_args[1]

    def test_container_logs_with_follow_and_tail(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            backend.container_logs("aptl-victim", follow=True, tail=100)
        cmd = mock_run.call_args[0][0]
        assert "-f" in cmd
        assert "--tail" in cmd
        tail_idx = cmd.index("--tail")
        assert cmd[tail_idx + 1] == "100"
        assert "aptl-victim" in cmd

    def test_container_logs_propagates_exit_code(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=2)
            exit_code = backend.container_logs("aptl-missing")
        assert exit_code == 2

    # container_logs_capture -----------------------------------------------

    def test_container_logs_capture_runs_docker_logs(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="line1\nline2\n", stderr="")
            result = backend.container_logs_capture("aptl-victim")
        cmd = mock_run.call_args[0][0]
        assert cmd[:3] == ["docker", "logs", "aptl-victim"]
        assert mock_run.call_args[1].get("capture_output") is True
        assert "line1" in result.stdout

    def test_container_logs_capture_passes_since_and_until(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.container_logs_capture(
                "aptl-suricata",
                since="2026-05-03T00:00:00Z",
                until="2026-05-03T01:00:00Z",
            )
        cmd = mock_run.call_args[0][0]
        assert "--since" in cmd
        since_idx = cmd.index("--since")
        assert cmd[since_idx + 1] == "2026-05-03T00:00:00Z"
        assert "--until" in cmd
        until_idx = cmd.index("--until")
        assert cmd[until_idx + 1] == "2026-05-03T01:00:00Z"

    # container_shell ------------------------------------------------------

    def test_container_shell_uses_docker_exec_it(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            exit_code = backend.container_shell("aptl-kali", shell="/bin/bash")
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "exec", "-it", "aptl-kali", "/bin/bash"]
        assert exit_code == 0
        # Streaming: no capture_output
        assert "capture_output" not in mock_run.call_args[1]

    def test_container_shell_default_shell_is_bash_with_sh_fallback(self, tmp_path):
        """When shell is None, try /bin/bash, fall back to /bin/sh on 126/127."""
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            # First call: bash returns 127 (not found)
            # Second call: sh returns 0
            mock_run.side_effect = [
                MagicMock(returncode=127),
                MagicMock(returncode=0),
            ]
            exit_code = backend.container_shell("aptl-alpine")
        assert exit_code == 0
        assert mock_run.call_count == 2
        first_cmd = mock_run.call_args_list[0][0][0]
        assert first_cmd[-1] == "/bin/bash"
        second_cmd = mock_run.call_args_list[1][0][0]
        assert second_cmd[-1] == "/bin/sh"

    def test_container_shell_no_fallback_when_shell_explicit(self, tmp_path):
        """Explicit --shell skips the fallback."""
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=127)
            exit_code = backend.container_shell("aptl-alpine", shell="/bin/zsh")
        assert exit_code == 127
        assert mock_run.call_count == 1

    def test_container_shell_no_fallback_on_non_127_exit(self, tmp_path):
        """Fallback only triggers on 126/127 (command-not-executable / not-found)."""
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            exit_code = backend.container_shell("aptl-victim")
        assert exit_code == 1
        assert mock_run.call_count == 1

    # container_exec -------------------------------------------------------

    def test_container_exec_runs_docker_exec_captured(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="hello", stderr="")
            result = backend.container_exec(
                "aptl-victim", ["echo", "hello"]
            )
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "exec", "aptl-victim", "echo", "hello"]
        assert "-it" not in cmd
        assert mock_run.call_args[1].get("capture_output") is True
        assert result.stdout == "hello"

    def test_container_exec_passes_timeout(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.container_exec("aptl-victim", ["true"], timeout=5)
        assert mock_run.call_args[1]["timeout"] == 5

    # container_inspect ----------------------------------------------------

    def test_container_inspect_parses_first_element(self, tmp_path):
        backend = self._make_backend(tmp_path)
        payload = json.dumps([
            {"Id": "abc", "NetworkSettings": {"Networks": {"net": {"IPAddress": "1.2.3.4"}}}},
        ])
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=payload, stderr="")
            data = backend.container_inspect("aptl-victim")
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "inspect", "aptl-victim"]
        assert data["Id"] == "abc"

    def test_container_inspect_returns_empty_dict_on_failure(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="No such object"
            )
            data = backend.container_inspect("aptl-missing")
        assert data == {}

    def test_container_inspect_returns_empty_dict_on_invalid_json(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="not-json", stderr="")
            data = backend.container_inspect("aptl-victim")
        assert data == {}

    def test_container_inspect_returns_empty_dict_on_empty_array(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="[]", stderr="")
            data = backend.container_inspect("aptl-victim")
        assert data == {}


# ---------------------------------------------------------------------------
# SSHComposeBackend tests
# ---------------------------------------------------------------------------


class TestSSHComposeBackend:
    """Tests for the SSH Remote Docker Compose backend."""

    def _make_backend(
        self,
        tmp_path: Path,
        host: str = "lab.example.com",
        user: str = "admin",
        **kwargs,
    ) -> SSHComposeBackend:
        return SSHComposeBackend(
            project_dir=tmp_path,
            host=host,
            user=user,
            **kwargs,
        )

    def test_docker_host_format(self, tmp_path):
        backend = self._make_backend(tmp_path)
        assert backend.docker_host == "ssh://admin@lab.example.com"

    def test_docker_host_with_custom_port(self, tmp_path):
        backend = self._make_backend(tmp_path, ssh_port=2222)
        assert backend.docker_host == "ssh://admin@lab.example.com:2222"

    def test_host_and_user_properties(self, tmp_path):
        backend = self._make_backend(tmp_path)
        assert backend.host == "lab.example.com"
        assert backend.user == "admin"

    def test_run_sets_docker_host_env(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.start(["wazuh"])

        call_kwargs = mock_run.call_args[1]
        env = call_kwargs["env"]
        assert env["DOCKER_HOST"] == "ssh://admin@lab.example.com"

    def test_run_sets_ssh_identity_when_key_provided(self, tmp_path):
        backend = self._make_backend(
            tmp_path, ssh_key="/home/user/.ssh/lab_key"
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.start(["wazuh"])

        call_kwargs = mock_run.call_args[1]
        env = call_kwargs["env"]
        assert env["DOCKER_SSH_IDENTITY"] == "/home/user/.ssh/lab_key"

    def test_inherits_start_behavior(self, tmp_path):
        """SSH backend start should produce same command structure."""
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = backend.start(["wazuh", "kali"])

        assert result.success is True
        cmd = mock_run.call_args[0][0]
        assert "docker" in cmd
        assert "compose" in cmd
        assert "up" in cmd

    def test_inherits_stop_behavior(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = backend.stop(["wazuh"], remove_volumes=True)

        assert result.success is True
        cmd = mock_run.call_args[0][0]
        assert "down" in cmd
        assert "-v" in cmd

    def test_validate_connection_success(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="24.0.7\n", stderr=""
            )
            ok, err = backend.validate_connection()

        assert ok is True
        assert err == ""

    def test_validate_connection_failure(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="Connection refused"
            )
            ok, err = backend.validate_connection()

        assert ok is False
        assert "Connection refused" in err

    def test_validate_connection_timeout(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(
                cmd="docker", timeout=30
            )
            ok, err = backend.validate_connection()

        assert ok is False
        assert "timed out" in err

    # CLI-004: streaming methods inject DOCKER_HOST too --------------------

    def test_container_shell_injects_docker_host(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            backend.container_shell("aptl-kali", shell="/bin/bash")
        env = mock_run.call_args[1]["env"]
        assert env["DOCKER_HOST"] == "ssh://admin@lab.example.com"

    def test_container_logs_injects_docker_host(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            backend.container_logs("aptl-victim", follow=True)
        env = mock_run.call_args[1]["env"]
        assert env["DOCKER_HOST"] == "ssh://admin@lab.example.com"

    def test_container_logs_streaming_injects_ssh_identity(self, tmp_path):
        backend = self._make_backend(
            tmp_path, ssh_key="/home/user/.ssh/lab_key"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            backend.container_logs("aptl-victim")
        env = mock_run.call_args[1]["env"]
        assert env["DOCKER_SSH_IDENTITY"] == "/home/user/.ssh/lab_key"

    def test_container_exec_uses_ssh_path(self, tmp_path):
        """container_exec is captured; verify it inherits the _run override."""
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.container_exec("aptl-victim", ["true"])
        env = mock_run.call_args[1]["env"]
        assert env["DOCKER_HOST"] == "ssh://admin@lab.example.com"

    def test_container_list_uses_ssh_path(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.container_list()
        env = mock_run.call_args[1]["env"]
        assert env["DOCKER_HOST"] == "ssh://admin@lab.example.com"


# ---------------------------------------------------------------------------
# Factory function tests
# ---------------------------------------------------------------------------


class TestGetBackend:
    """Tests for the get_backend factory function."""

    def test_returns_docker_compose_by_default(self, tmp_path):
        config = AptlConfig(lab={"name": "test"})
        backend = get_backend(config, tmp_path)
        assert isinstance(backend, DockerComposeBackend)

    def test_returns_docker_compose_explicitly(self, tmp_path):
        config = AptlConfig(
            lab={"name": "test"},
            deployment={"provider": "docker-compose"},
        )
        backend = get_backend(config, tmp_path)
        assert isinstance(backend, DockerComposeBackend)

    def test_returns_ssh_compose(self, tmp_path):
        config = AptlConfig(
            lab={"name": "test"},
            deployment={
                "provider": "ssh-compose",
                "ssh_host": "server.example.com",
                "ssh_user": "deploy",
            },
        )
        backend = get_backend(config, tmp_path)
        assert isinstance(backend, SSHComposeBackend)
        assert backend.host == "server.example.com"
        assert backend.user == "deploy"

    def test_ssh_compose_requires_host(self, tmp_path):
        config = AptlConfig(
            lab={"name": "test"},
            deployment={
                "provider": "ssh-compose",
                "ssh_user": "deploy",
            },
        )
        with pytest.raises(ValueError, match="ssh_host is required"):
            get_backend(config, tmp_path)

    def test_ssh_compose_requires_user(self, tmp_path):
        config = AptlConfig(
            lab={"name": "test"},
            deployment={
                "provider": "ssh-compose",
                "ssh_host": "server",
            },
        )
        with pytest.raises(ValueError, match="ssh_user is required"):
            get_backend(config, tmp_path)

    def test_passes_project_name(self, tmp_path):
        config = AptlConfig(
            lab={"name": "test"},
            deployment={"provider": "docker-compose", "project_name": "mylab"},
        )
        backend = get_backend(config, tmp_path)
        assert isinstance(backend, DockerComposeBackend)
        assert backend.project_name == "mylab"

    def test_passes_ssh_options(self, tmp_path):
        config = AptlConfig(
            lab={"name": "test"},
            deployment={
                "provider": "ssh-compose",
                "ssh_host": "server",
                "ssh_user": "admin",
                "ssh_key": "/path/to/key",
                "ssh_port": 2222,
                "remote_dir": "/opt/aptl",
            },
        )
        backend = get_backend(config, tmp_path)
        assert isinstance(backend, SSHComposeBackend)
        assert backend.docker_host == "ssh://admin@server:2222"


# ---------------------------------------------------------------------------
# Backward-compatibility: lab.py wrapper functions
# ---------------------------------------------------------------------------


class TestLabBackwardCompat:
    """Verify that lab.py wrapper functions still work without backend arg."""

    def test_start_lab_without_backend(self, mock_subprocess):
        from aptl.core.lab import start_lab

        config = AptlConfig(
            lab={"name": "test"},
            containers={"wazuh": True, "victim": True, "kali": False, "reverse": False},
        )
        mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = start_lab(config)

        assert result.success is True

    def test_stop_lab_without_backend(self, mock_subprocess, tmp_path):
        from aptl.core.lab import stop_lab

        mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = stop_lab(project_dir=tmp_path)

        assert result.success is True

    def test_lab_status_without_backend(self, mock_subprocess):
        from aptl.core.lab import lab_status

        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout='[{"Name":"aptl-victim","State":"running"}]',
            stderr="",
        )

        status = lab_status()

        assert status.running is True

    def test_start_lab_with_explicit_backend(self, tmp_path):
        """start_lab accepts an explicit backend."""
        from aptl.core.lab import start_lab

        config = AptlConfig(
            lab={"name": "test"},
            containers={"wazuh": True, "kali": False, "reverse": False},
        )

        mock_backend = MagicMock()
        mock_backend.start.return_value = LabResult(success=True, message="ok")

        result = start_lab(config, backend=mock_backend)

        assert result.success is True
        mock_backend.start.assert_called_once()


class TestKillBackwardCompat:
    """Verify kill_lab_containers still works without backend arg."""

    @patch("aptl.core.kill.subprocess.run")
    def test_kill_without_backend(self, mock_run):
        from aptl.core.kill import kill_lab_containers

        mock_run.return_value = MagicMock(returncode=0, stderr="")

        success, error = kill_lab_containers(project_dir=Path("/tmp/aptl"))

        assert success is True

    def test_kill_with_backend(self):
        from aptl.core.kill import kill_lab_containers

        mock_backend = MagicMock()
        mock_backend.kill.return_value = (True, "")

        success, error = kill_lab_containers(backend=mock_backend)

        assert success is True
        mock_backend.kill.assert_called_once()


# ---------------------------------------------------------------------------
# SSH parameter validation tests
# ---------------------------------------------------------------------------


class TestSSHComposeBackendValidation:
    """Validate that SSHComposeBackend rejects dangerous parameter values."""

    def test_rejects_host_with_at_sign(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid SSH host"):
            SSHComposeBackend(tmp_path, host="user@evil", user="deploy")

    def test_rejects_host_with_semicolon(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid SSH host"):
            SSHComposeBackend(tmp_path, host="host;rm -rf /", user="deploy")

    def test_rejects_host_with_spaces(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid SSH host"):
            SSHComposeBackend(tmp_path, host="host name", user="deploy")

    def test_rejects_user_with_spaces(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid SSH user"):
            SSHComposeBackend(tmp_path, host="example.com", user="admin root")

    def test_rejects_user_with_at_sign(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid SSH user"):
            SSHComposeBackend(tmp_path, host="example.com", user="user@host")

    def test_rejects_port_zero(self, tmp_path):
        with pytest.raises(ValueError, match="ssh_port must be int in 1-65535"):
            SSHComposeBackend(tmp_path, host="example.com", user="deploy", ssh_port=0)

    def test_rejects_port_negative(self, tmp_path):
        with pytest.raises(ValueError, match="ssh_port must be int in 1-65535"):
            SSHComposeBackend(tmp_path, host="example.com", user="deploy", ssh_port=-1)

    def test_rejects_port_over_65535(self, tmp_path):
        with pytest.raises(ValueError, match="ssh_port must be int in 1-65535"):
            SSHComposeBackend(tmp_path, host="example.com", user="deploy", ssh_port=70000)

    def test_rejects_relative_ssh_key(self, tmp_path):
        with pytest.raises(ValueError, match="absolute path"):
            SSHComposeBackend(
                tmp_path, host="example.com", user="deploy",
                ssh_key="relative/path/key",
            )

    def test_rejects_ssh_key_with_traversal(self, tmp_path):
        with pytest.raises(ValueError, match="must not contain"):
            SSHComposeBackend(
                tmp_path, host="example.com", user="deploy",
                ssh_key="/home/../etc/passwd",
            )

    def test_accepts_valid_ipv6_host(self, tmp_path):
        backend = SSHComposeBackend(tmp_path, host="[::1]", user="deploy")
        assert backend.docker_host == "ssh://deploy@[::1]"

    def test_accepts_valid_hostname(self, tmp_path):
        backend = SSHComposeBackend(tmp_path, host="lab.example.com", user="deploy")
        assert backend.docker_host == "ssh://deploy@lab.example.com"

    def test_accepts_valid_absolute_key(self, tmp_path):
        backend = SSHComposeBackend(
            tmp_path, host="example.com", user="deploy",
            ssh_key="/home/user/.ssh/id_rsa",
        )
        assert backend.docker_host == "ssh://deploy@example.com"

    def test_accepts_non_default_port(self, tmp_path):
        backend = SSHComposeBackend(
            tmp_path, host="example.com", user="deploy", ssh_port=2222,
        )
        assert backend.docker_host == "ssh://deploy@example.com:2222"
