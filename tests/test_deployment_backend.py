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
            tmp_path, ssh_key="~/.ssh/lab_key"
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.start(["wazuh"])

        call_kwargs = mock_run.call_args[1]
        env = call_kwargs["env"]
        assert env["DOCKER_SSH_IDENTITY"] == "~/.ssh/lab_key"

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
