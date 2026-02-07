"""Tests for lab lifecycle management.

Tests exercise our logic for starting/stopping the lab, profile selection,
compose command construction, and full orchestration. All subprocess/docker
calls are mocked.
"""

from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest


class TestComposeCommandBuilder:
    """Tests for building docker compose commands."""

    def test_build_up_command_with_profiles(self):
        """Should construct 'docker compose --profile X up -d' with correct profiles."""
        from aptl.core.lab import build_compose_command

        cmd = build_compose_command("up", profiles=["wazuh", "victim", "kali"])
        assert cmd[0] == "docker"
        assert cmd[1] == "compose"
        assert "--profile" in cmd
        assert "wazuh" in cmd
        assert "victim" in cmd
        assert "kali" in cmd
        assert "up" in cmd
        assert "-d" in cmd

    def test_build_down_command(self):
        """Should construct 'docker compose down'."""
        from aptl.core.lab import build_compose_command

        cmd = build_compose_command("down", profiles=[])
        assert "down" in cmd
        assert "-d" not in cmd

    def test_build_command_with_no_profiles(self):
        """An empty profile list should not add --profile flags."""
        from aptl.core.lab import build_compose_command

        cmd = build_compose_command("up", profiles=[])
        assert "--profile" not in cmd

    def test_build_ps_command(self):
        """Should construct 'docker compose ps' for status."""
        from aptl.core.lab import build_compose_command

        cmd = build_compose_command("ps", profiles=["wazuh"])
        assert "ps" in cmd

    def test_build_up_command_includes_build_flag(self):
        """Should include --build before -d for up action (C2)."""
        from aptl.core.lab import build_compose_command

        cmd = build_compose_command("up", profiles=["wazuh"])
        assert "--build" in cmd
        assert "-d" in cmd
        # --build should come before -d
        build_idx = cmd.index("--build")
        d_idx = cmd.index("-d")
        assert build_idx < d_idx

    def test_build_down_command_has_no_build_flag(self):
        """Should not include --build for down action."""
        from aptl.core.lab import build_compose_command

        cmd = build_compose_command("down", profiles=[])
        assert "--build" not in cmd


class TestLabStart:
    """Tests for lab start logic."""

    def test_start_calls_compose_up(self, mock_subprocess):
        """start_lab should invoke docker compose up with correct profiles."""
        from aptl.core.config import AptlConfig
        from aptl.core.lab import start_lab

        config = AptlConfig(
            lab={"name": "test"},
            containers={"wazuh": True, "victim": True, "kali": False, "reverse": False},
        )
        mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = start_lab(config)

        assert result.success is True
        mock_subprocess.assert_called_once()
        cmd_args = mock_subprocess.call_args[0][0]
        assert "up" in cmd_args
        assert "wazuh" in cmd_args
        assert "victim" in cmd_args
        assert "kali" not in cmd_args

    def test_start_returns_failure_on_nonzero_exit(self, mock_subprocess):
        """If docker compose fails, start_lab should return failure result."""
        from aptl.core.config import AptlConfig
        from aptl.core.lab import start_lab

        config = AptlConfig(lab={"name": "test"})
        mock_subprocess.return_value = MagicMock(
            returncode=1, stdout="", stderr="Error: something went wrong"
        )

        result = start_lab(config)

        assert result.success is False
        assert "something went wrong" in result.error

    def test_start_uses_project_dir(self, mock_subprocess):
        """start_lab should pass cwd to subprocess when project_dir is given."""
        from aptl.core.config import AptlConfig
        from aptl.core.lab import start_lab
        from pathlib import Path

        config = AptlConfig(lab={"name": "test"})
        mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")

        start_lab(config, project_dir=Path("/opt/aptl"))

        kwargs = mock_subprocess.call_args[1]
        assert kwargs["cwd"] == Path("/opt/aptl")


class TestLabStop:
    """Tests for lab stop logic."""

    def test_stop_calls_compose_down(self, mock_subprocess):
        """stop_lab should invoke docker compose down."""
        from aptl.core.lab import stop_lab

        mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = stop_lab()

        assert result.success is True
        cmd_args = mock_subprocess.call_args[0][0]
        assert "down" in cmd_args

    def test_stop_with_volumes_flag(self, mock_subprocess):
        """stop_lab with remove_volumes=True should pass -v flag."""
        from aptl.core.lab import stop_lab

        mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")

        stop_lab(remove_volumes=True)

        cmd_args = mock_subprocess.call_args[0][0]
        assert "-v" in cmd_args

    def test_stop_returns_failure_on_error(self, mock_subprocess):
        """If docker compose down fails, stop_lab returns failure."""
        from aptl.core.lab import stop_lab

        mock_subprocess.return_value = MagicMock(
            returncode=1, stdout="", stderr="Cannot stop"
        )

        result = stop_lab()

        assert result.success is False


class TestLabStatus:
    """Tests for lab status checking."""

    def test_status_parses_compose_ps_output(self, mock_subprocess):
        """lab_status should parse docker compose ps output."""
        from aptl.core.lab import lab_status

        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout='[{"Name":"aptl-victim","State":"running","Health":"healthy"}]',
            stderr="",
        )

        status = lab_status()

        assert status.running is True
        assert len(status.containers) == 1
        assert status.containers[0]["Name"] == "aptl-victim"

    def test_status_returns_not_running_when_no_containers(self, mock_subprocess):
        """If no containers are returned, status should indicate not running."""
        from aptl.core.lab import lab_status

        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout="[]", stderr=""
        )

        status = lab_status()

        assert status.running is False
        assert len(status.containers) == 0

    def test_status_handles_compose_failure(self, mock_subprocess):
        """If docker compose ps fails, status should handle gracefully."""
        from aptl.core.lab import lab_status

        mock_subprocess.return_value = MagicMock(
            returncode=1, stdout="", stderr="docker not found"
        )

        status = lab_status()

        assert status.running is False
        assert "docker not found" in status.error


class TestOrchestrateLabStart:
    """Tests for the full lab start orchestration."""

    def _make_env_vars(self):
        """Create a test EnvVars instance."""
        from aptl.core.env import EnvVars

        return EnvVars(
            indexer_username="admin",
            indexer_password="secret",
            api_username="wazuh-wui",
            api_password="apisecret",
            dashboard_username="kibanaserver",
            dashboard_password="kibanapass",
            wazuh_cluster_key="clusterkey",
        )

    def _make_config(self):
        """Create a test AptlConfig."""
        from aptl.core.config import AptlConfig

        return AptlConfig(
            lab={"name": "test-lab"},
            containers={"wazuh": True, "victim": True, "kali": True, "reverse": False},
        )

    def _patch_all_steps(self, mocker, tmp_path):
        """Patch all orchestration sub-functions and return mocks dict."""
        env_vars = self._make_env_vars()
        config = self._make_config()

        mocks = {}

        # .env file
        env_file = tmp_path / ".env"
        env_file.write_text(
            'INDEXER_USERNAME=admin\n'
            'INDEXER_PASSWORD=secret\n'
            'API_USERNAME=wazuh-wui\n'
            'API_PASSWORD=apisecret\n'
            'DASHBOARD_USERNAME=kibanaserver\n'
            'DASHBOARD_PASSWORD=kibanapass\n'
            'WAZUH_CLUSTER_KEY=clusterkey\n'
        )

        # aptl.json config
        import json
        config_file = tmp_path / "aptl.json"
        config_file.write_text(json.dumps({
            "lab": {"name": "test-lab"},
            "containers": {"wazuh": True, "victim": True, "kali": True, "reverse": False},
        }))

        # SSH keys dir
        keys_dir = tmp_path / "containers" / "keys"
        keys_dir.mkdir(parents=True)

        # Config dirs for credentials
        dashboard_dir = tmp_path / "config" / "wazuh_dashboard"
        dashboard_dir.mkdir(parents=True)
        (dashboard_dir / "wazuh.yml").write_text('password: "old"')

        manager_dir = tmp_path / "config" / "wazuh_cluster"
        manager_dir.mkdir(parents=True)
        (manager_dir / "wazuh_manager.conf").write_text('<key>old</key>')

        # SSL certs exist already
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        certs_dir.mkdir(parents=True)

        # MCP build script
        mcp_dir = tmp_path / "mcp"
        mcp_dir.mkdir()
        build_script = mcp_dir / "build-all-mcps.sh"
        build_script.write_text("#!/bin/bash\necho done")
        build_script.chmod(0o755)

        # Mock SSH key generation
        from aptl.core.ssh import SSHKeyResult
        mocks["ssh"] = mocker.patch(
            "aptl.core.lab.ensure_ssh_keys",
            return_value=SSHKeyResult(
                success=True,
                generated=False,
                key_path=Path.home() / ".ssh" / "aptl_lab_key",
            ),
        )

        # Mock sysreqs
        from aptl.core.sysreqs import SysReqResult
        mocks["sysreqs"] = mocker.patch(
            "aptl.core.lab.check_max_map_count",
            return_value=SysReqResult(passed=True, current_value=262144, required_value=262144),
        )

        # Mock credentials sync
        mocks["dashboard_creds"] = mocker.patch("aptl.core.lab.sync_dashboard_config")
        mocks["manager_creds"] = mocker.patch("aptl.core.lab.sync_manager_config")

        # Mock certs
        from aptl.core.certs import CertResult
        mocks["certs"] = mocker.patch(
            "aptl.core.lab.ensure_ssl_certs",
            return_value=CertResult(success=True, generated=False, certs_dir=certs_dir),
        )

        # Mock docker compose start
        from aptl.core.lab import LabResult
        mocks["start"] = mocker.patch(
            "aptl.core.lab.start_lab",
            return_value=LabResult(success=True, message="Lab started"),
        )

        # Mock service waiting
        from aptl.core.services import ServiceResult
        mocks["wait_indexer"] = mocker.patch(
            "aptl.core.lab.wait_for_service",
            return_value=ServiceResult(ready=True, elapsed_seconds=10.0),
        )

        # Mock SSH connection tests
        mocks["test_ssh"] = mocker.patch(
            "aptl.core.lab.test_ssh_connection",
            return_value=True,
        )

        # Mock connection info
        mocks["gen_info"] = mocker.patch(
            "aptl.core.lab.generate_connection_info",
            return_value="Connection info text",
        )
        mocks["write_info"] = mocker.patch("aptl.core.lab.write_connection_file")

        # Mock MCP build subprocess
        mocks["mcp_subprocess"] = mocker.patch(
            "aptl.core.lab.subprocess.run",
            return_value=MagicMock(returncode=0, stdout="", stderr=""),
        )

        return mocks

    def test_orchestrates_all_steps_in_order(self, mocker, tmp_path):
        """Should call all orchestration steps."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)

        result = orchestrate_lab_start(tmp_path)

        assert result.success is True
        mocks["ssh"].assert_called_once()
        mocks["sysreqs"].assert_called_once()
        mocks["certs"].assert_called_once()
        mocks["start"].assert_called_once()
        mocks["gen_info"].assert_called_once()
        mocks["write_info"].assert_called_once()

    def test_stops_on_env_loading_failure(self, mocker, tmp_path):
        """Should fail early if .env loading fails."""
        from aptl.core.lab import orchestrate_lab_start

        # No .env file exists
        # aptl.json still needed to not hit a different error first
        import json
        (tmp_path / "aptl.json").write_text(json.dumps({"lab": {"name": "test"}}))

        result = orchestrate_lab_start(tmp_path)

        assert result.success is False
        assert "env" in result.error.lower() or ".env" in result.error

    def test_stops_on_config_loading_failure(self, mocker, tmp_path):
        """Should fail early if config loading fails."""
        from aptl.core.lab import orchestrate_lab_start

        # .env exists but no aptl.json
        (tmp_path / ".env").write_text(
            'INDEXER_USERNAME=admin\n'
            'INDEXER_PASSWORD=secret\n'
            'API_USERNAME=wazuh-wui\n'
            'API_PASSWORD=apisecret\n'
        )

        result = orchestrate_lab_start(tmp_path)

        assert result.success is False
        assert "config" in result.error.lower() or "aptl.json" in result.error

    def test_stops_on_sysreqs_failure(self, mocker, tmp_path):
        """Should fail if system requirements check fails."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)

        from aptl.core.sysreqs import SysReqResult
        mocks["sysreqs"].return_value = SysReqResult(
            passed=False, current_value=65530, required_value=262144
        )

        result = orchestrate_lab_start(tmp_path)

        assert result.success is False
        assert "map_count" in result.error.lower() or "sysreq" in result.error.lower()
        # Should not have tried to start lab
        mocks["start"].assert_not_called()

    def test_stops_on_ssh_key_generation_failure(self, mocker, tmp_path):
        """Should fail if SSH key generation fails."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)

        from aptl.core.ssh import SSHKeyResult
        mocks["ssh"].return_value = SSHKeyResult(
            success=False, generated=False, error="Permission denied"
        )

        result = orchestrate_lab_start(tmp_path)

        assert result.success is False
        # Should not proceed to sysreqs
        mocks["sysreqs"].assert_not_called()

    def test_continues_past_ssh_test_failure(self, mocker, tmp_path):
        """Should continue (with warning) when SSH connection test fails."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)
        mocks["test_ssh"].return_value = False

        result = orchestrate_lab_start(tmp_path)

        # Overall should still succeed
        assert result.success is True
        mocks["gen_info"].assert_called_once()

    def test_continues_past_mcp_build_failure(self, mocker, tmp_path):
        """Should continue (with warning) when MCP build fails."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)
        mocks["mcp_subprocess"].return_value = MagicMock(
            returncode=1, stdout="", stderr="npm error"
        )

        result = orchestrate_lab_start(tmp_path)

        # Overall should still succeed
        assert result.success is True

    def test_passes_env_data_to_credentials_sync(self, mocker, tmp_path):
        """Should pass correct env values to credential sync functions."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)

        orchestrate_lab_start(tmp_path)

        # Dashboard config should be called with API password
        mocks["dashboard_creds"].assert_called_once()
        call_args = mocks["dashboard_creds"].call_args
        assert call_args[0][1] == "apisecret"

        # Manager config should be called with cluster key
        mocks["manager_creds"].assert_called_once()
        call_args = mocks["manager_creds"].call_args
        assert call_args[0][1] == "clusterkey"

    def test_stops_on_cert_generation_failure(self, mocker, tmp_path):
        """Should fail if certificate generation fails."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)

        from aptl.core.certs import CertResult
        mocks["certs"].return_value = CertResult(
            success=False, generated=False, error="docker not found"
        )

        result = orchestrate_lab_start(tmp_path)

        assert result.success is False
        mocks["start"].assert_not_called()

    def test_stops_on_docker_compose_start_failure(self, mocker, tmp_path):
        """Should fail if docker compose up fails."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)

        from aptl.core.lab import LabResult
        mocks["start"].return_value = LabResult(
            success=False, error="compose up failed"
        )

        result = orchestrate_lab_start(tmp_path)

        assert result.success is False
        mocks["gen_info"].assert_not_called()

    def test_continues_when_credential_sync_fails(self, mocker, tmp_path):
        """Should warn and continue when credential sync raises (C6)."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)
        mocks["dashboard_creds"].side_effect = RuntimeError("sync failed")

        result = orchestrate_lab_start(tmp_path)

        # Should still succeed overall -- credential sync is non-critical
        assert result.success is True
        mocks["start"].assert_called_once()

    def test_handles_empty_profiles(self, mocker, tmp_path):
        """Should work when all containers are disabled (C6)."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)

        # Override config to disable all containers
        import json
        config_file = tmp_path / "aptl.json"
        config_file.write_text(json.dumps({
            "lab": {"name": "test-lab"},
            "containers": {"wazuh": False, "victim": False, "kali": False, "reverse": False},
        }))

        # Re-mock start_lab and wait_for_service since config changes
        from aptl.core.lab import LabResult
        mocks["start"].return_value = LabResult(success=True, message="Lab started")

        result = orchestrate_lab_start(tmp_path)

        assert result.success is True

    def test_fails_on_nonexistent_project_dir(self, mocker, tmp_path):
        """Should fail when project_dir does not exist (C6)."""
        from aptl.core.lab import orchestrate_lab_start

        nonexistent = tmp_path / "does_not_exist"

        result = orchestrate_lab_start(nonexistent)

        assert result.success is False

    def test_pre_pull_runs_before_compose_up(self, mocker, tmp_path):
        """Should call docker pull for images before compose up."""
        from aptl.core.lab import orchestrate_lab_start

        mocks = self._patch_all_steps(mocker, tmp_path)

        result = orchestrate_lab_start(tmp_path)

        assert result.success is True
        # The mcp_subprocess mock also catches the docker pull calls
        pull_calls = [
            c for c in mocks["mcp_subprocess"].call_args_list
            if len(c[0]) > 0 and len(c[0][0]) > 1 and c[0][0][0] == "docker" and c[0][0][1] == "pull"
        ]
        assert len(pull_calls) >= 1
