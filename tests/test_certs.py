"""Tests for SSL certificate generation.

All subprocess calls are mocked. The ownership-repair step no longer uses
host ``sudo`` (#677): on a native Linux engine it chowns the bind-mounted
certs from inside a throwaway container; on Docker Desktop / non-Linux it is
skipped entirely. ``hostenv.needs_host_ownership_fix`` and ``os.getuid/getgid``
are mocked so the suite is deterministic and runs on any OS.
"""

import subprocess
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def linux_native(mocker):
    """Force the native-Linux ownership-repair branch with a fixed uid/gid."""
    mocker.patch(
        "aptl.core.certs.hostenv.needs_host_ownership_fix", return_value=True
    )
    mocker.patch("aptl.core.certs.os.getuid", return_value=1000)
    mocker.patch("aptl.core.certs.os.getgid", return_value=1000)


class TestEnsureSSLCerts:
    """Tests for SSL certificate generation and management."""

    def test_skips_generation_when_certs_dir_exists(self, tmp_path, mocker):
        """Should skip generation when certs directory already exists."""
        from aptl.core.certs import ensure_ssl_certs

        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        certs_dir.mkdir(parents=True)
        (certs_dir / "root-ca.pem").write_text("fake-cert")

        mock_run = mocker.patch("aptl.core.certs.subprocess.run")

        result = ensure_ssl_certs(tmp_path)

        assert result.success is True
        assert result.generated is False
        assert result.certs_dir == certs_dir
        mock_run.assert_not_called()

    def test_calls_docker_compose_when_certs_missing(self, tmp_path, mocker, linux_native):
        """Should run docker compose generate-indexer-certs.yml when no certs."""
        from aptl.core.certs import ensure_ssl_certs

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        certs_dir = config_dir / "wazuh_indexer_ssl_certs"

        def fake_compose(cmd, **kwargs):
            """Simulate cert generation creating the directory."""
            certs_dir.mkdir(parents=True, exist_ok=True)
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run = mocker.patch(
            "aptl.core.certs.subprocess.run",
            side_effect=fake_compose,
        )

        result = ensure_ssl_certs(tmp_path)

        assert result.success is True
        assert result.generated is True
        assert result.certs_dir == certs_dir

        first_call_cmd = mock_run.call_args_list[0][0][0]
        assert "docker" in first_call_cmd
        assert "compose" in first_call_cmd
        assert "generate-indexer-certs.yml" in " ".join(first_call_cmd)

    def test_handles_docker_compose_failure(self, tmp_path, mocker):
        """Should return failure when docker compose fails."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()

        mocker.patch(
            "aptl.core.certs.subprocess.run",
            return_value=MagicMock(
                returncode=1,
                stdout="",
                stderr="Error: service 'generator' failed",
            ),
        )

        result = ensure_ssl_certs(tmp_path)

        assert result.success is False
        assert result.generated is False
        assert "generator" in result.error.lower() or "failed" in result.error.lower()

    def test_ownership_fix_skipped_on_docker_desktop(self, tmp_path, mocker):
        """#677: no ownership step at all on Docker Desktop / non-Linux."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"

        mocker.patch(
            "aptl.core.certs.hostenv.needs_host_ownership_fix", return_value=False
        )

        def fake_compose(cmd, **kwargs):
            certs_dir.mkdir(parents=True, exist_ok=True)
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run = mocker.patch(
            "aptl.core.certs.subprocess.run", side_effect=fake_compose
        )

        result = ensure_ssl_certs(tmp_path)

        assert result.success is True
        assert result.generated is True
        # Only the generator ran; no ownership-repair call.
        assert mock_run.call_count == 1

    def test_ownership_repair_uses_container_not_sudo(self, tmp_path, mocker, linux_native):
        """#677: ownership repair chowns via a container, never host sudo."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"

        def fake_run(cmd, **kwargs):
            certs_dir.mkdir(parents=True, exist_ok=True)
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run = mocker.patch(
            "aptl.core.certs.subprocess.run", side_effect=fake_run
        )

        ensure_ssl_certs(tmp_path)

        assert mock_run.call_count == 2
        repair_cmd = mock_run.call_args_list[1][0][0]
        # Container-based chown, no host escalation.
        assert repair_cmd[0] == "docker"
        assert "run" in repair_cmd
        assert "--entrypoint" in repair_cmd and "chown" in repair_cmd
        assert f"{certs_dir}:/certificates" in repair_cmd

    def test_no_command_ever_uses_sudo(self, tmp_path, mocker, linux_native):
        """#677 guard: not a single issued command may invoke sudo."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"

        def fake_run(cmd, **kwargs):
            certs_dir.mkdir(parents=True, exist_ok=True)
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run = mocker.patch(
            "aptl.core.certs.subprocess.run", side_effect=fake_run
        )

        ensure_ssl_certs(tmp_path)

        for issued in mock_run.call_args_list:
            assert "sudo" not in issued[0][0]

    def test_generated_true_when_ownership_repair_fails(self, tmp_path, mocker, linux_native):
        """Should set generated=True when certs exist but ownership repair fails."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"

        call_count = 0

        def mock_side_effect(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                certs_dir.mkdir(parents=True, exist_ok=True)
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=1, stdout="", stderr="Permission denied")

        mocker.patch("aptl.core.certs.subprocess.run", side_effect=mock_side_effect)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is False
        assert result.generated is True

    def test_generated_true_when_ownership_repair_raises(self, tmp_path, mocker, linux_native):
        """Should set generated=True when the repair container raises OSError."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"

        call_count = 0

        def mock_side_effect(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                certs_dir.mkdir(parents=True, exist_ok=True)
                return MagicMock(returncode=0, stdout="", stderr="")
            raise OSError("docker not found")

        mocker.patch("aptl.core.certs.subprocess.run", side_effect=mock_side_effect)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is False
        assert result.generated is True

    def test_ownership_repair_timeout_returns_generated_true(self, tmp_path, mocker, linux_native):
        """Should return generated=True when the repair container times out."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"

        call_count = 0

        def mock_side_effect(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                certs_dir.mkdir(parents=True, exist_ok=True)
                return MagicMock(returncode=0, stdout="", stderr="")
            raise subprocess.TimeoutExpired(cmd="docker", timeout=60)

        mocker.patch("aptl.core.certs.subprocess.run", side_effect=mock_side_effect)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is False
        assert result.generated is True
        assert "timed out" in result.error.lower()

    def test_returns_correct_cert_result_fields(self, tmp_path, mocker):
        """Should return CertResult with all fields properly set."""
        from aptl.core.certs import CertResult, ensure_ssl_certs

        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        certs_dir.mkdir(parents=True)
        (certs_dir / "root-ca.pem").write_text("fake-cert")

        result = ensure_ssl_certs(tmp_path)

        assert isinstance(result, CertResult)
        assert result.success is True
        assert result.generated is False
        assert result.certs_dir == certs_dir
        assert result.error == ""

    def test_uses_project_dir_as_cwd(self, tmp_path, mocker, linux_native):
        """Should pass project_dir as cwd to subprocess calls."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"

        def fake_compose(cmd, **kwargs):
            certs_dir.mkdir(parents=True, exist_ok=True)
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run = mocker.patch(
            "aptl.core.certs.subprocess.run", side_effect=fake_compose
        )

        ensure_ssl_certs(tmp_path)

        for issued in mock_run.call_args_list:
            assert issued[1].get("cwd") == tmp_path

    def test_handles_subprocess_exception(self, tmp_path, mocker):
        """Should handle the generator subprocess raising an exception."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()

        mocker.patch(
            "aptl.core.certs.subprocess.run",
            side_effect=FileNotFoundError("docker not found"),
        )

        result = ensure_ssl_certs(tmp_path)

        assert result.success is False
        assert "not found" in result.error.lower()

    def test_docker_compose_timeout_returns_failure(self, tmp_path, mocker):
        """Should return generated=False when docker compose times out."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()

        mocker.patch(
            "aptl.core.certs.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=300),
        )

        result = ensure_ssl_certs(tmp_path)

        assert result.success is False
        assert result.generated is False
        assert "timed out" in result.error.lower()

    def test_subprocess_call_timeouts(self, tmp_path, mocker, linux_native):
        """Generator uses timeout=300; ownership repair uses timeout=60."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"

        def fake_run(cmd, **kwargs):
            certs_dir.mkdir(parents=True, exist_ok=True)
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run = mocker.patch(
            "aptl.core.certs.subprocess.run", side_effect=fake_run
        )

        ensure_ssl_certs(tmp_path)

        assert mock_run.call_args_list[0][1]["timeout"] == 300
        assert mock_run.call_args_list[1][1]["timeout"] == 60
