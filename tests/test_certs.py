"""Tests for SSL certificate generation.

Tests are written FIRST (TDD). All subprocess calls are mocked.
"""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest


class TestEnsureSSLCerts:
    """Tests for SSL certificate generation and management."""

    def test_skips_generation_when_certs_dir_exists(self, tmp_path, mocker):
        """Should skip generation when certs directory already exists."""
        from aptl.core.certs import ensure_ssl_certs

        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        certs_dir.mkdir(parents=True)

        mock_run = mocker.patch("aptl.core.certs.subprocess.run")

        result = ensure_ssl_certs(tmp_path)

        assert result.success is True
        assert result.generated is False
        assert result.certs_dir == certs_dir
        mock_run.assert_not_called()

    def test_calls_docker_compose_when_certs_missing(self, tmp_path, mocker):
        """Should run docker compose generate-indexer-certs.yml when no certs."""
        from aptl.core.certs import ensure_ssl_certs

        # Do NOT create the certs dir
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

        # Verify docker compose was called with the cert generation file
        assert mock_run.call_count >= 1
        first_call_cmd = mock_run.call_args_list[0][0][0]
        assert "docker" in first_call_cmd
        assert "compose" in first_call_cmd
        assert "generate-indexer-certs.yml" in " ".join(first_call_cmd)

    def test_handles_docker_compose_failure(self, tmp_path, mocker):
        """Should return failure when docker compose fails."""
        from aptl.core.certs import ensure_ssl_certs

        config_dir = tmp_path / "config"
        config_dir.mkdir()

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

    def test_handles_permission_fixing_failure(self, tmp_path, mocker):
        """Should return failure when chown/chmod fails."""
        from aptl.core.certs import ensure_ssl_certs

        config_dir = tmp_path / "config"
        config_dir.mkdir()

        certs_dir = config_dir / "wazuh_indexer_ssl_certs"

        call_count = 0

        def mock_side_effect(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # docker compose succeeds
                certs_dir.mkdir(parents=True, exist_ok=True)
                return MagicMock(returncode=0, stdout="", stderr="")
            else:
                # chown/chmod fails
                return MagicMock(
                    returncode=1,
                    stdout="",
                    stderr="Permission denied",
                )

        mocker.patch("aptl.core.certs.subprocess.run", side_effect=mock_side_effect)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is False
        assert "permission" in result.error.lower()

    def test_generated_true_when_compose_succeeds_but_chown_fails(self, tmp_path, mocker):
        """Should set generated=True when certs were created but chown fails (C3)."""
        from aptl.core.certs import ensure_ssl_certs

        config_dir = tmp_path / "config"
        config_dir.mkdir()

        certs_dir = config_dir / "wazuh_indexer_ssl_certs"

        call_count = 0

        def mock_side_effect(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # docker compose succeeds -- certs were generated
                certs_dir.mkdir(parents=True, exist_ok=True)
                return MagicMock(returncode=0, stdout="", stderr="")
            else:
                # chown fails
                return MagicMock(
                    returncode=1,
                    stdout="",
                    stderr="Permission denied",
                )

        mocker.patch("aptl.core.certs.subprocess.run", side_effect=mock_side_effect)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is False
        assert result.generated is True  # certs WERE generated, only perms failed

    def test_generated_true_when_compose_succeeds_but_chown_raises(self, tmp_path, mocker):
        """Should set generated=True when certs were created but chown raises OSError (C3)."""
        from aptl.core.certs import ensure_ssl_certs

        config_dir = tmp_path / "config"
        config_dir.mkdir()

        certs_dir = config_dir / "wazuh_indexer_ssl_certs"

        call_count = 0

        def mock_side_effect(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                certs_dir.mkdir(parents=True, exist_ok=True)
                return MagicMock(returncode=0, stdout="", stderr="")
            else:
                raise OSError("sudo not found")

        mocker.patch("aptl.core.certs.subprocess.run", side_effect=mock_side_effect)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is False
        assert result.generated is True

    def test_returns_correct_cert_result_fields(self, tmp_path, mocker):
        """Should return CertResult with all fields properly set."""
        from aptl.core.certs import ensure_ssl_certs, CertResult

        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        certs_dir.mkdir(parents=True)

        result = ensure_ssl_certs(tmp_path)

        assert isinstance(result, CertResult)
        assert result.success is True
        assert result.generated is False
        assert result.certs_dir == certs_dir
        assert result.error == ""

    def test_uses_project_dir_as_cwd(self, tmp_path, mocker):
        """Should pass project_dir as cwd to subprocess calls."""
        from aptl.core.certs import ensure_ssl_certs

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        certs_dir = config_dir / "wazuh_indexer_ssl_certs"

        def fake_compose(cmd, **kwargs):
            certs_dir.mkdir(parents=True, exist_ok=True)
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run = mocker.patch(
            "aptl.core.certs.subprocess.run",
            side_effect=fake_compose,
        )

        ensure_ssl_certs(tmp_path)

        # The docker compose call should use project_dir as cwd
        kwargs = mock_run.call_args_list[0][1]
        assert kwargs.get("cwd") == tmp_path

    def test_handles_subprocess_exception(self, tmp_path, mocker):
        """Should handle subprocess raising an exception."""
        from aptl.core.certs import ensure_ssl_certs

        config_dir = tmp_path / "config"
        config_dir.mkdir()

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

        config_dir = tmp_path / "config"
        config_dir.mkdir()

        mocker.patch(
            "aptl.core.certs.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=300),
        )

        result = ensure_ssl_certs(tmp_path)

        assert result.success is False
        assert result.generated is False
        assert "timed out" in result.error.lower()

    def test_chown_timeout_returns_generated_true(self, tmp_path, mocker):
        """Should return generated=True when chown times out after cert gen succeeds."""
        from aptl.core.certs import ensure_ssl_certs

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        certs_dir = config_dir / "wazuh_indexer_ssl_certs"

        call_count = 0

        def mock_side_effect(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                certs_dir.mkdir(parents=True, exist_ok=True)
                return MagicMock(returncode=0, stdout="", stderr="")
            else:
                raise subprocess.TimeoutExpired(cmd="sudo", timeout=30)

        mocker.patch("aptl.core.certs.subprocess.run", side_effect=mock_side_effect)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is False
        assert result.generated is True
        assert "timed out" in result.error.lower()

    def test_chown_uses_sudo_noninteractive_flag(self, tmp_path, mocker):
        """Should pass -n flag to sudo so it fails instead of prompting."""
        from aptl.core.certs import ensure_ssl_certs

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        certs_dir = config_dir / "wazuh_indexer_ssl_certs"

        def fake_run(cmd, **kwargs):
            certs_dir.mkdir(parents=True, exist_ok=True)
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run = mocker.patch(
            "aptl.core.certs.subprocess.run",
            side_effect=fake_run,
        )

        ensure_ssl_certs(tmp_path)

        # Second call is the chown
        assert mock_run.call_count == 2
        chown_cmd = mock_run.call_args_list[1][0][0]
        assert chown_cmd[0] == "sudo"
        assert chown_cmd[1] == "-n"
        assert chown_cmd[2] == "chown"

    def test_docker_compose_called_with_timeout(self, tmp_path, mocker):
        """Should pass timeout=300 to docker compose subprocess call."""
        from aptl.core.certs import ensure_ssl_certs

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        certs_dir = config_dir / "wazuh_indexer_ssl_certs"

        def fake_run(cmd, **kwargs):
            certs_dir.mkdir(parents=True, exist_ok=True)
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run = mocker.patch(
            "aptl.core.certs.subprocess.run",
            side_effect=fake_run,
        )

        ensure_ssl_certs(tmp_path)

        # First call: docker compose with timeout=300
        compose_kwargs = mock_run.call_args_list[0][1]
        assert compose_kwargs["timeout"] == 300

        # Second call: chown with timeout=30
        chown_kwargs = mock_run.call_args_list[1][1]
        assert chown_kwargs["timeout"] == 30

    def test_sudo_password_required_gives_actionable_error(self, tmp_path, mocker):
        """Should give actionable guidance when sudo requires a password."""
        from aptl.core.certs import ensure_ssl_certs

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        certs_dir = config_dir / "wazuh_indexer_ssl_certs"

        call_count = 0

        def mock_side_effect(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                certs_dir.mkdir(parents=True, exist_ok=True)
                return MagicMock(returncode=0, stdout="", stderr="")
            else:
                return MagicMock(
                    returncode=1,
                    stdout="",
                    stderr="sudo: a password is required",
                )

        mocker.patch("aptl.core.certs.subprocess.run", side_effect=mock_side_effect)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is False
        assert result.generated is True
        assert "manually" in result.error.lower() or "passwordless" in result.error.lower()
