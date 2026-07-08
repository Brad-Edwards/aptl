"""Tests for SSL certificate generation."""

import subprocess
from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def no_native_ownership_fix_by_default(mocker):
    """Avoid probing the real Docker engine in unit tests."""
    mocker.patch(
        "aptl.core.certs.hostenv.needs_host_ownership_fix", return_value=False
    )


@pytest.fixture
def linux_native(mocker):
    """Force native-Linux generation with a fixed uid/gid."""
    mocker.patch(
        "aptl.core.certs.hostenv.needs_host_ownership_fix", return_value=True
    )
    mocker.patch("aptl.core.certs.os.getuid", return_value=1000)
    mocker.patch("aptl.core.certs.os.getgid", return_value=1000)


def _successful_generator(mocker, certs_dir):
    def fake_run(cmd, **kwargs):
        certs_dir.mkdir(parents=True, exist_ok=True)
        (certs_dir / "root-ca.pem").write_text("fake-cert")
        return MagicMock(returncode=0, stdout="", stderr="")

    return mocker.patch("aptl.core.certs.subprocess.run", side_effect=fake_run)


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
        assert (certs_dir / "root-ca-manager.pem").read_text() == "fake-cert"
        mock_run.assert_not_called()

    def test_linux_native_generator_runs_as_host_user(
        self, tmp_path, mocker, linux_native
    ):
        """Native Linux should generate certs as the invoking host user."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        mock_run = _successful_generator(mocker, certs_dir)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is True
        assert result.generated is True
        assert result.certs_dir == certs_dir
        assert (certs_dir / "root-ca-manager.pem").read_text() == "fake-cert"
        assert mock_run.call_count == 1
        generator_cmd = mock_run.call_args_list[0][0][0]
        assert generator_cmd == [
            "docker",
            "compose",
            "-f",
            "generate-indexer-certs.yml",
            "run",
            "--rm",
            "--user",
            "1000:1000",
            "generator",
        ]

    def test_linux_native_precreates_output_dir(self, tmp_path, mocker, linux_native):
        """Precreating the bind mount avoids Docker making a root-owned dir."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"

        def fake_run(cmd, **kwargs):
            assert certs_dir.exists()
            (certs_dir / "root-ca.pem").write_text("fake-cert")
            return MagicMock(returncode=0, stdout="", stderr="")

        mocker.patch("aptl.core.certs.subprocess.run", side_effect=fake_run)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is True
        assert result.generated is True
        assert (certs_dir / "root-ca-manager.pem").read_text() == "fake-cert"

    def test_docker_desktop_generator_does_not_request_host_uid(
        self, tmp_path, mocker
    ):
        """Docker Desktop should rely on file sharing, not POSIX uid/gid."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        getuid = mocker.patch("aptl.core.certs.os.getuid")
        getgid = mocker.patch("aptl.core.certs.os.getgid")
        mock_run = _successful_generator(mocker, certs_dir)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is True
        assert result.generated is True
        generator_cmd = mock_run.call_args_list[0][0][0]
        assert "--user" not in generator_cmd
        assert generator_cmd[-1] == "generator"
        assert (certs_dir / "root-ca-manager.pem").read_text() == "fake-cert"
        getuid.assert_not_called()
        getgid.assert_not_called()

    def test_existing_manager_root_ca_alias_is_preserved(self, tmp_path, mocker):
        """Existing CA alias should not be rewritten on repeat starts."""
        from aptl.core.certs import ensure_ssl_certs

        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        certs_dir.mkdir(parents=True)
        (certs_dir / "root-ca.pem").write_text("new-cert")
        (certs_dir / "root-ca-manager.pem").write_text("existing-cert")
        mock_run = mocker.patch("aptl.core.certs.subprocess.run")

        result = ensure_ssl_certs(tmp_path)

        assert result.success is True
        assert result.generated is False
        assert (certs_dir / "root-ca-manager.pem").read_text() == "existing-cert"
        mock_run.assert_not_called()

    def test_missing_generated_root_ca_is_reported(self, tmp_path, mocker):
        """A generator success without root-ca.pem is a failed cert contract."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"

        def fake_run(cmd, **kwargs):
            certs_dir.mkdir(parents=True, exist_ok=True)
            return MagicMock(returncode=0, stdout="", stderr="")

        mocker.patch("aptl.core.certs.subprocess.run", side_effect=fake_run)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is False
        assert result.generated is False
        assert "root-ca.pem" in result.error

    def test_no_command_ever_uses_sudo(self, tmp_path, mocker, linux_native):
        """The cert path must never silently escalate on the host."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        mock_run = _successful_generator(mocker, certs_dir)

        ensure_ssl_certs(tmp_path)

        for issued in mock_run.call_args_list:
            assert "sudo" not in issued[0][0]

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
        assert result.generated is False
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

    def test_uses_project_dir_as_cwd(self, tmp_path, mocker):
        """Should pass project_dir as cwd to subprocess calls."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        mock_run = _successful_generator(mocker, certs_dir)

        ensure_ssl_certs(tmp_path)

        assert mock_run.call_args_list[0][1]["cwd"] == tmp_path

    def test_docker_compose_called_with_timeout(self, tmp_path, mocker):
        """Should pass timeout=300 to docker compose subprocess call."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        mock_run = _successful_generator(mocker, certs_dir)

        ensure_ssl_certs(tmp_path)

        assert mock_run.call_args_list[0][1]["timeout"] == 300
