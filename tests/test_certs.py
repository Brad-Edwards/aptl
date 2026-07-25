"""Tests for SSL certificate generation."""

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

_COMPOSE_PATH = Path(__file__).resolve().parent.parent / "generate-indexer-certs.yml"


@pytest.fixture(autouse=True)
def no_native_ownership_fix_by_default(mocker):
    """Avoid probing the real Docker engine in unit tests."""
    mocker.patch("aptl.core.certs.hostenv.needs_host_ownership_fix", return_value=False)


@pytest.fixture
def linux_native(mocker):
    """Force native-Linux generation with a fixed uid/gid.

    Native-Linux cert ownership repair (running the generator as root, then
    chowning back to the host uid/gid) is a POSIX-only code path: os.getuid /
    os.getgid do not exist on Windows, where the lab runs under Docker Desktop
    and this branch is never taken. Skip rather than fabricate a fake uid.
    """
    if os.name != "posix":
        pytest.skip("native-Linux uid/gid ownership repair is POSIX-only")
    mocker.patch("aptl.core.certs.hostenv.needs_host_ownership_fix", return_value=True)
    mocker.patch("aptl.core.certs.os.getuid", return_value=1000)
    mocker.patch("aptl.core.certs.os.getgid", return_value=1000)


def _successful_generator(mocker, certs_dir):
    def fake_run(cmd, **kwargs):
        if "down" in cmd:
            return MagicMock(returncode=0, stdout="", stderr="")

        certs_dir.mkdir(parents=True, exist_ok=True)
        root_ca = certs_dir / "root-ca.pem"
        root_ca.write_text("fake-cert")
        root_ca.chmod(0o400)
        generated_key = certs_dir / "wazuh.manager-key.pem"
        generated_key.write_text("fake-key")
        generated_key.chmod(0o400)
        certs_dir.chmod(0o500)
        return MagicMock(returncode=0, stdout="", stderr="")

    return mocker.patch("aptl.core.certs.subprocess.run", side_effect=fake_run)


def _mode(path):
    return path.stat().st_mode & 0o777


def _assert_posix_mode(path, expected):
    """Assert a POSIX file mode where the platform enforces one.

    These certs are hardened for non-root Linux container bind mounts, so the
    modes matter on the deployment target. On Windows the host filesystem does
    not carry POSIX modes (``st_mode`` reads 0o666/0o777 regardless of chmod),
    so the check is skipped there while the surrounding behaviour still runs.
    """
    if os.name != "posix":
        return
    actual = _mode(path)
    assert actual == expected, f"{path} mode {oct(actual)} != {oct(expected)}"


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
        _assert_posix_mode(certs_dir, 0o700)
        _assert_posix_mode(certs_dir / "root-ca.pem", 0o644)
        _assert_posix_mode(certs_dir / "root-ca-manager.pem", 0o644)
        mock_run.assert_not_called()

    def test_generation_uses_supplied_backend_runner(self, tmp_path, mocker):
        """Typed realization must keep Docker mutation behind its backend."""
        from aptl.core.certs import ensure_ssl_certs

        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        subprocess_run = mocker.patch("aptl.core.certs.subprocess.run")
        commands = []

        def backend_run(cmd, *, timeout=None):
            commands.append((cmd, timeout))
            if "run" in cmd:
                certs_dir.mkdir(parents=True, exist_ok=True)
                (certs_dir / "root-ca.pem").write_text("fake-cert")
            return MagicMock(returncode=0, stdout="", stderr="")

        result = ensure_ssl_certs(tmp_path, run_command=backend_run)

        assert result.success is True
        assert [command for command, _timeout in commands] == [
            [
                "docker",
                "compose",
                "-p",
                commands[0][0][3],
                "-f",
                "generate-indexer-certs.yml",
                "run",
                "--rm",
                "generator",
            ],
            [
                "docker",
                "compose",
                "-p",
                commands[0][0][3],
                "-f",
                "generate-indexer-certs.yml",
                "down",
                "--remove-orphans",
            ],
        ]
        subprocess_run.assert_not_called()

    def test_existing_certs_are_widened_for_non_root_container_mounts(
        self, tmp_path, mocker
    ):
        """Existing generated certs must be readable by non-root Wazuh images."""
        from aptl.core.certs import ensure_ssl_certs

        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        certs_dir.mkdir(parents=True)
        root_ca = certs_dir / "root-ca.pem"
        root_ca.write_text("fake-cert")
        dashboard_key = certs_dir / "wazuh.dashboard-key.pem"
        dashboard_key.write_text("fake-key")
        root_ca.chmod(0o600)
        dashboard_key.chmod(0o600)
        certs_dir.chmod(0o700)
        mock_run = mocker.patch("aptl.core.certs.subprocess.run")

        result = ensure_ssl_certs(tmp_path)

        assert result.success is True
        assert result.generated is False
        _assert_posix_mode(certs_dir, 0o700)
        _assert_posix_mode(root_ca, 0o644)
        _assert_posix_mode(dashboard_key, 0o644)
        _assert_posix_mode(certs_dir / "root-ca-manager.pem", 0o644)
        mock_run.assert_not_called()

    def test_linux_native_generator_runs_as_host_user(
        self, tmp_path, mocker, linux_native
    ):
        """Native Linux should run the generator as the host uid/gid, not root."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        mock_run = _successful_generator(mocker, certs_dir)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is True
        assert result.generated is True
        assert result.certs_dir == certs_dir
        assert (certs_dir / "root-ca-manager.pem").read_text() == "fake-cert"
        _assert_posix_mode(certs_dir / "root-ca.pem", 0o644)
        _assert_posix_mode(certs_dir / "wazuh.manager-key.pem", 0o644)
        _assert_posix_mode(certs_dir, 0o700)
        assert mock_run.call_count == 2
        generator_cmd = mock_run.call_args_list[0][0][0]
        assert generator_cmd[:3] == ["docker", "compose", "-p"]
        assert generator_cmd[3].startswith("aptl-certs-")
        assert generator_cmd[4:] == [
            "-f",
            "generate-indexer-certs.yml",
            "run",
            "--rm",
            "--user",
            "1000:1000",
            "generator",
        ]
        cleanup_cmd = mock_run.call_args_list[1][0][0]
        assert cleanup_cmd == [
            "docker",
            "compose",
            "-p",
            generator_cmd[3],
            "-f",
            "generate-indexer-certs.yml",
            "down",
            "--remove-orphans",
        ]
        for issued in mock_run.call_args_list:
            assert issued[0][0][:2] != ["docker", "run"]

    def test_linux_native_precreates_output_dir(self, tmp_path, mocker, linux_native):
        """Precreating the bind mount avoids Docker making a root-owned dir."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"

        def fake_run(cmd, **kwargs):
            assert certs_dir.exists()
            (certs_dir / "root-ca.pem").write_text("fake-cert")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run = mocker.patch("aptl.core.certs.subprocess.run", side_effect=fake_run)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is True
        assert result.generated is True
        assert (certs_dir / "root-ca-manager.pem").read_text() == "fake-cert"
        _assert_posix_mode(certs_dir / "root-ca.pem", 0o644)
        _assert_posix_mode(certs_dir, 0o700)
        generator_cmd = mock_run.call_args_list[0][0][0]
        assert "--user" in generator_cmd

    def test_docker_desktop_generator_does_not_request_host_uid(self, tmp_path, mocker):
        """Docker Desktop should rely on file sharing, not POSIX uid/gid."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        # create=True: os.getuid/getgid do not exist on Windows, but this test
        # asserts they are NOT consulted on the Docker Desktop path, so the
        # attributes must be patchable regardless of host.
        getuid = mocker.patch("aptl.core.certs.os.getuid", create=True)
        getgid = mocker.patch("aptl.core.certs.os.getgid", create=True)
        mock_run = _successful_generator(mocker, certs_dir)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is True
        assert result.generated is True
        generator_cmd = mock_run.call_args_list[0][0][0]
        assert "--user" not in generator_cmd
        assert generator_cmd[-1] == "generator"
        assert (certs_dir / "root-ca-manager.pem").read_text() == "fake-cert"
        _assert_posix_mode(certs_dir / "root-ca.pem", 0o644)
        _assert_posix_mode(certs_dir, 0o700)
        getuid.assert_not_called()
        getgid.assert_not_called()

    def test_linux_native_generator_failure_is_fail_closed(
        self, tmp_path, mocker, linux_native
    ):
        """A generator failure under --user must fail closed: no repair, no root retry."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()

        def fake_run(cmd, **kwargs):
            if "down" in cmd:
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=1, stdout="generator failed", stderr="")

        mock_run = mocker.patch("aptl.core.certs.subprocess.run", side_effect=fake_run)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is False
        assert result.generated is False
        assert "generator failed" in result.error
        assert mock_run.call_count == 2
        for issued in mock_run.call_args_list:
            assert issued[0][0][:2] == ["docker", "compose"]

    @pytest.mark.parametrize("native_linux", [True, False])
    def test_no_command_ever_escalates_or_overrides_entrypoint(
        self, tmp_path, mocker, native_linux
    ):
        """Neither platform path may escalate privileges or override the entrypoint."""
        from aptl.core.certs import ensure_ssl_certs

        mocker.patch(
            "aptl.core.certs.hostenv.needs_host_ownership_fix",
            return_value=native_linux,
        )
        if native_linux:
            if os.name != "posix":
                pytest.skip("native-Linux uid/gid path is POSIX-only")
            mocker.patch("aptl.core.certs.os.getuid", return_value=1000)
            mocker.patch("aptl.core.certs.os.getgid", return_value=1000)

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        mock_run = _successful_generator(mocker, certs_dir)

        ensure_ssl_certs(tmp_path)

        assert mock_run.call_args_list
        for issued in mock_run.call_args_list:
            cmd = issued[0][0]
            assert cmd[:2] == ["docker", "compose"]
            assert not any("sudo" in arg for arg in cmd)
            assert not any("chown" in arg for arg in cmd)
            assert not any("--entrypoint" in arg for arg in cmd)

    def test_existing_manager_root_ca_alias_is_preserved(self, tmp_path, mocker):
        """Existing CA alias should not be rewritten on repeat starts."""
        from aptl.core.certs import ensure_ssl_certs

        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"
        certs_dir.mkdir(parents=True)
        (certs_dir / "root-ca.pem").write_text("new-cert")
        (certs_dir / "root-ca-manager.pem").write_text("existing-cert")
        (certs_dir / "root-ca-manager.pem").chmod(0o400)
        mock_run = mocker.patch("aptl.core.certs.subprocess.run")

        result = ensure_ssl_certs(tmp_path)

        assert result.success is True
        assert result.generated is False
        assert (certs_dir / "root-ca-manager.pem").read_text() == "existing-cert"
        _assert_posix_mode(certs_dir / "root-ca-manager.pem", 0o644)
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

        mock_run = mocker.patch(
            "aptl.core.certs.subprocess.run",
            side_effect=[
                MagicMock(
                    returncode=1,
                    stdout="generator detail",
                    stderr="Error: service 'generator' failed",
                ),
                MagicMock(returncode=0, stdout="", stderr=""),
            ],
        )

        result = ensure_ssl_certs(tmp_path)

        assert result.success is False
        assert result.generated is False
        assert "generator detail" in result.error
        assert mock_run.call_args_list[1][0][0][-2:] == ["down", "--remove-orphans"]

    def test_cleanup_failure_blocks_start(self, tmp_path, mocker):
        """A leftover generator network would overlap TechVault and must fail."""
        from aptl.core.certs import ensure_ssl_certs

        (tmp_path / "config").mkdir()
        certs_dir = tmp_path / "config" / "wazuh_indexer_ssl_certs"

        def fake_run(cmd, **kwargs):
            if "down" in cmd:
                return MagicMock(returncode=1, stdout="", stderr="network is in use")
            certs_dir.mkdir(parents=True, exist_ok=True)
            (certs_dir / "root-ca.pem").write_text("fake-cert")
            return MagicMock(returncode=0, stdout="", stderr="")

        mocker.patch("aptl.core.certs.subprocess.run", side_effect=fake_run)

        result = ensure_ssl_certs(tmp_path)

        assert result.success is False
        assert "cleanup failed" in result.error.lower()
        assert "network is in use" in result.error

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


class TestCertGeneratorComposeFile:
    """Static guardrails on the generator's Compose service definition."""

    def test_generator_entrypoint_override_is_producer_owned(self):
        """The entrypoint override must run the same Wazuh cert workflow
        non-root, on the pinned image, with no chown."""
        compose = yaml.safe_load(_COMPOSE_PATH.read_text())
        generator = compose["services"]["generator"]

        assert generator["image"] == "wazuh/wazuh-certs-generator:0.0.2"
        assert generator["working_dir"] == "/tmp"
        assert "entrypoint" in generator

        entrypoint = generator["entrypoint"]
        script = entrypoint[-1] if isinstance(entrypoint, list) else entrypoint
        assert "wazuh-certs-tool.sh" in script
        assert "chown" not in script
