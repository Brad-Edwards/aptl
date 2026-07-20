"""Tests for SSH key generation and distribution.

Tests are written FIRST (TDD). All subprocess and filesystem calls are mocked.
Uses tmp_path for directory operations.
"""

from pathlib import Path
from unittest.mock import MagicMock, call

import pytest


class TestEnsureSSHKeys:
    """Tests for SSH key generation and distribution."""

    @pytest.fixture(autouse=True)
    def _default_posix_hardening(self, mocker):
        """Default key-hardening to the POSIX (os.chmod) path.

        On a Windows host the product hardens keys with ``icacls`` instead of
        ``chmod``; these tests assert the POSIX mechanics, so pin the gate to
        POSIX by default. The dedicated ``test_windows_*`` cases re-patch
        ``is_windows`` to ``True`` and that later patch wins for their duration.
        On Linux this is a no-op (``is_windows`` is already False).
        """
        mocker.patch("aptl.core.ssh.hostenv.is_windows", return_value=False)

    def test_existing_key_does_not_call_keygen(self, tmp_path, mocker):
        """When key already exists, ssh-keygen should not be called."""
        from aptl.core.ssh import ensure_ssh_keys

        host_ssh_dir = tmp_path / ".ssh"
        host_ssh_dir.mkdir()
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        # Create existing key pair
        private_key = host_ssh_dir / "aptl_lab_key"
        private_key.write_text("existing-private-key")
        public_key = host_ssh_dir / "aptl_lab_key.pub"
        public_key.write_text("existing-public-key")

        mock_run = mocker.patch("aptl.core.ssh.subprocess.run")
        mock_chmod = mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_ssh_keys(keys_dir=keys_dir, host_ssh_dir=host_ssh_dir)

        assert result.success is True
        assert result.generated is False
        # ssh-keygen should NOT have been called
        mock_run.assert_not_called()
        # Public key should be copied to keys_dir
        assert (keys_dir / "aptl_lab_key.pub").read_text() == "existing-public-key"
        assert (keys_dir / "authorized_keys").read_text() == "existing-public-key"

    def test_missing_key_calls_keygen(self, tmp_path, mocker):
        """When key doesn't exist, ssh-keygen should be called with correct args."""
        from aptl.core.ssh import ensure_ssh_keys

        host_ssh_dir = tmp_path / ".ssh"
        host_ssh_dir.mkdir()
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        key_path = host_ssh_dir / "aptl_lab_key"
        pub_path = host_ssh_dir / "aptl_lab_key.pub"

        def fake_keygen(cmd, **kwargs):
            """Simulate ssh-keygen creating the key files."""
            key_path.write_text("generated-private-key")
            pub_path.write_text("generated-public-key")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run = mocker.patch("aptl.core.ssh.subprocess.run", side_effect=fake_keygen)
        mock_chmod = mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_ssh_keys(keys_dir=keys_dir, host_ssh_dir=host_ssh_dir)

        assert result.success is True
        assert result.generated is True
        assert result.key_path == key_path

        # Verify ssh-keygen was called with correct args
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "ssh-keygen" in cmd
        assert "-t" in cmd
        assert "ed25519" in cmd
        assert "-N" in cmd  # No passphrase
        assert str(key_path) in cmd

    def test_creates_directories_if_missing(self, tmp_path, mocker):
        """Should create keys_dir and host_ssh_dir if they don't exist."""
        from aptl.core.ssh import ensure_ssh_keys

        host_ssh_dir = tmp_path / "new_ssh"
        keys_dir = tmp_path / "new_keys"

        # Neither directory exists yet
        assert not host_ssh_dir.exists()
        assert not keys_dir.exists()

        key_path = host_ssh_dir / "aptl_lab_key"
        pub_path = host_ssh_dir / "aptl_lab_key.pub"

        def fake_keygen(cmd, **kwargs):
            key_path.write_text("private-key")
            pub_path.write_text("public-key")
            return MagicMock(returncode=0, stdout="", stderr="")

        mocker.patch("aptl.core.ssh.subprocess.run", side_effect=fake_keygen)
        mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_ssh_keys(keys_dir=keys_dir, host_ssh_dir=host_ssh_dir)

        assert result.success is True
        assert host_ssh_dir.exists()
        assert keys_dir.exists()

    def test_keygen_failure_returns_error(self, tmp_path, mocker):
        """If ssh-keygen returns non-zero, should return failure result."""
        from aptl.core.ssh import ensure_ssh_keys

        host_ssh_dir = tmp_path / ".ssh"
        host_ssh_dir.mkdir()
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        mock_run = mocker.patch(
            "aptl.core.ssh.subprocess.run",
            return_value=MagicMock(
                returncode=1,
                stdout="",
                stderr="ssh-keygen: permission denied",
            ),
        )
        mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_ssh_keys(keys_dir=keys_dir, host_ssh_dir=host_ssh_dir)

        assert result.success is False
        assert "permission denied" in result.error

    def test_missing_ssh_keygen_returns_error(self, tmp_path, mocker):
        """Missing ssh-keygen should not crash lab startup."""
        from aptl.core.ssh import ensure_ssh_keys

        host_ssh_dir = tmp_path / ".ssh"
        host_ssh_dir.mkdir()
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        mocker.patch(
            "aptl.core.ssh.subprocess.run",
            side_effect=FileNotFoundError("ssh-keygen"),
        )
        mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_ssh_keys(keys_dir=keys_dir, host_ssh_dir=host_ssh_dir)

        assert result.success is False
        assert "ssh-keygen" in result.error

    def test_sets_correct_file_permissions(self, tmp_path, mocker):
        """Should set 600 on private key and 644 on public key."""
        from aptl.core.ssh import ensure_ssh_keys

        host_ssh_dir = tmp_path / ".ssh"
        host_ssh_dir.mkdir()
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        key_path = host_ssh_dir / "aptl_lab_key"
        pub_path = host_ssh_dir / "aptl_lab_key.pub"

        def fake_keygen(cmd, **kwargs):
            key_path.write_text("private-key")
            pub_path.write_text("public-key")
            return MagicMock(returncode=0, stdout="", stderr="")

        mocker.patch("aptl.core.ssh.subprocess.run", side_effect=fake_keygen)
        mock_chmod = mocker.patch("aptl.core.ssh.os.chmod")

        ensure_ssh_keys(keys_dir=keys_dir, host_ssh_dir=host_ssh_dir)

        # Verify chmod calls: 600 for private key, 644 for public key
        chmod_calls = mock_chmod.call_args_list
        paths_and_modes = [(str(c[0][0]), c[0][1]) for c in chmod_calls]

        assert (str(key_path), 0o600) in paths_and_modes
        assert (str(pub_path), 0o644) in paths_and_modes

    def test_windows_hardens_private_key_with_icacls(self, tmp_path, mocker):
        """Windows OpenSSH key privacy uses NTFS ACLs, not POSIX chmod."""
        from aptl.core.ssh import ensure_ssh_keys

        host_ssh_dir = tmp_path / ".ssh"
        host_ssh_dir.mkdir()
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        key_path = host_ssh_dir / "aptl_lab_key"
        pub_path = host_ssh_dir / "aptl_lab_key.pub"

        def fake_run(cmd, **kwargs):
            if cmd[0] == "ssh-keygen":
                key_path.write_text("private-key")
                pub_path.write_text("public-key")
            return MagicMock(returncode=0, stdout="", stderr="")

        mocker.patch("aptl.core.ssh.hostenv.is_windows", return_value=True)
        mocker.patch("aptl.core.ssh.getpass.getuser", return_value="alice")
        mock_run = mocker.patch("aptl.core.ssh.subprocess.run", side_effect=fake_run)
        mock_chmod = mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_ssh_keys(keys_dir=keys_dir, host_ssh_dir=host_ssh_dir)

        assert result.success is True
        mock_chmod.assert_not_called()
        assert [
            "icacls",
            str(key_path),
            "/inheritance:r",
            "/grant:r",
            "alice:R",
        ] in [call_args.args[0] for call_args in mock_run.call_args_list]

    def test_windows_icacls_failure_returns_error(self, tmp_path, mocker):
        """A failed Windows ACL hardening step should be explicit."""
        from aptl.core.ssh import ensure_ssh_keys

        host_ssh_dir = tmp_path / ".ssh"
        host_ssh_dir.mkdir()
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        key_path = host_ssh_dir / "aptl_lab_key"
        pub_path = host_ssh_dir / "aptl_lab_key.pub"

        def fake_run(cmd, **kwargs):
            if cmd[0] == "ssh-keygen":
                key_path.write_text("private-key")
                pub_path.write_text("public-key")
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=1, stdout="", stderr="Access is denied.")

        mocker.patch("aptl.core.ssh.hostenv.is_windows", return_value=True)
        mocker.patch("aptl.core.ssh.getpass.getuser", return_value="alice")
        mocker.patch("aptl.core.ssh.subprocess.run", side_effect=fake_run)
        mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_ssh_keys(keys_dir=keys_dir, host_ssh_dir=host_ssh_dir)

        assert result.success is False
        assert "icacls" in result.error
        assert "Access is denied" in result.error

    def test_copies_pub_to_both_locations(self, tmp_path, mocker):
        """Should copy .pub to both aptl_lab_key.pub and authorized_keys in keys_dir."""
        from aptl.core.ssh import ensure_ssh_keys

        host_ssh_dir = tmp_path / ".ssh"
        host_ssh_dir.mkdir()
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        key_path = host_ssh_dir / "aptl_lab_key"
        pub_path = host_ssh_dir / "aptl_lab_key.pub"

        def fake_keygen(cmd, **kwargs):
            key_path.write_text("private-key")
            pub_path.write_text("ssh-ed25519 AAAA... user@host")
            return MagicMock(returncode=0, stdout="", stderr="")

        mocker.patch("aptl.core.ssh.subprocess.run", side_effect=fake_keygen)
        mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_ssh_keys(keys_dir=keys_dir, host_ssh_dir=host_ssh_dir)

        assert result.success is True
        assert (keys_dir / "aptl_lab_key.pub").read_text() == "ssh-ed25519 AAAA... user@host"
        assert (keys_dir / "authorized_keys").read_text() == "ssh-ed25519 AAAA... user@host"

    def test_result_contains_key_path(self, tmp_path, mocker):
        """SSHKeyResult should contain the path to the private key."""
        from aptl.core.ssh import ensure_ssh_keys

        host_ssh_dir = tmp_path / ".ssh"
        host_ssh_dir.mkdir()
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        # Create existing keys
        private_key = host_ssh_dir / "aptl_lab_key"
        private_key.write_text("existing-key")
        pub_key = host_ssh_dir / "aptl_lab_key.pub"
        pub_key.write_text("existing-pub")

        mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_ssh_keys(keys_dir=keys_dir, host_ssh_dir=host_ssh_dir)

        assert result.key_path == private_key

    def test_missing_pubkey_after_keygen_returns_error(self, tmp_path, mocker):
        """Should return failure when keygen returns 0 but .pub is missing (C5)."""
        from aptl.core.ssh import ensure_ssh_keys

        host_ssh_dir = tmp_path / ".ssh"
        host_ssh_dir.mkdir()
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        key_path = host_ssh_dir / "aptl_lab_key"

        def fake_keygen(cmd, **kwargs):
            """Simulate keygen creating private key but NOT the .pub file."""
            key_path.write_text("generated-private-key")
            # Deliberately do NOT create .pub
            return MagicMock(returncode=0, stdout="", stderr="")

        mocker.patch("aptl.core.ssh.subprocess.run", side_effect=fake_keygen)
        mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_ssh_keys(keys_dir=keys_dir, host_ssh_dir=host_ssh_dir)

        assert result.success is False
        assert "public key" in result.error.lower() or "pub" in result.error.lower()

    def test_uses_correct_comment_string(self, tmp_path, mocker):
        """Should use 'aptl-local-lab' as the SSH key comment (B2)."""
        from aptl.core.ssh import ensure_ssh_keys

        host_ssh_dir = tmp_path / ".ssh"
        host_ssh_dir.mkdir()
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        key_path = host_ssh_dir / "aptl_lab_key"
        pub_path = host_ssh_dir / "aptl_lab_key.pub"

        def fake_keygen(cmd, **kwargs):
            key_path.write_text("private-key")
            pub_path.write_text("public-key")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run = mocker.patch("aptl.core.ssh.subprocess.run", side_effect=fake_keygen)
        mocker.patch("aptl.core.ssh.os.chmod")

        ensure_ssh_keys(keys_dir=keys_dir, host_ssh_dir=host_ssh_dir)

        cmd = mock_run.call_args[0][0]
        comment_idx = cmd.index("-C")
        assert cmd[comment_idx + 1] == "aptl-local-lab"


class TestEnsurePivotKey:
    """Tests for the kali pivot key (scenario content) — SEC #417."""

    @pytest.fixture(autouse=True)
    def _default_posix_hardening(self, mocker):
        """Default key-hardening to the POSIX (os.chmod) path; the
        ``test_windows_*`` case re-patches ``is_windows`` to True. See the
        matching fixture on TestEnsureSSHKeys for the full rationale."""
        mocker.patch("aptl.core.ssh.hostenv.is_windows", return_value=False)

    def test_generates_pivot_key_when_missing(self, tmp_path, mocker):
        from aptl.core.ssh import ensure_pivot_key

        pivot_dir = tmp_path / "config" / "lab-ssh"

        key_path = pivot_dir / "kali_pivot_key"
        pub_path = pivot_dir / "kali_pivot_key.pub"

        def fake_keygen(cmd, **kwargs):
            key_path.write_text("generated-pivot-private")
            pub_path.write_text("generated-pivot-public")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run = mocker.patch(
            "aptl.core.ssh.subprocess.run", side_effect=fake_keygen
        )
        mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_pivot_key(pivot_dir=pivot_dir)

        assert result.success is True
        assert result.generated is True
        assert result.key_path == key_path
        cmd = mock_run.call_args[0][0]
        assert "ed25519" in cmd
        comment_idx = cmd.index("-C")
        assert cmd[comment_idx + 1] == "aptl-kali-pivot"

    def test_existing_pivot_key_is_reused(self, tmp_path, mocker):
        from aptl.core.ssh import ensure_pivot_key

        pivot_dir = tmp_path / "config" / "lab-ssh"
        pivot_dir.mkdir(parents=True)
        (pivot_dir / "kali_pivot_key").write_text("existing-pivot-private")
        (pivot_dir / "kali_pivot_key.pub").write_text("existing-pivot-public")

        mock_run = mocker.patch("aptl.core.ssh.subprocess.run")
        mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_pivot_key(pivot_dir=pivot_dir)

        assert result.success is True
        assert result.generated is False
        mock_run.assert_not_called()

    def test_pivot_keygen_failure_returns_error(self, tmp_path, mocker):
        from aptl.core.ssh import ensure_pivot_key

        pivot_dir = tmp_path / "config" / "lab-ssh"

        mocker.patch(
            "aptl.core.ssh.subprocess.run",
            return_value=MagicMock(
                returncode=1, stdout="", stderr="ssh-keygen: disk full"
            ),
        )
        mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_pivot_key(pivot_dir=pivot_dir)

        assert result.success is False
        assert "disk full" in result.error

    def test_missing_pivot_ssh_keygen_returns_error(self, tmp_path, mocker):
        from aptl.core.ssh import ensure_pivot_key

        pivot_dir = tmp_path / "config" / "lab-ssh"
        mocker.patch(
            "aptl.core.ssh.subprocess.run",
            side_effect=FileNotFoundError("ssh-keygen"),
        )
        mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_pivot_key(pivot_dir=pivot_dir)

        assert result.success is False
        assert "ssh-keygen" in result.error

    def test_pivot_key_is_separate_from_control_plane_key(self, tmp_path, mocker):
        """The pivot key must never be the control-plane key name."""
        from aptl.core.ssh import ensure_pivot_key

        pivot_dir = tmp_path / "config" / "lab-ssh"

        def fake_keygen(cmd, **kwargs):
            (pivot_dir / "kali_pivot_key").write_text("priv")
            (pivot_dir / "kali_pivot_key.pub").write_text("pub")
            return MagicMock(returncode=0, stdout="", stderr="")

        mocker.patch("aptl.core.ssh.subprocess.run", side_effect=fake_keygen)
        mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_pivot_key(pivot_dir=pivot_dir)

        assert result.key_path.name == "kali_pivot_key"
        assert not (pivot_dir / "aptl_lab_key").exists()

    def test_windows_pivot_key_uses_icacls_not_chmod(self, tmp_path, mocker):
        """The Windows host never calls POSIX chmod for the pivot key."""
        from aptl.core.ssh import ensure_pivot_key

        pivot_dir = tmp_path / "config" / "lab-ssh"
        key_path = pivot_dir / "kali_pivot_key"
        pub_path = pivot_dir / "kali_pivot_key.pub"

        def fake_run(cmd, **kwargs):
            if cmd[0] == "ssh-keygen":
                key_path.write_text("priv")
                pub_path.write_text("pub")
            return MagicMock(returncode=0, stdout="", stderr="")

        mocker.patch("aptl.core.ssh.hostenv.is_windows", return_value=True)
        mocker.patch("aptl.core.ssh.getpass.getuser", return_value="alice")
        mock_run = mocker.patch("aptl.core.ssh.subprocess.run", side_effect=fake_run)
        mock_chmod = mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_pivot_key(pivot_dir=pivot_dir)

        assert result.success is True
        mock_chmod.assert_not_called()
        assert [
            "icacls",
            str(key_path),
            "/inheritance:r",
            "/grant:r",
            "alice:R",
        ] in [call_args.args[0] for call_args in mock_run.call_args_list]


class TestEnsureTargetAuthorizedKeys:
    """Tests for the combined target authorized_keys file — SEC #417 / #581.

    Targets (victim, workstation, ...) must authorize both the operator
    control-plane key and the kali pivot key, or kali's in-scenario SSH
    pivot into them fails. Caught by a real local live-gate boot: SSH to
    victim/kali timed out because no authorized_keys content was ever placed
    once these nodes moved off their hand-authored entrypoint scripts onto
    SDL-declared realization.
    """

    @pytest.fixture(autouse=True)
    def _default_posix_hardening(self, mocker):
        mocker.patch("aptl.core.ssh.hostenv.is_windows", return_value=False)

    def test_combines_both_public_keys(self, tmp_path, mocker):
        from aptl.core.ssh import ensure_target_authorized_keys

        keys_dir = tmp_path / "keys"
        pivot_dir = tmp_path / "config" / "lab-ssh"
        keys_dir.mkdir(parents=True)
        pivot_dir.mkdir(parents=True)
        (keys_dir / "aptl_lab_key.pub").write_text("ssh-ed25519 CONTROLPLANE\n")
        (pivot_dir / "kali_pivot_key.pub").write_text("ssh-ed25519 PIVOT")
        mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_target_authorized_keys(keys_dir=keys_dir, pivot_dir=pivot_dir)

        assert result.success is True
        combined = (keys_dir / "target_authorized_keys").read_text()
        assert combined == "ssh-ed25519 CONTROLPLANE\nssh-ed25519 PIVOT\n"

    def test_missing_control_plane_key_is_an_error(self, tmp_path, mocker):
        from aptl.core.ssh import ensure_target_authorized_keys

        keys_dir = tmp_path / "keys"
        pivot_dir = tmp_path / "config" / "lab-ssh"
        pivot_dir.mkdir(parents=True)
        (pivot_dir / "kali_pivot_key.pub").write_text("ssh-ed25519 PIVOT")
        mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_target_authorized_keys(keys_dir=keys_dir, pivot_dir=pivot_dir)

        assert result.success is False
        assert "aptl_lab_key.pub" in result.error

    def test_missing_pivot_key_is_an_error(self, tmp_path, mocker):
        from aptl.core.ssh import ensure_target_authorized_keys

        keys_dir = tmp_path / "keys"
        pivot_dir = tmp_path / "config" / "lab-ssh"
        keys_dir.mkdir(parents=True)
        (keys_dir / "aptl_lab_key.pub").write_text("ssh-ed25519 CONTROLPLANE")
        mocker.patch("aptl.core.ssh.os.chmod")

        result = ensure_target_authorized_keys(keys_dir=keys_dir, pivot_dir=pivot_dir)

        assert result.success is False
        assert "kali_pivot_key.pub" in result.error
