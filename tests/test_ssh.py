"""Tests for SSH key generation and distribution.

Tests are written FIRST (TDD). All subprocess and filesystem calls are mocked.
Uses tmp_path for directory operations.
"""

from pathlib import Path
from unittest.mock import MagicMock, call

import pytest


class TestEnsureSSHKeys:
    """Tests for SSH key generation and distribution."""

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
