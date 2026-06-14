"""Tests for terminal SSH host-key pinning (ADR-039, issue #418).

The terminal relay must verify SSH server identity. These tests cover the
lab-start trust material: where the ``known_hosts`` file lives, how a pin
line is rendered for standard vs. non-standard ports, and that pinning is
captured atomically and degrades gracefully when an endpoint is
unreachable.
"""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("asyncssh", reason="asyncssh not installed")

import asyncssh  # noqa: E402

from aptl.core.host_keys import (  # noqa: E402
    KNOWN_HOSTS_RELPATH,
    HostKeyPinResult,
    format_known_hosts_line,
    known_hosts_path,
    pin_terminal_host_keys,
)
from aptl.core.snapshot import SSHEndpoint  # noqa: E402


def _pubkey() -> "asyncssh.SSHKey":
    """A throwaway public key standing in for a server host key."""
    return asyncssh.generate_private_key("ssh-ed25519").convert_to_public()


class _FakeConn:
    """Async-context-manager stand-in for an ``asyncssh`` connection."""

    def __init__(self, key: "asyncssh.SSHKey") -> None:
        self._key = key

    async def __aenter__(self) -> "_FakeConn":
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    def get_server_host_key(self) -> "asyncssh.SSHKey":
        return self._key


class TestKnownHostsPath:
    def test_under_aptl_state_root(self, tmp_path):
        path = known_hosts_path(tmp_path)
        assert path.name == "known_hosts"
        assert ".aptl" in path.parts
        assert path.is_relative_to(tmp_path.resolve())
        assert path == tmp_path.resolve() / KNOWN_HOSTS_RELPATH


class TestFormatKnownHostsLine:
    def test_standard_port_uses_plain_host(self):
        line = format_known_hosts_line("172.20.2.20", 22, _pubkey())
        fields = line.split()
        assert fields[0] == "172.20.2.20"  # no [host]:port for port 22
        assert fields[1] == "ssh-ed25519"
        assert fields[2]  # base64 key blob present

    def test_non_standard_port_is_bracketed(self):
        line = format_known_hosts_line("localhost", 2027, _pubkey())
        assert line.split()[0] == "[localhost]:2027"

    def test_comment_is_dropped(self):
        # export_public_key may append a comment; the pin keeps only
        # "<keytype> <base64>".
        line = format_known_hosts_line("h", 22, _pubkey())
        assert len(line.split()) == 3


class TestPinTerminalHostKeys:
    def test_writes_file_with_one_line_per_endpoint(self, tmp_path):
        endpoints = [
            SSHEndpoint(name="Victim", host="172.20.2.20", port=22, user="labadmin"),
            SSHEndpoint(name="Reverse", host="172.20.0.27", port=22, user="labadmin"),
        ]
        with patch(
            "aptl.core.host_keys._capture_host_key", return_value=_pubkey()
        ):
            result = pin_terminal_host_keys(tmp_path, endpoints, Path("/fake/key"))

        path = known_hosts_path(tmp_path)
        assert path.exists()
        content = path.read_text()
        assert "172.20.2.20" in content
        assert "172.20.0.27" in content
        assert content.count("\n") == 2
        assert isinstance(result, HostKeyPinResult)
        assert sorted(result.pinned) == ["Reverse", "Victim"]
        assert result.failed == []

    @pytest.mark.skipif(os.name != "posix", reason="POSIX modes only")
    def test_public_file_under_owner_only_dir(self, tmp_path):
        endpoints = [SSHEndpoint(name="Victim", host="10.0.0.1", port=22, user="x")]
        with patch(
            "aptl.core.host_keys._capture_host_key", return_value=_pubkey()
        ):
            pin_terminal_host_keys(tmp_path, endpoints, Path("/fake/key"))
        path = known_hosts_path(tmp_path)
        assert (path.stat().st_mode & 0o777) == 0o644
        assert (path.parent.stat().st_mode & 0o777) == 0o700

    def test_unreachable_endpoint_skipped_not_fatal(self, tmp_path):
        endpoints = [
            SSHEndpoint(name="Victim", host="172.20.2.20", port=22, user="labadmin"),
            SSHEndpoint(name="Down", host="172.20.2.99", port=22, user="labadmin"),
        ]
        key = _pubkey()

        def fake_capture(endpoint, key_path):
            if endpoint.name == "Down":
                raise OSError("connection refused")
            return key

        with patch(
            "aptl.core.host_keys._capture_host_key", side_effect=fake_capture
        ):
            result = pin_terminal_host_keys(tmp_path, endpoints, Path("/fake/key"))

        assert result.pinned == ["Victim"]
        assert result.failed == ["Down"]
        content = known_hosts_path(tmp_path).read_text()
        assert "172.20.2.20" in content
        assert "172.20.2.99" not in content

    def test_no_endpoints_writes_empty_file(self, tmp_path):
        result = pin_terminal_host_keys(tmp_path, [], Path("/fake/key"))
        assert result.pinned == []
        assert result.failed == []
        # The file exists (empty) so the relay's fail-closed check finds a
        # present-but-unmatched known_hosts rather than a missing one.
        assert known_hosts_path(tmp_path).exists()
        assert known_hosts_path(tmp_path).read_text() == ""

    def test_rejects_preexisting_aptl_symlink_before_chmod(self, tmp_path):
        # A pre-existing .aptl symlink to an out-of-tree directory must be
        # rejected by the containment guard BEFORE any chmod/write follows
        # it (ADR-028/ADR-039 containment-before-I/O).
        from aptl.core.host_keys import HostKeyError

        outside = tmp_path / "outside"
        outside.mkdir()
        # Capture the outside dir's mode so we can prove chmod never ran.
        original_mode = outside.stat().st_mode & 0o777
        (tmp_path / ".aptl").symlink_to(outside, target_is_directory=True)

        endpoints = [
            SSHEndpoint(name="Victim", host="10.0.0.1", port=22, user="x")
        ]
        with patch(
            "aptl.core.host_keys._capture_host_key", return_value=_pubkey()
        ):
            with pytest.raises(HostKeyError):
                pin_terminal_host_keys(tmp_path, endpoints, Path("/fake/key"))

        # The out-of-tree target was never chmod'd or written into.
        if os.name == "posix":
            assert (outside.stat().st_mode & 0o777) == original_mode
        assert not (outside / "known_hosts").exists()

    def test_capture_uses_asyncssh_with_tofu_only_here(self, tmp_path):
        key = _pubkey()
        endpoints = [
            SSHEndpoint(name="Victim", host="172.20.2.20", port=22, user="labadmin")
        ]
        with patch(
            "aptl.core.host_keys.asyncssh.connect", return_value=_FakeConn(key)
        ) as mock_connect:
            result = pin_terminal_host_keys(tmp_path, endpoints, Path("/fake/key"))

        mock_connect.assert_called_once()
        kwargs = mock_connect.call_args.kwargs
        # TOFU capture is permitted ONLY inside provisioning.
        assert kwargs["known_hosts"] is None
        assert kwargs["host"] == "172.20.2.20"
        assert kwargs["port"] == 22
        assert kwargs["username"] == "labadmin"
        assert result.pinned == ["Victim"]
