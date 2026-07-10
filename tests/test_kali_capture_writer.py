"""Unit tests for the kali-capture sidecar writer daemon (ADR-041 / issue #305)."""
from __future__ import annotations

import base64
import importlib.util
import os
import stat
from pathlib import Path

import pytest

# The capture writer runs inside the (Linux) kali container; its 0o700/0o600
# hardening is unenforceable on a Windows host, where st_mode reads 0o666/0o777.
_skip_no_posix_modes = pytest.mark.skipif(
    os.name != "posix", reason="POSIX file modes are unenforced on Windows"
)

# Load writer module from containers/kali-capture/writer.py
_WRITER_PATH = Path(__file__).parent.parent / "containers/kali-capture/writer.py"

# Opaque connection-owner tokens (the writer treats them as hashable handles).
_OWNER_A = 1
_OWNER_B = 2


def _load_writer():
    if not _WRITER_PATH.exists():
        pytest.skip("containers/kali-capture/writer.py not yet written")
    spec = importlib.util.spec_from_file_location("kali_capture_writer", _WRITER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def writer_mod():
    return _load_writer()


class TestIdValidation:
    def test_valid_simple(self, writer_mod):
        assert writer_mod.validate_id("abc123", "x") == "abc123"

    def test_valid_underscore_prefix(self, writer_mod):
        assert writer_mod.validate_id("_unbound", "x") == "_unbound"

    def test_valid_dot_dash(self, writer_mod):
        assert writer_mod.validate_id("run-1.0", "x") == "run-1.0"

    def test_dotdot_rejected(self, writer_mod):
        with pytest.raises(ValueError, match=".."):
            writer_mod.validate_id("../evil", "x")

    def test_slash_rejected(self, writer_mod):
        with pytest.raises(ValueError, match="invalid"):
            writer_mod.validate_id("a/b", "x")

    def test_empty_rejected(self, writer_mod):
        with pytest.raises(ValueError):
            writer_mod.validate_id("", "x")

    def test_leading_dot_rejected(self, writer_mod):
        with pytest.raises(ValueError):
            writer_mod.validate_id(".hidden", "x")


class TestMessageParsing:
    def test_path_bearing_message_rejected(self, writer_mod):
        frame = {"type": "session_start", "run_id": "r1", "session_id": "s1", "output_path": "/evil"}
        with pytest.raises(ValueError, match="forbidden"):
            writer_mod.validate_frame(frame)

    def test_delete_message_rejected(self, writer_mod):
        frame = {"type": "delete", "run_id": "r1", "session_id": "s1"}
        with pytest.raises(ValueError, match="forbidden"):
            writer_mod.validate_frame(frame)

    def test_truncate_message_rejected(self, writer_mod):
        frame = {"type": "truncate", "run_id": "r1", "session_id": "s1"}
        with pytest.raises(ValueError, match="forbidden"):
            writer_mod.validate_frame(frame)

    def test_chmod_field_rejected(self, writer_mod):
        frame = {"type": "session_start", "run_id": "r1", "session_id": "s1", "chmod": "777"}
        with pytest.raises(ValueError, match="forbidden"):
            writer_mod.validate_frame(frame)

    def test_valid_session_start_accepted(self, writer_mod):
        frame = {"type": "session_start", "run_id": "r1", "session_id": "s1", "ts": 1}
        writer_mod.validate_frame(frame)  # should not raise

    def test_valid_pty_chunk_accepted(self, writer_mod):
        frame = {
            "type": "pty_chunk",
            "session_id": "s1",
            "ts": 1,
            "b64": base64.b64encode(b"hello").decode(),
        }
        writer_mod.validate_frame(frame)  # should not raise

    def test_valid_session_end_accepted(self, writer_mod):
        frame = {"type": "session_end", "session_id": "s1", "ts": 1}
        writer_mod.validate_frame(frame)  # should not raise


class TestSessionDirs:
    @_skip_no_posix_modes
    def test_session_start_creates_dirs(self, writer_mod, tmp_path):
        capture_root = str(tmp_path / "captures")
        state = writer_mod.WriterState(capture_root=capture_root)
        assert state.handle_session_start("runA", "sessB", _OWNER_A) is True
        pty_dir = tmp_path / "captures" / "runA" / "sessB" / "pty"
        pcap_dir = tmp_path / "captures" / "runA" / "sessB" / "pcap"
        assert pty_dir.is_dir()
        assert pcap_dir.is_dir()
        assert (stat.S_IMODE(pty_dir.stat().st_mode) & 0o777) == 0o700
        assert (stat.S_IMODE(pcap_dir.stat().st_mode) & 0o777) == 0o700

    def test_pty_chunk_appends_bytes(self, writer_mod, tmp_path):
        capture_root = str(tmp_path / "captures")
        state = writer_mod.WriterState(capture_root=capture_root)
        state.handle_session_start("runA", "sessB", _OWNER_A)
        raw = b"hello world"
        state.handle_pty_chunk("sessB", base64.b64encode(raw).decode(), _OWNER_A)
        ts_file = tmp_path / "captures" / "runA" / "sessB" / "pty" / "typescript"
        assert ts_file.read_bytes() == raw

    def test_pty_chunk_appends_multiple(self, writer_mod, tmp_path):
        capture_root = str(tmp_path / "captures")
        state = writer_mod.WriterState(capture_root=capture_root)
        state.handle_session_start("runX", "sessY", _OWNER_A)
        state.handle_pty_chunk("sessY", base64.b64encode(b"foo").decode(), _OWNER_A)
        state.handle_pty_chunk("sessY", base64.b64encode(b"bar").decode(), _OWNER_A)
        ts_file = tmp_path / "captures" / "runX" / "sessY" / "pty" / "typescript"
        assert ts_file.read_bytes() == b"foobar"

    def test_pty_chunk_unknown_session_ignored(self, writer_mod, tmp_path):
        capture_root = str(tmp_path / "captures")
        state = writer_mod.WriterState(capture_root=capture_root)
        # No session started — should not crash
        state.handle_pty_chunk("no_such_session", base64.b64encode(b"x").decode(), _OWNER_A)

    def test_session_end_marks_closed(self, writer_mod, tmp_path):
        capture_root = str(tmp_path / "captures")
        state = writer_mod.WriterState(capture_root=capture_root)
        state.handle_session_start("runA", "sessC", _OWNER_A)
        state.handle_session_end("sessC", _OWNER_A)
        assert "sessC" not in state.active_sessions

    @_skip_no_posix_modes
    def test_typescript_file_mode_0600(self, writer_mod, tmp_path):
        capture_root = str(tmp_path / "captures")
        state = writer_mod.WriterState(capture_root=capture_root)
        state.handle_session_start("runA", "sessD", _OWNER_A)
        state.handle_pty_chunk("sessD", base64.b64encode(b"x").decode(), _OWNER_A)
        state.handle_session_end("sessD", _OWNER_A)
        ts_file = tmp_path / "captures" / "runA" / "sessD" / "pty" / "typescript"
        if ts_file.exists():
            assert (stat.S_IMODE(ts_file.stat().st_mode) & 0o777) == 0o600


class TestConnectionOwnership:
    """Codex pre-push F1/F3: a session is owned by the connection that started
    it. Other connections cannot inject bytes into it, end it, or clobber it,
    and a dropped connection finalizes the sessions it owned.
    """

    def test_pty_chunk_from_non_owner_ignored(self, writer_mod, tmp_path):
        state = writer_mod.WriterState(capture_root=str(tmp_path / "captures"))
        state.handle_session_start("runA", "sess1", _OWNER_A)
        # Owner B tries to forge bytes into owner A's session — must be ignored.
        state.handle_pty_chunk("sess1", base64.b64encode(b"FORGED").decode(), _OWNER_B)
        # Owner A's legit bytes land.
        state.handle_pty_chunk("sess1", base64.b64encode(b"real").decode(), _OWNER_A)
        ts = tmp_path / "captures" / "runA" / "sess1" / "pty" / "typescript"
        assert ts.read_bytes() == b"real"

    def test_session_end_from_non_owner_ignored(self, writer_mod, tmp_path):
        state = writer_mod.WriterState(capture_root=str(tmp_path / "captures"))
        state.handle_session_start("runA", "sess2", _OWNER_A)
        # Owner B tries to end owner A's session early — must be ignored.
        state.handle_session_end("sess2", _OWNER_B)
        assert "sess2" in state.active_sessions
        # The real owner can still end it.
        state.handle_session_end("sess2", _OWNER_A)
        assert "sess2" not in state.active_sessions

    def test_duplicate_start_different_owner_rejected(self, writer_mod, tmp_path):
        state = writer_mod.WriterState(capture_root=str(tmp_path / "captures"))
        state.handle_session_start("runA", "sess3", _OWNER_A)
        state.handle_pty_chunk("sess3", base64.b64encode(b"keep").decode(), _OWNER_A)
        # Owner B re-starts the same session id: must be rejected, not clobber.
        assert state.handle_session_start("runA", "sess3", _OWNER_B) is False
        assert state.active_sessions["sess3"]["owner"] == _OWNER_A
        # Owner A's data is intact (no truncating re-open).
        state.handle_pty_chunk("sess3", base64.b64encode(b"more").decode(), _OWNER_A)
        ts = tmp_path / "captures" / "runA" / "sess3" / "pty" / "typescript"
        assert ts.read_bytes() == b"keepmore"

    def test_duplicate_start_same_owner_idempotent(self, writer_mod, tmp_path):
        state = writer_mod.WriterState(capture_root=str(tmp_path / "captures"))
        assert state.handle_session_start("runA", "sess4", _OWNER_A) is True
        assert state.handle_session_start("runA", "sess4", _OWNER_A) is True

    def test_reopen_after_finalize_rejected(self, writer_mod, tmp_path):
        # A session id is single-use: once finalized it must not be reopened for
        # append, or forged bytes could be tacked onto harvested evidence
        # (codex cycle 2 F3).
        state = writer_mod.WriterState(capture_root=str(tmp_path / "captures"))
        state.handle_session_start("runA", "sess5", _OWNER_A)
        state.handle_pty_chunk("sess5", base64.b64encode(b"original").decode(), _OWNER_A)
        state.handle_session_end("sess5", _OWNER_A)
        # A fresh connection tries to reopen the same id — must be rejected.
        assert state.handle_session_start("runA", "sess5", _OWNER_B) is False
        # And the post-finalize append is dropped (session is not active).
        state.handle_pty_chunk("sess5", base64.b64encode(b"FORGED").decode(), _OWNER_B)
        ts = tmp_path / "captures" / "runA" / "sess5" / "pty" / "typescript"
        assert ts.read_bytes() == b"original"

    def test_finalize_owner_closes_owned_sessions(self, writer_mod, tmp_path):
        state = writer_mod.WriterState(capture_root=str(tmp_path / "captures"))
        state.handle_session_start("runA", "sessE", _OWNER_A)
        state.handle_session_start("runA", "sessF", _OWNER_A)
        state.handle_session_start("runA", "sessG", _OWNER_B)
        # Connection A drops: only its sessions finalize; B's stays.
        state.finalize_owner(_OWNER_A)
        assert "sessE" not in state.active_sessions
        assert "sessF" not in state.active_sessions
        assert "sessG" in state.active_sessions

    def test_ping_and_peercred_helpers_exist(self, writer_mod):
        # The connection handler reads SO_PEERCRED for forensics; the helper
        # must be present and tolerate a non-socket gracefully.
        assert hasattr(writer_mod, "peer_credentials")
        assert writer_mod.peer_credentials(object()) is None


class _FakeProc:
    """Stand-in for a tcpdump subprocess.Popen handle."""

    def __init__(self):
        self.terminated = False
        self.killed = False
        self.waited = False

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.waited = True
        return 0

    def kill(self):
        self.killed = True


class TestPcapLifecycle:
    """tcpdump per-session lifecycle (ADR-041): the sidecar owns pcap.

    The real tcpdump is never spawned in unit tests — ``pcap_spawn`` is
    injected so the lifecycle (start on session_start, terminate on
    session_end) is asserted without NET_RAW or a packet source.
    """

    def test_pcap_disabled_by_default(self, writer_mod, tmp_path):
        # Default WriterState must NOT spawn tcpdump, so the bare unit tests
        # above never launch a real capture.
        calls = []

        def spy_spawn(argv, **kwargs):
            calls.append(argv)
            return _FakeProc()

        state = writer_mod.WriterState(
            capture_root=str(tmp_path / "captures"), pcap_spawn=spy_spawn
        )
        state.handle_session_start("runA", "sessP", _OWNER_A)
        assert calls == [], "tcpdump must not spawn when enable_pcap is False"

    def test_session_start_launches_pcap(self, writer_mod, tmp_path):
        calls = []

        def spy_spawn(argv, **kwargs):
            calls.append(argv)
            return _FakeProc()

        state = writer_mod.WriterState(
            capture_root=str(tmp_path / "captures"),
            enable_pcap=True,
            pcap_spawn=spy_spawn,
        )
        state.handle_session_start("runA", "sessP", _OWNER_A)
        assert len(calls) == 1, "tcpdump should be spawned once on session_start"
        argv = calls[0]
        assert argv[0] == "tcpdump"
        # Writes into the per-session pcap dir.
        pcap_path = str(tmp_path / "captures" / "runA" / "sessP" / "pcap" / "session.pcap")
        assert pcap_path in argv, f"tcpdump should target {pcap_path}; got {argv}"
        # Drops the SSH control noise.
        assert "not port 22" in argv

    def test_session_end_kills_pcap(self, writer_mod, tmp_path):
        fake = _FakeProc()

        def spy_spawn(argv, **kwargs):
            return fake

        state = writer_mod.WriterState(
            capture_root=str(tmp_path / "captures"),
            enable_pcap=True,
            pcap_spawn=spy_spawn,
        )
        state.handle_session_start("runA", "sessQ", _OWNER_A)
        assert not fake.terminated
        state.handle_session_end("sessQ", _OWNER_A)
        assert fake.terminated, "tcpdump must be terminated on session_end"

    def test_finalize_owner_kills_pcap(self, writer_mod, tmp_path):
        fake = _FakeProc()
        state = writer_mod.WriterState(
            capture_root=str(tmp_path / "captures"),
            enable_pcap=True,
            pcap_spawn=lambda argv, **kw: fake,
        )
        state.handle_session_start("runA", "sessQ2", _OWNER_A)
        # Connection drop (EOF) must stop the tcpdump too.
        state.finalize_owner(_OWNER_A)
        assert fake.terminated, "tcpdump must be terminated on connection drop"

    def test_pcap_command_uses_fixed_rotation(self, writer_mod, tmp_path):
        argv = writer_mod.default_pcap_command(tmp_path / "session.pcap")
        # Rotation flags cap a single session's pcap footprint.
        assert "-C" in argv and "100" in argv
        assert "-W" in argv and "10" in argv

    def test_pcap_start_failure_is_best_effort(self, writer_mod, tmp_path):
        # A tcpdump that fails to spawn must not break the session — the
        # typescript still records.
        def boom_spawn(argv, **kwargs):
            raise FileNotFoundError("tcpdump not installed")

        state = writer_mod.WriterState(
            capture_root=str(tmp_path / "captures"),
            enable_pcap=True,
            pcap_spawn=boom_spawn,
        )
        state.handle_session_start("runA", "sessR", _OWNER_A)  # must not raise
        state.handle_pty_chunk("sessR", base64.b64encode(b"data").decode(), _OWNER_A)
        state.handle_session_end("sessR", _OWNER_A)
        ts_file = tmp_path / "captures" / "runA" / "sessR" / "pty" / "typescript"
        assert ts_file.read_bytes() == b"data"
