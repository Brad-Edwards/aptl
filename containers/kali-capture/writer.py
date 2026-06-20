#!/usr/bin/env python3
"""APTL kali-capture sidecar writer daemon (ADR-041 / issue #305).

Binds an abstract Unix socket ``\x00aptl-capture-ctrl`` and handles
JSON-framed newline-delimited messages from the Kali workload wrapper.
All capture paths are derived from validated run/session IDs and a fixed
capture root — the RPC never accepts absolute paths, shell commands,
chmod/chown modes, delete or truncate requests.

Session lifecycle is **owned by a single connection** (codex pre-push
findings F1/F3): the connection that opens a session with ``session_start`` is
the only one allowed to feed it ``pty_chunk`` frames or end it, and the session
is finalized when that connection closes (EOF). A second connection cannot
inject bytes into, end, or clobber another connection's session — at worst it
starts its own. ``SO_PEERCRED`` is read and logged for forensics.

Capability requirements (on the sidecar, NOT the Kali workload):
  AUDIT_CONTROL, AUDIT_WRITE — auditd + auditctl
  SYS_PACCT                  — accton / process accounting
  NET_RAW                    — per-session tcpdump

Python 3.11+ is assumed.  The module is also importable from tests
(no ``__main__`` side-effects when imported).
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import socket
import struct
import subprocess
import threading
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
_log = logging.getLogger("aptl.capture.writer")

# ---------------------------------------------------------------------------
# ID validation — must match the canonical OBS-003 contract:
#   src/aptl/core/runstore.py  _ID_RE
#   mcp/aptl-mcp-common/src/runs.ts  ID_RE
#   containers/kali/scripts/aptl-wrap-shell.sh  valid_id()
# ---------------------------------------------------------------------------
_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")


def validate_id(value: str, kind: str) -> str:
    """Validate *value* as a run or session id.

    Raises :class:`ValueError` on any violation.  Returns *value* unchanged
    when valid so callers can use ``session_id = validate_id(raw, "session_id")``.
    """
    if not value:
        raise ValueError(f"{kind}: id must not be empty")
    if value.startswith("."):
        raise ValueError(f"{kind}: id must not start with '.' (got {value!r})")
    if ".." in value:
        raise ValueError(f"{kind}: id contains '..', which is forbidden (path traversal)")
    if "/" in value:
        raise ValueError(f"{kind}: id contains invalid character '/' (got {value!r})")
    if not _ID_RE.match(value):
        raise ValueError(
            f"{kind}: id {value!r} is invalid — must match {_ID_RE.pattern}"
        )
    return value


# ---------------------------------------------------------------------------
# Forbidden frame types and fields (RPC contract, ADR-041 §RPC Contract)
# ---------------------------------------------------------------------------
_FORBIDDEN_TYPES: frozenset[str] = frozenset(
    {"delete", "truncate", "chmod", "chown", "shell"}
)
_FORBIDDEN_FIELDS: frozenset[str] = frozenset(
    {"output_path", "path", "chmod", "chown", "shell", "cmd", "command", "delete", "truncate"}
)


def validate_frame(frame: dict[str, Any]) -> None:
    """Validate a decoded RPC frame.

    Raises :class:`ValueError` with a message containing ``"forbidden"``
    for any disallowed type or field so tests can ``match="forbidden"``.
    """
    msg_type = frame.get("type", "")
    if msg_type in _FORBIDDEN_TYPES:
        raise ValueError(
            f"forbidden frame type {msg_type!r} — the sidecar RPC does not "
            "accept delete, truncate, chmod, chown, or shell requests"
        )
    for field in _FORBIDDEN_FIELDS:
        if field in frame:
            raise ValueError(
                f"forbidden field {field!r} in frame — the sidecar RPC must not "
                "carry paths, shell commands, chmod/chown modes, or delete/truncate requests"
            )


# ---------------------------------------------------------------------------
# Per-session pcap (tcpdump) — runs in the sidecar, which shares the Kali
# network namespace (docker-compose `network_mode: service:kali`).  The Kali
# workload never runs tcpdump for capture, so a sudo-capable agent cannot stop
# it or delete the pcap.  Rotation (-C 100MB, -W 10) caps one session at ~1GB.
# ---------------------------------------------------------------------------
_PCAP_ROTATE_MB = 100
_PCAP_ROTATE_FILES = 10
# `not port 22` drops the MCP control SSH noise so the pcap stays tractable;
# mirrors the filter the in-Kali wrapper used before ADR-041.
_PCAP_FILTER = "not port 22"


def default_pcap_command(pcap_path: Path) -> list[str]:
    """Build the tcpdump argv for a per-session capture.

    Fixed recorder arguments only — never interpolates a user-controlled
    filter or path fragment (ADR-041 §Security Layers / Process argv).
    """
    return [
        "tcpdump",
        "-i", "any",
        "-w", str(pcap_path),
        "-C", str(_PCAP_ROTATE_MB),
        "-W", str(_PCAP_ROTATE_FILES),
        "-U",
        _PCAP_FILTER,
    ]


# ---------------------------------------------------------------------------
# WriterState — per-session capture lifecycle
# ---------------------------------------------------------------------------

class WriterState:
    """Manage the set of active capture sessions, keyed by session_id.

    Each session is **owned** by the opaque ``owner`` token passed to
    ``handle_session_start`` (the connection handler passes a unique token per
    socket connection).  ``handle_pty_chunk`` / ``handle_session_end`` are
    no-ops unless the caller presents the owning token, and a ``session_start``
    for an already-active session from a different owner is rejected rather
    than clobbering the live capture (codex F1/F3).  ``finalize_owner`` closes
    every session a departing connection owned (EOF-driven finalization).

    ``enable_pcap`` defaults to ``False`` so unit tests that only exercise the
    typescript/dir behaviour never spawn a real ``tcpdump``.  Production
    (``_main``) sets it ``True``.  ``pcap_spawn`` is injectable so tests can
    assert the tcpdump lifecycle with a fake process.
    """

    def __init__(
        self,
        capture_root: str,
        *,
        enable_pcap: bool = False,
        pcap_spawn: Any = None,
    ) -> None:
        self.capture_root = Path(capture_root)
        self.active_sessions: dict[str, dict] = {}
        # Every session id ever started in this writer's lifetime. A session id
        # is single-use: once finalized it must never be reopened for append,
        # or a Kali process could re-`session_start` a finalized id and tack
        # forged bytes onto harvested evidence (codex cycle 2 F3). Session ids
        # are unique per MCP session, so this never blocks a legitimate start.
        self._seen_session_ids: set[str] = set()
        self._lock = threading.Lock()
        self._owner_seq = 0
        self.enable_pcap = enable_pcap
        # Default to subprocess.Popen; injectable for tests.
        self._pcap_spawn = pcap_spawn if pcap_spawn is not None else subprocess.Popen

    def new_owner(self) -> int:
        """Return a process-unique owner token for a freshly-accepted connection."""
        with self._lock:
            self._owner_seq += 1
            return self._owner_seq

    def _start_pcap(self, pcap_dir: Path, session_id: str) -> Any:
        """Start a per-session tcpdump.  Best-effort: a failure (tcpdump
        missing, no NET_RAW) logs and returns ``None`` rather than breaking
        the session — the typescript and audit captures still proceed.
        """
        if not self.enable_pcap:
            return None
        pcap_path = pcap_dir / "session.pcap"
        argv = default_pcap_command(pcap_path)
        try:
            proc = self._pcap_spawn(
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _log.info("session=%s: tcpdump started -> %s", session_id, pcap_path)
            return proc
        except Exception as exc:
            _log.warning("session=%s: tcpdump start failed (degraded): %s", session_id, exc)
            return None

    def _stop_pcap(self, sess: dict, session_id: str) -> None:
        """Terminate the per-session tcpdump and chmod the pcap files 0600."""
        proc = sess.get("pcap_proc")
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception as exc:
                _log.warning("session=%s: error stopping tcpdump: %s", session_id, exc)
                try:
                    proc.kill()
                except Exception:
                    pass
        pcap_dir = sess.get("pcap_dir")
        if pcap_dir is not None:
            for pcap_file in Path(pcap_dir).glob("session.pcap*"):
                try:
                    os.chmod(pcap_file, 0o600)
                except Exception as exc:
                    _log.warning("session=%s: chmod pcap failed: %s", session_id, exc)

    def handle_session_start(self, run_id: str, session_id: str, owner: Any) -> bool:
        """Validate IDs, create 0700 dirs, open typescript file, start pcap.

        Returns ``True`` when the session is owned by ``owner`` after the call
        (freshly created, or already owned by the same connection — idempotent).
        Returns ``False`` without touching anything when the session is already
        active under a DIFFERENT owner: a second connection must not clobber a
        live capture or hijack its ownership.
        """
        run_id = validate_id(run_id, "run_id")
        session_id = validate_id(session_id, "session_id")

        with self._lock:
            existing = self.active_sessions.get(session_id)
            if existing is not None:
                if existing["owner"] == owner:
                    return True  # idempotent re-start on the same connection
                _log.warning(
                    "session=%s: session_start rejected — already owned by another "
                    "connection (refusing to clobber live capture)", session_id,
                )
                return False
            if session_id in self._seen_session_ids:
                # Already started (and since finalized) — refuse to reopen the
                # typescript for append (codex cycle 2 F3).
                _log.warning(
                    "session=%s: session_start rejected — id already used; "
                    "refusing to reopen a finalized session for append", session_id,
                )
                return False
            # Reserve the id now (under the lock) so a racing connection can't
            # double-create it during the unlocked file I/O below.
            self._seen_session_ids.add(session_id)

        sess_dir = self.capture_root / run_id / session_id
        pty_dir = sess_dir / "pty"
        pcap_dir = sess_dir / "pcap"

        for d in (pty_dir, pcap_dir):
            d.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(d, 0o700)

        typescript_path = pty_dir / "typescript"
        ts_file = typescript_path.open("ab")

        pcap_proc = self._start_pcap(pcap_dir, session_id)

        with self._lock:
            # Re-check under the lock in case a racing connection won the create.
            if session_id in self.active_sessions:
                ts_file.close()
                if pcap_proc is not None:
                    try:
                        pcap_proc.terminate()
                    except Exception:
                        pass
                return self.active_sessions[session_id]["owner"] == owner
            self.active_sessions[session_id] = {
                "run_id": run_id,
                "owner": owner,
                "typescript_path": typescript_path,
                "ts_file": ts_file,
                "pcap_dir": pcap_dir,
                "pcap_proc": pcap_proc,
            }
        _log.info("session_start run=%s session=%s owner=%s", run_id, session_id, owner)
        return True

    def handle_pty_chunk(self, session_id: str, b64_data: str, owner: Any) -> None:
        """Append decoded bytes to the session typescript.

        Silently ignores unknown sessions and frames from a non-owning
        connection (codex F3 — a different connection must not forge bytes
        into another session's transcript).
        """
        with self._lock:
            sess = self.active_sessions.get(session_id)
            if sess is None or sess["owner"] != owner:
                return
            ts_file = sess["ts_file"]
        try:
            raw = base64.b64decode(b64_data)
        except Exception:
            _log.warning("session=%s: invalid b64 chunk (discarded)", session_id)
            return
        ts_file.write(raw)
        ts_file.flush()

    def handle_session_end(self, session_id: str, owner: Any) -> None:
        """Finalize the session if ``owner`` owns it: close + chmod the
        typescript, stop tcpdump, remove from active sessions.

        A session_end from a non-owning connection is ignored (codex F3 — a
        different connection must not end another session's capture early).
        """
        with self._lock:
            sess = self.active_sessions.get(session_id)
            if sess is None or sess["owner"] != owner:
                return
            del self.active_sessions[session_id]
        self._finalize(sess, session_id)

    def finalize_owner(self, owner: Any) -> None:
        """Finalize every session owned by ``owner`` (EOF/disconnect cleanup).

        This is the EOF-driven finalization (codex F1): a wrapper that is
        killed or disconnects without a clean session_end still gets its
        typescript closed and its tcpdump stopped.
        """
        with self._lock:
            owned = [
                (sid, sess)
                for sid, sess in self.active_sessions.items()
                if sess["owner"] == owner
            ]
            for sid, _ in owned:
                del self.active_sessions[sid]
        for sid, sess in owned:
            self._finalize(sess, sid)

    def _finalize(self, sess: dict, session_id: str) -> None:
        """Close the typescript (chmod 0600) and stop tcpdump. No lock held."""
        ts_file = sess["ts_file"]
        ts_path: Path = sess["typescript_path"]
        try:
            ts_file.close()
        except Exception as exc:
            _log.warning("session=%s: error closing typescript: %s", session_id, exc)
        if ts_path.exists():
            try:
                os.chmod(ts_path, 0o600)
            except Exception as exc:
                _log.warning("session=%s: chmod 0600 failed: %s", session_id, exc)
        self._stop_pcap(sess, session_id)
        _log.info("session_end session=%s owner=%s", session_id, sess.get("owner"))


# ---------------------------------------------------------------------------
# Peer credentials (SO_PEERCRED) — forensic record of who opened a connection
# ---------------------------------------------------------------------------

def peer_credentials(conn: socket.socket) -> tuple[int, int, int] | None:
    """Return ``(pid, uid, gid)`` of the connecting peer, or ``None``.

    Read for forensics/logging; the authoritative authorization is
    connection-ownership (a session is bound to the connection that started
    it), which holds even when an attacker can become any uid via sudo.
    """
    try:
        data = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", data)
        return pid, uid, gid
    except Exception:
        return None


def _allowed_uids() -> set[int] | None:
    """Optional uid allowlist from ``APTL_CAPTURE_ALLOWED_UIDS`` (comma-sep).

    Returns ``None`` when unset (accept any peer; ownership is the boundary).
    """
    raw = os.environ.get("APTL_CAPTURE_ALLOWED_UIDS", "").strip()
    if not raw:
        return None
    out: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if part:
            try:
                out.add(int(part))
            except ValueError:
                _log.warning("ignoring non-integer uid in APTL_CAPTURE_ALLOWED_UIDS: %r", part)
    return out or None


# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------

def _handle_connection(
    conn: socket.socket,
    state: WriterState,
    allowed_uids: set[int] | None = None,
) -> None:
    """Handle one client connection.

    The connection owns every session it starts.  Newline-delimited JSON
    frames are dispatched; data/state frames for a session are honored only
    while this connection owns it.  When the connection closes (EOF), every
    session it owns is finalized.
    """
    owner = state.new_owner()
    cred = peer_credentials(conn)
    if cred is not None:
        _log.info("connection owner=%s peer pid=%s uid=%s gid=%s", owner, *cred)
        if allowed_uids is not None and cred[1] not in allowed_uids:
            _log.warning(
                "connection owner=%s rejected — peer uid=%s not in allowlist %s",
                owner, cred[1], sorted(allowed_uids),
            )
            try:
                conn.close()
            except Exception:
                pass
            return

    buf = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    frame = json.loads(line.decode("utf-8", errors="replace"))
                except Exception as exc:
                    _log.warning("malformed JSON frame: %s", exc)
                    continue
                if not isinstance(frame, dict):
                    _log.warning("frame is not an object; discarded")
                    continue
                try:
                    validate_frame(frame)
                except ValueError as exc:
                    _log.warning("rejected frame: %s", exc)
                    continue
                _dispatch_frame(frame, state, owner)
    except Exception as exc:
        _log.warning("connection error: %s", exc)
    finally:
        # EOF/disconnect: finalize every session this connection owned so a
        # killed/disconnected wrapper never leaks an open file or tcpdump.
        state.finalize_owner(owner)
        try:
            conn.close()
        except Exception:
            pass


def _dispatch_frame(frame: dict[str, Any], state: WriterState, owner: Any) -> None:
    """Dispatch a single validated frame for the connection identified by *owner*."""
    msg_type = frame.get("type", "")
    try:
        if msg_type == "ping":
            return  # reachability probe (the wrapper's wrapped-vs-unwrapped check)
        if msg_type == "session_start":
            state.handle_session_start(
                frame.get("run_id", ""),
                frame.get("session_id", ""),
                owner,
            )
        elif msg_type == "pty_chunk":
            state.handle_pty_chunk(
                frame.get("session_id", ""),
                frame.get("b64", ""),
                owner,
            )
        elif msg_type == "session_end":
            state.handle_session_end(frame.get("session_id", ""), owner)
        else:
            _log.debug("unhandled frame type: %s", msg_type)
    except Exception as exc:
        _log.warning("error handling frame type=%s: %s", msg_type, exc)


# ---------------------------------------------------------------------------
# Main server
# ---------------------------------------------------------------------------
#
# auditd, process accounting, and the readiness marker are owned by the
# sidecar's entrypoint.sh (which runs before this daemon). Doing it there too
# would start auditd twice — the second start fails and falsely reports the
# subsystem degraded. This module is solely the per-session capture writer.

_CAPTURE_ROOT = os.environ.get("APTL_CAPTURE_ROOT", "/var/log/aptl/captures")
_SOCKET_NAME = os.environ.get("APTL_CAPTURE_SOCKET", "\x00aptl-capture-ctrl")


def _main() -> None:
    capture_root = _CAPTURE_ROOT
    socket_name = _SOCKET_NAME
    allowed_uids = _allowed_uids()

    Path(capture_root).mkdir(mode=0o755, parents=True, exist_ok=True)

    print("=== APTL Kali Capture Writer listening ===", flush=True)
    if allowed_uids is not None:
        _log.info("peer uid allowlist active: %s", sorted(allowed_uids))

    state = WriterState(capture_root=capture_root, enable_pcap=True)

    # Bind abstract Unix socket
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(socket_name)
    srv.listen(64)
    _log.info("capture writer listening on %r", socket_name)

    while True:
        try:
            conn, _ = srv.accept()
        except KeyboardInterrupt:
            _log.info("capture writer shutting down")
            break
        except Exception as exc:
            _log.error("accept error: %s", exc)
            continue
        t = threading.Thread(
            target=_handle_connection,
            args=(conn, state, allowed_uids),
            daemon=True,
        )
        t.start()


if __name__ == "__main__":
    _main()
