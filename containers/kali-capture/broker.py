#!/usr/bin/env python3
"""Sidecar-owned SSH/PTY broker for admitted Kali session capture."""

from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import hashlib
import json
import os
import pty
import re
import selectors
import signal
import socket
import struct
import subprocess
import sys
import termios
import time
import tty
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Iterator, Mapping

_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")
_TRANSCRIPT_BINDING = "aptl.collector.redteam-session-transcript"
_RUNTIME_ROOT = Path(os.environ.get("APTL_CAPTURE_RUNTIME_ROOT", "/run/aptl-capture"))
_CAPTURE_ROOT = Path(os.environ.get("APTL_CAPTURE_ROOT", "/var/log/aptl/captures"))
_INNER_KEY = "/run/aptl-inner/id_ed25519"
_INNER_KNOWN_HOSTS = "/run/aptl-inner/known_hosts"
_MAX_FRAME_BYTES = 1024 * 1024
_MAX_CAPTURE_BYTES = 32 * 1024 * 1024
_MAX_ARTIFACT_COUNT = 4096
_MAX_SESSION_COUNT = _MAX_ARTIFACT_COUNT // 2
_MAX_LEDGER_BYTES = 1024 * 1024


@contextmanager
def _admission_lock(runtime_root: Path) -> Iterator[None]:
    """Serialize broker registration with the admission-closing marker."""

    runtime_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        runtime_root / "admission.lock",
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "capture write made no progress")
        offset += written


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def validate_id(value: str, kind: str) -> str:
    if (
        not value
        or value.startswith(".")
        or ".." in value
        or _ID_RE.fullmatch(value) is None
    ):
        raise ValueError(f"invalid {kind}")
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("capture document is not an object")
    return value


def activate_authority(
    runtime_root: Path,
    *,
    run_id: str,
    plan_id: str,
    binding_id: str,
    now: Callable[[], str] = utc_now,
) -> dict[str, object]:
    """Create the immutable capture authority consumed by the broker."""

    run_id = validate_id(run_id, "run id")
    plan_id = validate_id(plan_id, "plan id")
    if binding_id != _TRANSCRIPT_BINDING:
        raise ValueError("unsupported capture binding")
    path = runtime_root / "authority.json"
    requested = {
        "schema_version": "aptl-kali-capture-authority/v1",
        "run_id": run_id,
        "plan_id": plan_id,
        "binding_id": binding_id,
        "activated_at": now(),
    }
    try:
        _write_exclusive(path, _canonical(requested))
        return requested
    except FileExistsError:
        existing = _read_json(path)
        identity = ("schema_version", "run_id", "plan_id", "binding_id")
        if any(existing.get(key) != requested[key] for key in identity):
            raise ValueError("capture authority conflict") from None
        return existing


def read_authority(runtime_root: Path = _RUNTIME_ROOT) -> dict[str, object]:
    authority = _read_json(runtime_root / "authority.json")
    activate_authority_fields = (
        str(authority.get("run_id", "")),
        str(authority.get("plan_id", "")),
        str(authority.get("binding_id", "")),
    )
    validate_id(activate_authority_fields[0], "run id")
    validate_id(activate_authority_fields[1], "plan id")
    if activate_authority_fields[2] != _TRANSCRIPT_BINDING:
        raise ValueError("unsupported capture binding")
    return authority


def _append_line(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        _write_all(descriptor, _canonical(value) + b"\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _reserve_quota(
    run_root: Path,
    *,
    retained_bytes: int,
    artifacts: int,
    sessions: int = 0,
) -> bool:
    """Atomically reserve bounded run-wide transcript capacity."""

    run_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(run_root, 0o700)
    path = run_root / "quota.json"
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        payload = os.read(descriptor, 4097)
        if len(payload) > 4096:
            raise ValueError("capture quota state is oversized")
        value = json.loads(payload) if payload else {}
        if not isinstance(value, dict):
            raise ValueError("capture quota state is invalid")
        current = {
            key: value.get(key, 0)
            for key in ("retained_bytes", "artifacts", "sessions")
        }
        if any(
            not isinstance(item, int) or isinstance(item, bool) or item < 0
            for item in current.values()
        ):
            raise ValueError("capture quota state is invalid")
        proposed = {
            "retained_bytes": current["retained_bytes"] + retained_bytes,
            "artifacts": current["artifacts"] + artifacts,
            "sessions": current["sessions"] + sessions,
        }
        if (
            proposed["retained_bytes"] > _MAX_CAPTURE_BYTES
            or proposed["artifacts"] > _MAX_ARTIFACT_COUNT
            or proposed["sessions"] > _MAX_SESSION_COUNT
        ):
            return False
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        _write_all(descriptor, _canonical(proposed))
        os.fsync(descriptor)
        return True
    finally:
        os.close(descriptor)


class SessionRecorder:
    """Create-once custody records for one broker-owned PTY session."""

    def __init__(
        self,
        capture_root: Path,
        authority: dict[str, object],
        *,
        session_id: str,
        now: Callable[[], str] = utc_now,
    ) -> None:
        self._authority = authority
        self._now = now
        self.session_id = validate_id(session_id, "session id")
        self.started_at = now()
        self._sequence = 0
        self._chain = bytes(32)
        self._loss_count = 0
        run_id = validate_id(str(authority["run_id"]), "run id")
        self._run_root = capture_root / run_id
        if not _reserve_quota(
            self._run_root,
            retained_bytes=1024,
            artifacts=2,
            sessions=1,
        ):
            raise ValueError("capture session limit exhausted")
        sessions_root = self._run_root / "sessions"
        sessions_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(sessions_root, 0o700)
        self._session_root = sessions_root / self.session_id
        self._session_root.mkdir(mode=0o700)
        os.chmod(self._session_root, 0o700)
        self._frames_path = self._session_root / "frames.jsonl"
        _write_exclusive(self._frames_path, b"")
        _append_line(
            self._run_root / "accepted-sessions.jsonl",
            {"session_id": self.session_id, "started_at": self.started_at},
        )

    def append(self, direction: str, data: bytes) -> None:
        if direction not in {"input", "output"}:
            raise ValueError("invalid frame direction")
        if not data:
            return
        for offset in range(0, len(data), _MAX_FRAME_BYTES):
            chunk = data[offset : offset + _MAX_FRAME_BYTES]
            if not _reserve_quota(
                self._run_root,
                retained_bytes=len(chunk) + 256,
                artifacts=1,
            ):
                self._loss_count += 1
                continue
            self._sequence += 1
            timestamp = self._now()
            header = f"{self._sequence}\0{timestamp}\0{direction}\0".encode()
            self._chain = hashlib.sha256(self._chain + header + chunk).digest()
            _append_line(
                self._frames_path,
                {
                    "sequence": self._sequence,
                    "timestamp": timestamp,
                    "direction": direction,
                    "data_b64": base64.b64encode(chunk).decode("ascii"),
                },
            )

    def finish(self, close_reason: str) -> None:
        if close_reason not in {
            "clean-exit",
            "remote-eof",
            "signal",
            "forced-teardown",
        }:
            raise ValueError("invalid close reason")
        _write_exclusive(
            self._session_root / "metadata.json",
            _canonical(
                {
                    "session_id": self.session_id,
                    "started_at": self.started_at,
                    "finished_at": self._now(),
                    "close_reason": close_reason,
                    "final_chain_digest": "sha256:" + self._chain.hex(),
                    "loss_count": self._loss_count,
                    "frame_count": self._sequence,
                    "plan_id": self._authority["plan_id"],
                    "binding_id": self._authority["binding_id"],
                }
            ),
        )


def _read_json_lines(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    if path.stat().st_size > _MAX_LEDGER_BYTES + (2 * _MAX_CAPTURE_BYTES):
        raise ValueError("capture ledger is oversized")
    for line in path.read_bytes().splitlines():
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError("capture line is not an object")
        records.append(value)
    return records


def export_capture(
    capture_root: Path, authority: dict[str, object]
) -> dict[str, object]:
    """Return the complete finalized capture using path-free encoded frames."""

    run_id = validate_id(str(authority["run_id"]), "run id")
    run_root = capture_root / run_id
    ledger_path = run_root / "accepted-sessions.jsonl"
    accepted = _read_json_lines(ledger_path) if ledger_path.exists() else []
    accepted_ids = [
        validate_id(str(row["session_id"]), "session id") for row in accepted
    ]
    if len(accepted_ids) != len(set(accepted_ids)):
        raise ValueError("duplicate accepted session")
    sessions: list[dict[str, object]] = []
    for session_id in accepted_ids:
        root = run_root / "sessions" / session_id
        metadata_path = root / "metadata.json"
        if not metadata_path.is_file():
            raise ValueError("accepted session not finalized")
        metadata = _read_json(metadata_path)
        frames = _read_json_lines(root / "frames.jsonl")
        if metadata.get("session_id") != session_id:
            raise ValueError("session metadata identity mismatch")
        sessions.append({**metadata, "frames": frames})
    return {
        "authority": authority,
        "accepted_session_ids": accepted_ids,
        "sessions": sessions,
    }


def session_identity_from_environment(
    authority: Mapping[str, object],
    environment: Mapping[str, str] | None = None,
) -> str:
    """Return the canonical MCP session id after validating run correlation."""

    values = environment if environment is not None else os.environ
    session_id = validate_id(values.get("APTL_SESSION_ID", ""), "session id")
    run_id = validate_id(values.get("APTL_RUN_ID", ""), "run id")
    trace_id = validate_id(values.get("APTL_TRACE_ID", ""), "trace id")
    if run_id != trace_id or run_id != authority.get("run_id"):
        raise ValueError("capture session authority mismatch")
    return session_id


def inner_ssh_command(original_command: str | None) -> list[str]:
    command = [
        "ssh",
        "-tt",
        "-p",
        "2222",
        "-i",
        _INNER_KEY,
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={_INNER_KNOWN_HOSTS}",
        "--",
        "kali@127.0.0.1",
    ]
    if original_command:
        command.append(original_command)
    return command


class _ForcedTeardown(Exception):
    pass


def _copy_window_size(source_fd: int, target_fd: int) -> None:
    try:
        size = fcntl.ioctl(source_fd, termios.TIOCGWINSZ, b"\0" * 8)
        fcntl.ioctl(target_fd, termios.TIOCSWINSZ, size)
    except (OSError, ValueError):
        pass


def _relay(
    child: subprocess.Popen[bytes], master: int, recorder: SessionRecorder
) -> int:
    selector = selectors.DefaultSelector()
    selector.register(master, selectors.EVENT_READ, "output")
    selector.register(sys.stdin.fileno(), selectors.EVENT_READ, "input")
    input_open = True
    while selector.get_map():
        for key, _mask in selector.select(timeout=1.0):
            try:
                data = os.read(key.fd, 65536)
            except OSError as exc:
                if key.data == "output" and exc.errno == errno.EIO:
                    data = b""
                else:
                    raise
            if not data:
                selector.unregister(key.fd)
                if key.data == "input" and input_open:
                    input_open = False
                    _write_all(master, b"\x04")
                continue
            recorder.append(str(key.data), data)
            if key.data == "input":
                _write_all(master, data)
            else:
                _write_all(sys.stdout.fileno(), data)
        if child.poll() is not None and master not in selector.get_map():
            break
    return child.wait(timeout=10)


@contextmanager
def _raw_terminal(fd: int) -> Iterator[None]:
    if not os.isatty(fd):
        yield
        return
    saved = termios.tcgetattr(fd)
    try:
        tty.setraw(fd, when=termios.TCSANOW)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, saved)


def run_broker() -> int:
    recorder: SessionRecorder | None = None
    pid_path: Path | None = None
    master = -1
    slave = -1
    child: subprocess.Popen[bytes] | None = None
    close_reason = "signal"

    def forced_teardown(_signum: int, _frame: object) -> None:
        raise _ForcedTeardown

    try:
        signal.signal(signal.SIGTERM, forced_teardown)
        authority = read_authority(_RUNTIME_ROOT)
        with _admission_lock(_RUNTIME_ROOT):
            if (_RUNTIME_ROOT / "quiesce").exists():
                raise ValueError("capture session admission is closed")
            session_id = session_identity_from_environment(authority)
            registration = _RUNTIME_ROOT / "sessions" / f"{session_id}.pid"
            _write_exclusive(registration, f"{os.getpid()}\n".encode())
            pid_path = registration
            try:
                recorder = SessionRecorder(
                    _CAPTURE_ROOT,
                    authority,
                    session_id=session_id,
                )
            except BaseException:
                pid_path.unlink(missing_ok=True)
                raise
        original = os.environ.get("SSH_ORIGINAL_COMMAND")
        master, slave = pty.openpty()
        _copy_window_size(sys.stdin.fileno(), slave)
        with _raw_terminal(sys.stdin.fileno()):
            child = subprocess.Popen(
                inner_ssh_command(original),
                stdin=slave,
                stdout=slave,
                stderr=slave,
                start_new_session=True,
            )
            os.close(slave)
            slave = -1
            returncode = _relay(child, master, recorder)
        close_reason = "clean-exit" if returncode == 0 else "remote-eof"
        return returncode
    except _ForcedTeardown:
        close_reason = "forced-teardown"
        return 143
    finally:
        try:
            if child is not None and child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
            if slave >= 0:
                os.close(slave)
            if master >= 0:
                os.close(master)
        finally:
            try:
                if recorder is not None:
                    recorder.finish(close_reason)
            finally:
                if pid_path is not None:
                    pid_path.unlink(missing_ok=True)


def quiesce(runtime_root: Path = _RUNTIME_ROOT) -> None:
    sessions = runtime_root / "sessions"
    with _admission_lock(runtime_root):
        try:
            _write_exclusive(runtime_root / "quiesce", b"quiescing\n")
        except FileExistsError:
            pass
        pid_paths = [runtime_root / "sshd.pid"]
        pid_paths.extend(sessions.glob("*.pid") if sessions.is_dir() else ())
    for path in pid_paths:
        if not path.is_file():
            continue
        try:
            os.kill(int(path.read_text().strip()), signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 30
    while sessions.is_dir() and any(sessions.glob("*.pid")):
        if time.monotonic() >= deadline:
            raise TimeoutError("capture sessions did not quiesce")
        time.sleep(0.1)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action")
    activate = subparsers.add_parser("activate")
    activate.add_argument("--run-id", required=True)
    activate.add_argument("--plan-id", required=True)
    activate.add_argument("--binding-id", required=True)
    subparsers.add_parser("status")
    subparsers.add_parser("quiesce")
    subparsers.add_parser("export")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.action == "activate":
        value = activate_authority(
            _RUNTIME_ROOT,
            run_id=args.run_id,
            plan_id=args.plan_id,
            binding_id=args.binding_id,
        )
        print(json.dumps(value, separators=(",", ":")))
        return 0
    if args.action == "status":
        authority = read_authority()
        try:
            with socket.create_connection(("127.0.0.1", 22), timeout=1):
                pass
        except OSError:
            return 1
        print(json.dumps(authority, separators=(",", ":")))
        return 0
    if args.action == "quiesce":
        quiesce()
        return 0
    if args.action == "export":
        print(json.dumps(export_capture(_CAPTURE_ROOT, read_authority())))
        return 0
    return run_broker()


if __name__ == "__main__":
    raise SystemExit(main())
