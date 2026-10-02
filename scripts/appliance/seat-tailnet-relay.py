#!/usr/bin/python3
"""Bridge one ready desktop seat to a root-only Unix socket for Tailscale Serve."""

from __future__ import annotations

import json
import os
import pwd
import re
import selectors
import shutil
import socket
import socketserver
import stat
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SeatTarget:
    namespace_fd: int
    port: int


def _owner_json(path: Path, uid: int) -> dict:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 16384
        ):
            raise ValueError("seat metadata is unsafe")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            payload = source.read(16385)
        if len(payload) > 16384:
            raise ValueError("seat metadata is too large")
        result = json.loads(payload)
        if not isinstance(result, dict):
            raise ValueError("seat metadata is invalid")
        return result
    finally:
        os.close(descriptor)


def _start_ticks(path: Path) -> int:
    # The command name is parenthesized; starttime is field 22 (index 19 after it).
    fields = path.read_text().rsplit(") ", 1)[1].split()
    return int(fields[19])


def resolve_target(
    seat_root: Path,
    uid: int,
    qemu_executable: Path,
    *,
    proc_root: Path = Path("/proc"),
) -> SeatTarget:
    """Return a pinned namespace and only the staged Guacamole mapping."""

    root_info = seat_root.lstat()
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != uid
        or stat.S_IMODE(root_info.st_mode) & 0o077
    ):
        raise ValueError("seat root is unsafe")
    record = _owner_json(seat_root / "seat-state.json", uid)
    if record.get("lifecycle_state") != "ready" or record.get("taint_state") != "clean":
        raise ValueError("seat is not ready")
    mappings = record.get("mappings")
    if not isinstance(mappings, list) or len(mappings) != 1:
        raise ValueError("seat does not have one desktop mapping")
    mapping = mappings[0]
    if not isinstance(mapping, dict) or any(
        mapping.get(name) != value
        for name, value in (
            ("audience", "participant"),
            ("protocol", "tcp"),
            ("address", "127.0.0.1"),
            ("guest_address", "127.0.0.1"),
            ("guest_port", 8080),
        )
    ):
        raise ValueError("seat desktop mapping is invalid")
    port = mapping.get("port")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("seat desktop port is invalid")
    seat_id = record.get("seat_id")
    if (
        not isinstance(seat_id, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", seat_id) is None
        or ".." in seat_id
        or record.get("overlay_path") != f"instances/{seat_id}.qcow2"
    ):
        raise ValueError("seat overlay is invalid")
    overlay = seat_root / "instances" / f"{seat_id}.qcow2"
    if overlay.is_symlink() or not overlay.is_file():
        raise ValueError("seat overlay is unavailable")

    tracked = _owner_json(seat_root / "vm.pid", uid)
    pid = tracked.get("pid")
    ticks = tracked.get("start_time_ticks")
    if type(pid) is not int or pid <= 1 or type(ticks) is not int or ticks <= 0:
        raise ValueError("tracked VM identity is invalid")
    process = proc_root / str(pid)
    if process.stat().st_uid != uid:
        raise ValueError("tracked VM owner differs")
    if os.readlink(process / "exe") != str(qemu_executable.resolve()):
        raise ValueError("tracked process is not QEMU")
    command = (process / "cmdline").read_bytes().split(b"\0")
    drive = f"file={overlay},format=qcow2".encode()
    forward = f"hostfwd=tcp:127.0.0.1:{port}-10.0.2.15:8080".encode()
    if not any(arg.startswith(drive) for arg in command) or not any(
        forward in arg for arg in command
    ):
        raise ValueError("tracked VM does not publish this desktop")
    if _start_ticks(process / "stat") != ticks:
        raise ValueError("tracked VM process has changed")

    descriptor = os.open(process / "ns/net", os.O_RDONLY | os.O_CLOEXEC)
    try:
        if os.fstat(descriptor).st_ino == Path("/proc/self/ns/net").stat().st_ino:
            raise ValueError("seat has no private network")
        if _start_ticks(process / "stat") != ticks:
            raise ValueError("tracked VM process has changed")
        return SeatTarget(descriptor, port)
    except BaseException:
        os.close(descriptor)
        raise


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        try:
            target = resolve_target(server.seat_root, server.owner_uid, server.qemu_executable)
            try:
                os.setns(target.namespace_fd, os.CLONE_NEWNET)
            finally:
                os.close(target.namespace_fd)
            upstream = socket.create_connection(("127.0.0.1", target.port), 5)
            upstream.settimeout(None)
            with upstream, selectors.DefaultSelector() as poller:
                poller.register(self.request, selectors.EVENT_READ, upstream)
                poller.register(upstream, selectors.EVENT_READ, self.request)
                while True:
                    for key, _ in poller.select(60):
                        payload = key.fileobj.recv(65536)
                        if not payload:
                            return
                        key.data.sendall(payload)
        except (OSError, ValueError, KeyError, IndexError, json.JSONDecodeError) as exc:
            print(f"seat relay refused connection: {type(exc).__name__}: {exc}", file=sys.stderr)


class RelayServer(socketserver.ForkingUnixStreamServer):
    request_queue_size = 128


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2 or not hasattr(os, "setns"):
        raise SystemExit("usage: seat-tailnet-relay OWNER SOCKET_PATH (Linux only)")
    owner = pwd.getpwnam(args[0])
    seat_root = Path(owner.pw_dir) / ".local/state/aptl/seat"
    qemu = shutil.which("qemu-system-x86_64")
    if qemu is None:
        raise SystemExit("qemu-system-x86_64 is unavailable")
    socket_path = Path(args[1])
    parent = socket_path.parent
    parent_info = parent.lstat()
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != 0
        or stat.S_IMODE(parent_info.st_mode) != 0o700
    ):
        raise SystemExit("relay socket directory must be root-owned and private")
    try:
        existing = socket_path.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != 0:
            raise SystemExit("relay socket path is unsafe")
        socket_path.unlink()
    os.umask(0o077)
    try:
        with RelayServer(str(socket_path), RelayHandler) as server:
            socket_path.chmod(0o600)
            server.seat_root = seat_root
            server.owner_uid = owner.pw_uid
            server.qemu_executable = Path(qemu)
            server.serve_forever()
    finally:
        socket_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
