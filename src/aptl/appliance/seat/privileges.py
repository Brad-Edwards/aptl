"""Private host-to-guest input for an administrative desktop seat."""

from __future__ import annotations

import json
import socket
import time
from pathlib import Path

from aptl.appliance.seat.errors import SeatLauncherError
from aptl.utils.pathsafe import PathContainmentError, open_contained_nofollow

MAX_PASSWORD_LENGTH = 1024
MAX_FRAME_BYTES = 4096


def validate_sudo_password(password: str) -> str:
    """Accept a deliberate empty password, but never ambiguous line framing."""

    if (
        not isinstance(password, str)
        or len(password.encode("utf-8")) > MAX_PASSWORD_LENGTH
        or any(character in password for character in ("\x00", "\n", "\r"))
    ):
        raise SeatLauncherError("invalid-sudo-password", "sudo password input is invalid")
    return password


def read_private_password(path: Path) -> str:
    """Read a bounded operator file without symlinks or permissive modes."""

    import os
    import stat

    base = Path(path.anchor) if path.is_absolute() else Path.cwd()
    relative = path.relative_to(base) if path.is_absolute() else path
    try:
        with open_contained_nofollow(base, relative) as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("unsafe password file")
            payload = source.read(MAX_PASSWORD_LENGTH + 1)
        return validate_sudo_password(payload.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, PathContainmentError) as exc:
        raise SeatLauncherError("invalid-sudo-password", "sudo password file is invalid") from exc


def _receive_frame(connection: socket.socket) -> dict[str, object]:
    payload = bytearray()
    while b"\n" not in payload:
        if len(payload) >= MAX_FRAME_BYTES:
            raise ValueError("admin channel frame is too large")
        chunk = connection.recv(min(512, MAX_FRAME_BYTES - len(payload)))
        if not chunk:
            raise ValueError("admin channel closed")
        payload.extend(chunk)
    line, _, rest = payload.partition(b"\n")
    if rest:
        raise ValueError("admin channel sent extra data")
    result = json.loads(line)
    if not isinstance(result, dict):
        raise ValueError("admin channel frame is invalid")
    return result


def deliver_sudo_password(
    socket_path: Path, *, password: str | None, instance_id: str,
    descriptor_digest: str, process_alive, timeout_seconds: float = 180,
) -> None:
    """Send a first-start password only after the correct guest asks for it."""

    deadline = time.monotonic() + timeout_seconds
    connection: socket.socket | None = None
    try:
        while connection is None:
            if not process_alive() or time.monotonic() >= deadline:
                raise ValueError("admin channel unavailable")
            try:
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.settimeout(2)
                connection.connect(str(socket_path))
            except (OSError, socket.timeout):
                connection.close()
                connection = None
                time.sleep(0.2)
        with connection:
            connection.settimeout(max(1, deadline - time.monotonic()))
            request = _receive_frame(connection)
            if (request.get("instance_id") != instance_id
                    or request.get("descriptor_digest") != descriptor_digest):
                raise ValueError("admin channel identity mismatch")
            if request.get("kind") == "already-applied":
                if password is not None:
                    raise ValueError("admin password input was not applied")
                return
            if request.get("kind") != "needs-password" or password is None:
                raise ValueError("admin password input is required")
            validate_sudo_password(password)
            payload = json.dumps({"password": password}, ensure_ascii=False).encode() + b"\n"
            connection.sendall(payload)
            if _receive_frame(connection) != {"kind": "applied"}:
                raise ValueError("admin channel did not acknowledge application")
    except (OSError, ValueError, socket.timeout) as exc:
        raise SeatLauncherError(
            "failed-admin-setup", "administrative desktop setup did not complete"
        ) from exc
