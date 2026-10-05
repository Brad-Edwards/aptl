#!/usr/bin/python3
"""Apply one immutable desktop privilege choice before participant login."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

from aptl.appliance.seat.launch_descriptor import verify_seat_launch
from aptl.appliance.seat.privileges import MAX_FRAME_BYTES, validate_sudo_password
from aptl.utils.strict_json import loads_strict

LAUNCH = Path("/run/aptl-launch/appliance-launch.json")
CHALLENGE = Path("/run/aptl-launch/readiness-challenge.json")
DEVICE = Path("/dev/virtio-ports/org.aptl.privileges")
STATE = Path("/var/lib/aptl/overlay/desktop-privileges.json")
PASSWORD = Path("/var/lib/aptl/overlay/desktop-admin-password")
SUDOERS = Path("/etc/sudoers.d/90-aptl-desktop")


def _write_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_frame(channel) -> dict[str, object]:
    payload = channel.readline(MAX_FRAME_BYTES + 1)
    if len(payload) > MAX_FRAME_BYTES or not payload.endswith(b"\n"):
        raise ValueError("invalid privilege channel frame")
    result = loads_strict(payload)
    if not isinstance(result, dict):
        raise ValueError("invalid privilege channel frame")
    return result


def _send_frame(channel, value: dict[str, object]) -> None:
    channel.write(json.dumps(value, separators=(",", ":")).encode() + b"\n")


def _command(*argv: str, input_value: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(argv), input=input_value, text=True,
        check=True, capture_output=True, timeout=30,
    )


def _root_private(path: Path) -> bool:
    info = path.stat()
    return (
        not path.is_symlink() and stat.S_ISREG(info.st_mode)
        and info.st_uid == 0 and info.st_gid == 0
        and not info.st_mode & 0o077
    )


def _saved_state(expected: dict[str, str]) -> dict[str, str] | None:
    if not STATE.exists():
        return None
    if not _root_private(STATE):
        raise ValueError("privilege state is unsafe")
    saved = loads_strict(STATE.read_bytes())
    if not isinstance(saved, dict) or any(
        saved.get(key) != value for key, value in expected.items()
    ):
        raise ValueError("privilege selection differs from overlay")
    return saved


def _remove_direct_root_access() -> None:
    groups = set(_command("id", "-nG", "aptl").stdout.split())
    for group in ("docker", "sudo"):
        if group in groups:
            _command("gpasswd", "-d", "aptl", group)


def _saved_admin_authentication(saved: dict[str, str]) -> str:
    authentication = saved.get("authentication")
    if authentication not in {"password", "passwordless"}:
        raise ValueError("privilege state has invalid authentication")
    if authentication == "password":
        if not _root_private(PASSWORD) or not PASSWORD.read_bytes():
            raise ValueError("administrative password state is unsafe")
    elif PASSWORD.exists():
        raise ValueError("passwordless seat has a password file")
    return authentication


def _check(mode: str, authentication: str) -> None:
    groups = set(_command("id", "-nG", "aptl").stdout.split())
    if groups & {"docker", "sudo"}:
        raise ValueError("desktop account has privileged group membership")
    if Path("/var/run/docker.sock").exists():
        _command(
            "su", "-s", "/bin/sh", "-c",
            "test ! -r /var/run/docker.sock && test ! -w /var/run/docker.sock", "aptl",
        )
    listing = subprocess.run(
        ["sudo", "-l", "-U", "aptl"], capture_output=True, timeout=15,
        env={**os.environ, "LC_ALL": "C"},
    )
    grants = listing.stdout.decode(errors="replace")
    no_grant = listing.returncode == 0 and any(
        re.fullmatch(r"User aptl is not allowed to run sudo on .+\.", line)
        for line in grants.splitlines()
    )
    if mode == "event":
        if SUDOERS.exists() or not no_grant:
            raise ValueError("event account has sudo authorization")
        return
    expected = (
        "aptl ALL=(ALL:ALL) NOPASSWD:ALL\n"
        if authentication == "passwordless" else "aptl ALL=(ALL:ALL) ALL\n"
    )
    info = SUDOERS.stat()
    if (info.st_uid, info.st_gid, info.st_mode & 0o777) != (0, 0, 0o440):
        raise ValueError("sudoers permissions are invalid")
    if SUDOERS.read_text() != expected or listing.returncode != 0 or no_grant:
        raise ValueError("administrative sudo rule is invalid")
    if authentication == "password" and "NOPASSWD:" in grants:
        raise ValueError("administrative sudo is unexpectedly passwordless")
    if authentication == "passwordless" and "NOPASSWD:" not in grants:
        raise ValueError("administrative sudo is not passwordless")
    _command("visudo", "-cf", "/etc/sudoers")


def apply() -> None:
    descriptor, _policy = verify_seat_launch(LAUNCH)
    if descriptor.desktop_mode not in {"administrative", "event"}:
        raise ValueError("image does not support desktop privilege selection")
    challenge = loads_strict(CHALLENGE.read_bytes())
    instance_id = challenge["instance_id"]
    digest = "sha256:" + hashlib.sha256(LAUNCH.read_bytes()).hexdigest()
    if challenge["launch_descriptor_digest"] != digest:
        raise ValueError("launch challenge differs from descriptor")
    expected = {"instance_id": instance_id, "descriptor_digest": digest,
                "mode": descriptor.desktop_mode}
    saved = _saved_state(expected)
    _remove_direct_root_access()
    if descriptor.desktop_mode == "event":
        SUDOERS.unlink(missing_ok=True)
        PASSWORD.unlink(missing_ok=True)
        authentication = "none"
    else:
        device_info = DEVICE.stat()
        if not stat.S_ISCHR(device_info.st_mode):
            raise ValueError("administrative channel is not a character device")
        os.chown(DEVICE, 0, 0)
        os.chmod(DEVICE, 0o600)
        with DEVICE.open("r+b", buffering=0) as channel:
            _send_frame(channel, {
                "kind": "already-applied" if saved else "needs-password",
                "instance_id": instance_id, "descriptor_digest": digest,
            })
            if saved:
                authentication = _saved_admin_authentication(saved)
            else:
                message = _read_frame(channel)
                if set(message) != {"password"} or not isinstance(message["password"], str):
                    raise ValueError("administrative password is missing")
                password = validate_sudo_password(message["password"])
                authentication = "passwordless" if password == "" else "password"
                if password:
                    _write_private(PASSWORD, password.encode("utf-8"))
                    _command("chpasswd", input_value=f"aptl:{password}\n")
                else:
                    PASSWORD.unlink(missing_ok=True)
                SUDOERS.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                SUDOERS.write_text(
                    "aptl ALL=(ALL:ALL) NOPASSWD:ALL\n" if not password
                    else "aptl ALL=(ALL:ALL) ALL\n"
                )
                SUDOERS.chmod(0o440)
            _check(descriptor.desktop_mode, authentication)
            if not saved:
                _write_private(STATE, json.dumps({**expected, "authentication": authentication}).encode())
                _send_frame(channel, {"kind": "applied"})
        return
    _check(descriptor.desktop_mode, authentication)
    if not saved:
        _write_private(STATE, json.dumps({**expected, "authentication": authentication}).encode())


if __name__ == "__main__":
    apply()
