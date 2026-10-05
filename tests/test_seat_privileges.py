"""Seat privilege input stays private and bound to one launch."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import socket
import stat
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from aptl.appliance.seat.context import StartSeatOptions
from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.privileges import (
    deliver_sudo_password,
    read_private_password,
    validate_sudo_password,
)


def _guest_module():
    path = Path(__file__).resolve().parents[1] / "appliance/guest/seat-privileges.py"
    spec = importlib.util.spec_from_file_location("seat_privileges_guest", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def short_socket_path():
    with tempfile.TemporaryDirectory(prefix="aptl-seat-", dir="/tmp") as folder:
        yield Path(folder) / "channel.sock"


@pytest.mark.parametrize("password", ["", "correct horse battery staple", "pa:ss'\\word☃"])
def test_password_input_preserves_deliberate_values(password: str) -> None:
    assert validate_sudo_password(password) == password
    assert password not in repr(StartSeatOptions(sudo_password=password)) if password else True


@pytest.mark.parametrize("password", ["a\nb", "a\rb", "a\x00b", "a" * 1025])
def test_password_input_rejects_unsafe_frames(password: str) -> None:
    with pytest.raises(SeatLauncherError, match="invalid"):
        validate_sudo_password(password)


def test_private_password_file_accepts_explicit_empty_and_rejects_symlink(tmp_path: Path) -> None:
    source = tmp_path / "password"
    source.write_bytes(b"")
    source.chmod(0o600)
    assert read_private_password(source) == ""
    source.write_text("long phrase ☃")
    assert read_private_password(source) == "long phrase ☃"
    source.chmod(0o644)
    with pytest.raises(SeatLauncherError):
        read_private_password(source)
    source.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(source)
    with pytest.raises(SeatLauncherError):
        read_private_password(link)
    parent_link = tmp_path / "linked-parent"
    parent_link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(SeatLauncherError):
        read_private_password(parent_link / "password")


def test_host_sends_password_only_to_matching_guest(short_socket_path: Path) -> None:
    path = short_socket_path
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)

    def guest() -> str:
        with server:
            connection, _ = server.accept()
            with connection:
                connection.sendall(json.dumps({
                    "kind": "needs-password", "instance_id": "i",
                    "descriptor_digest": "sha256:a",
                }).encode() + b"\n")
                payload = b""
                while not payload.endswith(b"\n"):
                    payload += connection.recv(4096)
                connection.sendall(b'{"kind":"applied"}\n')
                return json.loads(payload)["password"]

    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(guest)
        deliver_sudo_password(
            path, password="pass'☃", instance_id="i",
            descriptor_digest="sha256:a", process_alive=lambda: True,
            timeout_seconds=5,
        )
        assert result.result(timeout=5) == "pass'☃"


def test_host_rejects_unused_replacement_password(short_socket_path: Path) -> None:
    path = short_socket_path
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)

    def guest() -> None:
        with server:
            connection, _ = server.accept()
            with connection:
                connection.sendall(json.dumps({
                    "kind": "already-applied", "instance_id": "i",
                    "descriptor_digest": "sha256:a",
                }).encode() + b"\n")

    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(guest)
        with pytest.raises(SeatLauncherError, match="did not complete"):
            deliver_sudo_password(
                path, password="replacement", instance_id="i",
                descriptor_digest="sha256:a", process_alive=lambda: True,
                timeout_seconds=5,
            )
        result.result(timeout=5)


def test_guest_removes_privileged_groups_from_textual_id_output(monkeypatch) -> None:
    guest = _guest_module()
    calls = []

    def command(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(stdout="aptl docker sudo")

    monkeypatch.setattr(guest, "_command", command)
    guest._remove_direct_root_access()
    assert ("gpasswd", "-d", "aptl", "docker") in calls
    assert ("gpasswd", "-d", "aptl", "sudo") in calls
    with pytest.raises(ValueError, match="privileged group"):
        guest._check("event", "none")


def test_guest_command_requests_text_output(monkeypatch) -> None:
    guest = _guest_module()
    with patch.object(guest.subprocess, "run", return_value=SimpleNamespace(stdout="aptl")) as run:
        guest._command("id", "-nG", "aptl")
    assert run.call_args.kwargs["text"] is True


def test_guest_event_mode_removes_managed_privileges_before_ready(tmp_path: Path, monkeypatch) -> None:
    guest = _guest_module()
    launch = tmp_path / "appliance-launch.json"
    launch.write_bytes(b"launch")
    challenge = tmp_path / "readiness-challenge.json"
    challenge.write_text(json.dumps({
        "instance_id": "instance",
        "launch_descriptor_digest": "sha256:" + hashlib.sha256(b"launch").hexdigest(),
    }))
    for name, value in (
        ("LAUNCH", launch), ("CHALLENGE", challenge),
        ("STATE", tmp_path / "state.json"),
        ("PASSWORD", tmp_path / "password"),
        ("SUDOERS", tmp_path / "sudoers"),
    ):
        monkeypatch.setattr(guest, name, value)
    guest.PASSWORD.write_text("old password")
    guest.SUDOERS.write_text("old rule")
    monkeypatch.setattr(guest, "verify_seat_launch", lambda _path: (
        SimpleNamespace(desktop_mode="event"), None,
    ))
    monkeypatch.setattr(guest, "_command", lambda *args, **kwargs: SimpleNamespace(stdout="aptl"))
    checked = []
    monkeypatch.setattr(guest, "_check", lambda mode, auth: checked.append((mode, auth)))
    monkeypatch.setattr(guest, "_root_private", lambda _path: True)

    guest.apply()
    guest.apply()

    assert not guest.PASSWORD.exists()
    assert not guest.SUDOERS.exists()
    assert checked == [("event", "none"), ("event", "none")]
    assert json.loads(guest.STATE.read_text())["mode"] == "event"


def test_guest_event_check_rejects_another_effective_sudo_grant(tmp_path: Path, monkeypatch) -> None:
    guest = _guest_module()
    monkeypatch.setattr(guest, "SUDOERS", tmp_path / "managed-rule")
    monkeypatch.setattr(guest, "_command", lambda *args, **kwargs: SimpleNamespace(stdout="aptl"))
    with patch.object(guest.subprocess, "run", return_value=SimpleNamespace(
        returncode=0, stdout=b"aptl may run ALL\n",
    )):
        with pytest.raises(ValueError, match="sudo authorization"):
            guest._check("event", "none")


def test_guest_event_check_accepts_sudo_no_grant_with_zero_exit(tmp_path: Path, monkeypatch) -> None:
    guest = _guest_module()
    monkeypatch.setattr(guest, "SUDOERS", tmp_path / "managed-rule")
    monkeypatch.setattr(guest, "_command", lambda *args, **kwargs: SimpleNamespace(stdout="aptl"))
    with patch.object(guest.subprocess, "run", return_value=SimpleNamespace(
        returncode=0, stdout=b"User aptl is not allowed to run sudo on (none).\n",
    )) as run:
        guest._check("event", "none")
    assert run.call_args.kwargs["env"]["LC_ALL"] == "C"


def test_guest_admin_applies_password_and_does_not_reask_on_restart(tmp_path: Path, monkeypatch) -> None:
    guest = _guest_module()
    launch = tmp_path / "appliance-launch.json"
    launch.write_bytes(b"launch")
    challenge = tmp_path / "challenge.json"
    challenge.write_text(json.dumps({
        "instance_id": "instance",
        "launch_descriptor_digest": "sha256:" + hashlib.sha256(b"launch").hexdigest(),
    }))
    for name, value in (
        ("LAUNCH", launch), ("CHALLENGE", challenge),
        ("STATE", tmp_path / "state.json"),
        ("PASSWORD", tmp_path / "password"),
        ("SUDOERS", tmp_path / "sudoers"),
    ):
        monkeypatch.setattr(guest, name, value)
    monkeypatch.setattr(guest, "verify_seat_launch", lambda _path: (
        SimpleNamespace(desktop_mode="administrative"), None,
    ))
    calls = []
    def command(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(stdout="aptl")
    monkeypatch.setattr(guest, "_command", command)
    monkeypatch.setattr(guest, "_check", lambda *_args: None)
    monkeypatch.setattr(guest, "_root_private", lambda _path: True)

    class Channel:
        def __init__(self, answer: bytes):
            self.answer = io.BytesIO(answer)
            self.writes = []
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def write(self, payload: bytes):
            self.writes.append(json.loads(payload))
        def readline(self, limit: int):
            return self.answer.readline(limit)

    first = Channel(json.dumps({"password": "pass☃"}).encode() + b"\n")
    second = Channel(b"")
    channels = iter((first, second))
    monkeypatch.setattr(guest, "DEVICE", SimpleNamespace(
        stat=lambda: SimpleNamespace(st_mode=stat.S_IFCHR | 0o600),
        open=lambda *_args, **_kwargs: next(channels),
    ))
    monkeypatch.setattr(guest.os, "chown", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(guest.os, "chmod", lambda *_args, **_kwargs: None)

    guest.apply()
    guest.apply()

    assert guest.PASSWORD.read_text() == "pass☃"
    assert guest.SUDOERS.read_text() == "aptl ALL=(ALL:ALL) ALL\n"
    assert any(args == ("chpasswd",) and "pass☃" in kwargs["input_value"]
               for args, kwargs in calls if "input_value" in kwargs)
    assert first.writes[-1] == {"kind": "applied"}
    assert second.writes[0]["kind"] == "already-applied"


def test_guest_admin_empty_choice_grants_sudo_without_empty_unix_password(
    tmp_path: Path, monkeypatch,
) -> None:
    guest = _guest_module()
    launch = tmp_path / "appliance-launch.json"
    launch.write_bytes(b"launch")
    digest = "sha256:" + hashlib.sha256(b"launch").hexdigest()
    challenge = tmp_path / "challenge.json"
    challenge.write_text(json.dumps({
        "instance_id": "instance", "launch_descriptor_digest": digest,
    }))
    for name, value in (
        ("LAUNCH", launch), ("CHALLENGE", challenge),
        ("STATE", tmp_path / "state.json"),
        ("PASSWORD", tmp_path / "password"),
        ("SUDOERS", tmp_path / "sudoers"),
    ):
        monkeypatch.setattr(guest, name, value)
    monkeypatch.setattr(guest, "verify_seat_launch", lambda _path: (
        SimpleNamespace(desktop_mode="administrative"), None,
    ))
    calls = []
    def command(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(stdout="aptl")
    monkeypatch.setattr(guest, "_command", command)
    monkeypatch.setattr(guest, "_check", lambda *_args: None)
    class Channel:
        def __init__(self):
            self.answer = io.BytesIO(b'{"password":""}\n')
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def write(self, _payload):
            return None
        def readline(self, limit):
            return self.answer.readline(limit)
    monkeypatch.setattr(guest, "DEVICE", SimpleNamespace(
        stat=lambda: SimpleNamespace(st_mode=stat.S_IFCHR | 0o600),
        open=lambda *_args, **_kwargs: Channel(),
    ))
    monkeypatch.setattr(guest.os, "chown", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(guest.os, "chmod", lambda *_args, **_kwargs: None)

    guest.apply()

    assert guest.SUDOERS.read_text() == "aptl ALL=(ALL:ALL) NOPASSWD:ALL\n"
    assert not guest.PASSWORD.exists()
    assert ("chpasswd",) not in calls
    assert json.loads(guest.STATE.read_text())["authentication"] == "passwordless"
