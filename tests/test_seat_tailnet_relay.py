"""The host relay must only enter the tracked ready desktop VM namespace."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/appliance/seat-tailnet-relay.py"
SPEC = importlib.util.spec_from_file_location("seat_tailnet_relay", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
relay = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = relay
SPEC.loader.exec_module(relay)


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def _seat_fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict, dict]:
    seat_root = tmp_path / "seat"
    seat_root.mkdir(mode=0o700)
    overlay = seat_root / "instances/seat-01.qcow2"
    overlay.parent.mkdir()
    overlay.write_bytes(b"fixture")
    mapping = {
        "audience": "participant", "protocol": "tcp",
        "address": "127.0.0.1", "port": 55812,
        "guest_address": "127.0.0.1", "guest_port": 8080,
    }
    record = {
        "seat_id": "seat-01", "overlay_path": "instances/seat-01.qcow2",
        "lifecycle_state": "ready", "taint_state": "clean",
        "mappings": [mapping],
    }
    _write_json(seat_root / "seat-state.json", record)
    tracked = {"pid": 1234, "start_time_ticks": 99}
    _write_json(seat_root / "vm.pid", tracked)

    proc = tmp_path / "proc"
    process = proc / "1234"
    (process / "ns").mkdir(parents=True)
    (process / "ns/net").write_bytes(b"private namespace")
    qemu = tmp_path / "qemu-system-x86_64"
    qemu.write_bytes(b"fixture")
    (process / "exe").symlink_to(qemu)
    command = [
        "qemu-system-x86_64", "-drive", f"file={overlay},format=qcow2,if=virtio",
        "-netdev", "user,id=participant,hostfwd=tcp:127.0.0.1:55812-10.0.2.15:8080",
    ]
    (process / "cmdline").write_bytes("\0".join(command).encode() + b"\0")
    # /proc/<pid>/stat fields after the command name begin at field 3.
    (process / "stat").write_text("1234 (qemu-system-x86) " + " ".join(
        ["S", *("0" for _ in range(18)), "99", "0"
        ]) + "\n")
    return seat_root, proc, qemu, record, tracked


def test_relay_accepts_only_the_tracked_ready_desktop(tmp_path: Path) -> None:
    seat_root, proc, qemu, _, _ = _seat_fixture(tmp_path)
    target = relay.resolve_target(seat_root, os.getuid(), qemu, proc_root=proc)
    try:
        assert target.port == 55812
        assert os.fstat(target.namespace_fd).st_ino == (proc / "1234/ns/net").stat().st_ino
    finally:
        os.close(target.namespace_fd)


@pytest.mark.parametrize("change,expected", [
    ("unready", "not ready"),
    ("wrong_guest_port", "mapping is invalid"),
    ("changed_outer_port", "does not publish"),
    ("reused_pid", "process has changed"),
    ("unsafe_overlay", "overlay is invalid"),
])
def test_relay_rejects_stale_or_changed_seat(
    tmp_path: Path, change: str, expected: str,
) -> None:
    seat_root, proc, qemu, record, tracked = _seat_fixture(tmp_path)
    if change == "unready":
        record["lifecycle_state"] = "staged"
    elif change == "wrong_guest_port":
        record["mappings"][0]["guest_port"] = 22
    elif change == "changed_outer_port":
        record["mappings"][0]["port"] = 55813
    elif change == "reused_pid":
        tracked["start_time_ticks"] = 100
    else:
        record["overlay_path"] = "instances/../seat-01.qcow2"
    _write_json(seat_root / "seat-state.json", record)
    _write_json(seat_root / "vm.pid", tracked)
    with pytest.raises(ValueError, match=expected):
        relay.resolve_target(seat_root, os.getuid(), qemu, proc_root=proc)


def test_relay_rejects_symlinked_seat_metadata(tmp_path: Path) -> None:
    seat_root, proc, qemu, _, _ = _seat_fixture(tmp_path)
    metadata = seat_root / "seat-state.json"
    copy = tmp_path / "record.json"
    metadata.replace(copy)
    metadata.symlink_to(copy)
    with pytest.raises(OSError):
        relay.resolve_target(seat_root, os.getuid(), qemu, proc_root=proc)
