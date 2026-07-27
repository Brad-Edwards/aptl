"""Seat path and VM argv validation tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.paths import contained_path, validate_seat_id
from aptl.appliance.seat.vm import VmLaunchSpec, build_qemu_argv


def test_validate_seat_id_rejects_path_traversal() -> None:
    with pytest.raises(SeatLauncherError) as exc:
        validate_seat_id("../etc/passwd")

    assert exc.value.code == "invalid-seat-id"


def test_build_qemu_argv_mounts_readonly_launch_directory(tmp_path: Path) -> None:
    launch_mount = tmp_path / "launch"
    launch_mount.mkdir()
    overlay = tmp_path / "overlay.qcow2"
    overlay.write_bytes(b"overlay")
    spec = VmLaunchSpec(
        overlay_path=overlay,
        launch_mount=launch_mount,
        vcpus=8,
        memory_mib=16384,
    )

    argv = build_qemu_argv(spec)

    assert "-fsdev" in argv
    fsdev_index = argv.index("-fsdev")
    assert "readonly=on" in argv[fsdev_index + 1]
    assert str(launch_mount.resolve()) in argv[fsdev_index + 1]
    assert "virtio-9p-pci,fsdev=aptl-launch,mount_tag=aptl-launch" in argv


def test_contained_path_rejects_escape(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    seat_root.mkdir()

    with pytest.raises(SeatLauncherError) as exc:
        contained_path(seat_root, "../outside", label="overlay")

    assert exc.value.code == "invalid-seat-id"

