"""Race-safe outer endpoint reservation tests."""

from __future__ import annotations

import os
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

import aptl.appliance.seat.allocation as allocation
from aptl.appliance.seat.allocation import (
    _require_resource_capacity,
    _running_resource_reservations,
    launch_with_automatic_mappings,
    launch_with_reserved_mappings,
    reserve_outer_mappings,
)
from aptl.appliance.seat.errors import SeatLauncherError
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint


def _mapping(port: int) -> BoundaryEndpoint:
    return BoundaryEndpoint(
        audience="participant",
        address="127.0.0.1",
        port=port,
        protocol="tcp",
        guest_address="127.0.0.1",
        guest_port=443,
    )


def _free_port() -> int:
    with socket.socket() as candidate:
        candidate.bind(("127.0.0.1", 0))
        return candidate.getsockname()[1]


def test_reservation_rejects_an_occupied_explicit_pin() -> None:
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        mapping = _mapping(occupied.getsockname()[1])

        with pytest.raises(SeatLauncherError) as exc:
            with reserve_outer_mappings((mapping,)):
                pass

    assert exc.value.code == "mapping-unavailable"


def test_launcher_handoff_waits_for_new_owner() -> None:
    mapping = _mapping(_free_port())

    class Handle:
        def __init__(self) -> None:
            self.listener = socket.socket()
            self.listener.bind((mapping.address, mapping.port))
            self.listener.listen(1)

        def poll(self):
            return None

    handle = launch_with_reserved_mappings((mapping,), Handle)
    try:
        assert handle.listener.getsockname() == (mapping.address, mapping.port)
    finally:
        handle.listener.close()


def test_automatic_allocator_selects_distinct_ports_and_holds_launch_lock() -> None:
    publications = (
        _mapping(443),
        _mapping(9443).model_copy(update={"audience": "recovery"}),
    )
    listeners: list[socket.socket] = []

    def launch(mappings: tuple[BoundaryEndpoint, ...]):
        assert len({mapping.port for mapping in mappings}) == 2
        assert [mapping.guest_port for mapping in mappings] == [443, 9443]
        for mapping in mappings:
            listener = socket.socket()
            listener.bind((mapping.address, mapping.port))
            listener.listen(1)
            listeners.append(listener)
        return mappings

    selected = launch_with_automatic_mappings(publications, launch)
    try:
        assert all(mapping.address == "127.0.0.1" for mapping in selected)
    finally:
        for listener in listeners:
            listener.close()


def test_allocator_lock_falls_back_to_file_lock_off_linux(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(allocation.sys, "platform", "darwin")
    monkeypatch.setattr(allocation.tempfile, "gettempdir", lambda: str(tmp_path))
    mapping = _mapping(_free_port())

    with reserve_outer_mappings((mapping,)):
        lock = tmp_path / f"aptl-seat-mapping-allocation-v1-{os.getuid()}.lock"
        assert lock.is_file()


def test_resource_admission_accounts_for_running_seats(tmp_path: Path) -> None:
    _require_resource_capacity(
        (8, 16 * 1024**3, 100 * 1024**3),
        seat_root=tmp_path,
        reservations=(8, 16 * 1024**3, 100 * 1024**3),
        capacity=(16, 32 * 1024**3, 200 * 1024**3),
    )

    with pytest.raises(SeatLauncherError) as exc:
        _require_resource_capacity(
            (8, 16 * 1024**3, 100 * 1024**3),
            seat_root=tmp_path,
            reservations=(9, 16 * 1024**3, 100 * 1024**3),
            capacity=(16, 32 * 1024**3, 200 * 1024**3),
        )

    assert exc.value.code == "resource-capacity-exhausted"


def test_resource_admission_preserves_host_memory_headroom(tmp_path: Path) -> None:
    resources = (8, 32 * 1024**3, 100 * 1024**3)
    capacity = (16, 128 * 1024**3, 500 * 1024**3)
    with pytest.raises(SeatLauncherError) as exc:
        _require_resource_capacity(
            resources,
            seat_root=tmp_path,
            reservations=(0, 0, 0),
            capacity=capacity,
            available=(16, 40 * 1024**3, 400 * 1024**3),
        )
    assert exc.value.code == "resource-capacity-exhausted"

    _require_resource_capacity(
        resources,
        seat_root=tmp_path,
        reservations=(0, 0, 0),
        capacity=capacity,
        available=(16, 48 * 1024**3, 400 * 1024**3),
    )


def test_resource_reservations_are_discovered_from_qemu_argv(tmp_path: Path) -> None:
    process = tmp_path / "42"
    process.mkdir()
    (process / "cmdline").write_bytes(
        b"/usr/bin/qemu-system-x86_64\0-fw_cfg\0"
        b"name=opt/aptl/resource-reservation,string=8:17179869184:107374182400\0"
    )

    assert _running_resource_reservations(tmp_path) == (
        8,
        16 * 1024**3,
        100 * 1024**3,
    )


def test_resource_admission_observes_live_host_capacity(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        allocation.os,
        "sched_getaffinity",
        lambda pid: {0, 1, 2, 3},
        raising=False,
    )
    monkeypatch.setattr(
        allocation.os,
        "sysconf",
        lambda name: {"SC_PHYS_PAGES": 8 * 1024**2, "SC_PAGE_SIZE": 4096}[name],
    )
    monkeypatch.setattr(
        allocation.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(total=500 * 1024**3, free=400 * 1024**3),
    )
    original_read_text = Path.read_text

    def read_text(path: Path, *args, **kwargs):
        if path == Path("/proc/meminfo"):
            return "MemAvailable: 25165824 kB\n"
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)

    _require_resource_capacity(
        (2, 4 * 1024**3, 20 * 1024**3),
        seat_root=tmp_path,
        reservations=(0, 0, 0),
    )


def test_reserved_launcher_rejects_missing_resource_root_and_early_exit() -> None:
    mapping = _mapping(_free_port())
    with pytest.raises(SeatLauncherError, match="seat root is required"):
        launch_with_reserved_mappings(
            (mapping,),
            lambda: object(),
            resources=(1, 1, 1),
        )

    class Exited:
        def poll(self):
            return 1

    with pytest.raises(SeatLauncherError, match="VM exited during port bind"):
        launch_with_reserved_mappings((mapping,), Exited)


def test_automatic_launcher_requires_resource_root() -> None:
    mappings = (_mapping(443),)
    with pytest.raises(SeatLauncherError, match="seat root is required"):
        launch_with_automatic_mappings(
            mappings,
            lambda mappings: mappings,
            resources=(1, 1, 1),
        )
