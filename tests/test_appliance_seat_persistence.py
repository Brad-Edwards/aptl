"""Persistence tests for the appliance seat launcher."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.models import SeatRecord
from aptl.appliance.seat.persistence import load_seat_record, persist_seat_record


def _record() -> SeatRecord:
    return SeatRecord(
        schema_version="aptl.seat-record/v1",
        seat_id="seat-01",
        selected_release_id="aptl-v1",
        launch_descriptor_digest="sha256:" + "a" * 64,
        overlay_path="instances/seat-01.qcow2",
        host_observation_id="host-1",
        lifecycle_state="staged",
        taint_state="clean",
        host_boot_id="boot-1",
    )


def test_persist_and_load_seat_record(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    record = _record()

    persist_seat_record(seat_root, record)

    loaded = load_seat_record(seat_root)
    assert loaded == record
    state_path = seat_root / "seat-state.json"
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600


def test_load_seat_record_returns_none_when_missing(tmp_path: Path) -> None:
    assert load_seat_record(tmp_path) is None


def test_load_seat_record_rejects_world_readable_state(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    seat_root.mkdir(mode=0o700)
    state_path = seat_root / "seat-state.json"
    state_path.write_text(_record().model_dump_json(), encoding="utf-8")
    state_path.chmod(0o644)

    with pytest.raises(SeatLauncherError) as exc:
        load_seat_record(seat_root)

    assert exc.value.code == "corrupt-seat-state"


def test_persist_seat_record_rejects_symlink_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    record = _record()

    with pytest.raises(SeatLauncherError) as exc:
        persist_seat_record(link, record)

    assert exc.value.code == "corrupt-seat-state"


def test_load_seat_record_rejects_invalid_json(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    seat_root.mkdir(mode=0o700)
    state_path = seat_root / "seat-state.json"
    state_path.write_text("{not-json", encoding="utf-8")
    state_path.chmod(0o600)

    with pytest.raises(SeatLauncherError) as exc:
        load_seat_record(seat_root)

    assert exc.value.code == "corrupt-seat-state"
