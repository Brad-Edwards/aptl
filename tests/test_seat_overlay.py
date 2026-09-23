"""Disposable overlay creation over a cached seat image."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from aptl.appliance.seat import overlay as overlay_module
from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.overlay import create_seat_overlay, require_standalone_image


def _image(tmp_path: Path, *, mode: int = 0o444) -> Path:
    path = tmp_path / "seat-disk.qcow2"
    path.write_bytes(b"qcow2")
    path.chmod(mode)
    return path


def _info(
    monkeypatch: pytest.MonkeyPatch, document: dict[str, object]
) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_run(argv: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[1] == "info":
            return subprocess.CompletedProcess(argv, 0, json.dumps(document), "")
        Path(argv[-1]).write_bytes(b"overlay")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(overlay_module, "_run", fake_run)
    return calls


def test_creates_an_overlay_backed_by_the_cached_image(tmp_path, monkeypatch) -> None:
    image = _image(tmp_path)
    calls = _info(monkeypatch, {"format": "qcow2"})
    overlay = tmp_path / "instances" / "seat-01.qcow2"

    created = create_seat_overlay(overlay, image_path=image)

    assert created == overlay
    create = next(argv for argv in calls if argv[1] == "create")
    # The cached image is the backing file; the overlay never rewrites it.
    assert "-b" in create
    assert create[create.index("-b") + 1] == str(image)
    assert overlay.stat().st_mode & 0o777 == 0o600


def test_refuses_a_writable_base(tmp_path, monkeypatch) -> None:
    image = _image(tmp_path, mode=0o644)
    _info(monkeypatch, {"format": "qcow2"})

    with pytest.raises(SeatLauncherError, match="read-only"):
        create_seat_overlay(tmp_path / "overlay.qcow2", image_path=image)


def test_refuses_a_base_with_its_own_backing_file(tmp_path, monkeypatch) -> None:
    image = _image(tmp_path)
    # A backing chain would make the overlay depend on something outside the
    # image that was verified.
    _info(monkeypatch, {"format": "qcow2", "backing-filename": "/elsewhere.qcow2"})

    with pytest.raises(SeatLauncherError, match="external file"):
        create_seat_overlay(tmp_path / "overlay.qcow2", image_path=image)


def test_refuses_a_base_with_an_external_data_file(tmp_path, monkeypatch) -> None:
    image = _image(tmp_path)
    _info(monkeypatch, {"format": "qcow2", "data-file": "/elsewhere.raw"})

    with pytest.raises(SeatLauncherError, match="external file"):
        create_seat_overlay(tmp_path / "overlay.qcow2", image_path=image)


def test_refuses_a_base_that_is_not_qcow2(tmp_path, monkeypatch) -> None:
    image = _image(tmp_path)
    _info(monkeypatch, {"format": "raw"})

    with pytest.raises(SeatLauncherError, match="qcow2"):
        create_seat_overlay(tmp_path / "overlay.qcow2", image_path=image)


def test_refuses_unreadable_metadata(tmp_path, monkeypatch) -> None:
    image = _image(tmp_path)
    monkeypatch.setattr(
        overlay_module,
        "_run",
        lambda argv: subprocess.CompletedProcess(argv, 0, "not json", ""),
    )

    with pytest.raises(SeatLauncherError, match="metadata is invalid"):
        require_standalone_image(image)


def test_refuses_oversized_metadata(tmp_path, monkeypatch) -> None:
    image = _image(tmp_path)
    monkeypatch.setattr(
        overlay_module,
        "_run",
        lambda argv: subprocess.CompletedProcess(argv, 0, "x" * (2 * 1024 * 1024), ""),
    )

    with pytest.raises(SeatLauncherError, match="admission limit"):
        require_standalone_image(image)


def test_refuses_a_missing_base(tmp_path) -> None:
    with pytest.raises(SeatLauncherError, match="unreadable"):
        require_standalone_image(tmp_path / "absent.qcow2")


def test_refuses_to_replace_an_existing_overlay(tmp_path, monkeypatch) -> None:
    image = _image(tmp_path)
    _info(monkeypatch, {"format": "qcow2"})
    overlay = tmp_path / "overlay.qcow2"
    overlay.write_bytes(b"existing")

    # Replacing one would silently discard a seat's disposable state.
    with pytest.raises(SeatLauncherError, match="already exists"):
        create_seat_overlay(overlay, image_path=image)


def test_a_failing_qemu_leaves_no_partial_overlay(tmp_path, monkeypatch) -> None:
    image = _image(tmp_path)

    def fake_run(argv: list[str]) -> subprocess.CompletedProcess[str]:
        if argv[1] == "info":
            return subprocess.CompletedProcess(
                argv, 0, json.dumps({"format": "qcow2"}), ""
            )
        raise SeatLauncherError("corrupt-overlay", "qemu-img failed")

    monkeypatch.setattr(overlay_module, "_run", fake_run)
    overlay = tmp_path / "overlay.qcow2"

    with pytest.raises(SeatLauncherError):
        create_seat_overlay(overlay, image_path=image)

    assert not overlay.exists()
    assert not list(tmp_path.glob("overlay.qcow2.candidate-*"))
