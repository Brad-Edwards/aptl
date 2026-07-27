"""Overlay artifact removal for seat reset operations."""

from __future__ import annotations

from pathlib import Path

from aptl.appliance.seat.errors import SeatLauncherError


def remove_overlay_artifacts(*targets: Path) -> None:
    """Delete overlay files or directories without touching the golden release."""

    for target in targets:
        if target.is_dir():
            for child in sorted(target.rglob("*"), reverse=True):
                try:
                    child.unlink()
                except OSError:
                    pass
            try:
                target.rmdir()
            except OSError:
                pass
        elif target.exists() or target.is_symlink():
            try:
                target.unlink()
            except OSError as exc:
                raise SeatLauncherError("corrupt-overlay", "overlay reset failed") from exc
