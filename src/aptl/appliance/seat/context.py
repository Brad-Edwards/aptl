"""Shared seat launcher path and option contracts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aptl.appliance.seat.observation import ListenerProbe


@dataclass(frozen=True)
class StartSeatOptions:
    """Optional probes and overrides for ``start_seat``."""

    prereq_overrides: dict[str, object] | None = None
    listener_probe: ListenerProbe | None = None
    docker_daemon_running: bool | None = None


@dataclass(frozen=True)
class SeatPaths:
    """Contained directory layout for one physical seat."""

    seat_root: Path
    release_dir: Path
    release_public_key: Path
    qualification_public_key: Path
    launch_dir: Path
    launch_descriptor: Path
    overlay_path: Path
    overlay_state_dir: Path
