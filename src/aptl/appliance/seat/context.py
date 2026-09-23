"""Shared seat launcher path and option contracts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from aptl.appliance.seat.observation import ListenerProbe
from aptl.appliance.seat.access import SeatAccessEnrollment
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint
from aptl.core.appliance_boundary_inventory import GuestBoundaryObservation


@dataclass(frozen=True)
class StartSeatOptions:
    """Optional probes and overrides for ``start_seat``."""

    prereq_overrides: dict[str, object] | None = None
    listener_probe: ListenerProbe | None = None
    docker_daemon_running: bool | None = None
    mappings: tuple[BoundaryEndpoint, ...] | None = None
    forbidden_reachability_probe: Callable[[], bool] | None = None
    guest_readiness_probe: Callable[[], GuestBoundaryObservation] | None = None
    readiness_timeout_seconds: float = 1800
    listener_timeout_seconds: float = 10
    reserve_outer_mappings: bool = True
    access_enrollment: SeatAccessEnrollment | None = None
    access_identity_file: Path | None = None
    access_project_dir: Path | None = None
    access_clients: tuple[str, ...] = ()
    check_for_image_update: bool = True

    def with_mappings(self, mappings: tuple[BoundaryEndpoint, ...]) -> Self:
        """Clone options with allocator-selected mappings and reservation disabled."""

        return type(self)(
            prereq_overrides=self.prereq_overrides,
            listener_probe=self.listener_probe,
            docker_daemon_running=self.docker_daemon_running,
            mappings=mappings,
            forbidden_reachability_probe=self.forbidden_reachability_probe,
            guest_readiness_probe=self.guest_readiness_probe,
            readiness_timeout_seconds=self.readiness_timeout_seconds,
            listener_timeout_seconds=self.listener_timeout_seconds,
            reserve_outer_mappings=False,
            access_enrollment=self.access_enrollment,
            access_identity_file=self.access_identity_file,
            access_project_dir=self.access_project_dir,
            access_clients=self.access_clients,
            check_for_image_update=self.check_for_image_update,
        )


@dataclass(frozen=True)
class SeatPaths:
    """Contained directory layout for one physical seat."""

    seat_root: Path
    image_reference: str
    image_cache_dir: Path
    launch_dir: Path
    launch_descriptor: Path
    boundary_policy: Path
    overlay_path: Path
    overlay_state_dir: Path
