"""Host-side appliance seat lifecycle adapter."""

from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.lifecycle import (
    open_participant_kiosk,
    reconcile_seat_after_reboot,
    recover_seat,
    reset_seat,
    stage_seat,
    start_seat,
    status_seat,
    stop_seat,
)
from aptl.appliance.seat.models import SeatRecord, SeatStatusProjection

__all__ = [
    "SeatLauncherError",
    "SeatRecord",
    "SeatStatusProjection",
    "open_participant_kiosk",
    "reconcile_seat_after_reboot",
    "recover_seat",
    "reset_seat",
    "stage_seat",
    "start_seat",
    "status_seat",
    "stop_seat",
]
