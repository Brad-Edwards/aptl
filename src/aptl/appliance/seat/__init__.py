"""Host-side appliance seat lifecycle adapter."""

from __future__ import annotations

from importlib import import_module
from typing import Any

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

_EXPORT_MODULES = {
    "SeatLauncherError": "aptl.appliance.seat.errors",
    "SeatRecord": "aptl.appliance.seat.models",
    "SeatStatusProjection": "aptl.appliance.seat.models",
    "open_participant_kiosk": "aptl.appliance.seat.kiosk",
    "reconcile_seat_after_reboot": "aptl.appliance.seat.lifecycle",
    "recover_seat": "aptl.appliance.seat.lifecycle",
    "reset_seat": "aptl.appliance.seat.lifecycle",
    "stage_seat": "aptl.appliance.seat.lifecycle",
    "start_seat": "aptl.appliance.seat.lifecycle",
    "status_seat": "aptl.appliance.seat.lifecycle",
    "stop_seat": "aptl.appliance.seat.lifecycle",
}


def __getattr__(name: str) -> Any:
    """Load public adapters lazily to keep model imports cycle-free."""

    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(name)
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value
