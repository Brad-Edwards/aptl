"""Host-side appliance seat lifecycle adapter."""

from __future__ import annotations

from importlib import import_module
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

_LIFECYCLE_MODULE = "aptl.appliance.seat.lifecycle"
_EXPORT_MODULES = {
    "SeatLauncherError": "aptl.appliance.seat.errors",
    "SeatRecord": "aptl.appliance.seat.models",
    "SeatStatusProjection": "aptl.appliance.seat.models",
    "open_participant_kiosk": "aptl.appliance.seat.kiosk",
    "reconcile_seat_after_reboot": _LIFECYCLE_MODULE,
    "recover_seat": _LIFECYCLE_MODULE,
    "reset_seat": _LIFECYCLE_MODULE,
    "stage_seat": _LIFECYCLE_MODULE,
    "start_seat": _LIFECYCLE_MODULE,
    "status_seat": _LIFECYCLE_MODULE,
    "stop_seat": _LIFECYCLE_MODULE,
}


def __getattr__(name: str) -> object:
    """Load public adapters lazily to keep model imports cycle-free."""

    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(name)
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value
