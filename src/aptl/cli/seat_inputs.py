"""Validate seat CLI inputs before image acquisition or VM mutation."""

from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path

from pydantic import ValidationError

from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.launch_descriptor import SeatLaunchDescriptor
from aptl.appliance.seat.paths import default_seat_root
from aptl.appliance.seat.persistence import load_seat_record
from aptl.appliance.seat.privileges import read_private_password, validate_sudo_password
from aptl.cli._common import resolve_optional_config_for_cli
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint
from aptl.utils.strict_json import model_validate_json_strict

DEFAULT_SEAT_IMAGE = "ghcr.io/brad-edwards/aptl-seat:latest"


def _selected_source(image: str | None, seat_root: Path) -> str:
    """Honor explicit/configured sources and the existing seat before defaults."""

    config = resolve_optional_config_for_cli(Path.cwd())
    if image is not None:
        return image
    if config.seat.image is not None:
        return config.seat.image
    record = load_seat_record(seat_root)
    return record.image_reference if record is not None else DEFAULT_SEAT_IMAGE


def _parse_mappings(values: list[str] | None) -> tuple[BoundaryEndpoint, ...] | None:
    """Parse repeated audience,protocol,outer,port,guest,port mappings."""

    if not values:
        return None
    mappings: list[BoundaryEndpoint] = []
    try:
        for value in values:
            parts = value.split(",")
            if len(parts) != 6:
                raise ValueError("mapping requires six comma-separated fields")
            audience, protocol, address, port, guest_address, guest_port = parts
            mappings.append(
                BoundaryEndpoint(
                    audience=audience,
                    protocol=protocol,
                    address=address,
                    port=int(port),
                    guest_address=guest_address,
                    guest_port=int(guest_port),
                )
            )
    except (TypeError, ValueError, ValidationError) as exc:
        raise SeatLauncherError(
            "invalid-mapping",
            "mapping must be audience,protocol,outer-address,outer-port,guest-address,guest-port",
        ) from exc
    return tuple(mappings)


def _resolved_seat_root(seat_root: Path | None) -> Path:
    """Resolve an explicit root or the current user's private default."""

    return (seat_root if seat_root is not None else default_seat_root()).resolve()


def _current_desktop_mode(seat_root: Path) -> str | None:
    """Project the operator's immutable privilege choice from launch bytes."""

    descriptor_path = seat_root / "launch/appliance-launch.json"
    if not descriptor_path.is_file():
        return None
    return model_validate_json_strict(
        SeatLaunchDescriptor, descriptor_path.read_bytes()
    ).desktop_mode


def _sudo_password_for_load(
    mode: str | None, source: Path | None, *, first_load: bool,
) -> str | None:
    """Take a deliberate hidden/file input only for the first admin load."""

    if source is not None and mode != "administrative":
        raise SeatLauncherError(
            "invalid-sudo-password", "sudo password requires administrative mode"
        )
    if source is not None and not first_load:
        raise SeatLauncherError(
            "desktop-mode-mismatch", "reset the seat to change sudo password"
        )
    if mode != "administrative" or not first_load:
        return None
    if source is not None:
        return read_private_password(source)
    if not sys.stdin.isatty():
        raise SeatLauncherError(
            "missing-sudo-password", "use a private sudo password file in noninteractive mode"
        )
    try:
        return validate_sudo_password(
            getpass.getpass("Guest aptl sudo password (empty = passwordless): ")
        )
    except (EOFError, KeyboardInterrupt) as exc:
        raise SeatLauncherError(
            "missing-sudo-password", "administrative sudo password was not supplied"
        ) from exc


def _default_appliance_cache() -> Path:
    """Return the current user's XDG-compatible appliance cache."""

    configured = os.environ.get("XDG_CACHE_HOME")
    if configured:
        candidate = Path(configured)
        if candidate.is_absolute():
            return candidate / "aptl" / "appliance"
    return Path.home() / ".cache" / "aptl" / "appliance"
