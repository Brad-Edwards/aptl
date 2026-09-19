"""CLI for host-side appliance seat lifecycle operations."""

from __future__ import annotations

import getpass
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import typer
from pydantic import ValidationError

from aptl.appliance.seat.context import StartSeatOptions
from aptl.appliance.public_install import (
    AppliancePublicInstallError,
    PublicReleaseSelection,
    install_public_release,
)
from aptl.appliance.manifest import ApplianceManifestError
from aptl.appliance.seat.access import SeatAccessEnrollment, ensure_transport_identity
from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.kiosk import open_participant_kiosk
from aptl.appliance.seat.lifecycle import (
    reconcile_seat_after_reboot,
    recover_seat,
    reset_seat,
    release_requires_host_access,
    stage_seat,
    start_seat,
    status_seat,
    stop_seat,
)
from aptl.appliance.seat.persistence import load_seat_record
from aptl.appliance.seat.paths import default_seat_root
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint
from aptl.workbench.profiles import WorkbenchConfigurationError

app = typer.Typer(help="Operate one disposable appliance seat on a physical host.")


def _emit(payload: dict[str, object]) -> None:
    """Print one bounded JSON payload on stdout."""

    typer.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def _fail(exc: SeatLauncherError) -> None:
    """Print one bounded JSON error and exit with code 2."""

    typer.echo(json.dumps({"error": exc.code, "message": exc.message}), err=True)
    raise typer.Exit(code=2) from exc


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


def _resolved_release_inputs(
    seat_root: Path,
    release_dir: Path | None,
    release_public_key: Path | None,
    qualification_public_key: Path | None,
) -> tuple[Path, Path, Path]:
    """Resolve the release installed in the seat's private launch directory."""

    launch_dir = seat_root / "launch"
    return (
        release_dir or launch_dir / "release",
        release_public_key or launch_dir / "release-public.pem",
        qualification_public_key or launch_dir / "qualification-public.pem",
    )


def _default_appliance_cache() -> Path:
    """Return the current user's XDG-compatible appliance cache."""

    configured = os.environ.get("XDG_CACHE_HOME")
    if configured:
        candidate = Path(configured)
        if candidate.is_absolute():
            return candidate / "aptl" / "appliance"
    return Path.home() / ".cache" / "aptl" / "appliance"


@app.command("install")
def install(
    tag: str = typer.Option(..., "--tag"),
    release_public_key: Path = typer.Option(..., "--release-public-key"),
    qualification_public_key: Path = typer.Option(..., "--qualification-public-key"),
    repository: str = typer.Option("Brad-Edwards/aptl", "--repository"),
    release_id: str | None = typer.Option(None, "--release-id"),
    seat_root: Path | None = typer.Option(None, "--seat-root"),
    cache_dir: Path | None = typer.Option(None, "--cache-dir"),
) -> None:
    """Install and verify a public appliance release for this user."""

    selected_release_id = release_id or f"aptl-{tag}-x86_64"
    try:
        result = install_public_release(
            selection=PublicReleaseSelection(
                repository=repository, tag=tag, release_id=selected_release_id
            ),
            release_public_key=release_public_key,
            qualification_public_key=qualification_public_key,
            seat_root=_resolved_seat_root(seat_root),
            cache_dir=cache_dir or _default_appliance_cache(),
        )
    except AppliancePublicInstallError as exc:
        _fail(SeatLauncherError("public-install-failed", str(exc)))
    _emit(
        {
            "installed": True,
            "release_id": result.release_id,
            "release_dir": str(result.release_dir),
            "reused": result.reused,
        }
    )


@app.command("stage")
def stage(
    seat_root: Path | None = typer.Option(None, "--seat-root"),
    seat_id: str = typer.Option("seat-01", "--seat-id"),
    release_dir: Path | None = typer.Option(None, "--release-dir"),
    release_public_key: Path | None = typer.Option(None, "--release-public-key"),
    qualification_public_key: Path | None = typer.Option(
        None, "--qualification-public-key"
    ),
    mapping: list[str] | None = typer.Option(None, "--mapping"),
) -> None:
    """Verify release admission and persist a staged seat record."""

    try:
        seat_root = _resolved_seat_root(seat_root)
        release_dir, release_public_key, qualification_public_key = (
            _resolved_release_inputs(
                seat_root,
                release_dir,
                release_public_key,
                qualification_public_key,
            )
        )
        mappings = _parse_mappings(mapping)
        record = stage_seat(
            seat_root,
            seat_id=seat_id,
            release_dir=release_dir,
            release_public_key=release_public_key,
            qualification_public_key=qualification_public_key,
            mappings=mappings,
        )
    except SeatLauncherError as exc:
        _fail(exc)
    _emit({"staged": True, "seat": record.model_dump(mode="json")})


@app.command("start")
def start(
    seat_root: Path | None = typer.Option(None, "--seat-root"),
    seat_id: str = typer.Option("seat-01", "--seat-id"),
    release_dir: Path | None = typer.Option(None, "--release-dir"),
    release_public_key: Path | None = typer.Option(None, "--release-public-key"),
    qualification_public_key: Path | None = typer.Option(
        None, "--qualification-public-key"
    ),
    mapping: list[str] | None = typer.Option(None, "--mapping"),
    access_owner: str | None = typer.Option(None, "--access-owner"),
    access_public_key: Path | None = typer.Option(None, "--access-public-key"),
    access_identity_file: Path | None = typer.Option(None, "--access-identity-file"),
    access_project_dir: Path | None = typer.Option(None, "--access-project-dir"),
    access_profile: str = typer.Option("red", "--access-profile"),
    access_client: list[str] | None = typer.Option(None, "--access-client"),
    access_hours: int = typer.Option(8, "--access-hours", min=1, max=24),
    qualification_candidate: bool = typer.Option(
        False, "--qualification-candidate", hidden=True
    ),
) -> None:
    """Start the seat VM and validate host exposure."""

    try:
        seat_root = _resolved_seat_root(seat_root)
        release_dir, release_public_key, qualification_public_key = (
            _resolved_release_inputs(
                seat_root,
                release_dir,
                release_public_key,
                qualification_public_key,
            )
        )
        mappings = _parse_mappings(mapping)
        access_values = (
            access_owner,
            access_public_key,
            access_identity_file,
            access_project_dir,
        )
        if not any(value is not None for value in access_values) and (
            release_requires_host_access(
                release_dir=release_dir,
                release_public_key=release_public_key,
                qualification_public_key=qualification_public_key,
                candidate_trust=qualification_candidate,
            )
        ):
            access_identity_file, access_public_key = ensure_transport_identity(
                seat_root
            )
            access_owner = getpass.getuser().lower()
            access_project_dir = Path.cwd()
            access_client = ["claude", "codex"]
            access_values = (
                access_owner,
                access_public_key,
                access_identity_file,
                access_project_dir,
            )
        if any(value is not None for value in access_values) and not all(
            value is not None for value in access_values
        ):
            raise SeatLauncherError(
                "invalid-host-access", "all host access options must be supplied"
            )
        enrollment = None
        clients: tuple[str, ...] = ()
        if access_owner is not None:
            if access_profile not in {"red", "blue"}:
                raise SeatLauncherError(
                    "invalid-host-access", "access profile must be red or blue"
                )
            assert access_public_key is not None
            enrollment = SeatAccessEnrollment(
                owner_id=access_owner,
                grant_id=f"{seat_id}-{access_profile}",
                public_key=access_public_key.read_text(encoding="utf-8"),
                profile=access_profile,
                expires_at=datetime.now(UTC) + timedelta(hours=access_hours),
            )
            clients = tuple(access_client or ("claude", "codex"))
        record = start_seat(
            seat_root,
            seat_id=seat_id,
            release_dir=release_dir,
            release_public_key=release_public_key,
            qualification_public_key=qualification_public_key,
            options=StartSeatOptions(
                mappings=mappings,
                access_enrollment=enrollment,
                access_identity_file=access_identity_file,
                access_project_dir=access_project_dir,
                access_clients=clients,
                candidate_trust=qualification_candidate,
            ),
        )
    except ApplianceManifestError as exc:
        _fail(SeatLauncherError("invalid-release", str(exc)))
    except WorkbenchConfigurationError as exc:
        _fail(SeatLauncherError("invalid-host-access", str(exc)))
    except (OSError, ValidationError) as exc:
        _fail(SeatLauncherError("invalid-host-access", "host access input is invalid"))
    except SeatLauncherError as exc:
        _fail(exc)
    _emit({"started": True, "seat": record.model_dump(mode="json")})


@app.command("stop")
def stop(seat_root: Path | None = typer.Option(None, "--seat-root")) -> None:
    """Stop the seat VM without destroying overlay state."""

    try:
        seat_root = _resolved_seat_root(seat_root)
        record = stop_seat(seat_root)
    except SeatLauncherError as exc:
        _fail(exc)
    _emit({"stopped": True, "seat": record.model_dump(mode="json")})


@app.command("reset")
def reset(
    seat_root: Path | None = typer.Option(None, "--seat-root"),
    seat_id: str = typer.Option("seat-01", "--seat-id"),
    release_dir: Path | None = typer.Option(None, "--release-dir"),
    release_public_key: Path | None = typer.Option(None, "--release-public-key"),
    qualification_public_key: Path | None = typer.Option(
        None, "--qualification-public-key"
    ),
) -> None:
    """Destroy overlay state and restage the seat."""

    try:
        seat_root = _resolved_seat_root(seat_root)
        release_dir, release_public_key, qualification_public_key = (
            _resolved_release_inputs(
                seat_root,
                release_dir,
                release_public_key,
                qualification_public_key,
            )
        )
        record = reset_seat(
            seat_root,
            seat_id=seat_id,
            release_dir=release_dir,
            release_public_key=release_public_key,
            qualification_public_key=qualification_public_key,
        )
    except SeatLauncherError as exc:
        _fail(exc)
    _emit({"reset": True, "seat": record.model_dump(mode="json")})


@app.command("recover")
def recover(
    seat_root: Path | None = typer.Option(None, "--seat-root"),
    seat_id: str = typer.Option("seat-01", "--seat-id"),
    release_dir: Path | None = typer.Option(None, "--release-dir"),
    release_public_key: Path | None = typer.Option(None, "--release-public-key"),
    qualification_public_key: Path | None = typer.Option(
        None, "--qualification-public-key"
    ),
) -> None:
    """Instructor recovery: reset and start the seat."""

    try:
        seat_root = _resolved_seat_root(seat_root)
        release_dir, release_public_key, qualification_public_key = (
            _resolved_release_inputs(
                seat_root,
                release_dir,
                release_public_key,
                qualification_public_key,
            )
        )
        record = recover_seat(
            seat_root,
            seat_id=seat_id,
            release_dir=release_dir,
            release_public_key=release_public_key,
            qualification_public_key=qualification_public_key,
        )
    except SeatLauncherError as exc:
        _fail(exc)
    _emit({"recovered": True, "seat": record.model_dump(mode="json")})


@app.command("reconcile")
def reconcile(seat_root: Path | None = typer.Option(None, "--seat-root")) -> None:
    """Reconcile seat state after a physical-host reboot."""

    try:
        seat_root = _resolved_seat_root(seat_root)
        record = reconcile_seat_after_reboot(seat_root)
    except SeatLauncherError as exc:
        _fail(exc)
    _emit({"reconciled": True, "seat": record.model_dump(mode="json")})


@app.command("status")
def status(seat_root: Path | None = typer.Option(None, "--seat-root")) -> None:
    """Print coarse seat health without credentials."""

    projection = status_seat(_resolved_seat_root(seat_root))
    _emit(projection.model_dump(mode="json"))


@app.command("open-kiosk")
def open_kiosk(
    participant_port: int | None = typer.Option(None, "--participant-port"),
    seat_root: Path | None = typer.Option(None, "--seat-root"),
    browser_command: str | None = typer.Option(None, "--browser-command"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Launch the participant browser kiosk wrapper."""

    try:
        resolved_root = _resolved_seat_root(seat_root)
        record = load_seat_record(resolved_root)
        if record is not None:
            participants = tuple(
                mapping
                for mapping in record.mappings
                if mapping.audience == "participant" and mapping.protocol == "tcp"
            )
            if len(participants) != 1:
                raise SeatLauncherError(
                    "invalid-mapping", "seat requires one participant mapping"
                )
            if (
                participant_port is not None
                and participant_port != participants[0].port
            ):
                raise SeatLauncherError(
                    "invalid-mapping", "participant port differs from staged mapping"
                )
            participant_port = participants[0].port
    except SeatLauncherError as exc:
        _fail(exc)
    plan = open_participant_kiosk(
        participant_port=participant_port or 443,
        browser_command=browser_command,
        dry_run=dry_run,
    )
    _emit({"kiosk": True, "argv": list(plan.argv), "url": plan.url})
