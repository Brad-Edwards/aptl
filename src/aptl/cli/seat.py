"""CLI for host-side appliance seat lifecycle operations."""

from __future__ import annotations

import json
from pathlib import Path

import typer

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

app = typer.Typer(help="Operate one disposable appliance seat on a physical host.")


def _emit(payload: dict[str, object]) -> None:
    typer.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def _fail(exc: SeatLauncherError) -> None:
    typer.echo(json.dumps({"error": exc.code, "message": exc.message}), err=True)
    raise typer.Exit(code=2) from exc


@app.command("stage")
def stage(
    seat_root: Path = typer.Option(..., "--seat-root"),
    seat_id: str = typer.Option("seat-01", "--seat-id"),
    release_dir: Path = typer.Option(..., "--release-dir"),
    release_public_key: Path = typer.Option(..., "--release-public-key"),
    qualification_public_key: Path = typer.Option(..., "--qualification-public-key"),
) -> None:
    """Verify release admission and persist a staged seat record."""

    try:
        record = stage_seat(
            seat_root,
            seat_id=seat_id,
            release_dir=release_dir,
            release_public_key=release_public_key,
            qualification_public_key=qualification_public_key,
        )
    except SeatLauncherError as exc:
        _fail(exc)
    _emit({"staged": True, "seat": record.model_dump(mode="json")})


@app.command("start")
def start(
    seat_root: Path = typer.Option(..., "--seat-root"),
    seat_id: str = typer.Option("seat-01", "--seat-id"),
    release_dir: Path = typer.Option(..., "--release-dir"),
    release_public_key: Path = typer.Option(..., "--release-public-key"),
    qualification_public_key: Path = typer.Option(..., "--qualification-public-key"),
) -> None:
    """Start the seat VM and validate host exposure."""

    try:
        record = start_seat(
            seat_root,
            seat_id=seat_id,
            release_dir=release_dir,
            release_public_key=release_public_key,
            qualification_public_key=qualification_public_key,
        )
    except SeatLauncherError as exc:
        _fail(exc)
    _emit({"started": True, "seat": record.model_dump(mode="json")})


@app.command("stop")
def stop(seat_root: Path = typer.Option(..., "--seat-root")) -> None:
    """Stop the seat VM without destroying overlay state."""

    try:
        record = stop_seat(seat_root)
    except SeatLauncherError as exc:
        _fail(exc)
    _emit({"stopped": True, "seat": record.model_dump(mode="json")})


@app.command("reset")
def reset(
    seat_root: Path = typer.Option(..., "--seat-root"),
    seat_id: str = typer.Option("seat-01", "--seat-id"),
    release_dir: Path = typer.Option(..., "--release-dir"),
    release_public_key: Path = typer.Option(..., "--release-public-key"),
    qualification_public_key: Path = typer.Option(..., "--qualification-public-key"),
) -> None:
    """Destroy overlay state and restage the seat."""

    try:
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
    seat_root: Path = typer.Option(..., "--seat-root"),
    seat_id: str = typer.Option("seat-01", "--seat-id"),
    release_dir: Path = typer.Option(..., "--release-dir"),
    release_public_key: Path = typer.Option(..., "--release-public-key"),
    qualification_public_key: Path = typer.Option(..., "--qualification-public-key"),
) -> None:
    """Instructor recovery: reset and start the seat."""

    try:
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
def reconcile(seat_root: Path = typer.Option(..., "--seat-root")) -> None:
    """Reconcile seat state after a physical-host reboot."""

    try:
        record = reconcile_seat_after_reboot(seat_root)
    except SeatLauncherError as exc:
        _fail(exc)
    _emit({"reconciled": True, "seat": record.model_dump(mode="json")})


@app.command("status")
def status(seat_root: Path = typer.Option(..., "--seat-root")) -> None:
    """Print coarse seat health without credentials."""

    projection = status_seat(seat_root)
    _emit(projection.model_dump(mode="json"))


@app.command("open-kiosk")
def open_kiosk(
    participant_port: int = typer.Option(443, "--participant-port"),
    browser_command: str | None = typer.Option(None, "--browser-command"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Launch the participant browser kiosk wrapper."""

    plan = open_participant_kiosk(
        participant_port=participant_port,
        browser_command=browser_command,
        dry_run=dry_run,
    )
    _emit({"kiosk": True, "argv": list(plan.argv), "url": plan.url})
