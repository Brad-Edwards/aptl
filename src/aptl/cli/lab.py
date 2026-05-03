"""CLI commands for lab lifecycle management."""

import json
from pathlib import Path
from typing import Optional

import typer

from aptl.core.lab import (
    lab_status,
    orchestrate_lab_start,
    stop_lab,
)
from aptl.utils.logging import get_logger

log = get_logger("cli.lab")

app = typer.Typer(help="Lab lifecycle management.")


@app.command()
def start(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    skip_seed: bool = typer.Option(
        False,
        "--skip-seed",
        help="Skip SOC tool seeding after startup.",
    ),
) -> None:
    """Start the APTL lab environment."""
    log.info("Starting lab from %s", project_dir)

    result = orchestrate_lab_start(project_dir, skip_seed=skip_seed)

    if result.success:
        typer.echo("Lab started successfully.")
    else:
        typer.echo(f"Lab start failed: {result.error}")
        raise typer.Exit(code=1)


@app.command()
def stop(
    volumes: bool = typer.Option(
        False,
        "--volumes",
        "-v",
        help="Also remove Docker volumes (full cleanup).",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip confirmation prompt when removing volumes.",
    ),
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
) -> None:
    """Stop the APTL lab environment."""
    if volumes and not yes:
        typer.echo(
            "\n  WARNING: This will destroy all lab data including:\n"
            "    - Wazuh SIEM indexes and configuration\n"
            "    - MISP threat intelligence data\n"
            "    - TheHive cases and analysis\n"
            "    - Shuffle SOAR workflows\n"
            "    - All container logs and state\n"
        )
        if not typer.confirm("  Continue?", default=False):
            typer.echo("Aborted.")
            raise typer.Exit(code=0)

    log.info("Stopping lab (volumes=%s)", volumes)

    result = stop_lab(remove_volumes=volumes, project_dir=project_dir)

    if result.success:
        typer.echo("Lab stopped successfully.")
    else:
        typer.echo(f"Lab stop failed: {result.error}")
        raise typer.Exit(code=1)


def _emit_snapshot_json(project_dir: Path, output_file: Optional[Path]) -> None:
    from aptl.cli._common import resolve_config_for_cli
    from aptl.core.deployment import get_backend
    from aptl.core.snapshot import capture_snapshot

    # `capture_snapshot` requires an explicit backend (no silent default).
    # Resolve from the project's `aptl.json`; fail loudly if it's missing
    # or invalid, so a misconfigured SSH lab doesn't get snapshotted
    # against the local daemon.
    config, project_root = resolve_config_for_cli(project_dir)
    backend = get_backend(config, project_root)

    snapshot = capture_snapshot(config_dir=project_root, backend=backend)
    data = json.dumps(snapshot.to_dict(), indent=2)

    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(data)
        output_file.chmod(0o600)
        typer.echo(f"Snapshot written to {output_file}")
    else:
        typer.echo(data)


def _emit_status_text(current) -> None:
    if not current.running:
        typer.echo("Lab is not running.")
        if current.error:
            typer.echo(f"Error: {current.error}")
        return

    typer.echo("Lab is running.")
    for container in current.containers:
        name = container.get("Name", "unknown")
        state = container.get("State", "unknown")
        health = container.get("Health", "")
        line = f"  {name}: {state}"
        if health:
            line += f" ({health})"
        typer.echo(line)


@app.command()
def status(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output full range snapshot as JSON.",
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write JSON output to file instead of stdout.",
    ),
) -> None:
    """Show the current lab status."""
    log.info("Checking lab status")

    if output_json or output_file:
        _emit_snapshot_json(project_dir, output_file)
        return

    _emit_status_text(lab_status(project_dir=project_dir))
