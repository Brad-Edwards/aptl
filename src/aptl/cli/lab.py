"""CLI commands for lab lifecycle management."""

import json
from pathlib import Path
from typing import Optional

import typer

from aptl.core.lab import (
    LabResult,
    LabStatus,
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
        from aptl.core.config import find_config, load_config
        from aptl.core.deployment import get_backend
        from aptl.core.snapshot import capture_snapshot

        # Resolve backend from config so SSH-remote labs are snapshotted
        # against the right Docker daemon. Falls back to defaults if no
        # aptl.json is present (status remains useful in fresh dirs).
        config_path = find_config(project_dir)
        if config_path is None:
            backend = None
        else:
            try:
                cfg = load_config(config_path)
            except (FileNotFoundError, ValueError):
                backend = None
            else:
                backend = get_backend(cfg, project_dir)

        snapshot = capture_snapshot(config_dir=project_dir, backend=backend)
        data = json.dumps(snapshot.to_dict(), indent=2)

        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(data)
            output_file.chmod(0o600)
            typer.echo(f"Snapshot written to {output_file}")
        else:
            typer.echo(data)
        return

    current = lab_status(project_dir=project_dir)

    if current.running:
        typer.echo("Lab is running.")
        for container in current.containers:
            name = container.get("Name", "unknown")
            state = container.get("State", "unknown")
            health = container.get("Health", "")
            line = f"  {name}: {state}"
            if health:
                line += f" ({health})"
            typer.echo(line)
    else:
        typer.echo("Lab is not running.")
        if current.error:
            typer.echo(f"Error: {current.error}")
