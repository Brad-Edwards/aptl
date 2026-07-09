"""CLI commands for lab lifecycle management."""

import json
from pathlib import Path
from typing import Optional

import typer

from aptl.cli import lab_init, lifecycle
from aptl.cli.continuity import continuity_audit
from aptl.cli.lab_render import (
    emit_lab_access_summary,
    live_resolved_ports,
    render_start_result,
)
from aptl.core.lab import (
    clean_boot_lab,
    lab_status,
    orchestrate_lab_start,
    stop_lab,
)
from aptl.core.lab_types import LabStatus
from aptl.core.scenario_catalog import (
    load_scenario_catalog,
    resolve_scenario_selection,
)
from aptl.utils.logging import get_logger

log = get_logger("cli.lab")

app = typer.Typer(help="Lab lifecycle management.")

# `continuity-audit` lives in aptl.cli.continuity (issue #252) so this
# module stays focused on lifecycle commands. Register it under `lab`
# so the command stays at `aptl lab continuity-audit` (no UX change).
app.command("continuity-audit")(continuity_audit)

# `init` (DEP-008) lives in aptl.cli.lab_init so this module stays the focused
# lifecycle facade; registered here so the command remains `aptl lab init`.
lab_init.register(app)

# Ephemeral lifecycle policy commands (DEP-003) live in aptl.cli.lifecycle so
# this module stays focused; register them under `lab` (no UX change:
# `aptl lab enforce` / `monitor` / `policy show`).
lifecycle.register(app)


# Shared destructive-data warning. Both `stop --volumes` and
# `start --clean` remove Compose-managed volumes, so the operator sees one
# canonical statement of what gets destroyed.
_DESTRUCTIVE_DATA_WARNING = (
    "\n  WARNING: This will destroy all lab data including:\n"
    "    - Wazuh SIEM indexes and configuration\n"
    "    - MISP threat intelligence data\n"
    "    - TheHive cases and analysis\n"
    "    - Shuffle SOAR workflows\n"
    "    - All container logs and state\n"
)


def _emit_lab_start_progress(message: str) -> None:
    """Print participant-facing startup progress."""
    typer.echo(f"[lab start] {message}")


def _confirm_destructive(skip_prompt: bool) -> bool:
    """Confirm a volume-destroying action; return False if the operator aborts.

    Centralizes the destructive-action gate shared by ``stop --volumes`` and
    ``start --clean``: print the canonical warning and require an explicit
    ``y`` unless ``skip_prompt`` (``--yes``) was passed.
    """
    if skip_prompt:
        return True
    typer.echo(_DESTRUCTIVE_DATA_WARNING)
    if not typer.confirm("  Continue?", default=False):
        typer.echo("Aborted.")
        return False
    return True


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
    scenario: Optional[str] = typer.Option(
        None,
        "--scenario",
        help="Curated ACES startup scenario id from the catalog.",
    ),
    scenario_path: Optional[Path] = typer.Option(
        None,
        "--scenario-path",
        help="Explicit ACES SDL scenario path under the project directory.",
    ),
    clean: bool = typer.Option(
        False,
        "--clean",
        "-c",
        help=(
            "Ephemeral clean boot (RNG-001): tear down the lab and remove "
            "Compose volumes before starting, guaranteeing clean state "
            "between runs. Destroys all lab data."
        ),
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the confirmation prompt for --clean.",
    ),
) -> None:
    """Start the APTL lab environment."""
    log.info("Starting lab from %s (clean=%s)", project_dir, clean)

    try:
        selected_scenario = resolve_scenario_selection(
            project_dir,
            scenario_id=scenario,
            scenario_path=scenario_path,
        )
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)

    if clean:
        if not _confirm_destructive(yes):
            raise typer.Exit(code=0)
        result = clean_boot_lab(
            project_dir,
            remove_volumes=True,
            skip_seed=skip_seed,
            scenario_path=selected_scenario,
            progress=_emit_lab_start_progress,
        )
    else:
        result = orchestrate_lab_start(
            project_dir,
            skip_seed=skip_seed,
            scenario_path=selected_scenario,
            progress=_emit_lab_start_progress,
        )

    render_start_result(result)
    if result.success:
        emit_lab_access_summary(project_dir, result.resolved_ports)
    if not result.success:
        raise typer.Exit(code=1)


@app.command("info")
def info(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
) -> None:
    """Show lab access URLs and credential locations."""
    env_path = project_dir / ".env"
    if not env_path.exists():
        typer.echo(
            f"Credentials file not found at {env_path}; run `aptl lab start` first.",
            err=True,
        )
        raise typer.Exit(code=1)
    # Reconstruct the ResolvedPort list from docker's runtime state so the
    # printed URLs reflect the actual published ports (#737).
    emit_lab_access_summary(project_dir, live_resolved_ports(project_dir))


@app.command("scenarios")
def scenarios(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
) -> None:
    """List curated ACES startup scenarios."""
    try:
        catalog = load_scenario_catalog(project_dir)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)

    for entry in catalog.scenarios:
        description = f" - {entry.description}" if entry.description else ""
        typer.echo(f"{entry.id}\t{entry.path}\t{entry.name}{description}")


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
    if volumes and not _confirm_destructive(yes):
        raise typer.Exit(code=0)

    log.info("Stopping lab (volumes=%s)", volumes)

    result = stop_lab(remove_volumes=volumes, project_dir=project_dir)

    if result.success:
        typer.echo("Lab stopped successfully.")
    else:
        typer.echo(f"Lab stop failed: {result.error}")
        raise typer.Exit(code=1)


def _emit_snapshot_json(project_dir: Path, output_file: Optional[Path]) -> None:
    """Capture and emit a redacted range snapshot as JSON.

    Writes to ``output_file`` (mode 0600) when given, otherwise prints it.
    """
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


def _emit_status_text(current: LabStatus) -> None:
    """Print a human-readable summary of the current lab status."""
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


_LIVE_GATE_WARNING = (
    "\n  WARNING: the live validation gate runs `aptl lab stop -v` and then\n"
    "  re-boots the lab through the ACES start path. This DESTROYS all lab\n"
    "  data (Wazuh/MISP/TheHive/Shuffle volumes). Pass --skip-clean-boot to\n"
    "  validate the already-running lab without destroying it.\n"
)


@app.command("validate-live")
def validate_live(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    scenario: Optional[Path] = typer.Option(
        None,
        "--scenario",
        help="ACES SDL scenario (default: scenarios/techvault-operational.sdl.yaml).",
    ),
    profile: str = typer.Option(
        "full-remote-control-plane",
        "--profile",
        help="ACES backend capability profile to validate against.",
    ),
    run_id: Optional[str] = typer.Option(
        None,
        "--run-id",
        help="Run id for the live-gate archive (default: generated).",
    ),
    skip_clean_boot: bool = typer.Option(
        False,
        "--skip-clean-boot",
        help="Validate the running lab without the destructive stop -v + reboot.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the data-destruction confirmation prompt.",
    ),
) -> None:
    """Run the live ACES validation gate (boots the lab end-to-end; DESTRUCTIVE).

    Proves a fresh TechVault lab is realized from the interpreted ACES model
    through the public start path and captures operational + provenance evidence
    in the run archive. Intended for maintainers / a documented CI runner — not
    fast CI: it needs Docker, the SOC stack's resources, and minutes of startup.
    """
    from aptl.cli._common import resolve_config_for_cli, resolve_run_store
    from aptl.core.runstore import _validate_id
    from aptl.validation.techvault_live_gate import (
        LiveGateOptions,
        validate_live_deployment,
    )

    config, project_root = resolve_config_for_cli(project_dir)
    if run_id is not None:
        try:
            _validate_id(run_id, "run_id")
        except ValueError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=2)
    if not skip_clean_boot and not yes:
        typer.echo(_LIVE_GATE_WARNING)
        if not typer.confirm("  Continue?", default=False):
            typer.echo("Aborted.")
            raise typer.Exit(code=0)

    log.info("Running live validation gate from %s", project_root)
    report = validate_live_deployment(
        scenario,
        project_dir=project_root,
        config=config,
        options=LiveGateOptions(
            profile=profile, run_id=run_id, skip_clean_boot=skip_clean_boot
        ),
        run_store=resolve_run_store(project_root, config),
    )
    typer.echo(report.render())
    if not report.passed:
        raise typer.Exit(code=1)
