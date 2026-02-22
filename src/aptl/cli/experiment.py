"""CLI commands for experiment run management.

Provides commands to:
  - run: Execute a scenario as a tracked experiment with full data capture
  - collect: Collect artefacts from the most recent scenario run
  - export: Package and export experiment data (local or S3)
  - list: List completed experiments
  - show: Show details of a specific experiment
  - reset: Reset the range for the next experiment run
"""

from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from aptl.core.collector import collect_all
from aptl.core.events import EventLog, EventType, make_event
from aptl.core.experiment import (
    ExperimentManifest,
    capture_range_snapshot,
    copy_aptl_config,
    copy_docker_compose,
    copy_pyproject,
    copy_scenario_yaml,
    copy_wazuh_configs,
    create_experiment_dir,
    generate_run_id,
    experiment_dir,
    list_experiments,
    load_manifest,
    reset_range,
    write_manifest,
    write_snapshot,
)
from aptl.core.exporter import ExportResult, compute_dir_checksums, export_local, export_s3
from aptl.core.objectives import ObjectiveStatus, evaluate_all
from aptl.core.scenarios import (
    ScenarioNotFoundError,
    ScenarioStateError,
    ScenarioValidationError,
    find_scenarios,
    load_scenario,
)
from aptl.core.scoring import calculate_score, generate_report, write_report
from aptl.core.session import ScenarioSession
from aptl.utils.logging import get_logger

log = get_logger("cli.experiment")

app = typer.Typer(help="Experiment run management with full data capture.")
console = Console()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _state_dir(project_dir: Path) -> Path:
    return project_dir / ".aptl"


def _resolve_scenarios_dir(project_dir: Path, scenarios_dir: Path | None) -> Path:
    if scenarios_dir is not None:
        return scenarios_dir
    return project_dir / "scenarios"


def _find_scenario_path(scenarios_dir: Path, name: str) -> Path:
    if name.endswith(".yaml"):
        candidate = scenarios_dir / name
    else:
        candidate = scenarios_dir / f"{name}.yaml"
    if candidate.is_file():
        return candidate
    raise ScenarioNotFoundError(name)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def run(
    name: str = typer.Argument(help="Scenario name or filename to run as an experiment."),
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir", "-d",
        help="Path to the APTL project directory.",
    ),
    scenarios_dir: Path | None = typer.Option(
        None,
        "--scenarios-dir", "-s",
        help="Path to scenarios directory.",
    ),
    tags: list[str] = typer.Option(
        [],
        "--tag", "-t",
        help="Tags for the experiment (repeatable).",
    ),
    notes: str = typer.Option(
        "",
        "--notes", "-n",
        help="Free-text notes for the experiment.",
    ),
    auto_reset: bool = typer.Option(
        False,
        "--auto-reset",
        help="Automatically reset the range before starting.",
    ),
) -> None:
    """Start a scenario as a tracked experiment with full data capture.

    This command:
      1. Optionally resets the range (--auto-reset)
      2. Captures a range snapshot (software versions, configs, rules)
      3. Starts the scenario session
      4. Prints instructions for the operator

    After completing the scenario, use 'aptl experiment collect' to
    gather all artefacts, or 'aptl scenario stop' followed by
    'aptl experiment collect'.
    """
    resolved_dir = _resolve_scenarios_dir(project_dir, scenarios_dir)

    try:
        scenario_path = _find_scenario_path(resolved_dir, name)
        scenario = load_scenario(scenario_path)
    except (ScenarioNotFoundError, ScenarioValidationError, FileNotFoundError) as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(code=1) from e

    state = _state_dir(project_dir)
    session_mgr = ScenarioSession(state)

    # Optional pre-reset
    if auto_reset:
        typer.echo("Resetting range...")
        reset_result = reset_range(project_dir)
        if reset_result["session_cleared"]:
            typer.echo("  Cleared previous session state")

    # Check no active session
    if session_mgr.is_active():
        typer.echo(
            "Error: A scenario is already active. Stop it first with "
            "'aptl scenario stop' or use 'aptl experiment reset'."
        )
        raise typer.Exit(code=1)

    # Generate experiment run ID and create directory
    run_id = generate_run_id()
    exp_dir = create_experiment_dir(state, run_id)

    typer.echo(f"Experiment run ID: {run_id}")
    typer.echo(f"Data directory: {exp_dir}")

    # Capture range snapshot
    typer.echo("Capturing range snapshot...")
    snapshot = capture_range_snapshot(project_dir)
    write_snapshot(exp_dir, snapshot)

    # Copy config artefacts into the experiment
    copy_scenario_yaml(exp_dir, scenario_path)
    copy_docker_compose(exp_dir, project_dir)
    copy_aptl_config(exp_dir, project_dir)
    copy_pyproject(exp_dir, project_dir)
    copy_wazuh_configs(exp_dir, project_dir)

    typer.echo(f"  Snapshot: {len(snapshot.containers)} containers, "
               f"{snapshot.wazuh_rules.rules_count} rules")

    # Start scenario session
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    events_dir = state / "events"
    events_file = events_dir / f"{scenario.metadata.id}_{ts}.jsonl"

    try:
        session = session_mgr.start(scenario, events_file)
    except ScenarioStateError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(code=1) from e

    event_log = EventLog(state / session.events_file)
    event_log.append(make_event(
        EventType.SCENARIO_STARTED,
        scenario.metadata.id,
        {
            "mode": scenario.mode.value,
            "experiment_run_id": run_id,
        },
    ))

    # Write initial manifest
    manifest = ExperimentManifest(
        run_id=run_id,
        scenario_id=scenario.metadata.id,
        scenario_name=scenario.metadata.name,
        scenario_version=scenario.metadata.version,
        started_at=session.started_at,
        tags=tags,
        notes=notes,
    )
    write_manifest(exp_dir, manifest)

    # Store run_id in session state dir for easy retrieval by collect
    run_id_file = state / "current_experiment_run_id"
    run_id_file.write_text(run_id, encoding="utf-8")

    typer.echo("")
    typer.echo(f"Experiment started: {scenario.metadata.name}")
    typer.echo(f"  Mode:       {scenario.mode.value}")
    typer.echo(f"  Objectives: {len(scenario.objectives.all_objectives())}")
    typer.echo(f"  Run ID:     {run_id}")
    typer.echo("")
    typer.echo("Run your scenario now. When finished:")
    typer.echo("  aptl scenario stop          # Stop scenario and generate report")
    typer.echo("  aptl experiment collect      # Collect all artefacts")
    typer.echo("  aptl experiment export       # Package for export")


@app.command()
def collect(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir", "-d",
        help="Path to the APTL project directory.",
    ),
    run_id: str = typer.Option(
        "",
        "--run-id", "-r",
        help="Experiment run ID. Defaults to the most recent.",
    ),
) -> None:
    """Collect all artefacts from a scenario run into the experiment directory.

    Gathers container logs, Wazuh alerts, event timelines, reports,
    shell histories, and Kali activity logs.
    """
    state = _state_dir(project_dir)

    # Determine run ID
    if not run_id:
        run_id_file = state / "current_experiment_run_id"
        if run_id_file.exists():
            run_id = run_id_file.read_text().strip()
        else:
            typer.echo("No active experiment. Specify --run-id or start an experiment first.")
            raise typer.Exit(code=1)

    exp_dir = experiment_dir(state, run_id)
    if not exp_dir.exists():
        typer.echo(f"Experiment directory not found: {exp_dir}")
        raise typer.Exit(code=1)

    # Load manifest
    manifest = load_manifest(state, run_id)
    if manifest is None:
        typer.echo(f"Manifest not found for run {run_id}")
        raise typer.Exit(code=1)

    # Determine time bounds and scenario info
    start_time = manifest.started_at
    end_time = datetime.now(timezone.utc).isoformat()
    scenario_id = manifest.scenario_id

    # Try to get events file from session (may have been stopped already)
    events_file = ""
    session_mgr = ScenarioSession(state)
    session = session_mgr.get_active()
    if session:
        events_file = session.events_file
    else:
        # Look for events file matching scenario_id
        events_dir = state / "events"
        if events_dir.exists():
            candidates = sorted(
                events_dir.glob(f"{scenario_id}_*.jsonl"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if candidates:
                try:
                    events_file = str(candidates[0].relative_to(state))
                except ValueError:
                    events_file = str(candidates[0])

    typer.echo(f"Collecting artefacts for experiment {run_id}...")
    typer.echo(f"  Scenario: {scenario_id}")
    typer.echo(f"  Window:   {start_time} to {end_time}")

    summary = collect_all(
        exp_dir,
        state_dir=state,
        project_dir=project_dir,
        scenario_id=scenario_id,
        start_time=start_time,
        end_time=end_time,
        events_file=events_file,
    )

    # Update manifest with end time and checksums
    manifest.finished_at = end_time
    if manifest.started_at:
        start_dt = datetime.fromisoformat(manifest.started_at)
        end_dt = datetime.fromisoformat(end_time)
        manifest.duration_seconds = (end_dt - start_dt).total_seconds()

    checksums = compute_dir_checksums(exp_dir)
    manifest.artefact_checksums = checksums
    write_manifest(exp_dir, manifest)

    # Display summary
    artefacts = summary.get("artefacts", {})
    collected_count = sum(
        1 for v in artefacts.values()
        if v is not None and v != [] and v != "None"
    )

    typer.echo(f"\nCollection complete: {collected_count} artefact groups")
    for key, value in artefacts.items():
        if value and value != "None":
            if isinstance(value, list):
                typer.echo(f"  {key}: {len(value)} files")
            else:
                typer.echo(f"  {key}: collected")
        else:
            typer.echo(f"  {key}: -")


@app.command()
def export(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir", "-d",
        help="Path to the APTL project directory.",
    ),
    run_id: str = typer.Option(
        "",
        "--run-id", "-r",
        help="Experiment run ID. Defaults to the most recent.",
    ),
    output_dir: Path | None = typer.Option(
        None,
        "--output", "-o",
        help="Output directory for the archive. Defaults to current directory.",
    ),
    s3_bucket: str = typer.Option(
        "",
        "--s3-bucket",
        help="S3 bucket name for remote export.",
    ),
    s3_prefix: str = typer.Option(
        "aptl-experiments",
        "--s3-prefix",
        help="S3 key prefix.",
    ),
) -> None:
    """Package and export experiment data as a tar.gz archive.

    Exports locally by default. Use --s3-bucket to upload to S3.
    """
    state = _state_dir(project_dir)

    if not run_id:
        run_id_file = state / "current_experiment_run_id"
        if run_id_file.exists():
            run_id = run_id_file.read_text().strip()
        else:
            typer.echo("No active experiment. Specify --run-id.")
            raise typer.Exit(code=1)

    exp_dir = experiment_dir(state, run_id)
    if not exp_dir.exists():
        typer.echo(f"Experiment directory not found: {exp_dir}")
        raise typer.Exit(code=1)

    if output_dir is None:
        output_dir = Path(".")

    result: ExportResult

    if s3_bucket:
        typer.echo(f"Exporting experiment {run_id} to s3://{s3_bucket}/{s3_prefix}/...")
        result = export_s3(exp_dir, bucket=s3_bucket, prefix=s3_prefix, run_id=run_id)
    else:
        typer.echo(f"Exporting experiment {run_id} to local archive...")
        result = export_local(exp_dir, output_dir=output_dir, run_id=run_id)

    if result.success:
        typer.echo(f"Export successful:")
        if result.s3_uri:
            typer.echo(f"  S3 URI:   {result.s3_uri}")
        if result.path:
            typer.echo(f"  Archive:  {result.path}")
        typer.echo(f"  Size:     {result.size_bytes:,} bytes")
        typer.echo(f"  SHA-256:  {result.checksum_sha256}")
    else:
        typer.echo(f"Export failed: {result.error}")
        raise typer.Exit(code=1)


@app.command("list")
def list_cmd(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir", "-d",
        help="Path to the APTL project directory.",
    ),
) -> None:
    """List completed experiments."""
    state = _state_dir(project_dir)
    manifests = list_experiments(state)

    if not manifests:
        typer.echo("No experiments found.")
        return

    table = Table(title="Experiments")
    table.add_column("Run ID", style="cyan", no_wrap=True)
    table.add_column("Scenario")
    table.add_column("Started")
    table.add_column("Duration", justify="right")
    table.add_column("Tags")

    for m in manifests:
        duration = ""
        if m.duration_seconds > 0:
            mins = int(m.duration_seconds // 60)
            secs = int(m.duration_seconds % 60)
            duration = f"{mins}m {secs}s"

        started = m.started_at[:19] if m.started_at else ""
        table.add_row(
            m.run_id,
            m.scenario_id,
            started,
            duration,
            ", ".join(m.tags) if m.tags else "",
        )

    console.print(table)


@app.command()
def show(
    run_id: str = typer.Argument(help="Experiment run ID to show."),
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir", "-d",
        help="Path to the APTL project directory.",
    ),
) -> None:
    """Show details of a specific experiment."""
    state = _state_dir(project_dir)
    manifest = load_manifest(state, run_id)

    if manifest is None:
        typer.echo(f"Experiment not found: {run_id}")
        raise typer.Exit(code=1)

    typer.echo(f"Experiment: {manifest.run_id}")
    typer.echo(f"  Scenario:     {manifest.scenario_id} ({manifest.scenario_name})")
    typer.echo(f"  Version:      {manifest.scenario_version}")
    typer.echo(f"  Started:      {manifest.started_at}")
    typer.echo(f"  Finished:     {manifest.finished_at or '(in progress)'}")

    if manifest.duration_seconds > 0:
        mins = int(manifest.duration_seconds // 60)
        secs = int(manifest.duration_seconds % 60)
        typer.echo(f"  Duration:     {mins}m {secs}s")

    if manifest.tags:
        typer.echo(f"  Tags:         {', '.join(manifest.tags)}")
    if manifest.notes:
        typer.echo(f"  Notes:        {manifest.notes}")

    # Show artefact summary
    exp = experiment_dir(state, run_id)
    if exp.exists():
        typer.echo("")
        typer.echo("Artefacts:")
        for subdir in ["range_snapshot", "scenario", "events", "logs", "alerts", "report", "detection"]:
            d = exp / subdir
            if d.exists():
                files = list(d.rglob("*"))
                file_count = sum(1 for f in files if f.is_file())
                total_size = sum(f.stat().st_size for f in files if f.is_file())
                if file_count > 0:
                    typer.echo(f"  {subdir}: {file_count} files ({total_size:,} bytes)")
                else:
                    typer.echo(f"  {subdir}: (empty)")

    if manifest.artefact_checksums:
        typer.echo(f"\n  Total tracked files: {len(manifest.artefact_checksums)}")


@app.command()
def reset(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir", "-d",
        help="Path to the APTL project directory.",
    ),
    flush_alerts: bool = typer.Option(
        False,
        "--flush-alerts",
        help="Also flush Wazuh alert indices.",
    ),
    restart: list[str] = typer.Option(
        [],
        "--restart-container", "-c",
        help="Container to restart (repeatable). E.g. -c aptl-victim-1 -c aptl-kali-1",
    ),
) -> None:
    """Reset the range for the next experiment run.

    Clears scenario session state and optionally flushes Wazuh indices
    and restarts containers. This is a fast reset that avoids a full
    lab stop/start cycle.
    """
    typer.echo("Resetting range...")

    result = reset_range(
        project_dir,
        flush_wazuh_indices=flush_alerts,
        restart_containers=restart if restart else None,
    )

    if result["session_cleared"]:
        typer.echo("  Cleared session state")
    else:
        typer.echo("  No active session to clear")

    if result["indices_flushed"]:
        typer.echo("  Flushed Wazuh alert indices")

    if result["containers_restarted"]:
        for c in result["containers_restarted"]:
            typer.echo(f"  Restarted: {c}")

    # Clear current experiment tracking
    run_id_file = _state_dir(project_dir) / "current_experiment_run_id"
    if run_id_file.exists():
        run_id_file.unlink()

    typer.echo("Range reset complete. Ready for next experiment.")
