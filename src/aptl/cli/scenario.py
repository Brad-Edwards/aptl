"""CLI commands for scenario management."""

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import sys

import typer
from rich.console import Console
from rich.table import Table

from aptl.core.config import AptlConfig, find_config, load_config
from aptl.core.env import load_dotenv
from aptl.core.events import EventLog, EventType, make_event
from aptl.core.flags import collect_flags
from aptl.core.run_assembler import assemble_run
from aptl.core.runstore import LocalRunStore
from aptl.core.scenarios import (
    ScenarioDefinition,
    ScenarioNotFoundError,
    ScenarioStateError,
    ScenarioValidationError,
    find_scenarios,
    load_scenario,
    validate_scenario_containers,
)
from aptl.core.session import ActiveSession, ScenarioSession
from aptl.utils.logging import get_logger

log = get_logger("cli.scenario")

app = typer.Typer(help="Scenario management.")
console = Console()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _state_dir(project_dir: Path) -> Path:
    """Return the .aptl/ state directory for a project."""
    return project_dir / ".aptl"


def _resolve_scenarios_dir(project_dir: Path, scenarios_dir: Path | None) -> Path:
    """Resolve the scenarios directory path."""
    if scenarios_dir is not None:
        return scenarios_dir
    return project_dir / "scenarios"


def _find_scenario_by_name(scenarios_dir: Path, name: str) -> Path:
    """Find a scenario file by name (with or without .yaml extension).

    Raises:
        ScenarioNotFoundError: If no matching file is found.
    """
    if name.endswith(".yaml"):
        candidate = scenarios_dir / name
    else:
        candidate = scenarios_dir / f"{name}.yaml"

    if candidate.is_file():
        return candidate

    raise ScenarioNotFoundError(name)


def _load_scenario_or_exit(
    scenarios_dir: Path,
    name: str,
) -> ScenarioDefinition:
    """Find and load a scenario, or exit with an error message.

    Args:
        scenarios_dir: Resolved scenarios directory.
        name: Scenario name or filename.

    Returns:
        Loaded and validated ScenarioDefinition.

    Raises:
        typer.Exit: If the scenario cannot be found or loaded.
    """
    try:
        path = _find_scenario_by_name(scenarios_dir, name)
        return load_scenario(path)
    except (ScenarioNotFoundError, ScenarioValidationError, FileNotFoundError) as e:
        log.error("Failed to load scenario '%s': %s", name, e)
        typer.echo(f"Error: {e}")
        raise typer.Exit(code=1) from e


def _require_active_session(
    session_mgr: ScenarioSession,
) -> ActiveSession:
    """Get the active session or exit with an error.

    Returns:
        The active session.

    Raises:
        typer.Exit: If no scenario is active.
    """
    session = session_mgr.get_active()
    if session is None or not session_mgr.is_active():
        typer.echo("No active scenario.")
        raise typer.Exit(code=1)
    return session


def _load_active_scenario(
    session: ActiveSession,
    project_dir: Path,
    scenarios_dir: Path | None,
) -> ScenarioDefinition:
    """Load the scenario definition for an active session.

    Args:
        session: Active session with a scenario_id.
        project_dir: Project directory.
        scenarios_dir: Explicit scenarios dir, or None for default.

    Returns:
        The loaded ScenarioDefinition.

    Raises:
        typer.Exit: If the scenario cannot be loaded.
    """
    resolved_dir = _resolve_scenarios_dir(project_dir, scenarios_dir)
    return _load_scenario_or_exit(resolved_dir, session.scenario_id)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command("list")
def list_scenarios(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    scenarios_dir: Path | None = typer.Option(
        None,
        "--scenarios-dir",
        "-s",
        help="Path to scenarios directory. Defaults to <project-dir>/scenarios.",
    ),
) -> None:
    """List available scenarios."""
    log.info("Listing scenarios")
    resolved_dir = _resolve_scenarios_dir(project_dir, scenarios_dir)
    paths = find_scenarios(resolved_dir)

    if not paths:
        typer.echo(f"No scenarios found in {resolved_dir}")
        return

    if sys.stdout.isatty():
        table = Table(title="Available Scenarios")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Name")
        table.add_column("Difficulty", style="green")
        table.add_column("Mode", style="yellow")
        table.add_column("Steps", justify="right")
        table.add_column("Tags")

        for path in paths:
            try:
                scenario = load_scenario(path)
                meta = scenario.metadata
                table.add_row(
                    meta.id,
                    meta.name,
                    meta.difficulty.value,
                    scenario.mode.value,
                    str(len(scenario.steps)),
                    ", ".join(meta.tags),
                )
            except (ScenarioValidationError, FileNotFoundError) as e:
                log.warning("Skipping invalid scenario %s: %s", path.name, e)
                table.add_row(
                    path.stem,
                    f"[red]ERROR: {e}[/red]",
                    "",
                    "",
                    "",
                    "",
                )

        console.print(table)
    else:
        # Plain text output for non-interactive use (pipes, tests)
        for path in paths:
            try:
                scenario = load_scenario(path)
                meta = scenario.metadata
                typer.echo(
                    f"{meta.id}\t{meta.name}\t"
                    f"{meta.difficulty.value}\t{scenario.mode.value}\t"
                    f"{len(scenario.steps)}\t{', '.join(meta.tags)}"
                )
            except (ScenarioValidationError, FileNotFoundError) as e:
                log.warning("Skipping invalid scenario %s: %s", path.name, e)
                typer.echo(f"{path.stem}\tERROR: {e}")


@app.command()
def show(
    name: str = typer.Argument(help="Scenario name or filename."),
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    scenarios_dir: Path | None = typer.Option(
        None,
        "--scenarios-dir",
        "-s",
        help="Path to scenarios directory. Defaults to <project-dir>/scenarios.",
    ),
) -> None:
    """Show details of a specific scenario."""
    log.info("Showing scenario: %s", name)
    resolved_dir = _resolve_scenarios_dir(project_dir, scenarios_dir)
    scenario = _load_scenario_or_exit(resolved_dir, name)

    meta = scenario.metadata
    typer.echo(f"Scenario: {meta.name}")
    typer.echo(f"  ID:          {meta.id}")
    typer.echo(f"  Version:     {meta.version}")
    typer.echo(f"  Author:      {meta.author or '(none)'}")
    typer.echo(f"  Difficulty:  {meta.difficulty.value}")
    typer.echo(f"  Mode:        {scenario.mode.value}")
    typer.echo(f"  Est. Time:   {meta.estimated_minutes} minutes")
    typer.echo(f"  Tags:        {', '.join(meta.tags) or '(none)'}")

    if meta.mitre_attack.tactics or meta.mitre_attack.techniques:
        typer.echo(f"  MITRE ATT&CK:")
        if meta.mitre_attack.tactics:
            typer.echo(f"    Tactics:    {', '.join(meta.mitre_attack.tactics)}")
        if meta.mitre_attack.techniques:
            typer.echo(f"    Techniques: {', '.join(meta.mitre_attack.techniques)}")

    typer.echo(f"  Containers:  {', '.join(scenario.containers.required)}")

    if scenario.preconditions:
        typer.echo(f"  Preconditions: {len(scenario.preconditions)}")

    typer.echo("")
    typer.echo("Objectives:")

    if scenario.objectives.red:
        typer.echo("  Red Team:")
        for obj in scenario.objectives.red:
            hint_count = len(obj.hints)
            hints_label = f" ({hint_count} hints)" if hint_count else ""
            typer.echo(
                f"    [{obj.id}] {obj.description} "
                f"({obj.points} pts, {obj.type.value}){hints_label}"
            )

    if scenario.objectives.blue:
        typer.echo("  Blue Team:")
        for obj in scenario.objectives.blue:
            hint_count = len(obj.hints)
            hints_label = f" ({hint_count} hints)" if hint_count else ""
            typer.echo(
                f"    [{obj.id}] {obj.description} "
                f"({obj.points} pts, {obj.type.value}){hints_label}"
            )

    if scenario.steps:
        typer.echo("")
        if scenario.attack_chain:
            typer.echo(f"Attack Chain: {scenario.attack_chain}")
        typer.echo("")
        typer.echo("Attack Steps:")
        for step in scenario.steps:
            typer.echo(
                f"  Step {step.step_number}: [{step.technique_id}] "
                f"{step.technique_name} ({step.tactic})"
            )
            typer.echo(f"    Target: {step.target}")
            typer.echo(f"    {step.description}")

            if step.commands:
                typer.echo("    Commands:")
                for cmd in step.commands:
                    typer.echo(f"      $ {cmd}")

            if step.expected_detections:
                typer.echo("    Expected Detections:")
                for det in step.expected_detections:
                    uid_info = f" (rule {det.analytic_uid})" if det.analytic_uid else ""
                    typer.echo(
                        f"      [{det.product_name}] {det.description}"
                        f"{uid_info} - {det.severity_id.name}"
                    )

            if step.investigation_hints:
                typer.echo("    Investigation Hints:")
                for ih in step.investigation_hints:
                    typer.echo(f"      - {ih}")

            typer.echo("")

    typer.echo(f"  Description:  {meta.description.strip()}")


@app.command()
def validate(
    path: Path = typer.Argument(help="Path to a scenario YAML file."),
) -> None:
    """Validate a scenario YAML file."""
    log.info("Validating scenario: %s", path)

    try:
        scenario = load_scenario(path)
    except FileNotFoundError as e:
        log.error("Scenario file not found: %s", path)
        typer.echo(f"Error: {e}")
        raise typer.Exit(code=1) from e
    except ScenarioValidationError as e:
        log.error("Scenario validation failed: %s", e)
        typer.echo(f"Validation failed: {e}")
        raise typer.Exit(code=1) from e

    meta = scenario.metadata
    obj_count = len(scenario.objectives.red) + len(scenario.objectives.blue)
    step_count = len(scenario.steps)
    typer.echo(
        f"Valid: {meta.name} ({meta.id}) - "
        f"{meta.difficulty.value}, {scenario.mode.value} mode, "
        f"{obj_count} objectives, {step_count} steps"
    )


@app.command()
def start(
    name: str = typer.Argument(help="Scenario name or filename."),
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    scenarios_dir: Path | None = typer.Option(
        None,
        "--scenarios-dir",
        "-s",
        help="Path to scenarios directory. Defaults to <project-dir>/scenarios.",
    ),
) -> None:
    """Start a scenario session."""
    log.info("Starting scenario: %s", name)
    resolved_dir = _resolve_scenarios_dir(project_dir, scenarios_dir)
    scenario = _load_scenario_or_exit(resolved_dir, name)

    # Validate required containers are enabled
    config_path = find_config(project_dir)
    config = load_config(config_path) if config_path else AptlConfig()
    missing = validate_scenario_containers(scenario, config)
    if missing:
        typer.echo(
            f"Error: Scenario '{scenario.metadata.id}' requires disabled profiles: "
            f"{', '.join(missing)}\n"
            f"Enable them in aptl.json or start the lab with the required profiles."
        )
        raise typer.Exit(code=1)

    state = _state_dir(project_dir)
    session_mgr = ScenarioSession(state)

    # Create events directory and log
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    events_dir = state / "events"
    events_file = events_dir / f"{scenario.metadata.id}_{ts}.jsonl"

    try:
        session = session_mgr.start(scenario, events_file)
    except ScenarioStateError as e:
        log.error("Cannot start scenario: %s", e)
        typer.echo(f"Error: {e}")
        raise typer.Exit(code=1) from e

    # Generate run_id and store in session
    run_id = uuid4().hex
    session.run_id = run_id
    session_mgr._write(session)

    # Set trace directory for MCP servers and clean stale traces
    trace_dir = state / "traces"
    if trace_dir.exists():
        shutil.rmtree(trace_dir)
    trace_dir.mkdir(parents=True, exist_ok=True)
    os.environ["APTL_TRACE_DIR"] = str(trace_dir)

    # Collect CTF flags from running containers
    flags = collect_flags()
    if flags:
        session.flags = flags
        session_mgr._write(session)
        flag_count = sum(len(v) for v in flags.values())
        log.info("Captured %d flags from %d containers", flag_count, len(flags))
    else:
        log.warning("No CTF flags collected (containers may not be running)")

    event_log = EventLog(state / session.events_file)
    event_log.append(make_event(
        EventType.SCENARIO_STARTED,
        scenario.metadata.id,
        {
            "mode": scenario.mode.value,
            "flags_collected": len(flags),
            "run_id": run_id,
        },
    ))

    typer.echo(f"Started scenario: {scenario.metadata.name}")
    typer.echo(f"  ID:         {scenario.metadata.id}")
    typer.echo(f"  Run ID:     {run_id}")
    typer.echo(f"  Mode:       {scenario.mode.value}")
    typer.echo(f"  Objectives: {len(scenario.objectives.all_objectives())}")
    typer.echo(f"  Flags:      {sum(len(v) for v in flags.values())} captured")
    typer.echo(f"  Events:     {session.events_file}")
    typer.echo(f"  Traces:     {trace_dir}")


@app.command()
def status(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
) -> None:
    """Show active scenario status."""
    state = _state_dir(project_dir)
    session_mgr = ScenarioSession(state)

    session = session_mgr.get_active()
    if session is None:
        typer.echo("No active scenario.")
        return

    # Compute elapsed time
    started = datetime.fromisoformat(session.started_at)
    elapsed = datetime.now(timezone.utc) - started
    minutes = int(elapsed.total_seconds() // 60)
    seconds = int(elapsed.total_seconds() % 60)

    typer.echo(f"Active scenario: {session.scenario_id}")
    typer.echo(f"  State:       {session.state.value}")
    if session.run_id:
        typer.echo(f"  Run ID:      {session.run_id}")
    typer.echo(f"  Started:     {session.started_at}")
    typer.echo(f"  Elapsed:     {minutes}m {seconds}s")
    typer.echo(f"  Completed:   {len(session.completed_objectives)} objectives")
    typer.echo(f"  Hints used:  {len(session.hints_used)}")


@app.command()
def stop(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    scenarios_dir: Path | None = typer.Option(
        None,
        "--scenarios-dir",
        "-s",
        help="Path to scenarios directory. Defaults to <project-dir>/scenarios.",
    ),
) -> None:
    """Stop the active scenario and assemble the run archive."""
    state = _state_dir(project_dir)
    session_mgr = ScenarioSession(state)
    session = _require_active_session(session_mgr)

    scenario = _load_active_scenario(session, project_dir, scenarios_dir)

    # Log stop event
    event_log = EventLog(state / session.events_file)
    event_log.append(make_event(
        EventType.SCENARIO_STOPPED,
        session.scenario_id,
    ))

    # Calculate duration
    started = datetime.fromisoformat(session.started_at)
    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)

    # Finish session
    finished_session = session_mgr.finish()

    # Read events
    events = event_log.read_all()

    # Load .env into os.environ so collectors in assemble_run() can
    # read credentials via os.getenv() (issue #184).
    env_path = project_dir / ".env"
    try:
        raw_env = load_dotenv(env_path)
        os.environ.update(raw_env)
    except FileNotFoundError:
        log.warning(".env not found at %s; collectors will use defaults", env_path)

    # Assemble experiment run directory (if run_id was set)
    run_dir = None
    if session.run_id:
        try:
            config_path = find_config(project_dir)
            config = load_config(config_path) if config_path else AptlConfig()

            local_path = Path(config.run_storage.local_path)
            if not local_path.is_absolute():
                local_path = project_dir / local_path

            store = LocalRunStore(local_path)

            resolved_dir = _resolve_scenarios_dir(project_dir, scenarios_dir)
            scenario_path = _find_scenario_by_name(
                resolved_dir, session.scenario_id
            )

            run_dir = assemble_run(
                store=store,
                run_id=session.run_id,
                session=finished_session,
                scenario=scenario,
                scenario_path=scenario_path,
                events=events,
                config=config,
            )
        except Exception as e:
            log.error("Failed to assemble run: %s", e)
            typer.echo(f"Warning: Run assembly failed: {e}")

    # Clear session
    session_mgr.clear()

    # Display summary
    typer.echo(f"Scenario stopped: {scenario.metadata.name}")
    typer.echo(f"  Duration: {minutes}m {seconds}s")
    flag_count = sum(len(v) for v in session.flags.values())
    typer.echo(f"  Flags:    {flag_count}")
    if run_dir:
        typer.echo(f"  Run:      {run_dir}")
