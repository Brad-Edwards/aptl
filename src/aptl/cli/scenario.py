"""CLI commands for scenario management."""

import asyncio
import os
import signal
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import sys

import typer
from rich.console import Console
from rich.table import Table

from aptl.core.config import AptlConfig, find_config, load_config
from aptl.core.env import load_dotenv
from aptl.core.flags import collect_flags
from aptl.core.run_assembler import assemble_run
from aptl.core.runstore import LocalRunStore
from aptl.core.scenarios import (
    ObjectiveType,
    ScenarioDefinition,
    ScenarioNotFoundError,
    ScenarioStateError,
    ScenarioValidationError,
    find_scenarios,
    load_scenario,
    validate_scenario_containers,
)
from aptl.core.scoring import ScoreReport, compute_score
from aptl.core.session import ActiveSession, ScenarioSession
from aptl.core.telemetry import (
    create_child_span,
    create_root_span,
    get_tracer,
    init_tracing,
    make_parent_context,
    shutdown_tracing,
    write_trace_context,
)
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


def _load_env(project_dir: Path) -> None:
    """Load .env into os.environ so evaluators/collectors can read credentials."""
    env_path = project_dir / ".env"
    try:
        raw_env = load_dotenv(env_path)
        os.environ.update(raw_env)
    except FileNotFoundError:
        log.warning(".env not found at %s; evaluators will use defaults", env_path)


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

    try:
        session = session_mgr.start(scenario)
    except ScenarioStateError as e:
        log.error("Cannot start scenario: %s", e)
        typer.echo(f"Error: {e}")
        raise typer.Exit(code=1) from e

    # Generate run_id and store in session
    run_id = uuid4().hex
    session.run_id = run_id
    session_mgr._write(session)

    # Write trace context for MCP servers to read
    write_trace_context(state, session.trace_id, session.span_id)

    # Collect CTF flags from running containers
    flags = collect_flags()
    if flags:
        session.flags = flags
        session_mgr._write(session)
        flag_count = sum(len(v) for v in flags.values())
        log.info("Captured %d flags from %d containers", flag_count, len(flags))
    else:
        log.warning("No CTF flags collected (containers may not be running)")

    # Emit a lightweight OTel span marking scenario start
    init_tracing()
    try:
        tracer = get_tracer()
        parent_ctx = make_parent_context(session.trace_id, session.span_id)
        span = create_child_span(tracer, parent_ctx, "scenario.started", {
            "aptl.scenario.id": scenario.metadata.id,
            "aptl.scenario.mode": scenario.mode.value,
            "aptl.run.id": run_id,
            "aptl.flags.collected": sum(len(v) for v in flags.values()),
        })
        span.end()
    finally:
        shutdown_tracing()

    typer.echo(f"Started scenario: {scenario.metadata.name}")
    typer.echo(f"  ID:         {scenario.metadata.id}")
    typer.echo(f"  Run ID:     {run_id}")
    typer.echo(f"  Mode:       {scenario.mode.value}")
    typer.echo(f"  Objectives: {len(scenario.objectives.all_objectives())}")
    typer.echo(f"  Flags:      {sum(len(v) for v in flags.values())} captured")
    typer.echo(f"  Trace ID:   {session.trace_id}")


@app.command()
def status(
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
    """Show active scenario status with scoring."""
    state = _state_dir(project_dir)
    session_mgr = ScenarioSession(state)

    session = session_mgr.get_active()
    if session is None:
        typer.echo("No active scenario.")
        return

    # Compute elapsed time
    started = datetime.fromisoformat(session.started_at)
    elapsed = datetime.now(timezone.utc) - started
    elapsed_seconds = elapsed.total_seconds()
    minutes = int(elapsed_seconds // 60)
    seconds = int(elapsed_seconds % 60)

    typer.echo(f"Active scenario: {session.scenario_id}")
    typer.echo(f"  State:       {session.state.value}")
    if session.run_id:
        typer.echo(f"  Run ID:      {session.run_id}")
    typer.echo(f"  Started:     {session.started_at}")
    typer.echo(f"  Elapsed:     {minutes}m {seconds}s")
    typer.echo(f"  Completed:   {len(session.completed_objectives)} objectives")
    typer.echo(f"  Hints used:  {len(session.hints_used)}")

    # Show scoring if we can load the scenario definition
    try:
        resolved_dir = _resolve_scenarios_dir(project_dir, scenarios_dir)
        scenario = _load_scenario_or_exit(resolved_dir, session.scenario_id)
        score = compute_score(
            scenario,
            session.completed_objectives,
            session.hints_used,
            elapsed_seconds,
        )
        _print_score_summary(score)
    except SystemExit:
        pass  # _load_scenario_or_exit raises typer.Exit on missing file
    except Exception as e:
        log.debug("Could not compute score for status: %s", e)


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
    _stop_scenario(project_dir, scenarios_dir, session_mgr, session)


# ---------------------------------------------------------------------------
# Scoring display helper
# ---------------------------------------------------------------------------


def _print_score_summary(score: ScoreReport) -> None:
    """Print a formatted score summary."""
    typer.echo("")
    typer.echo("Score:")
    status_label = "PASS" if score.passed else "FAIL"
    typer.echo(f"  Total:       {score.total_score}/{score.max_score} [{status_label}]")
    typer.echo(f"  Passing:     {score.passing_score}")
    if score.time_bonus > 0:
        typer.echo(f"  Time bonus:  +{score.time_bonus}")
    if score.hint_penalties > 0:
        typer.echo(f"  Penalties:   -{score.hint_penalties}")

    typer.echo("")
    typer.echo("Objectives:")
    for os_ in score.objective_scores:
        status = "DONE" if os_.completed else "    "
        penalty_str = f" (-{os_.hint_penalty})" if os_.hint_penalty > 0 else ""
        typer.echo(
            f"  [{status}] {os_.objective_id}: "
            f"{os_.earned}/{os_.base_points} pts{penalty_str}"
        )


# ---------------------------------------------------------------------------
# Evaluate command
# ---------------------------------------------------------------------------


@app.command()
def evaluate(
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
    """Run a single evaluation pass against the active scenario."""
    from aptl.core.engine import ScenarioEngine

    state = _state_dir(project_dir)
    session_mgr = ScenarioSession(state)
    session = _require_active_session(session_mgr)
    scenario = _load_active_scenario(session, project_dir, scenarios_dir)

    # Load .env so evaluators can read credentials (Wazuh Indexer, etc.)
    _load_env(project_dir)

    engine = ScenarioEngine(scenario, session_mgr)
    results = asyncio.run(engine.evaluate_once())

    if not results:
        typer.echo("No evaluable objectives pending.")
        return

    typer.echo("Evaluation results:")
    for er in results:
        status = "PASS" if er.passed else "FAIL"
        typer.echo(f"  [{status}] {er.objective_id}: {er.detail}")

    # Show current score
    score = engine.get_score()
    if score is not None:
        _print_score_summary(score)


# ---------------------------------------------------------------------------
# Run command (combined start + evaluate loop + stop)
# ---------------------------------------------------------------------------


def _stop_scenario(
    project_dir: Path,
    scenarios_dir: Path | None,
    session_mgr: ScenarioSession,
    session: ActiveSession,
) -> None:
    """Reusable stop logic (extracted from the stop command)."""
    scenario = _load_active_scenario(session, project_dir, scenarios_dir)
    started = datetime.fromisoformat(session.started_at)
    now = datetime.now(timezone.utc)
    elapsed = (now - started).total_seconds()
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)

    if session.trace_id:
        init_tracing()
        try:
            tracer = get_tracer()
            start_ns = int(started.timestamp() * 1e9)
            end_ns = int(now.timestamp() * 1e9)
            create_root_span(
                tracer=tracer,
                scenario_id=session.scenario_id,
                run_id=session.run_id,
                start_time=start_ns,
                end_time=end_ns,
                trace_id=session.trace_id,
                span_id=session.span_id,
            )
        finally:
            shutdown_tracing()
        time.sleep(2)

    finished_session = session_mgr.finish()

    # Load .env so collectors in assemble_run() can read credentials (issue #184).
    _load_env(project_dir)

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
                config=config,
            )
        except Exception as e:
            log.error("Failed to assemble run: %s", e)
            typer.echo(f"Warning: Run assembly failed: {e}")

    session_mgr.clear()
    state = _state_dir(project_dir)
    ctx_file = state / "trace-context.json"
    if ctx_file.exists():
        ctx_file.unlink()

    typer.echo(f"Scenario stopped: {scenario.metadata.name}")
    typer.echo(f"  Duration: {minutes}m {seconds}s")
    flag_count = sum(len(v) for v in session.flags.values())
    typer.echo(f"  Flags:    {flag_count}")
    if run_dir:
        typer.echo(f"  Run:      {run_dir}")


@app.command()
def run(
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
    poll_interval: float = typer.Option(
        10.0,
        "--poll-interval",
        help="Seconds between evaluation cycles.",
    ),
    timeout: float | None = typer.Option(
        None,
        "--timeout",
        help="Override timeout in minutes (default: scenario estimated_minutes).",
    ),
) -> None:
    """Start a scenario, evaluate objectives in real time, then stop.

    Combines start + evaluation loop + stop into a single command.
    The engine periodically checks non-manual objectives against live
    infrastructure. Press Ctrl+C for graceful shutdown.
    """
    from aptl.core.engine import ScenarioEngine

    # --- Start phase (same as `aptl scenario start`) ---
    log.info("Starting scenario run: %s", name)
    resolved_dir = _resolve_scenarios_dir(project_dir, scenarios_dir)
    scenario = _load_scenario_or_exit(resolved_dir, name)

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

    try:
        session = session_mgr.start(scenario)
    except ScenarioStateError as e:
        log.error("Cannot start scenario: %s", e)
        typer.echo(f"Error: {e}")
        raise typer.Exit(code=1) from e

    run_id = uuid4().hex
    session.run_id = run_id
    session_mgr._write(session)
    write_trace_context(state, session.trace_id, session.span_id)

    flags = collect_flags()
    if flags:
        session.flags = flags
        session_mgr._write(session)

    init_tracing()
    try:
        tracer = get_tracer()
        parent_ctx = make_parent_context(session.trace_id, session.span_id)
        span = create_child_span(tracer, parent_ctx, "scenario.started", {
            "aptl.scenario.id": scenario.metadata.id,
            "aptl.scenario.mode": scenario.mode.value,
            "aptl.run.id": run_id,
        })
        span.end()
    finally:
        shutdown_tracing()

    # Count evaluable objectives
    evaluable = [
        o for o in scenario.objectives.all_objectives()
        if o.type != ObjectiveType.MANUAL
    ]
    manual = [
        o for o in scenario.objectives.all_objectives()
        if o.type == ObjectiveType.MANUAL
    ]

    typer.echo(f"Started scenario: {scenario.metadata.name}")
    typer.echo(f"  Run ID:     {run_id}")
    typer.echo(f"  Evaluable:  {len(evaluable)} objectives (auto-checked)")
    typer.echo(f"  Manual:     {len(manual)} objectives (require manual completion)")
    typer.echo(f"  Trace ID:   {session.trace_id}")
    typer.echo("")

    if not evaluable:
        typer.echo("No auto-evaluable objectives. Use 'aptl scenario stop' when done.")
        return

    # Load .env so evaluators can read credentials (Wazuh Indexer, etc.)
    _load_env(project_dir)

    # --- Engine phase ---
    timeout_minutes = timeout if timeout is not None else float(
        scenario.metadata.estimated_minutes
    )

    def on_progress(cycle: int, results: list, score: ScoreReport) -> None:
        completed = sum(1 for os_ in score.objective_scores if os_.completed)
        total = len(score.objective_scores)
        newly_passed = [r for r in results if r.passed]
        if newly_passed:
            for r in newly_passed:
                typer.echo(f"  [PASS] {r.objective_id}: {r.detail}")
        typer.echo(
            f"  Cycle {cycle}: {completed}/{total} objectives, "
            f"score {score.total_score}/{score.max_score}"
        )

    engine = ScenarioEngine(
        scenario=scenario,
        session_mgr=session_mgr,
        poll_interval=poll_interval,
        timeout_minutes=timeout_minutes,
        on_progress=on_progress,
    )

    shutdown_event = asyncio.Event()

    typer.echo(f"Evaluation engine started (poll every {poll_interval}s, "
               f"timeout {timeout_minutes:.0f}m)")
    typer.echo("Press Ctrl+C to stop gracefully.")
    typer.echo("")

    def _signal_handler(sig: int, frame: object) -> None:
        typer.echo("\nShutdown signal received, finishing current cycle...")
        shutdown_event.set()

    original_sigint = signal.getsignal(signal.SIGINT)
    original_sigterm = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    try:
        engine_result = asyncio.run(engine.run(shutdown_event))
    finally:
        signal.signal(signal.SIGINT, original_sigint)
        signal.signal(signal.SIGTERM, original_sigterm)

    # --- Report ---
    typer.echo("")
    if engine_result.timed_out:
        typer.echo("Engine stopped: timeout reached")
    else:
        typer.echo("Engine stopped: evaluation complete")

    if engine_result.score is not None:
        _print_score_summary(engine_result.score)

    typer.echo(f"\n  Cycles:  {engine_result.evaluation_cycles}")
    typer.echo(f"  Elapsed: {int(engine_result.elapsed_seconds // 60)}m "
               f"{int(engine_result.elapsed_seconds % 60)}s")

    # --- Stop phase ---
    typer.echo("")
    session = session_mgr.get_active()
    if session is not None and session_mgr.is_active():
        _stop_scenario(project_dir, scenarios_dir, session_mgr, session)
