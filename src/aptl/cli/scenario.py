"""CLI commands for scenario management."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from aptl.core.events import EventLog, EventType, make_event
from aptl.core.objectives import ObjectiveStatus, evaluate_all
from aptl.core.scenarios import (
    ScenarioDefinition,
    ScenarioNotFoundError,
    ScenarioStateError,
    ScenarioValidationError,
    find_scenarios,
    load_scenario,
    validate_scenario_containers,
)
from aptl.core.scoring import calculate_score, generate_report, write_report
from aptl.core.session import ScenarioSession
from aptl.utils.logging import get_logger

log = get_logger("cli.scenario")

app = typer.Typer(help="Scenario management.")
console = Console()


def _state_dir(project_dir: Path) -> Path:
    """Return the .aptl/ state directory for a project."""
    return project_dir / ".aptl"


def _resolve_scenarios_dir(project_dir: Path, scenarios_dir: Path | None) -> Path:
    """Resolve the scenarios directory path.

    Args:
        project_dir: The APTL project directory.
        scenarios_dir: Explicit scenarios directory, or None to use default.

    Returns:
        Resolved path to the scenarios directory.
    """
    if scenarios_dir is not None:
        return scenarios_dir
    return project_dir / "scenarios"


def _find_scenario_by_name(scenarios_dir: Path, name: str) -> Path:
    """Find a scenario file by name (with or without .yaml extension).

    Args:
        scenarios_dir: Directory to search.
        name: Scenario name or filename.

    Returns:
        Path to the scenario file.

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

    table = Table(title="Available Scenarios")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Difficulty", style="green")
    table.add_column("Mode", style="yellow")
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
            )

    console.print(table)


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

    try:
        path = _find_scenario_by_name(resolved_dir, name)
        scenario = load_scenario(path)
    except (ScenarioNotFoundError, ScenarioValidationError, FileNotFoundError) as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(code=1)

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

    scoring = scenario.scoring
    typer.echo("")
    typer.echo("Scoring:")
    typer.echo(f"  Max Score:      {scoring.max_score}")
    typer.echo(f"  Passing Score:  {scoring.passing_score}")
    if scoring.time_bonus.enabled:
        typer.echo(
            f"  Time Bonus:     up to {scoring.time_bonus.max_bonus} pts "
            f"(decays after {scoring.time_bonus.decay_after_minutes} min)"
        )


@app.command()
def validate(
    path: Path = typer.Argument(help="Path to a scenario YAML file."),
) -> None:
    """Validate a scenario YAML file."""
    log.info("Validating scenario: %s", path)

    try:
        scenario = load_scenario(path)
    except FileNotFoundError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(code=1)
    except ScenarioValidationError as e:
        typer.echo(f"Validation failed: {e}")
        raise typer.Exit(code=1)

    meta = scenario.metadata
    obj_count = len(scenario.objectives.red) + len(scenario.objectives.blue)
    typer.echo(
        f"Valid: {meta.name} ({meta.id}) - "
        f"{meta.difficulty.value}, {scenario.mode.value} mode, "
        f"{obj_count} objectives"
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

    try:
        path = _find_scenario_by_name(resolved_dir, name)
        scenario = load_scenario(path)
    except (ScenarioNotFoundError, ScenarioValidationError, FileNotFoundError) as e:
        typer.echo(f"Error: {e}")
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
        typer.echo(f"Error: {e}")
        raise typer.Exit(code=1)

    event_log = EventLog(state / session.events_file)
    event_log.append(make_event(
        EventType.SCENARIO_STARTED,
        scenario.metadata.id,
        {"mode": scenario.mode.value},
    ))

    typer.echo(f"Started scenario: {scenario.metadata.name}")
    typer.echo(f"  ID:         {scenario.metadata.id}")
    typer.echo(f"  Mode:       {scenario.mode.value}")
    typer.echo(f"  Objectives: {len(scenario.objectives.all_objectives())}")
    typer.echo(f"  Events:     {session.events_file}")


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
    typer.echo(f"  Started:     {session.started_at}")
    typer.echo(f"  Elapsed:     {minutes}m {seconds}s")
    typer.echo(f"  Completed:   {len(session.completed_objectives)} objectives")
    typer.echo(f"  Hints used:  {len(session.hints_used)}")


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
    """Run objective evaluation against live lab state."""
    state = _state_dir(project_dir)
    session_mgr = ScenarioSession(state)

    session = session_mgr.get_active()
    if session is None or not session_mgr.is_active():
        typer.echo("No active scenario to evaluate.")
        raise typer.Exit(code=1)

    # Load scenario definition
    resolved_dir = _resolve_scenarios_dir(project_dir, scenarios_dir)
    try:
        path = _find_scenario_by_name(resolved_dir, session.scenario_id)
        scenario = load_scenario(path)
    except (ScenarioNotFoundError, ScenarioValidationError, FileNotFoundError) as e:
        typer.echo(f"Error loading scenario definition: {e}")
        raise typer.Exit(code=1)

    all_objectives = scenario.objectives.all_objectives()
    completed_ids = set(session.completed_objectives)

    eval_result = evaluate_all(
        all_objectives,
        scenario_start_time=session.started_at,
        completed_ids=completed_ids,
    )

    # Record newly completed objectives
    event_log = EventLog(state / session.events_file)
    new_completions = 0
    for r in eval_result.results:
        if r.status == ObjectiveStatus.COMPLETED and r.objective_id not in completed_ids:
            session_mgr.record_objective_complete(r.objective_id)
            event_log.append(make_event(
                EventType.OBJECTIVE_COMPLETED,
                session.scenario_id,
                {"objective_id": r.objective_id, "details": r.details},
            ))
            new_completions += 1

    event_log.append(make_event(
        EventType.EVALUATION_RUN,
        session.scenario_id,
        {"new_completions": new_completions},
    ))

    # Display results
    table = Table(title="Evaluation Results")
    table.add_column("Objective", style="cyan")
    table.add_column("Status")
    table.add_column("Details")

    for r in eval_result.results:
        status_style = "green" if r.status == ObjectiveStatus.COMPLETED else "yellow"
        table.add_row(
            r.objective_id,
            f"[{status_style}]{r.status.value}[/{status_style}]",
            r.details,
        )

    console.print(table)

    completed_count = sum(
        1 for r in eval_result.results if r.status == ObjectiveStatus.COMPLETED
    )
    typer.echo(
        f"\n{completed_count}/{len(eval_result.results)} objectives completed"
    )
    if eval_result.all_complete:
        typer.echo("All objectives complete! Run 'aptl scenario stop' to finish.")


@app.command()
def hint(
    objective_id: str = typer.Argument(help="Objective ID to get a hint for."),
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
    """Reveal the next hint for an objective."""
    state = _state_dir(project_dir)
    session_mgr = ScenarioSession(state)

    session = session_mgr.get_active()
    if session is None or not session_mgr.is_active():
        typer.echo("No active scenario.")
        raise typer.Exit(code=1)

    # Load scenario to find hints
    resolved_dir = _resolve_scenarios_dir(project_dir, scenarios_dir)
    try:
        path = _find_scenario_by_name(resolved_dir, session.scenario_id)
        scenario = load_scenario(path)
    except (ScenarioNotFoundError, ScenarioValidationError, FileNotFoundError) as e:
        typer.echo(f"Error loading scenario definition: {e}")
        raise typer.Exit(code=1)

    # Find the objective
    all_objectives = scenario.objectives.all_objectives()
    obj = next((o for o in all_objectives if o.id == objective_id), None)
    if obj is None:
        typer.echo(f"Objective not found: {objective_id}")
        raise typer.Exit(code=1)

    if not obj.hints:
        typer.echo(f"No hints available for objective '{objective_id}'.")
        return

    # Find the next hint level
    current_level = session.hints_used.get(objective_id, 0)
    next_hint = None
    for h in sorted(obj.hints, key=lambda x: x.level):
        if h.level > current_level:
            next_hint = h
            break

    if next_hint is None:
        typer.echo(f"All hints already revealed for '{objective_id}'.")
        return

    # Record and display
    session_mgr.record_hint(objective_id, next_hint.level)

    event_log = EventLog(state / session.events_file)
    event_log.append(make_event(
        EventType.HINT_REQUESTED,
        session.scenario_id,
        {"objective_id": objective_id, "level": next_hint.level},
    ))

    penalty_note = ""
    if next_hint.point_penalty > 0:
        penalty_note = f" (-{next_hint.point_penalty} pts)"

    typer.echo(f"Hint (level {next_hint.level}/{len(obj.hints)}){penalty_note}:")
    typer.echo(f"  {next_hint.text}")


@app.command()
def complete(
    objective_id: str = typer.Argument(help="Objective ID to mark as complete."),
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
    """Manually mark a MANUAL objective as complete."""
    state = _state_dir(project_dir)
    session_mgr = ScenarioSession(state)

    session = session_mgr.get_active()
    if session is None or not session_mgr.is_active():
        typer.echo("No active scenario.")
        raise typer.Exit(code=1)

    # Load scenario to verify it's a manual objective
    resolved_dir = _resolve_scenarios_dir(project_dir, scenarios_dir)
    try:
        path = _find_scenario_by_name(resolved_dir, session.scenario_id)
        scenario = load_scenario(path)
    except (ScenarioNotFoundError, ScenarioValidationError, FileNotFoundError) as e:
        typer.echo(f"Error loading scenario definition: {e}")
        raise typer.Exit(code=1)

    all_objectives = scenario.objectives.all_objectives()
    obj = next((o for o in all_objectives if o.id == objective_id), None)
    if obj is None:
        typer.echo(f"Objective not found: {objective_id}")
        raise typer.Exit(code=1)

    from aptl.core.scenarios import ObjectiveType

    if obj.type != ObjectiveType.MANUAL:
        typer.echo(
            f"Objective '{objective_id}' is type '{obj.type.value}', "
            "not 'manual'. Only manual objectives can be completed manually."
        )
        raise typer.Exit(code=1)

    if objective_id in session.completed_objectives:
        typer.echo(f"Objective '{objective_id}' is already completed.")
        return

    session_mgr.record_objective_complete(objective_id)

    event_log = EventLog(state / session.events_file)
    event_log.append(make_event(
        EventType.OBJECTIVE_COMPLETED,
        session.scenario_id,
        {"objective_id": objective_id, "manual": True},
    ))

    typer.echo(f"Objective '{objective_id}' marked as complete.")


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
    """Stop the active scenario and generate a report."""
    state = _state_dir(project_dir)
    session_mgr = ScenarioSession(state)

    session = session_mgr.get_active()
    if session is None or not session_mgr.is_active():
        typer.echo("No active scenario to stop.")
        raise typer.Exit(code=1)

    # Load scenario definition
    resolved_dir = _resolve_scenarios_dir(project_dir, scenarios_dir)
    try:
        path = _find_scenario_by_name(resolved_dir, session.scenario_id)
        scenario = load_scenario(path)
    except (ScenarioNotFoundError, ScenarioValidationError, FileNotFoundError) as e:
        typer.echo(f"Error loading scenario definition: {e}")
        raise typer.Exit(code=1)

    # Run final evaluation
    all_objectives = scenario.objectives.all_objectives()
    completed_ids = set(session.completed_objectives)

    eval_result = evaluate_all(
        all_objectives,
        scenario_start_time=session.started_at,
        completed_ids=completed_ids,
    )

    # Record any new completions
    event_log = EventLog(state / session.events_file)
    for r in eval_result.results:
        if r.status == ObjectiveStatus.COMPLETED and r.objective_id not in completed_ids:
            session_mgr.record_objective_complete(r.objective_id)

    # Re-read session with updated completions
    session = session_mgr.get_active()

    # Log stop event
    event_log.append(make_event(
        EventType.SCENARIO_STOPPED,
        session.scenario_id,
    ))

    # Calculate score
    started = datetime.fromisoformat(session.started_at)
    elapsed = (datetime.now(timezone.utc) - started).total_seconds()

    score = calculate_score(
        all_objectives,
        eval_result.results,
        scenario.scoring,
        elapsed,
        session.hints_used,
    )

    # Finish session
    finished_session = session_mgr.finish()

    # Read events and generate report
    events = event_log.read_all()
    report = generate_report(scenario, finished_session, eval_result.results, events, score)

    # Write report
    reports_dir = state / "reports"
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    report_path = reports_dir / f"{session.scenario_id}_{ts}.json"
    write_report(report, report_path)

    # Clear session
    session_mgr.clear()

    # Display summary
    typer.echo(f"Scenario stopped: {scenario.metadata.name}")
    typer.echo("")

    table = Table(title="Final Results")
    table.add_column("Objective", style="cyan")
    table.add_column("Status")
    table.add_column("Points")

    for r in eval_result.results:
        obj = next((o for o in all_objectives if o.id == r.objective_id), None)
        points = obj.points if obj and r.status == ObjectiveStatus.COMPLETED else 0
        status_style = "green" if r.status == ObjectiveStatus.COMPLETED else "red"
        table.add_row(
            r.objective_id,
            f"[{status_style}]{r.status.value}[/{status_style}]",
            str(points),
        )

    console.print(table)

    typer.echo("")
    typer.echo(f"Score: {score.total}/{score.max_possible}")
    if score.time_bonus > 0:
        typer.echo(f"  Time bonus:     +{score.time_bonus}")
    if score.hint_penalties > 0:
        typer.echo(f"  Hint penalties: -{score.hint_penalties}")

    result_text = "[green]PASS[/green]" if score.passing else "[red]FAIL[/red]"
    console.print(f"Result: {result_text}")
    typer.echo(f"Report: {report_path}")
