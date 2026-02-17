"""CLI commands for scenario management."""

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from aptl.core.scenarios import (
    ScenarioNotFoundError,
    ScenarioValidationError,
    find_scenarios,
    load_scenario,
    validate_scenario_containers,
)
from aptl.utils.logging import get_logger

log = get_logger("cli.scenario")

app = typer.Typer(help="Scenario management.")
console = Console()


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
