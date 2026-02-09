"""CLI commands for scenario management."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from aptl.scenarios.engine import list_scenarios, load_scenario
from aptl.scenarios.models import Scenario

app = typer.Typer(help="Manage purple team scenarios")
console = Console()

DEFAULT_SCENARIOS_DIR = Path("scenarios")


@app.command("list")
def scenario_list(
    scenarios_dir: Optional[Path] = typer.Option(
        None,
        "--dir",
        "-d",
        help="Scenarios directory (default: ./scenarios)",
    ),
) -> None:
    """List available scenarios."""
    search_dir = scenarios_dir or DEFAULT_SCENARIOS_DIR
    scenarios = list_scenarios(search_dir)

    if not scenarios:
        console.print(f"No scenarios found in {search_dir}")
        raise typer.Exit(1)

    table = Table(title="Available Scenarios")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Difficulty", style="yellow")
    table.add_column("Steps", justify="right")
    table.add_column("Time (min)", justify="right")
    table.add_column("Techniques", justify="right")
    table.add_column("Prerequisites")

    for s in scenarios:
        table.add_row(
            s.id,
            s.name,
            s.difficulty.value,
            str(len(s.steps)),
            str(s.estimated_time_minutes),
            str(len(s.mitre_techniques)),
            ", ".join(s.prerequisites),
        )

    console.print(table)


@app.command("show")
def scenario_show(
    scenario_id: str = typer.Argument(help="Scenario ID or JSON file path"),
    scenarios_dir: Optional[Path] = typer.Option(
        None,
        "--dir",
        "-d",
        help="Scenarios directory (default: ./scenarios)",
    ),
) -> None:
    """Show details of a specific scenario."""
    scenario = _resolve_scenario(scenario_id, scenarios_dir)
    if not scenario:
        console.print(f"Scenario not found: {scenario_id}", style="red")
        raise typer.Exit(1)

    name = scenario.name
    desc = scenario.description
    console.print(f"\n[bold cyan]{name}[/]")
    console.print(f"[dim]{desc}[/]\n")
    diff = scenario.difficulty.value
    console.print(f"Difficulty: [yellow]{diff}[/]")
    t_min = scenario.estimated_time_minutes
    console.print(f"Time: {t_min} minutes")
    console.print(f"Chain: {scenario.attack_chain}")
    prereqs = ", ".join(scenario.prerequisites)
    console.print(f"Prerequisites: {prereqs}")

    n_tech = len(scenario.mitre_techniques)
    console.print(
        f"\n[bold]MITRE ATT&CK Techniques ({n_tech}):[/]"
    )
    for step in scenario.steps:
        t = step.technique
        det_count = len(step.expected_detections)
        plural = "s" if det_count != 1 else ""
        console.print(
            f"  {step.step_number}. [{t.tactic}] "
            f"{t.technique_id} "
            f"{t.technique_name} -> {t.target} "
            f"({det_count} expected detection{plural})"
        )

    console.print("\n[bold]Attack Steps:[/]")
    for step in scenario.steps:
        t = step.technique
        console.print(
            f"\n  [cyan]Step {step.step_number}: "
            f"{t.technique_name}[/]"
        )
        console.print(f"  {t.description}")
        if t.commands:
            console.print("  Commands:")
            for cmd in t.commands:
                console.print(f"    $ {cmd}")
        if step.expected_detections:
            console.print("  Expected Detections:")
            for d in step.expected_detections:
                sev = d.severity.value
                src = d.source.value
                console.print(
                    f"    [{sev}] {src}: "
                    f"{d.description}"
                )


def _resolve_scenario(
    scenario_id: str,
    scenarios_dir: Optional[Path],
) -> Optional[Scenario]:
    """Resolve a scenario by ID or file path."""
    # Try as file path first
    path = Path(scenario_id)
    if path.exists() and path.suffix == ".json":
        return load_scenario(path)

    # Search in scenarios directory
    search_dir = scenarios_dir or DEFAULT_SCENARIOS_DIR
    scenarios = list_scenarios(search_dir)
    return next((s for s in scenarios if s.id == scenario_id), None)
