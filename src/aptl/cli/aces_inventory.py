"""CLI commands for ACES inventory methodology artifacts."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from aptl.core.aces_inventory import (
    format_gap_report,
    format_validation_result,
    gap_report,
    mapping_ledger_schema,
    validate_mapping_ledger,
)

app = typer.Typer(help="Validate ACES inventory mapping ledgers.")


@app.command()
def validate(
    path: Path = typer.Argument(
        ...,
        help="Inventory bundle directory or mapping-ledger.yaml path.",
    ),
) -> None:
    """Validate a mapping ledger and its evidence references."""
    result = validate_mapping_ledger(path)
    typer.echo(format_validation_result(result))
    if not result.ok:
        raise typer.Exit(code=1)


@app.command()
def gaps(
    path: Path = typer.Argument(
        ...,
        help="Inventory bundle directory or mapping-ledger.yaml path.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON.",
    ),
) -> None:
    """List blocked and untriaged ACES/APTL mapping gaps."""
    result = validate_mapping_ledger(path)
    if not result.ok:
        typer.echo(format_validation_result(result), err=True)
        raise typer.Exit(code=1)
    report = gap_report(path)
    if json_output:
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        typer.echo(format_gap_report(report))


@app.command()
def schema() -> None:
    """Print the JSON Schema for mapping-ledger.yaml."""
    typer.echo(json.dumps(mapping_ledger_schema(), indent=2, sort_keys=True))
