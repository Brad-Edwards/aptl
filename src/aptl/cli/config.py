"""CLI commands for configuration management.

Implements:
- ``aptl config validate`` (CLI-002)
- ``aptl config show`` (CLI-007)
"""

import json as _json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from aptl.cli._common import resolve_config_for_cli
from aptl.utils.logging import get_logger

log = get_logger("cli.config")

app = typer.Typer(help="Configuration management.")
console = Console()


_PROJECT_DIR_OPTION = typer.Option(
    Path("."),
    "--project-dir",
    "-d",
    help="Path to the APTL project directory.",
)


def _format_value(value: object) -> str:
    """Render a Pydantic field value for the show table."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


@app.command()
def show(
    project_dir: Path = _PROJECT_DIR_OPTION,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit the resolved configuration as machine-readable JSON.",
    ),
) -> None:
    """Display the resolved APTL configuration.

    Loads ``aptl.json`` via the same discovery rules as the rest of the
    CLI, validates it, and renders the resulting Pydantic model — defaults
    included.
    """
    config, _ = resolve_config_for_cli(project_dir)

    payload = config.model_dump(mode="json")
    if json_output:
        typer.echo(_json.dumps(payload, indent=2))
        return

    # Render each top-level field as its own table. ``model_dump`` keeps
    # the same field order as the Pydantic model declaration, so the
    # output ordering is stable across runs.
    for label, fields in payload.items():
        table = Table(title=label, show_header=True, header_style="bold cyan")
        table.add_column("Field")
        table.add_column("Value")
        if isinstance(fields, dict):
            for field_name, value in fields.items():
                table.add_row(field_name, _format_value(value))
        else:
            table.add_row(label, _format_value(fields))
        console.print(table)


@app.command()
def validate(
    project_dir: Path = _PROJECT_DIR_OPTION,
) -> None:
    """Validate the APTL configuration file.

    Loads ``aptl.json`` through the same path used by deployment
    operations and reports any JSON, type, or constraint errors.
    """
    _, project_root = resolve_config_for_cli(project_dir)
    typer.echo(f"{project_root / 'aptl.json'}: OK")
