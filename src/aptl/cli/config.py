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

from aptl.core.config import AptlConfig, find_config, load_config
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


def _resolve_config(project_dir: Path) -> AptlConfig:
    """Locate and load aptl.json under ``project_dir``.

    Raises ``typer.Exit(1)`` with a stderr message on any failure
    (missing file, invalid JSON, Pydantic validation error).
    """
    config_path = find_config(project_dir)
    if config_path is None:
        typer.echo(
            f"no aptl.json found in {project_dir}",
            err=True,
        )
        raise typer.Exit(code=1)
    try:
        return load_config(config_path)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except ValueError as exc:
        # Pydantic ValidationError is a ValueError subclass, so this
        # catches both invalid JSON and field-level validation failures.
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


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
    config = _resolve_config(project_dir)

    if json_output:
        typer.echo(_json.dumps(config.model_dump(mode="json"), indent=2))
        return

    sections = [
        ("lab", config.lab),
        ("containers", config.containers),
        ("deployment", config.deployment),
        ("run_storage", config.run_storage),
    ]
    for label, model in sections:
        table = Table(title=label, show_header=True, header_style="bold cyan")
        table.add_column("Field")
        table.add_column("Value")
        for field_name in type(model).model_fields:
            value = getattr(model, field_name)
            table.add_row(field_name, _format_value(value))
        console.print(table)


@app.command()
def validate(
    project_dir: Path = _PROJECT_DIR_OPTION,
) -> None:
    """Validate the APTL configuration file.

    Loads ``aptl.json`` through the same path used by deployment
    operations and reports any JSON, type, or constraint errors.
    """
    config_path = find_config(project_dir)
    if config_path is None:
        typer.echo(
            f"no aptl.json found in {project_dir}",
            err=True,
        )
        raise typer.Exit(code=1)
    try:
        load_config(config_path)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"{config_path}: OK")
