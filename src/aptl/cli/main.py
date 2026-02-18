"""Main entry point for the APTL CLI."""

import logging
from typing import Optional

import typer

import aptl
from aptl.cli import lab, config, container, scenario
from aptl.utils.logging import setup_logging

app = typer.Typer(
    name="aptl",
    help="Advanced Purple Team Lab CLI",
    no_args_is_help=True,
)

app.add_typer(lab.app, name="lab")
app.add_typer(config.app, name="config")
app.add_typer(container.app, name="container")
app.add_typer(scenario.app, name="scenario")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"aptl {aptl.__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
    log_level: str = typer.Option(
        "INFO",
        "--log-level",
        help="Logging level (DEBUG, INFO, WARNING, ERROR).",
        envvar="APTL_LOG_LEVEL",
    ),
) -> None:
    """Advanced Purple Team Lab CLI."""
    level = getattr(logging, log_level.upper(), logging.INFO)
    setup_logging(level=level)
