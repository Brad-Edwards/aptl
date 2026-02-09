"""CLI commands for configuration management."""

import typer

from aptl.utils.logging import get_logger

log = get_logger("cli.config")

app = typer.Typer(help="Configuration management.")


@app.command()
def show() -> None:
    """Display the current APTL configuration."""
    log.info("Config show not yet implemented")
    typer.echo("Config show: not yet implemented")


@app.command()
def validate() -> None:
    """Validate the APTL configuration file."""
    log.info("Config validate not yet implemented")
    typer.echo("Config validate: not yet implemented")
