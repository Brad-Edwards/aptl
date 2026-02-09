"""CLI commands for container operations."""

import typer

from aptl.utils.logging import get_logger

log = get_logger("cli.container")

app = typer.Typer(help="Container operations.")


@app.command("list")
def list_containers() -> None:
    """List lab containers and their status."""
    log.info("Container list not yet implemented")
    typer.echo("Container list: not yet implemented")


@app.command()
def logs(name: str = typer.Argument(help="Container name")) -> None:
    """Show logs for a specific container."""
    log.info("Container logs not yet implemented")
    typer.echo(f"Container logs for '{name}': not yet implemented")
