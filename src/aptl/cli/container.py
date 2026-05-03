"""CLI commands for container operations.

Implements ``aptl container list``, ``aptl container shell``, and
``aptl container logs`` (CLI-004). Each command resolves the project's
``aptl.json``, instantiates the configured deployment backend, and
delegates to the backend's container_* methods so local Docker Compose
and SSH-remote deployments behave identically.
"""

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from aptl.cli._common import resolve_config_for_cli
from aptl.core.deployment import DeploymentBackend, get_backend
from aptl.utils.logging import get_logger

log = get_logger("cli.container")

app = typer.Typer(help="Container operations.")
console = Console()


_PROJECT_DIR_OPTION = typer.Option(
    Path("."),
    "--project-dir",
    "-d",
    help="Path to the APTL project directory.",
)


def _resolve_backend(project_dir: Path) -> DeploymentBackend:
    """Resolve the deployment backend for this project.

    Uses ``config_path.parent`` as the backend's project_dir so docker
    compose runs in the directory that actually owns ``aptl.json``.
    """
    config, project_root = resolve_config_for_cli(project_dir)
    return get_backend(config, project_root)


def _ensure_project_container(backend: DeploymentBackend, name: str) -> None:
    """Reject container names that aren't part of this lab's compose project.

    Defense-in-depth against typos and against shared-daemon scenarios
    where the docker host has containers from other projects: ``aptl
    container shell`` / ``logs`` should never `exec`/`logs` into a
    non-APTL container even if the user types its name. Uses the
    backend's typed ``container_exists`` check (one ``docker inspect``
    against this project) instead of enumerating every container.
    """
    if not backend.container_exists(name):
        typer.echo(
            f"container {name!r} is not part of this lab's compose project. "
            f"Run `aptl container list` to see valid names.",
            err=True,
        )
        raise typer.Exit(code=1)


@app.command("list")
def list_containers(
    project_dir: Path = _PROJECT_DIR_OPTION,
) -> None:
    """List lab containers and their status."""
    backend = _resolve_backend(project_dir)
    containers = backend.container_list(all_containers=True)
    if not containers:
        typer.echo("No containers.")
        return

    table = Table(title="Containers", show_header=True, header_style="bold cyan")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("State")
    table.add_column("Health")
    table.add_column("Image")
    for c in containers:
        table.add_row(
            str(c.get("Name", "")),
            str(c.get("State", "")),
            str(c.get("Health", "")),
            str(c.get("Image", "")),
        )
    console.print(table)


@app.command()
def logs(
    name: str = typer.Argument(..., help="Container name (e.g. aptl-victim)."),
    follow: bool = typer.Option(
        False, "--follow", "-f", help="Stream logs as they arrive."
    ),
    tail: int = typer.Option(
        None,
        "--tail",
        help="Show only the last N lines.",
    ),
    project_dir: Path = _PROJECT_DIR_OPTION,
) -> None:
    """Show logs for a specific container."""
    backend = _resolve_backend(project_dir)
    _ensure_project_container(backend, name)
    exit_code = backend.container_logs(name, follow=follow, tail=tail)
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


@app.command()
def shell(
    name: str = typer.Argument(..., help="Container name (e.g. aptl-kali)."),
    shell: str = typer.Option(
        None,
        "--shell",
        help="Shell to launch (default: try /bin/bash, fall back to /bin/sh).",
    ),
    project_dir: Path = _PROJECT_DIR_OPTION,
) -> None:
    """Open an interactive shell inside a running container."""
    backend = _resolve_backend(project_dir)
    _ensure_project_container(backend, name)
    exit_code = backend.container_shell(name, shell=shell)
    if exit_code != 0:
        raise typer.Exit(code=exit_code)
