"""Emergency kill switch CLI command."""

from pathlib import Path

import typer

from aptl.core.kill import execute_kill
from aptl.utils.logging import get_logger

log = get_logger("cli.kill")

app = typer.Typer(help="Emergency kill switch.", invoke_without_command=True)


@app.callback(invoke_without_command=True)
def kill_command(
    containers: bool = typer.Option(
        False,
        "--containers",
        "-c",
        help="Also force-stop all lab Docker containers.",
    ),
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
) -> None:
    """Immediately terminate all MCP server processes and agent activity.

    Sends SIGTERM to all running MCP server processes, waits briefly for
    graceful shutdown, then sends SIGKILL to any survivors. Clears any
    active scenario session and removes trace context files.

    Use --containers to also force-stop all lab Docker containers.
    """
    log.info("Kill switch activated (containers=%s)", containers)

    result = execute_kill(containers=containers, project_dir=project_dir)

    # Print summary
    if result.mcp_processes_killed > 0:
        typer.echo(f"Killed {result.mcp_processes_killed} MCP server process(es).")
    else:
        typer.echo("No MCP server processes found.")

    if containers:
        if result.containers_stopped:
            typer.echo("Lab containers stopped.")
        else:
            typer.echo("Failed to stop lab containers.")

    if result.session_cleared:
        typer.echo("Active scenario session cleared.")

    if result.trace_context_cleaned:
        typer.echo("Trace context file removed.")

    if result.errors:
        typer.echo("")
        for error in result.errors:
            typer.echo(f"  Warning: {error}")

    if not result.success:
        raise typer.Exit(code=1)
