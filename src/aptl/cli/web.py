"""Web UI server command."""

from typing import Optional

import typer

app = typer.Typer(help="Web UI server management.")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address."),
    port: int = typer.Option(8400, help="Bind port."),
    reload: bool = typer.Option(False, help="Enable auto-reload for development."),
    workers: int = typer.Option(1, help="Number of uvicorn workers."),
    project_dir: Optional[str] = typer.Option(
        None,
        help="Project directory (default: current directory).",
    ),
) -> None:
    """Start the APTL web API server."""
    try:
        import uvicorn
    except ImportError:
        typer.echo(
            "Web dependencies not installed. "
            'Install with: pip install -e ".[web]"',
            err=True,
        )
        raise typer.Exit(1)

    import os
    from pathlib import Path as _Path

    if project_dir:
        resolved = _Path(project_dir).resolve()
        if not resolved.is_dir():
            typer.echo(f"Error: project directory does not exist: {resolved}", err=True)
            raise typer.Exit(1)
        os.environ["APTL_PROJECT_DIR"] = str(resolved)

    typer.echo(f"Starting APTL web API on {host}:{port}")
    uvicorn.run(
        "aptl.api.main:app",
        host=host,
        port=port,
        reload=reload,
        workers=workers,
        log_level="info",
        timeout_keep_alive=65,
        access_log=True,
    )
