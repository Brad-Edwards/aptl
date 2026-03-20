"""Web UI server command."""

from typing import Optional

import typer

app = typer.Typer(help="Web UI server management.")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address."),
    port: int = typer.Option(8400, help="Bind port."),
    reload: bool = typer.Option(False, help="Enable auto-reload for development."),
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

    if project_dir:
        os.environ["APTL_PROJECT_DIR"] = project_dir

    typer.echo(f"Starting APTL web API on {host}:{port}")
    uvicorn.run(
        "aptl.api.main:app",
        host=host,
        port=port,
        reload=reload,
    )
