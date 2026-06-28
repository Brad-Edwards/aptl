"""Web UI server command."""

from typing import Optional

import typer

from aptl.api.deps import get_web_asset_root
from aptl.api.session import (
    LAUNCH_TOKEN_ENV,
    SESSION_SECRET_ENV,
    generate_secret,
)

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
    web_root: Optional[str] = typer.Option(
        None,
        help=(
            "Path to the built web UI assets directory (must contain index.html). "
            "Overrides APTL_WEB_ROOT env var and the packaged/repo-relative defaults. "
            "If omitted, the server searches standard candidate locations and fails "
            "hard when none are found (use --api-only to run without the GUI)."
        ),
    ),
    api_only: bool = typer.Option(
        False,
        "--api-only",
        help=(
            "Serve only the JSON API, without the built GUI. Required when no web "
            "assets are available (e.g. the split aptl-web-api container behind a "
            "separate static server). Without this flag, a missing GUI build is a "
            "fatal error rather than a silent degrade to API-only mode."
        ),
    ),
    public_origin: Optional[str] = typer.Option(
        None,
        "--public-origin",
        envvar="APTL_WEB_PUBLIC_ORIGIN",
        help=(
            "Browser-facing origin (scheme://host[:port]) to print in the one-time "
            "login URL. Set this when the API runs behind a same-origin reverse "
            "proxy (the split aptl-web-ui profile) so the URL points at the origin "
            "the operator's browser uses, not this process's bind address. Defaults "
            "to the bind host:port."
        ),
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

    # Resolve the web asset root and set the env var so the uvicorn worker
    # picks it up when it imports aptl.api.main (which calls get_web_asset_root()).
    resolved_root = get_web_asset_root(explicit=web_root)
    if resolved_root is not None:
        os.environ["APTL_WEB_ROOT"] = str(resolved_root)
        typer.echo(f"Serving GUI from {resolved_root}")
    elif api_only:
        # Explicit API-only mode: the split aptl-web-api container runs behind a
        # separate static server (Caddy) that serves the GUI, so this process is
        # deliberately GUI-less. The operator asked for it; no GUI is expected.
        typer.echo(
            "Starting in API-only mode (--api-only): the GUI is not served by "
            "this process.",
            err=True,
        )
    else:
        # The shipped single-origin contract serves the built GUI from this
        # process. When no assets resolve (no --web-root, no APTL_WEB_ROOT, no
        # packaged web_static, no repo-relative web/build) and the operator did
        # not ask for --api-only, fail hard rather than silently degrade to an
        # API-only server that looks broken in a browser.
        typer.echo(
            "ERROR: no built web assets were found, so the GUI cannot be served.\n"
            "  To serve the GUI, build the frontend (cd web && npm run build) or "
            "pass --web-root /path/to/build (must contain index.html).\n"
            "  To run the JSON API without the GUI, pass --api-only.",
            err=True,
        )
        raise typer.Exit(1)

    if workers > 1:
        typer.echo(
            "WARNING: --workers > 1 is not supported — the browser-session "
            "secrets, one-time launch token, and terminal-ticket store are "
            "in-process and not shared across workers, so login and terminals "
            "would be flaky. Falling back to a single worker.",
            err=True,
        )
        workers = 1

    if not os.environ.get("APTL_API_TOKEN"):
        typer.echo(
            "WARNING: APTL_API_TOKEN is not set — all API requests will return "
            "401. Generate one with: "
            "python3 -c 'import secrets; print(secrets.token_hex(32))'",
            err=True,
        )

    # Mint the per-serve browser-session secrets (UI-008a / ADR-039) and export
    # them so every uvicorn worker shares one value (module-level generation
    # would differ per worker and reject each other's cookies). The operator
    # bootstraps a session by opening the launch URL below; the launch token is
    # exchanged for an HttpOnly cookie so the browser never holds the API token,
    # and a sibling local process — which never sees this terminal output —
    # cannot obtain a session.
    launch_token = generate_secret()
    os.environ[LAUNCH_TOKEN_ENV] = launch_token
    os.environ.setdefault(SESSION_SECRET_ENV, generate_secret())

    # The login URL must point at the origin the OPERATOR'S BROWSER uses. In the
    # single-origin `aptl web serve` model that is this process's bind address;
    # but in the split aptl-web-api + aptl-web-ui delivery the API runs --api-only
    # behind the Caddy UI origin, so printing the API bind URL would send the
    # operator to an unreachable origin and store the session header token in the
    # wrong origin's sessionStorage. --public-origin / APTL_WEB_PUBLIC_ORIGIN lets
    # the deployment declare the browser-facing origin.
    display_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    login_base = (
        public_origin.rstrip("/")
        if public_origin
        else f"http://{display_host}:{port}"
    )
    typer.echo(f"Starting APTL web API on {host}:{port}")
    typer.echo("")
    typer.echo("To open the GUI, visit this one-time login URL (keep it secret):")
    typer.echo(f"  {login_base}/api/auth/login?token={launch_token}")
    typer.echo("")
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
