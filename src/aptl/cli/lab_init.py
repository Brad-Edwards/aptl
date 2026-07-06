"""`aptl lab init` command (DEP-008, issue #659).

Kept in its own module so ``aptl/cli/lab.py`` stays the focused lifecycle
facade (and under the file-size gate). Registered onto the ``lab`` Typer app
by :func:`register`, so the command remains ``aptl lab init`` with no UX
change.
"""

from pathlib import Path

import typer

from aptl.core.assets import AssetError, materialize


def init(
    directory: Path = typer.Argument(
        ...,
        help="Directory to materialize the lab project into (created if missing).",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing files in the target directory.",
    ),
) -> None:
    """Materialize a self-contained lab project into DIRECTORY.

    Copies the bundled lab assets (docker-compose.yml, scenarios, config,
    containers, web, scripts, and the source that container images build
    from) and writes a default aptl.json, so a `pipx install aptl-labs`
    can run a lab without cloning the repository (DEP-008). After it
    finishes, run `aptl lab start` from the initialized directory.
    """
    try:
        result = materialize(directory, force=force)
    except AssetError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(
        f"Initialized lab project in {result.target_dir} "
        f"({result.files_written} files)."
    )
    if result.config_created:
        typer.echo(f"    wrote default {result.target_dir / 'aptl.json'}")
    typer.echo("\nNext steps:")
    typer.echo(f"    cd {result.target_dir}")
    typer.echo("    aptl lab start")


def register(app: typer.Typer) -> None:
    """Register the ``init`` command onto the given ``lab`` Typer app."""
    app.command("init")(init)
