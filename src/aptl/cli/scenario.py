"""CLI commands for scenario lifecycle (#310 / SCN-010).

ACES SDL is APTL's scenario authoring surface. ``aptl scenario list``
discovers ``scenarios/*.sdl.yaml`` files; ``aptl scenario start/stop``
drive the lab through the ACES :class:`RuntimeManager` against the
:class:`aptl.backends.aces.AptlProvisioner` adapter, translating
:class:`aces_processor.models.ApplyResult` diagnostics into APTL's
:class:`LabResult` envelope at the boundary (ADR-035 § Update 2026-05-19).

``start``/``stop`` are not yet wired end-to-end; the integration test
``TestScenarioHarness::test_scenario_lifecycle_with_live_detection``
will go green once they are.
"""

from __future__ import annotations

from pathlib import Path

import typer

from aptl.utils.logging import get_logger

log = get_logger("cli.scenario")

app = typer.Typer(help="Scenario authoring lifecycle (ACES SDL).")


#: Filename suffix for ACES SDL scenario documents under ``scenarios/``.
SDL_SUFFIX = ".sdl.yaml"


def _find_sdl_scenarios(scenarios_dir: Path) -> list[Path]:
    """Return sorted paths to ``*.sdl.yaml`` files in ``scenarios_dir``.

    Non-recursive. Returns ``[]`` when the directory is missing — the
    CLI surfaces that as "no scenarios discovered" rather than an error
    so a fresh project tree doesn't fail the listing command.
    """
    if not scenarios_dir.is_dir():
        return []
    return sorted(scenarios_dir.glob(f"*{SDL_SUFFIX}"))


def _scenario_id_from_path(path: Path) -> str:
    """Strip the ``.sdl.yaml`` suffix from a scenario file's stem.

    ``Path.stem`` only strips one suffix; for ``foo.sdl.yaml`` the stem
    is ``foo.sdl``. The user-visible scenario id is just ``foo``.
    """
    name = path.name
    if name.endswith(SDL_SUFFIX):
        return name[: -len(SDL_SUFFIX)]
    return path.stem


@app.command("list")
def list_scenarios(
    scenarios_dir: Path = typer.Option(
        Path("scenarios"),
        "--scenarios-dir",
        help="Directory to search for *.sdl.yaml scenario files.",
    ),
) -> None:
    """List ACES SDL scenarios discovered under ``scenarios-dir``."""
    paths = _find_sdl_scenarios(scenarios_dir)
    if not paths:
        typer.echo(f"No scenarios found in {scenarios_dir}", err=True)
        raise typer.Exit(code=0)
    for path in paths:
        typer.echo(_scenario_id_from_path(path))


@app.command("start")
def start_scenario(
    scenario_id: str = typer.Argument(
        ...,
        help="Scenario id (filename stem without the .sdl.yaml suffix).",
    ),
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    scenarios_dir: Path = typer.Option(
        Path("scenarios"),
        "--scenarios-dir",
        help="Directory to search for *.sdl.yaml scenario files.",
    ),
) -> None:
    """Start a scenario via the ACES backend.

    Loads the SDL document, plans through ACES's
    :class:`RuntimeManager` against an APTL :class:`RuntimeTarget`
    wired to the project's :class:`DeploymentBackend`, applies the
    plan, and records the session.

    Not yet wired end-to-end — exits with code 2 and a structured
    "not implemented" message until the scenario engine lands. The
    contract surface (CLI args, project-state file path, success
    message format) is locked in here so the integration test's
    expectations can be pinned today.
    """
    _ = scenarios_dir  # consumed once the loader is wired
    typer.echo(
        f"aptl scenario start is not yet wired through the ACES "
        f"backend — scenario_id={scenario_id!r}, "
        f"project_dir={project_dir!s}",
        err=True,
    )
    raise typer.Exit(code=2)


@app.command("stop")
def stop_scenario(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
) -> None:
    """Stop the active scenario in ``project-dir``.

    Not yet wired — see ``start`` docstring.
    """
    _ = project_dir
    typer.echo(
        "aptl scenario stop is not yet wired through the ACES backend",
        err=True,
    )
    raise typer.Exit(code=2)
