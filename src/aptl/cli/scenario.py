"""CLI commands for scenario lifecycle (#310 / SCN-010).

ACES SDL is APTL's scenario authoring surface. ``aptl scenario list``
discovers ``scenarios/*.sdl.yaml`` files; ``aptl scenario start/stop``
drive the lab through the ACES :class:`RuntimeManager` against the
:class:`aptl.backends.aces.AptlProvisioner` adapter, translating
:class:`aces_processor.models.ApplyResult` diagnostics into APTL's
:class:`LabResult` envelope at the boundary (ADR-035 § Update 2026-05-19).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer

from aptl.core.config import AptlConfig, find_config, load_config
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from aces_processor.models import ApplyResult

log = get_logger("cli.scenario")

app = typer.Typer(help="Scenario authoring lifecycle (ACES SDL).")

#: Filename suffix for ACES SDL scenario documents under ``scenarios/``.
SDL_SUFFIX = ".sdl.yaml"


def _find_sdl_scenarios(scenarios_dir: Path) -> list[Path]:
    """Return sorted paths to ``*.sdl.yaml`` files in ``scenarios_dir``."""
    if not scenarios_dir.is_dir():
        return []
    return sorted(scenarios_dir.glob(f"*{SDL_SUFFIX}"))


def _scenario_id_from_path(path: Path) -> str:
    """Strip ``.sdl.yaml`` to produce the user-visible scenario id.

    ``Path.stem`` only strips one suffix; for ``foo.sdl.yaml`` the stem
    is ``foo.sdl``. We want ``foo``.
    """
    name = path.name
    if name.endswith(SDL_SUFFIX):
        return name[: -len(SDL_SUFFIX)]
    return path.stem


def _scenario_path_for_id(scenarios_dir: Path, scenario_id: str) -> Path:
    """Return the expected file path for a scenario id (no IO)."""
    return scenarios_dir / f"{scenario_id}{SDL_SUFFIX}"


def _resolve_scenario_runtime(
    project_dir: Path,
) -> tuple[AptlConfig, Path]:
    """Resolve config + deployment dir for ``aptl scenario`` commands.

    Unlike ``aptl lab``, scenarios don't require a project-local
    ``aptl.json``. ``project_dir`` is for session state
    (``.aptl/session.json``); the deployment-backend working dir is
    wherever ``aptl.json`` lives (walked up from CWD), falling back to
    :class:`AptlConfig` defaults (docker-compose against CWD) when
    none exists. Lets ``aptl scenario start <id>
    --project-dir /tmp/xyz`` work against the global lab without
    requiring the user to copy ``aptl.json`` into the project dir.
    """
    config_path = find_config(Path.cwd())
    if config_path is None:
        return AptlConfig(), Path.cwd()
    config = load_config(config_path)
    return config, config_path.parent


def _emit_apply_diagnostics(result: "ApplyResult") -> None:
    """Print each ACES diagnostic on stderr in the same severity-tagged
    shape APTL's existing CLI renders ``StartupDiagnostic`` entries —
    keeps the user-visible failure output indistinguishable from the
    pre-cutover lab-start path (ADR-035 invariant 4)."""
    for diag in result.diagnostics:
        typer.echo(
            f"[{diag.severity.name}] {diag.code}: {diag.message}",
            err=True,
        )


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
    skip_seed: bool = typer.Option(
        False,
        "--skip-seed",
        help="Skip SOC tool seeding after startup (forwards to lab start).",
    ),
) -> None:
    """Start a scenario through the ACES backend.

    SDL → :func:`aces_sdl.parse_sdl_file` →
    :meth:`aces_processor.manager.RuntimeManager.plan` →
    :meth:`~aces_processor.manager.RuntimeManager.apply` against APTL's
    :class:`~aptl.backends.aces.AptlProvisioner` (wired to the project's
    :class:`~aptl.core.deployment.backend.DeploymentBackend`). Writes
    ``.aptl/session.json`` on success so subsequent commands see the
    active scenario.
    """
    sdl_path = _scenario_path_for_id(scenarios_dir, scenario_id)
    if not sdl_path.exists():
        typer.echo(
            f"Scenario '{scenario_id}' not found at {sdl_path}",
            err=True,
        )
        raise typer.Exit(code=1)

    # Imports stay local: aces-sdl is an optional dev dep, and CLI startup
    # for unrelated subcommands (``aptl lab start``, ``aptl runs list``)
    # shouldn't pay the ACES import cost.
    try:
        from aces_sdl import parse_sdl_file
        from aces_processor.manager import RuntimeManager
    except ImportError as exc:
        typer.echo(
            f"ACES SDL not installed: {exc}. See docs/lessons/2026-05-19-aces-backend-integration.md "
            "for the install recipe.",
            err=True,
        )
        raise typer.Exit(code=1) from exc

    from aptl.backends.aces import create_aptl_target
    from aptl.core.deployment import get_backend
    from aptl.core.session import ScenarioSession

    config, deployment_dir = _resolve_scenario_runtime(project_dir)

    project_dir.mkdir(parents=True, exist_ok=True)
    session = ScenarioSession(state_dir=project_dir / ".aptl")
    if session.is_active():
        existing = session.get_active()
        active_id = existing.scenario_id if existing else "<unknown>"
        typer.echo(
            f"Scenario '{active_id}' is already active in {project_dir}; "
            "stop it first with 'aptl scenario stop'.",
            err=True,
        )
        raise typer.Exit(code=1)

    backend = get_backend(config, deployment_dir)
    target = create_aptl_target(backend=backend, build=not skip_seed)
    sdl = parse_sdl_file(sdl_path)

    manager = RuntimeManager(target=target)
    plan = manager.plan(scenario=sdl)
    result = manager.apply(plan)

    if not result.success:
        _emit_apply_diagnostics(result)
        typer.echo(
            f"Failed to start scenario '{scenario_id}'.",
            err=True,
        )
        raise typer.Exit(code=1)

    session.start(scenario_id)
    typer.echo(f"Started scenario '{scenario_id}'")


@app.command("stop")
def stop_scenario(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    volumes: bool = typer.Option(
        False,
        "--volumes",
        "-v",
        help="Also remove Docker volumes (full cleanup).",
    ),
    scenarios_dir: Path = typer.Option(
        Path("scenarios"),
        "--scenarios-dir",
        help=(
            "Ignored by stop — accepted for symmetry with `start`/`list` "
            "so wrapping scripts can pass the same flags to all three."
        ),
    ),
) -> None:
    """Stop the active scenario.

    Loads the active session, stops the lab via the project's
    :class:`DeploymentBackend`, and clears ``.aptl/session.json``.
    """
    from aptl.backends.aces import DEFAULT_PROFILES
    from aptl.core.deployment import get_backend
    from aptl.core.session import ScenarioSession

    config, deployment_dir = _resolve_scenario_runtime(project_dir)
    session = ScenarioSession(state_dir=project_dir / ".aptl")

    active = session.get_active()
    if active is None:
        typer.echo(
            f"No active scenario in {project_dir}.",
            err=True,
        )
        raise typer.Exit(code=1)

    backend = get_backend(config, deployment_dir)
    lab_result = backend.stop(list(DEFAULT_PROFILES), remove_volumes=volumes)
    if not lab_result.success:
        message = lab_result.error or lab_result.message or "stop failed"
        typer.echo(message, err=True)
        raise typer.Exit(code=1)

    session.clear()
    typer.echo(f"Scenario stopped: '{active.scenario_id}'")
