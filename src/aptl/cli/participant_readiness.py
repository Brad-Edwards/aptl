"""CLI entry point for bounded participant readiness."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer


def participant_readiness(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    provider: str = typer.Option(
        "deterministic",
        "--provider",
        help="Decision provider: deterministic, claude, or codex.",
    ),
    behavior: str = typer.Option(
        "green-normal-session",
        "--behavior",
        help="One named green, red, or blue bounded behavior.",
    ),
    turns: int = typer.Option(
        1,
        "--turns",
        min=1,
        max=8,
        help="Number of governed RAES v2 decision/admission turns.",
    ),
    run_id: Optional[str] = typer.Option(
        None,
        "--run-id",
        help="Readiness archive run id (default: generated).",
    ),
    suite: bool = typer.Option(
        True,
        "--suite/--single-trajectory",
        help=(
            "Run the complete deterministic qualification and optional "
            "installed-provider checks, or one selected trajectory."
        ),
    ),
    installed_turns: int = typer.Option(
        8,
        "--installed-turns",
        min=1,
        max=8,
        help="Turns per installed-provider episode in suite mode.",
    ),
) -> None:
    """Exercise governed participant agency against an already-running lab."""

    from aptl.cli._common import resolve_config_for_cli, resolve_run_store
    from aptl.core.runstore import _validate_id
    from aptl.validation.participant_agency_qualification import (
        validate_participant_agency_qualification,
    )
    from aptl.validation.participant_agency_readiness import (
        ParticipantReadinessRequest,
        validate_participant_agency_readiness,
    )

    config, project_root = resolve_config_for_cli(project_dir)
    if run_id is not None:
        try:
            _validate_id(run_id, "run_id")
        except ValueError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=2)
    try:
        store = resolve_run_store(project_root, config)
        if suite:
            report = validate_participant_agency_qualification(
                project_dir=project_root,
                config=config,
                run_store=store,
                run_id=run_id,
                installed_provider=(None if provider == "deterministic" else provider),
                installed_turns=installed_turns,
            )
        else:
            report = validate_participant_agency_readiness(
                ParticipantReadinessRequest(
                    project_dir=project_root,
                    config=config,
                    run_store=store,
                    provider_name=provider,
                    behavior_name=behavior,
                    turns=turns,
                    run_id=run_id,
                )
            )
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)
    typer.echo(report.render())
    if not report.passed:
        raise typer.Exit(code=1)
