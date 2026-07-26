"""CLI boundary for participant-profile qualification evidence."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from aptl.cli._common import resolve_run_store
from aptl.core.runstore import _validate_id
from aptl.validation.participant_profile import (
    ParticipantProfileError,
    load_participant_profile,
)
from aptl.validation.participant_qualification import (
    ParticipantQualificationError,
    evaluate_participant_qualification,
    load_participant_qualification_report,
    persist_participant_qualification,
)

DEFAULT_PARTICIPANT_PROFILE = Path("participant-profiles/guided-purple-v1/profile.json")


def qualify_profile(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the materialized APTL project directory.",
    ),
    profile: Path = typer.Option(
        DEFAULT_PARTICIPANT_PROFILE,
        "--profile",
        help="Project-contained participant profile manifest.",
    ),
    report: Path = typer.Option(
        ...,
        "--report",
        help="Project-contained machine-readable profile qualification report.",
    ),
    public_key: Path = typer.Option(
        ...,
        "--public-key",
        help=(
            "Project-contained Ed25519 public key trusted by the qualification "
            "pipeline."
        ),
    ),
    run_id: str = typer.Option(
        ...,
        "--run-id",
        help="Run archive id that will own the evaluated report.",
    ),
) -> None:
    """Validate and persist a bounded participant-profile report."""

    project_root = project_dir.resolve()
    try:
        safe_run_id = _validate_id(run_id, "run_id")
        resolved = load_participant_profile(project_root, profile)
        evidence = load_participant_qualification_report(
            project_root,
            report,
            public_key,
        )
    except (
        OSError,
        ParticipantProfileError,
        ParticipantQualificationError,
        ValueError,
    ) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    evaluation = evaluate_participant_qualification(resolved, evidence)
    store = resolve_run_store(project_root, resolved.config)
    store.create_run(safe_run_id)
    persist_participant_qualification(
        store,
        safe_run_id,
        evidence,
        evaluation,
    )
    typer.echo(
        json.dumps(
            {
                "profile_id": resolved.manifest.profile_id,
                "profile_version": resolved.manifest.version,
                **evaluation.to_dict(),
            },
            separators=(",", ":"),
        )
    )
    if not evaluation.passed:
        raise typer.Exit(code=1)
