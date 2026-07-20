"""CLI for ACES experiment admission (ADR-047 "Experiment-controller
boundary", EXP-002 / issue #438).

This module exposes ONLY the admission phase — ``aptl experiment admit``
resolves the authoring-input spec and its associated-artifact manifest,
runs :class:`~aptl.core.experiment.controller.ExperimentController`, and
prints the result. It never starts the lab: it does not import
``aptl.core.lab``, ``DeploymentBackend``, ``.env`` hydration, or any other
range-mutating entry point (ADR-047 "Range-mutation gate"). EXECUTION
(running an admitted plan's trials) is downstream work (#437/#459) and has
no CLI surface here.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import typer

from aptl.backends.aces_diagnostics import render_aces_diagnostics
from aptl.cli._common import resolve_run_store
from aptl.core.experiment.controller import ExperimentController
from aptl.core.experiment.errors import EXPERIMENT_ADMISSION_STAGE_LABEL, AdmissionRejection
from aptl.core.experiment.policy import default_admission_policy
from aptl.core.experiment.resolver import ProjectContainedResolver, parse_locator
from aptl.utils.logging import get_logger

log = get_logger("cli.experiment")

app = typer.Typer(help="ACES experiment admission (EXP-002).")


def _print_diagnostics(diagnostics) -> None:
    """Render already-safe diagnostics to stderr via the shared formatter."""
    typer.echo(
        render_aces_diagnostics(list(diagnostics), stage_label=EXPERIMENT_ADMISSION_STAGE_LABEL),
        err=True,
    )


@app.command("admit")
def admit(
    spec_path: str = typer.Argument(
        ...,
        help="Experiment authoring-input document, as a project-relative locator resolved against --base-dir.",
    ),
    manifest: str = typer.Option(
        ...,
        "--manifest",
        help=(
            "Associated-artifact manifest (project-relative locator, resolved against --base-dir) "
            "that binds the experiment's task/scenario/capture-spec references to project files. "
            "Required: reference resolution has no other source."
        ),
    ),
    base_dir: Path = typer.Option(
        Path("."),
        "--base-dir",
        "-d",
        help="Containment boundary every relative locator (spec, manifest, and its bound artifacts) is resolved against.",
    ),
    allow_uncertified_apparatus: bool = typer.Option(
        False,
        "--allow-uncertified-apparatus",
        help=(
            "DEBUG/DEV ONLY — do NOT use in production. Bypasses the strict backend/processor "
            "mutual-compatibility gate, downgrading it to a warning instead of a rejection."
        ),
    ),
) -> None:
    """Admit an ACES experiment (ADR-047) without starting the lab.

    Runs ADMISSION ONLY: bounded artifact resolution, ACES validation and
    planning, apparatus/capture capability checks, and create-once
    persistence of the resulting immutable trial plan. This command never
    hydrates ``.env``, generates credentials or certificates, pulls images,
    or otherwise mutates the range — that is downstream EXECUTION work.

    On rejection, prints safe diagnostics (no raw exception text, no input
    values, no paths) to stderr and exits 1. On admission, prints the plan
    identity, trial count/IDs, the persisted path, and any warnings, and
    exits 0.
    """
    try:
        policy = default_admission_policy()
        if allow_uncertified_apparatus:
            policy = dataclasses.replace(policy, allow_uncertified_apparatus=True)

        try:
            resolver = ProjectContainedResolver(base_dir=base_dir)
            locator = parse_locator(spec_path, address="spec_path")
            experiment_root = resolver.resolve(locator, policy=policy)
        except AdmissionRejection as exc:
            _print_diagnostics(exc.diagnostics)
            raise typer.Exit(code=1)

        store = resolve_run_store(base_dir)
        controller = ExperimentController(run_store=store, policy=policy)

        result = controller.admit(
            experiment_root=experiment_root,
            base_dir=base_dir,
            manifest_locator=manifest,
        )

        if not result.admitted:
            _print_diagnostics(result.diagnostics)
            raise typer.Exit(code=1)

        typer.echo(f"Admitted plan {result.plan.plan_id}")
        typer.echo(f"  digest:    {result.plan_digest}")
        typer.echo(f"  trials:    {len(result.trial_ids)}")
        for trial_id in result.trial_ids:
            typer.echo(f"    - {trial_id}")
        typer.echo(f"  persisted: {result.persisted_path}")

        if result.warnings:
            typer.echo("")
            typer.echo(
                render_aces_diagnostics(list(result.warnings), stage_label=EXPERIMENT_ADMISSION_STAGE_LABEL)
            )
    except typer.Exit:
        raise
    except Exception:
        # Defense in depth: every documented admission failure is already
        # returned as safe diagnostics (rejected AdmissionResult) or caught
        # above (AdmissionRejection from the root-locator resolve step).
        # Anything else reaching here is unexpected — never surface a raw
        # exception message, stack trace, or path to the caller.
        log.exception("unexpected error during experiment admission")
        typer.echo("Error: experiment admission failed unexpectedly.", err=True)
        raise typer.Exit(code=1)
