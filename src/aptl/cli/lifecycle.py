"""CLI commands for ephemeral lifecycle policy (DEP-003).

Registered onto the ``aptl lab`` Typer app by :func:`register`, so the commands
stay at ``aptl lab enforce`` / ``aptl lab monitor`` / ``aptl lab policy show``.
Policy authoring lives in ``aptl.json`` (strict first-party config, ADR-025);
this surface is read-only inspection plus the enforcement entrypoints.
"""

import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import typer

from aptl.core.lab_types import LabResult

_PROJECT_DIR_OPTION = typer.Option(
    Path("."),
    "--project-dir",
    "-d",
    help="Path to the APTL project directory.",
)

policy_app = typer.Typer(help="Inspect the ephemeral lifecycle policy (DEP-003).")


def _render_lifecycle_result(result: LabResult) -> None:
    """Print a lifecycle enforcement result line plus any diagnostics."""
    typer.echo(result.message)
    for diag in result.diagnostics:
        typer.echo(f"  {diag.message}")
    if not result.success and result.error:
        typer.echo(f"  error: {result.error}", err=True)


def enforce(
    project_dir: Path = _PROJECT_DIR_OPTION,
    grace_minutes: int = typer.Option(
        60,
        "--grace-minutes",
        help=(
            "How many minutes after a scheduled time a tick may still "
            "provision (so a tick running late does not boot a stale window)."
        ),
    ),
) -> None:
    """Evaluate the lifecycle policy once and act (idempotent, DEP-003).

    One evaluate-and-act tick: auto-teardown an expired (TTL) or idle range,
    or provision a due scheduled range. Designed to be driven by a systemd
    timer or cron entry. A no-op when no ``lifecycle_policy`` is configured.
    """
    from aptl.core.lifecycle_enforce import LifecycleBusyError, enforce_once

    try:
        result = enforce_once(project_dir, grace_minutes=grace_minutes)
    except LifecycleBusyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1)

    _render_lifecycle_result(result)
    if not result.success:
        raise typer.Exit(code=1)


def monitor(
    project_dir: Path = _PROJECT_DIR_OPTION,
    interval: int = typer.Option(
        60, "--interval", help="Seconds to wait between enforcement ticks."
    ),
    max_ticks: Optional[int] = typer.Option(
        None,
        "--max-ticks",
        help="Stop after this many ticks (default: run until interrupted).",
    ),
    grace_minutes: int = typer.Option(
        60, "--grace-minutes", help="Scheduled-provisioning grace window in minutes."
    ),
) -> None:
    """Run lifecycle enforcement in a single-owner loop (DEP-003).

    A thin convenience wrapper over ``aptl lab enforce`` for hosts without a
    systemd timer / cron. Holds the project lifecycle lock for its whole run,
    so a second monitor (or a one-shot ``enforce``) cannot act concurrently.
    """
    from aptl.core.lifecycle_enforce import LifecycleBusyError, run_monitor

    try:
        results = run_monitor(
            project_dir,
            interval_seconds=interval,
            max_ticks=max_ticks,
            grace_minutes=grace_minutes,
        )
    except LifecycleBusyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1)
    except KeyboardInterrupt:
        typer.echo("monitor stopped.")
        raise typer.Exit(code=0)

    for result in results:
        _render_lifecycle_result(result)


@policy_app.command("show")
def policy_show(
    project_dir: Path = _PROJECT_DIR_OPTION,
    json_output: bool = typer.Option(
        False, "--json", help="Emit policy + state as machine-readable JSON."
    ),
) -> None:
    """Show the resolved lifecycle policy and current lifecycle state."""
    from aptl.cli._common import resolve_config_for_cli
    from aptl.core.lifecycle_policy import load_state

    config, project_root = resolve_config_for_cli(project_dir)
    policy = config.lifecycle_policy
    state = load_state(project_root)

    if json_output:
        payload = {
            "policy": policy.model_dump(mode="json") if policy else None,
            "state": asdict(state),
        }
        typer.echo(json.dumps(payload, indent=2))
        return

    if policy is None:
        typer.echo("No lifecycle_policy configured.")
    else:
        typer.echo("Lifecycle policy:")
        typer.echo(f"  ttl_minutes: {policy.ttl_minutes}")
        typer.echo(f"  idle_timeout_minutes: {policy.idle_timeout_minutes}")
        typer.echo(f"  teardown_remove_volumes: {policy.teardown_remove_volumes}")
        typer.echo(f"  schedule entries: {len(policy.schedule)}")
        for entry in policy.schedule:
            days = ",".join(entry.days) if entry.days else "every day"
            scenario = f" scenario={entry.scenario}" if entry.scenario else ""
            typer.echo(f"    - {entry.at} UTC [{days}]{scenario}")

    typer.echo("State:")
    typer.echo(f"  provisioned_at: {state.provisioned_at}")
    typer.echo(f"  last_action: {state.last_action} (result={state.last_result})")
    typer.echo(f"  last_action_at: {state.last_action_at}")


def register(lab_app: typer.Typer) -> None:
    """Register the lifecycle commands onto the ``aptl lab`` Typer app."""
    lab_app.command("enforce")(enforce)
    lab_app.command("monitor")(monitor)
    lab_app.add_typer(policy_app, name="policy")
