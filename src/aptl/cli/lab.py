"""CLI commands for lab lifecycle management."""

import json
from pathlib import Path
from typing import Optional

import typer

from aptl.cli.continuity import continuity_audit
from aptl.core.lab import (
    LabResult,
    lab_status,
    orchestrate_lab_start,
    stop_lab,
)
from aptl.core.lab_types import LabStatus, StartupDiagnostic, StartupOutcome
from aptl.utils.logging import get_logger

log = get_logger("cli.lab")

app = typer.Typer(help="Lab lifecycle management.")

# `continuity-audit` lives in aptl.cli.continuity (issue #252) so this
# module stays focused on lifecycle commands. Register it under `lab`
# so the command stays at `aptl lab continuity-audit` (no UX change).
app.command("continuity-audit")(continuity_audit)


# Headline phrasing per outcome — kept beside the renderer so the CLI's
# user-visible classification stays in one place (ADR-030 anti-pattern:
# never reclassify based on English text). Values are the same stable
# wire strings as the StartupOutcome enum so an operator (or a parser)
# can grep for them.
_OUTCOME_HEADLINES: dict[StartupOutcome, str] = {
    StartupOutcome.READY: "Lab is ready.",
    StartupOutcome.DEGRADED_USABLE: (
        "Lab is degraded_usable — telemetry/cosmetic warnings, scenarios "
        "should still run."
    ),
    StartupOutcome.DEGRADED_UNUSABLE: (
        "Lab is degraded_unusable — some capabilities or SSH targets "
        "are not reachable."
    ),
    StartupOutcome.FAILED: "Lab start failed.",
}


def _render_start_result(result: LabResult) -> None:
    """Print a structured summary of a lab-start result.

    Always emits the outcome value (stable wire string from
    ``StartupOutcome``) so automation can parse a single line instead of
    scraping the diagnostic list. Diagnostics are grouped by impact so
    an operator can scan for ``readiness`` / ``capability`` rows when
    triaging a partial-readiness lab.
    """
    typer.echo(_OUTCOME_HEADLINES[result.outcome])
    if result.outcome is StartupOutcome.FAILED and result.error:
        typer.echo(f"  error: {result.error}")
    if not result.diagnostics:
        return
    typer.echo(f"  diagnostics ({len(result.diagnostics)}):")
    # Group by impact so a scanning operator sees all readiness rows
    # together, then capability, telemetry, cosmetic. Iteration order
    # below follows the severity hierarchy from worst to least-worst.
    impacts_in_order = ["readiness", "capability", "telemetry", "cosmetic"]
    grouped: dict[str, list[StartupDiagnostic]] = {}
    for diag in result.diagnostics:
        grouped.setdefault(diag.impact.value, []).append(diag)
    for impact in impacts_in_order:
        for diag in grouped.get(impact, []):
            label = f"{diag.step}/{diag.component}" if diag.component else diag.step
            typer.echo(
                f"    [{diag.impact.value}|{diag.severity.value}] "
                f"{label} — {diag.message}"
            )
            if diag.operator_action:
                typer.echo(f"      action: {diag.operator_action}")


@app.command()
def start(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    skip_seed: bool = typer.Option(
        False,
        "--skip-seed",
        help="Skip SOC tool seeding after startup.",
    ),
) -> None:
    """Start the APTL lab environment."""
    log.info("Starting lab from %s", project_dir)

    result = orchestrate_lab_start(project_dir, skip_seed=skip_seed)

    _render_start_result(result)
    if not result.success:
        raise typer.Exit(code=1)


@app.command()
def stop(
    volumes: bool = typer.Option(
        False,
        "--volumes",
        "-v",
        help="Also remove Docker volumes (full cleanup).",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip confirmation prompt when removing volumes.",
    ),
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
) -> None:
    """Stop the APTL lab environment."""
    if volumes and not yes:
        typer.echo(
            "\n  WARNING: This will destroy all lab data including:\n"
            "    - Wazuh SIEM indexes and configuration\n"
            "    - MISP threat intelligence data\n"
            "    - TheHive cases and analysis\n"
            "    - Shuffle SOAR workflows\n"
            "    - All container logs and state\n"
        )
        if not typer.confirm("  Continue?", default=False):
            typer.echo("Aborted.")
            raise typer.Exit(code=0)

    log.info("Stopping lab (volumes=%s)", volumes)

    result = stop_lab(remove_volumes=volumes, project_dir=project_dir)

    if result.success:
        typer.echo("Lab stopped successfully.")
    else:
        typer.echo(f"Lab stop failed: {result.error}")
        raise typer.Exit(code=1)


def _emit_snapshot_json(project_dir: Path, output_file: Optional[Path]) -> None:
    """Capture and emit a redacted range snapshot as JSON.

    Writes to ``output_file`` (mode 0600) when given, otherwise prints it.
    """
    from aptl.cli._common import resolve_config_for_cli
    from aptl.core.deployment import get_backend
    from aptl.core.snapshot import capture_snapshot

    # `capture_snapshot` requires an explicit backend (no silent default).
    # Resolve from the project's `aptl.json`; fail loudly if it's missing
    # or invalid, so a misconfigured SSH lab doesn't get snapshotted
    # against the local daemon.
    config, project_root = resolve_config_for_cli(project_dir)
    backend = get_backend(config, project_root)

    snapshot = capture_snapshot(config_dir=project_root, backend=backend)
    data = json.dumps(snapshot.to_dict(), indent=2)

    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(data)
        output_file.chmod(0o600)
        typer.echo(f"Snapshot written to {output_file}")
    else:
        typer.echo(data)


def _emit_status_text(current: LabStatus) -> None:
    """Print a human-readable summary of the current lab status."""
    if not current.running:
        typer.echo("Lab is not running.")
        if current.error:
            typer.echo(f"Error: {current.error}")
        return

    typer.echo("Lab is running.")
    for container in current.containers:
        name = container.get("Name", "unknown")
        state = container.get("State", "unknown")
        health = container.get("Health", "")
        line = f"  {name}: {state}"
        if health:
            line += f" ({health})"
        typer.echo(line)


@app.command()
def status(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output full range snapshot as JSON.",
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write JSON output to file instead of stdout.",
    ),
) -> None:
    """Show the current lab status."""
    log.info("Checking lab status")

    if output_json or output_file:
        _emit_snapshot_json(project_dir, output_file)
        return

    _emit_status_text(lab_status(project_dir=project_dir))


_LIVE_GATE_WARNING = (
    "\n  WARNING: the live validation gate runs `aptl lab stop -v` and then\n"
    "  re-boots the lab through the ACES start path. This DESTROYS all lab\n"
    "  data (Wazuh/MISP/TheHive/Shuffle volumes). Pass --skip-clean-boot to\n"
    "  validate the already-running lab without destroying it.\n"
)


@app.command("validate-live")
def validate_live(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    scenario: Optional[Path] = typer.Option(
        None,
        "--scenario",
        help="ACES SDL scenario (default: scenarios/techvault-operational.sdl.yaml).",
    ),
    profile: str = typer.Option(
        "orchestration-evaluation",
        "--profile",
        help="ACES backend capability profile to validate against.",
    ),
    run_id: Optional[str] = typer.Option(
        None,
        "--run-id",
        help="Run id for the live-gate archive (default: generated).",
    ),
    skip_clean_boot: bool = typer.Option(
        False,
        "--skip-clean-boot",
        help="Validate the running lab without the destructive stop -v + reboot.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the data-destruction confirmation prompt.",
    ),
) -> None:
    """Run the live ACES validation gate (boots the lab end-to-end; DESTRUCTIVE).

    Proves a fresh TechVault lab is realized from the interpreted ACES model
    through the public start path and captures operational + provenance evidence
    in the run archive. Intended for maintainers / a documented CI runner — not
    fast CI: it needs Docker, the SOC stack's resources, and minutes of startup.
    """
    from aptl.cli._common import resolve_config_for_cli, resolve_run_store
    from aptl.core.runstore import _validate_id
    from aptl.validation.techvault_live_gate import (
        LiveGateOptions,
        validate_live_deployment,
    )

    config, project_root = resolve_config_for_cli(project_dir)
    if run_id is not None:
        try:
            _validate_id(run_id, "run_id")
        except ValueError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=2)
    if not skip_clean_boot and not yes:
        typer.echo(_LIVE_GATE_WARNING)
        if not typer.confirm("  Continue?", default=False):
            typer.echo("Aborted.")
            raise typer.Exit(code=0)

    log.info("Running live validation gate from %s", project_root)
    report = validate_live_deployment(
        scenario,
        project_dir=project_root,
        config=config,
        options=LiveGateOptions(
            profile=profile, run_id=run_id, skip_clean_boot=skip_clean_boot
        ),
        run_store=resolve_run_store(project_root, config),
    )
    typer.echo(report.render())
    if not report.passed:
        raise typer.Exit(code=1)
