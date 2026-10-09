"""CLI commands for lab lifecycle management."""

import json
from collections.abc import Callable
from dataclasses import asdict
from functools import partial
from pathlib import Path
from typing import Optional

import typer

from aptl.cli import lab_init, lifecycle
from aptl.cli._common import (
    EXIT_FAILED,
    emit_json_result,
    exit_status,
    redact_text,
    refuse_json_prompt,
)
from aptl.cli.participant_profile import qualify_profile
from aptl.cli.continuity import continuity_audit
from aptl.cli.lab_render import (
    emit_lab_access_summary,
    emit_execution_boundary_summary,
    fresh_execution_boundary,
    live_resolved_ports,
    published_access_ports,
    render_start_result,
)
from aptl.core.lab import (
    clean_boot_lab,
    lab_status,
    orchestrate_lab_start,
    reset_lab,
    stop_lab,
)
from aptl.core.lab_types import (
    LabResetResult,
    LabResult,
    LabStatus,
    describe_project_runtime,
)
from aptl.core.scenario_catalog import (
    load_scenario_catalog,
    resolve_scenario_selection,
)
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

log = get_logger("cli.lab")

app = typer.Typer(help="Lab lifecycle management.")

# `continuity-audit` lives in aptl.cli.continuity (issue #252) so this
# module stays focused on lifecycle commands. Register it under `lab`
# so the command stays at `aptl lab continuity-audit` (no UX change).
app.command("continuity-audit")(continuity_audit)

# `init` (DEP-008) lives in aptl.cli.lab_init so this module stays the focused
# lifecycle facade; registered here so the command remains `aptl lab init`.
lab_init.register(app)

# Ephemeral lifecycle policy commands (DEP-003) live in aptl.cli.lifecycle so
# this module stays focused; register them under `lab` (no UX change:
# `aptl lab enforce` / `monitor` / `policy show`).
lifecycle.register(app)
app.command("qualify-profile")(qualify_profile)


# Shared destructive-data warning. Both `stop --volumes` and
# `start --clean` remove Compose-managed volumes, so the operator sees one
# canonical statement of what gets destroyed.
_DESTRUCTIVE_DATA_WARNING = (
    "\n  WARNING: This will destroy all lab data including:\n"
    "    - Wazuh SIEM indexes and configuration\n"
    "    - MISP threat intelligence data\n"
    "    - TheHive cases and analysis\n"
    "    - Shuffle SOAR workflows\n"
    "    - All container logs and state\n"
)


def _emit_lab_start_progress(message: str, *, err: bool = False) -> None:
    """Print participant-facing startup progress."""
    typer.echo(f"[lab start] {message}", err=err)


def _start_progress(output_json: bool) -> Callable[[str], None]:
    """Keep standard output for the JSON result; progress then goes to stderr."""
    return partial(_emit_lab_start_progress, err=output_json)


def _confirm_destructive(
    skip_prompt: bool, *, output_json: bool = False, option: str = "--volumes"
) -> bool:
    """Confirm a volume-destroying action; return False if the operator aborts.

    Centralizes the destructive-action gate shared by ``stop --volumes`` and
    ``start --clean``: print the canonical warning and require an explicit
    ``y`` unless ``skip_prompt`` (``--yes``) was passed. JSON output cannot
    prompt, so it requires ``--yes`` and otherwise exits with status 2.
    """
    if skip_prompt:
        return True
    if output_json:
        refuse_json_prompt(option)
    typer.echo(_DESTRUCTIVE_DATA_WARNING)
    if not typer.confirm("  Continue?", default=False):
        typer.echo("Aborted.")
        return False
    return True


@app.command()
def start(  # NOSONAR - Typer exposes one parameter per user-visible CLI option.
    project_dir: Path = typer.Option(  # NOSONAR - required Typer option surface.
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
    scenario: Optional[str] = typer.Option(
        None,
        "--scenario",
        help="Acquired RAES environment-pack id from the catalog.",
    ),
    scenario_path: Optional[Path] = typer.Option(
        None,
        "--scenario-path",
        help="Explicit RAES SDL scenario path under the project directory.",
    ),
    clean: bool = typer.Option(
        False,
        "--clean",
        "-c",
        help=(
            "Ephemeral clean boot (RNG-001): tear down the lab and remove "
            "Compose volumes before starting, guaranteeing clean state "
            "between runs. Destroys all lab data."
        ),
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the confirmation prompt for --clean.",
    ),
    teardown_on_failure: bool = typer.Option(
        False,
        "--teardown-on-failure",
        help=(
            "If the start fails, stop the containers and networks it created "
            "and keep the volumes. By default a failed start leaves them in "
            "place for diagnosis."
        ),
    ),
    offline_staged: bool = typer.Option(
        False,
        "--offline-staged",
        help=(
            "Use only pre-staged appliance images and MCP artifacts; "
            "forbid pulls and builds."
        ),
    ),
    appliance_launch_descriptor: Optional[Path] = typer.Option(
        None,
        "--appliance-launch-descriptor",
        help="Create-once descriptor for a verified appliance release.",
    ),
    appliance_release_public_key: Optional[Path] = typer.Option(
        None,
        "--appliance-release-public-key",
        help="Release trust anchor used to reverify the launch descriptor.",
    ),
    appliance_qualification_public_key: Optional[Path] = typer.Option(
        None,
        "--appliance-qualification-public-key",
        help="Independent APP-2 qualification trust anchor.",
    ),
    appliance_readiness_challenge: Optional[Path] = typer.Option(
        None,
        "--appliance-readiness-challenge",
        hidden=True,
    ),
    appliance_readiness_device: Optional[Path] = typer.Option(
        None,
        "--appliance-readiness-device",
        hidden=True,
    ),
    appliance_access_request: Optional[Path] = typer.Option(
        None, "--appliance-access-request", hidden=True
    ),
    appliance_access_device: Optional[Path] = typer.Option(
        None, "--appliance-access-device", hidden=True
    ),
    appliance_access_output_dir: Optional[Path] = typer.Option(
        None, "--appliance-access-output-dir", hidden=True
    ),
    appliance_candidate_trust: bool = typer.Option(
        False, "--appliance-candidate-trust", hidden=True
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Print the result as one JSON object; progress goes to stderr.",
    ),
) -> None:
    """Start the APTL lab environment.

    Exit status: 0 when the lab started (read the outcome for degraded
    states), 1 when the start failed, 2 for invalid options.
    """
    log.info("Starting lab from %s (clean=%s)", project_dir, clean)

    try:
        selected_scenario = resolve_scenario_selection(
            project_dir,
            scenario_id=scenario,
            scenario_path=scenario_path,
        )
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)

    launch_values = (appliance_launch_descriptor,)
    readiness_values = (
        appliance_readiness_challenge,
        appliance_readiness_device,
    )
    if any(launch_values) and not offline_staged:
        typer.echo(
            "error: appliance launch requires --offline-staged",
            err=True,
        )
        raise typer.Exit(code=2)
    if appliance_candidate_trust:
        typer.echo(
            "error: candidate trust is unavailable for seat images",
            err=True,
        )
        raise typer.Exit(code=2)
    if (appliance_release_public_key or appliance_qualification_public_key) and not appliance_launch_descriptor:
        typer.echo("error: appliance trust anchors require a launch descriptor", err=True)
        raise typer.Exit(code=2)
    if any(readiness_values) and (
        not all(readiness_values) or not appliance_launch_descriptor or not offline_staged
    ):
        typer.echo(
            "error: appliance readiness requires a verified offline launch",
            err=True,
        )
        raise typer.Exit(code=2)
    access_values = (
        appliance_access_request,
        appliance_access_device,
        appliance_access_output_dir,
    )
    if any(access_values) and (not all(access_values) or not all(readiness_values)):
        typer.echo(
            "error: appliance access requires complete readiness and access channels",
            err=True,
        )
        raise typer.Exit(code=2)
    from aptl.core.lab import ApplianceStartOptions

    appliance_kwargs = {}
    if offline_staged or appliance_launch_descriptor is not None:
        appliance_kwargs["appliance"] = ApplianceStartOptions(
            offline_staged=offline_staged,
            launch_descriptor=appliance_launch_descriptor,
            release_public_key=appliance_release_public_key,
            qualification_public_key=appliance_qualification_public_key,
            readiness_challenge=appliance_readiness_challenge,
            readiness_device=appliance_readiness_device,
            access_request=appliance_access_request,
            access_device=appliance_access_device,
            access_output_dir=appliance_access_output_dir,
            candidate_trust=appliance_candidate_trust,
        )
    if clean:
        if not _confirm_destructive(yes, output_json=output_json, option="--clean"):
            raise typer.Exit(code=0)
        result = clean_boot_lab(
            project_dir,
            remove_volumes=True,
            skip_seed=skip_seed,
            scenario_path=selected_scenario,
            progress=_start_progress(output_json),
            teardown_on_failure=teardown_on_failure,
            **appliance_kwargs,
        )
    else:
        result = orchestrate_lab_start(
            project_dir,
            skip_seed=skip_seed,
            scenario_path=selected_scenario,
            progress=_start_progress(output_json),
            teardown_on_failure=teardown_on_failure,
            **appliance_kwargs,
        )
    _report_start_result(project_dir, result, output_json)


def _start_result_fields(project_dir: Path, result: LabResult) -> dict[str, object]:
    """Return the ``lab start --json`` fields for one start result (#1218).

    They carry the same result the text summary renders: the outcome and
    error, the execution boundary, the admission time, every diagnostic, the
    host ports the access summary reports and any failed-start residue.
    Free-form text is redacted before serialization (ADR-012).
    """

    boundary = result.execution_boundary
    return {
        "outcome": result.outcome.value,
        "error": redact_text(result.error) or None,
        "execution_boundary": (
            boundary.model_dump(mode="json") if boundary is not None else None
        ),
        "admission_seconds": result.admission_seconds,
        "diagnostics": [
            {
                "step": diag.step,
                "component": diag.component,
                "impact": diag.impact.value,
                "severity": diag.severity.value,
                "message": redact_text(diag.message),
                "operator_action": redact_text(diag.operator_action),
            }
            for diag in result.diagnostics
        ],
        **_published_port_fields(project_dir, result),
        "residue": asdict(result.residue) if result.residue is not None else None,
    }


def _published_port_fields(project_dir: Path, result: LabResult) -> dict[str, object]:
    """Return the host ports the text access summary reports for this start.

    Both read :func:`published_access_ports`: live Docker bindings first, the
    start-time plan only when Docker reports none. A failed start prints no
    access summary, so it reports no ports.
    """

    ports, observed = (
        published_access_ports(project_dir, result.resolved_ports)
        if result.success
        else ([], False)
    )
    return {
        "published_ports": [
            {
                "service": port.service,
                "default_port": port.default_port,
                "host_port": port.resolved_port,
                "protocols": list(port.protos),
                "host_ip": port.host_ip,
                "remapped": port.remapped,
            }
            for port in ports
        ],
        "published_ports_observed": observed,
    }


def _report_start_result(
    project_dir: Path, result: LabResult, output_json: bool
) -> None:
    """Print the start result as text or JSON and exit with its status."""
    if output_json:
        fields = _start_result_fields(project_dir, result)
        emit_json_result("lab start", result.success, fields)
    else:
        render_start_result(result, project_dir)
        if result.success:
            emit_lab_access_summary(
                project_dir,
                result.resolved_ports,
                execution_boundary=result.execution_boundary,
            )
    if not result.success:
        raise typer.Exit(code=EXIT_FAILED)


@app.command("info")
def info(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
) -> None:
    """Show lab access URLs and credential locations."""
    boundary = fresh_execution_boundary(project_dir)
    emit_execution_boundary_summary(boundary)
    env_path = project_dir / ".env"
    if not env_path.exists():
        typer.echo(
            f"Credentials file not found at {env_path}; run `aptl lab start` first.",
            err=True,
        )
        raise typer.Exit(code=1)
    # Reconstruct the ResolvedPort list from docker's runtime state so the
    # printed URLs reflect the actual published ports (#737).
    emit_lab_access_summary(
        project_dir,
        live_resolved_ports(project_dir),
        execution_boundary=boundary,
    )


@app.command("scenarios")
def scenarios(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
) -> None:
    """List validated acquired-pack identities."""
    try:
        catalog = load_scenario_catalog(project_dir)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)

    with catalog:
        for entry in catalog.scenarios:
            description = f" - {entry.description}" if entry.description else ""
            identity = catalog.pack_identity
            typer.echo(
                f"{entry.id}\t{identity.pack_version}\t{catalog.maturity}\t"
                f"{identity.set_digest}\t{entry.name}{description}"
            )


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
    output_json: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Print the result as one JSON object.",
    ),
) -> None:
    """Stop the APTL lab environment.

    Exit status: 0 when the project is stopped, also when it was not running,
    1 when the stop failed, 2 for invalid options.
    """
    if volumes and not _confirm_destructive(yes, output_json=output_json):
        raise typer.Exit(code=0)

    log.info("Stopping lab (volumes=%s)", volumes)

    result = stop_lab(remove_volumes=volumes, project_dir=project_dir)

    if output_json:
        emit_json_result(
            "lab stop",
            result.success,
            {"volumes": volumes, "error": redact_text(result.error) or None},
        )
    elif result.success:
        typer.echo("Lab stopped successfully.")
    else:
        typer.echo(f"Lab stop failed: {result.error}")
    raise exit_status(result.success)


@app.command()
def reset(
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the confirmation prompt.",
    ),
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
        help="Print the result as one JSON object.",
    ),
) -> None:
    """Reset the lab: remove its containers, networks and volumes.

    It also finishes pending host-side cleanup, so the next `aptl lab start`
    begins clean. Configuration, .env, SSH keys, certificates and run records
    are kept. Exit status: 0 when the project is reset, also when nothing was
    running, 1 when the reset failed or host cleanup is still pending, 2 for
    invalid options.
    """
    if not _confirm_destructive(yes, output_json=output_json, option="aptl lab reset"):
        raise typer.Exit(code=0)
    log.info("Resetting lab")
    _report_reset_result(reset_lab(project_dir), output_json)


def _report_reset_result(outcome: LabResetResult, output_json: bool) -> None:
    """Print the reset result as text or JSON and exit with its status."""
    result = outcome.result
    if output_json:
        emit_json_result(
            "lab reset",
            result.success,
            {
                "containers_found": outcome.containers_found,
                "networks_found": outcome.networks_found,
                "error": result.error or None,
            },
        )
    elif result.success:
        found = (
            describe_project_runtime(outcome.containers_found, outcome.networks_found)
            if outcome.containers_found is not None
            and outcome.networks_found is not None
            else "the project's containers and networks"
        )
        typer.echo(
            f"Lab reset: removed {found} and the project's volumes, and finished "
            "pending host cleanup."
        )
    else:
        typer.echo(f"Lab reset failed: {result.error}")
    raise exit_status(result.success)


def _emit_snapshot_json(project_dir: Path, output_file: Optional[Path]) -> None:
    """Capture and emit a redacted range snapshot as JSON.

    Writes to ``output_file`` (mode 0600) when given, otherwise prints it.
    """
    from aptl.cli._common import resolve_config_for_cli
    from aptl.core.deployment import get_backend
    from aptl.core.deployment.errors import BackendObservationError
    from aptl.core.snapshot import capture_snapshot

    # `capture_snapshot` requires an explicit backend (no silent default).
    # Resolve from the project's `aptl.json`; fail loudly if it's missing
    # or invalid, so a misconfigured SSH lab doesn't get snapshotted
    # against the local daemon.
    config, project_root = resolve_config_for_cli(project_dir)
    backend = get_backend(config, project_root)

    try:
        snapshot = capture_snapshot(config_dir=project_root, backend=backend)
    except BackendObservationError as exc:
        typer.echo(f"Error: {redact(str(exc))}", err=True)
        raise typer.Exit(code=1) from exc
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
    else:
        typer.echo("Lab is running.")
    for container in current.containers:
        name = container.get("Name", container.get("name", "unknown"))
        state = container.get("State", container.get("state", "unknown"))
        health = container.get("Health", container.get("health", ""))
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
    """Show the current lab status.

    Exit status: 0 when the project state was observed, whether or not the
    lab is running, 1 when it could not be observed, 2 for invalid options.
    """
    log.info("Checking lab status")

    if output_json or output_file:
        _emit_snapshot_json(project_dir, output_file)
        return

    current = lab_status(project_dir=project_dir)
    _emit_status_text(current)
    raise exit_status(not current.error)


_LIVE_GATE_WARNING = (
    "\n  WARNING: the live validation gate runs `aptl lab stop -v` and then\n"
    "  re-boots the lab through the RAES start path. This DESTROYS all lab\n"
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
        help=(
            "Explicit project-tree RAES SDL override "
            "(default: the configured acquired TechVault pack)."
        ),
    ),
    profile: str = typer.Option(
        "full-remote-control-plane",
        "--profile",
        help="RAES backend capability profile to validate against.",
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
    """Run the live RAES validation gate (boots the lab end-to-end; DESTRUCTIVE).

    Proves a fresh TechVault lab is realized from the interpreted RAES model
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
