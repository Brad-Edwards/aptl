"""CLI commands for lab lifecycle management."""

import json
from pathlib import Path
from typing import Optional

import typer

from aptl.core.lab import (
    lab_status,
    orchestrate_lab_start,
    stop_lab,
)
from aptl.utils.logging import get_logger

log = get_logger("cli.lab")

app = typer.Typer(help="Lab lifecycle management.")


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

    if result.success:
        typer.echo("Lab started successfully.")
    else:
        typer.echo(f"Lab start failed: {result.error}")
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


def _emit_status_text(current) -> None:
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


_DEFAULT_WHITELIST_RELPATH = Path(
    "config/wazuh_cluster/etc/lists/active-response-whitelist"
)


def _resolve_run_store(project_root: Path, config) -> "LocalRunStore":
    """Build a LocalRunStore against the project's configured runs path.

    Mirrors :func:`aptl.cli.runs._get_store` without importing it (avoids
    a CLI-internal circular dependency).
    """
    from aptl.core.runstore import LocalRunStore

    local_path = Path(config.run_storage.local_path)
    if not local_path.is_absolute():
        local_path = project_root / local_path
    return LocalRunStore(local_path)


@app.command("continuity-audit")
def continuity_audit(
    project_dir: Path = typer.Option(
        Path("."),
        "--project-dir",
        "-d",
        help="Path to the APTL project directory.",
    ),
    targets: Optional[list[str]] = typer.Option(
        None,
        "--target",
        "-t",
        help=(
            "Container name to audit (repeatable). Defaults to the full"
            " AR-capable agent set."
        ),
    ),
    whitelist_path: Optional[Path] = typer.Option(
        None,
        "--whitelist",
        help=(
            "Override path to the kali source-IP whitelist."
            " Defaults to the in-repo lab whitelist."
        ),
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit the full event list as JSON instead of a text summary.",
    ),
) -> None:
    """Audit each target's INPUT chain and revert blanket kali source-IP DROPs.

    Detects rules that drop or reject a kali source IP with no other
    matchers (port, protocol, payload, interface, state, or
    timeout). Granular rules with any qualifier are preserved. See
    ADR-024 and ADR-021 for the design.

    Runs unconditionally — APTL is purple-team-only by design. When SDL
    formalizes a ``mode`` field (issue #263) the audit will gate on
    ``scenario.mode == PURPLE``.
    """
    from aptl.cli._common import resolve_config_for_cli
    from aptl.core.continuity import (
        audit_and_revert,
        default_targets,
        kali_source_ips,
    )
    from aptl.core.deployment import get_backend
    from aptl.core.session import ScenarioSession

    config, project_root = resolve_config_for_cli(project_dir)
    backend = get_backend(config, project_root)

    target_list = list(targets) if targets else default_targets()

    # Validate every target belongs to this compose project. Without
    # this gate, a `--target aptl-victim` could redirect to any other
    # container on a shared Docker daemon — `backend.container_exec`
    # has no project-ownership check, but `backend.container_exists`
    # does (it inspects compose-project labels). Codex security
    # finding S1 (cycle 1).
    unknown = [t for t in target_list if not backend.container_exists(t)]
    if unknown:
        typer.echo(
            f"error: not part of this lab project: {', '.join(unknown)}",
            err=True,
        )
        raise typer.Exit(code=2)

    wl_path = whitelist_path or (project_root / _DEFAULT_WHITELIST_RELPATH)
    kali_ips = set(kali_source_ips(whitelist_path=wl_path))
    if not kali_ips:
        typer.echo(
            f"warning: no kali IPs found in {wl_path}; audit will be a no-op.",
            err=True,
        )

    # If a scenario session is active with a run_id, archive the audit
    # events to that run's events.jsonl. Otherwise the audit still runs;
    # only the persistence layer is skipped (safe for ad-hoc smoke tests).
    state_dir = project_root / ".aptl"
    session_mgr = ScenarioSession(state_dir)
    session = session_mgr.get_active()
    run_store = None
    run_id: Optional[str] = None
    if session is not None and session.run_id:
        run_store = _resolve_run_store(project_root, config)
        run_id = session.run_id

    log.info(
        "Continuity audit: targets=%s run_id=%s", target_list, run_id or "(none)",
    )

    events = audit_and_revert(
        backend,
        target_list,
        kali_ips=kali_ips,
        run_store=run_store,
        run_id=run_id,
    )

    if output_json:
        from dataclasses import asdict

        typer.echo(json.dumps([asdict(e) for e in events], indent=2))
        # Even in JSON mode, exit non-zero if anything failed so
        # automation can detect partial success without parsing output.
        if any(e.action != "REVERTED" for e in events):
            raise typer.Exit(code=1)
        return

    if not events:
        typer.echo("Continuity audit: no blanket kali source-IP rules found.")
        return

    reverted = sum(1 for e in events if e.action == "REVERTED")
    revert_failed = sum(1 for e in events if e.action == "REVERT_FAILED")
    audit_failed = sum(1 for e in events if e.action == "AUDIT_FAILED")
    typer.echo(
        f"Continuity audit: {reverted} reverted, {revert_failed} revert-failed, "
        f"{audit_failed} audit-failed across {len(target_list)} targets."
    )
    for event in events:
        if event.action == "REVERTED":
            prefix = "REVERTED  "
            detail = event.rule_text
        elif event.action == "REVERT_FAILED":
            prefix = "REVERT-FAIL"
            detail = event.rule_text
        else:
            prefix = "AUDIT-FAIL "
            detail = "iptables inspection failed"
        line = f"  [{prefix}] {event.target}: {detail}"
        if event.error:
            line += f"  ({event.error})"
        typer.echo(line)
    if run_id:
        typer.echo(f"  events archived to run {run_id} continuity-events.jsonl")
    # Exit non-zero if any target failed inspection or any reversion
    # failed — automation watching the exit code must see the signal.
    # Codex finding C5 (cycle 1).
    if revert_failed or audit_failed:
        raise typer.Exit(code=1)
