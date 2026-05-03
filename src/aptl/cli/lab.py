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


def _emit_continuity_text(events, target_list, run_id) -> None:
    """Render the human-readable summary for ``aptl lab continuity-audit``."""
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
        prefix, detail = _format_continuity_event_line(event)
        line = f"  [{prefix}] {event.target}: {detail}"
        if event.error:
            line += f"  ({event.error})"
        typer.echo(line)
    if run_id:
        typer.echo(
            f"  events archived to run {run_id} continuity-events.jsonl"
        )


def _format_continuity_event_line(event) -> tuple[str, str]:
    """Pick the per-event ``[PREFIX] target: detail`` shape."""
    if event.action == "REVERTED":
        return "REVERTED  ", event.rule_text
    if event.action == "REVERT_FAILED":
        return "REVERT-FAIL", event.rule_text
    return "AUDIT-FAIL ", "iptables inspection failed"


def _validate_continuity_targets(
    backend, targets: list[str], *, explicit: bool,
) -> list[str]:
    """Resolve which targets the audit should actually inspect.

    When the user passes ``--target`` explicitly, every name must
    belong to this compose project; an unknown name is a hard error
    (security finding S1, cycle 1). When the user takes the defaults,
    a missing default in the active profile is *not* a hard error —
    it just means that profile isn't running this lab session, and
    auditing the remaining defaults is still useful (codex finding C8,
    cycle 2). In that case we filter to the present subset and warn.

    Returns the list to audit (possibly narrowed). Raises ``typer.Exit``
    on the strict-validation-failure paths.
    """
    present = [t for t in targets if backend.container_exists(t)]
    missing = [t for t in targets if t not in present]

    if missing and explicit:
        typer.echo(
            f"error: not part of this lab project: {', '.join(missing)}",
            err=True,
        )
        raise typer.Exit(code=2)

    if missing and not present:
        typer.echo(
            "error: none of the default targets are present in the active"
            f" compose profile (looked for {', '.join(targets)}).",
            err=True,
        )
        raise typer.Exit(code=2)

    if missing:
        typer.echo(
            "Continuity audit: skipping defaults not in active profile: "
            f"{', '.join(missing)}",
            err=True,
        )

    return present


def _resolve_continuity_run_archive(
    project_root: Path, config, *, override: str | None = None,
) -> tuple[object | None, str | None]:
    """Resolve the (run_store, run_id) pair for archive emission.

    Resolution order:
      1. An explicit ``--run-id`` override (CLI flag) wins.
      2. The active scenario session's ``run_id`` (when populated).
      3. ``(None, None)`` — audit runs but events are not persisted.

    Step 2 is currently never populated by ``ScenarioSession.start()``
    in production flows; the session-bound archival path lights up
    once #263/RTE-001 wires the runtime engine. Until then, the
    ``--run-id`` override is the supported path for archive emission.
    Codex finding C10 (cycle 3).
    """
    from aptl.core.session import ScenarioSession

    if override:
        return _resolve_run_store(project_root, config), override

    state_dir = project_root / ".aptl"
    session = ScenarioSession(state_dir).get_active()
    if session is None or not session.run_id:
        return None, None
    return _resolve_run_store(project_root, config), session.run_id


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
    run_id_override: Optional[str] = typer.Option(
        None,
        "--run-id",
        help=(
            "Archive events under this run id. Falls back to the active"
            " session's run_id if a session is open. Without either, the"
            " audit runs but events are not persisted."
        ),
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
    from dataclasses import asdict

    from aptl.cli._common import resolve_config_for_cli
    from aptl.core.continuity import (
        audit_and_revert,
        default_targets,
        kali_source_ips,
    )
    from aptl.core.deployment import get_backend

    config, project_root = resolve_config_for_cli(project_dir)
    backend = get_backend(config, project_root)

    explicit_targets = bool(targets)
    requested = list(targets) if targets else default_targets()
    target_list = _validate_continuity_targets(
        backend, requested, explicit=explicit_targets,
    )

    wl_path = whitelist_path or (project_root / _DEFAULT_WHITELIST_RELPATH)
    kali_ips = set(kali_source_ips(whitelist_path=wl_path))
    if not kali_ips:
        # Empty whitelist means the audit would protect zero source IPs —
        # the carve-out is effectively disabled. A silent zero-exit lets
        # automation believe the run is clean while it's actually
        # uninstrumented. Fail loudly. Codex finding C7 (cycle 2).
        typer.echo(
            f"error: no kali IPs found in {wl_path}; whitelist appears to"
            " be empty or missing. Refusing to run an audit that would"
            " protect no source IPs.",
            err=True,
        )
        raise typer.Exit(code=2)

    run_store, run_id = _resolve_continuity_run_archive(
        project_root, config, override=run_id_override,
    )
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
        typer.echo(json.dumps([asdict(e) for e in events], indent=2))
    else:
        _emit_continuity_text(events, target_list, run_id)

    # Exit non-zero if any target failed inspection or any reversion
    # failed — automation watching the exit code must see the signal.
    # Codex finding C5 (cycle 1).
    if any(e.action != "REVERTED" for e in events):
        raise typer.Exit(code=1)
