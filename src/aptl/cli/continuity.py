"""CLI implementation of ``aptl lab continuity-audit`` (issue #252).

Lives in its own module so :mod:`aptl.cli.lab` stays focused on the
lab-lifecycle commands (``start``/``stop``/``status``); the lab module
imports :func:`continuity_audit` and registers it as a subcommand of
``aptl lab``. See ADR-024 for the design and ADR-021 for the in-band
counterpart.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import typer

from aptl.cli._common import resolve_config_for_cli, resolve_run_store
from aptl.core.continuity import (
    ContinuityAuditResult,
    KaliCarveOutEvent,
    audit_and_revert,
    default_targets,
    kali_source_ips,
)
from aptl.core.deployment import get_backend
from aptl.utils.logging import get_logger


log = get_logger("cli.continuity")

_DEFAULT_WHITELIST_RELPATH = Path(
    "config/wazuh_cluster/etc/lists/active-response-whitelist"
)

# Matches every safe path-segment shape; rejects "../escape" etc.
_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9_-]+$")


class _RunIdValidationError(Exception):
    """Internal: raised by :func:`_validate_run_id_for_archive` (lenient mode)."""


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
    config, project_root = resolve_config_for_cli(project_dir)
    backend = get_backend(config, project_root)

    explicit_targets = bool(targets)
    requested = list(targets) if targets else default_targets()
    target_list = _validate_continuity_targets(
        backend, requested, explicit=explicit_targets,
    )

    wl_path = whitelist_path or (project_root / _DEFAULT_WHITELIST_RELPATH)
    kali_ips = _load_kali_ips_or_exit(wl_path)

    run_store, run_id = _resolve_continuity_run_archive(
        project_root, config, override=run_id_override,
    )
    log.info(
        "Continuity audit: targets=%s run_id=%s", target_list, run_id or "(none)",
    )

    result = audit_and_revert(
        backend,
        target_list,
        kali_ips=kali_ips,
        run_store=run_store,
        run_id=run_id,
    )
    archived = run_id is not None and result.archive_error is None

    if output_json:
        typer.echo(json.dumps([asdict(e) for e in result.events], indent=2))
    else:
        _emit_continuity_text(
            result.events, target_list, run_id if archived else None,
        )
        if result.archive_error:
            typer.echo(
                f"  ERROR: events were NOT archived to run {run_id}:"
                f" {result.archive_error}",
                err=True,
            )

    if _continuity_exit_code(result) != 0:
        raise typer.Exit(code=1)


def _load_kali_ips_or_exit(whitelist_path: Path) -> set[str]:
    """Load + validate the protected-source set, exiting on empty.

    Empty whitelist means the audit would protect zero source IPs —
    the carve-out is effectively disabled. A silent zero-exit lets
    automation believe the run is clean while it's actually
    uninstrumented; fail loudly with exit code 2.
    """
    kali_ips = set(kali_source_ips(whitelist_path=whitelist_path))
    if not kali_ips:
        typer.echo(
            f"error: no kali IPs found in {whitelist_path}; whitelist appears"
            " to be empty or missing. Refusing to run an audit that would"
            " protect no source IPs.",
            err=True,
        )
        raise typer.Exit(code=2)
    return kali_ips


def _continuity_exit_code(result: ContinuityAuditResult) -> int:
    """Return 1 if any event is non-REVERTED or the archive write failed.

    Three failure classes feed the exit code: ``REVERT_FAILED`` events
    (a known wedge couldn't be undone), ``AUDIT_FAILED`` events
    (a target couldn't be inspected at all), and a populated
    ``archive_error`` (events were produced but not persisted).
    Automation watching the exit code must see all three.
    """
    if result.archive_error:
        return 1
    if any(e.action != "REVERTED" for e in result.events):
        return 1
    return 0


def _validate_continuity_targets(
    backend, targets: list[str], *, explicit: bool,
) -> list[str]:
    """Resolve which targets the audit should actually inspect.

    When the user passes ``--target`` explicitly, every name must
    belong to this compose project; an unknown name is a hard error
    so a stray ``--target foreign-container`` cannot redirect at
    another project on a shared Docker daemon. When the user takes
    the defaults, a missing default in the active profile is *not*
    a hard error — that profile just isn't running this lab session,
    and auditing the remaining defaults is still useful. In that
    case we filter to the present subset and warn.

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


def _format_continuity_event_line(event: KaliCarveOutEvent) -> tuple[str, str]:
    """Pick the per-event ``[PREFIX] target: detail`` shape."""
    if event.action == "REVERTED":
        return "REVERTED  ", event.rule_text
    if event.action == "REVERT_FAILED":
        return "REVERT-FAIL", event.rule_text
    return "AUDIT-FAIL ", "iptables inspection failed"


def _resolve_continuity_run_archive(
    project_root: Path, config, *, override: str | None = None,
) -> tuple[object | None, str | None]:
    """Resolve the (run_store, run_id) pair for archive emission.

    Resolution order:
      1. An explicit ``--run-id`` override (CLI flag) wins. The id must
         match a safe character class and reference an existing run
         (the run directory and its ``manifest.json`` must already be
         present, so a typo creates a clear error rather than a stray
         orphan archive that ``aptl runs list`` cannot find).
      2. The active scenario session's ``run_id`` (when populated). A
         corrupt ``.aptl/session.json`` is non-fatal here — the audit
         should still repair iptables even if archive discovery fails.
         The session-derived id passes through the same shape +
         existence validation as the explicit override; if it fails,
         the audit degrades to "no archive" with a warning rather than
         failing loudly (the firewall repair is more important than
         archive discovery).
      3. ``(None, None)`` — audit runs but events are not persisted.

    Step 2 is currently never populated by ``ScenarioSession.start()``
    in production flows; the session-bound archival path lights up
    once #263/RTE-001 wires the runtime engine. Until then, the
    ``--run-id`` override is the supported path for archive emission.
    """
    from aptl.core.scenarios import ScenarioStateError
    from aptl.core.session import ScenarioSession

    if override:
        store = resolve_run_store(project_root, config)
        _validate_run_id_for_archive(store, override, source="--run-id")
        return store, override

    state_dir = project_root / ".aptl"
    try:
        session = ScenarioSession(state_dir).get_active()
    except ScenarioStateError as exc:
        log.warning(
            "Continuity audit: could not load session at %s (%s);"
            " events will not be archived.",
            state_dir, exc,
        )
        return None, None
    if session is None or not session.run_id:
        return None, None

    store = resolve_run_store(project_root, config)
    try:
        _validate_run_id_for_archive(
            store, session.run_id, source="session.run_id", strict=False,
        )
    except _RunIdValidationError as exc:
        log.warning(
            "Continuity audit: session.run_id=%r is not usable for archive"
            " (%s); events will not be archived.",
            session.run_id, exc,
        )
        return None, None
    return store, session.run_id


def _validate_run_id_for_archive(
    store, run_id: str, *, source: str, strict: bool = True,
) -> None:
    """Common validation for explicit and session-derived run ids.

    Checks both the run-id shape (rejects path-traversal) and that the
    run exists in the store (manifest.json present). When ``strict``
    is True, validation failures raise ``typer.Exit(2)`` with a CLI
    error message. When ``strict`` is False, failures raise
    ``_RunIdValidationError`` so the caller can degrade gracefully.
    """
    if not _SAFE_RUN_ID.match(run_id):
        msg = f"{source}={run_id!r} must match {_SAFE_RUN_ID.pattern!r}"
        if strict:
            typer.echo(f"error: {msg}", err=True)
            raise typer.Exit(code=2)
        raise _RunIdValidationError(msg)

    run_dir = store.get_run_path(run_id)
    manifest = run_dir / "manifest.json"
    if not manifest.exists():
        msg = (
            f"{source}={run_id!r} does not exist in the run store"
            f" ({run_dir} has no manifest.json)"
        )
        if strict:
            typer.echo(
                f"error: {msg}. Create the run first or omit"
                f" {source.split('=')[0]}.",
                err=True,
            )
            raise typer.Exit(code=2)
        raise _RunIdValidationError(msg)
