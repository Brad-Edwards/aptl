"""Ephemeral lifecycle enforcement runtime (DEP-003).

The side-effecting half of the lifecycle feature: it observes the lab, computes
the activity signal, resolves a decision via the pure evaluators in
:mod:`aptl.core.lifecycle_policy`, acts through the existing deployment backend
(``lab_status`` / ``stop_lab`` / ``clean_boot_lab``), and persists narrow state.

``enforce_once`` is a single idempotent evaluate-and-act tick; ``run_monitor``
is a thin single-owner loop over it. See ADR-045.
"""

from __future__ import annotations

import fcntl
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from aptl.core.config import (
    AptlConfig,
    LabLifecyclePolicyConfig,
    find_config,
    load_config,
)
from aptl.core.lab import clean_boot_lab, lab_status, stop_lab
from aptl.core.lab_types import (
    DiagnosticImpact,
    DiagnosticSeverity,
    LabResult,
    StartupDiagnostic,
    StartupOutcome,
)
from aptl.core.lifecycle_policy import (
    LifecycleBusyError,
    LifecycleDecision,
    LifecycleState,
    _parse_iso,
    _to_utc,
    decide,
    load_state,
    save_state,
    state_path,
)
from aptl.core.runstore import resolve_active_run_dir
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

log = get_logger("lifecycle_enforce")


# ---------------------------------------------------------------------------
# Activity signal + single-owner lock
# ---------------------------------------------------------------------------


def _newest_mtime(directory: Optional[Path]) -> Optional[datetime]:
    """Return the newest file mtime (UTC) under ``directory``, or None."""
    if directory is None or not directory.exists():
        return None
    newest: Optional[float] = None
    for child in directory.rglob("*"):
        # The activity signal is when MCP servers last wrote evidence files;
        # directory mtimes track structural changes (entries added/removed) and
        # would otherwise report the run-dir creation time as fresh activity.
        if not child.is_file():
            continue
        try:
            mtime = child.stat().st_mtime
        except OSError:
            continue
        if newest is None or mtime > newest:
            newest = mtime
    return datetime.fromtimestamp(newest, tz=timezone.utc) if newest else None


def _latest_activity_at(project_dir: Path, state: LifecycleState) -> Optional[datetime]:
    """Newest of: provisioning time and most-recent capture under the active run.

    Capture recency under the active run directory is the narrow
    control-plane activity signal — when the red/blue MCP servers last wrote
    evidence. Falls back to provisioning time when no scenario is active.
    """
    candidates: list[datetime] = []
    provisioned = _parse_iso(state.provisioned_at)
    if provisioned is not None:
        candidates.append(provisioned)
    active = resolve_active_run_dir(project_dir / ".aptl")
    newest = _newest_mtime(active)
    if newest is not None:
        candidates.append(newest)
    return max(candidates) if candidates else None


@contextmanager
def _single_owner_lock(project_dir: Path) -> Iterator[None]:
    """Hold an exclusive non-blocking flock for the duration of a tick/loop.

    Raises :class:`LifecycleBusyError` when another owner already holds it.
    """
    lock_path = state_path(project_dir).parent / ".lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("w")
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise LifecycleBusyError(
                "another lifecycle owner is active (enforce/monitor lock held)"
            ) from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        handle.close()


# ---------------------------------------------------------------------------
# Policy resolution
# ---------------------------------------------------------------------------


def _load_policy(
    project_dir: Path,
) -> tuple[Optional[AptlConfig], Optional[LabLifecyclePolicyConfig]]:
    """Load the config and its lifecycle policy, or (None, None) with no config."""
    config_path = find_config(project_dir)
    if config_path is None:
        return None, None
    config = load_config(config_path)
    return config, config.lifecycle_policy


def _policy_or_failure(
    project_dir: Path,
) -> tuple[Optional[LabLifecyclePolicyConfig], Optional[LabResult]]:
    """Resolve the policy, or a FAILED result when ``aptl.json`` is malformed.

    A missing config (no ``aptl.json``) or an absent ``lifecycle_policy`` is a
    legitimate no-op. A config that is present but invalid must NOT read as a
    clean no-op — that would let a typo silently disable an unattended TTL or
    idle timer — so it surfaces as a failed tick the scheduler can detect.
    """
    try:
        _, policy = _load_policy(project_dir)
    except (OSError, ValueError) as exc:
        return None, LabResult(
            success=False,
            message="lifecycle: invalid configuration",
            error=redact(f"invalid aptl.json: {exc}"),
            outcome=StartupOutcome.FAILED,
        )
    return policy, None


# ---------------------------------------------------------------------------
# Action application
# ---------------------------------------------------------------------------


def _diag(message: str) -> StartupDiagnostic:
    """Build a cosmetic/info lifecycle diagnostic with a redaction-safe message."""
    return StartupDiagnostic(
        step="lifecycle_enforce",
        impact=DiagnosticImpact.COSMETIC,
        severity=DiagnosticSeverity.INFO,
        message=message,
    )


def _apply_teardown(
    project_dir: Path,
    policy: LabLifecyclePolicyConfig,
    state: LifecycleState,
    decision: LifecycleDecision,
    now: datetime,
    backend: Optional["DeploymentBackend"],
) -> LabResult:
    """Tear the range down via ``stop_lab`` and record the outcome in state."""
    log.info("Lifecycle teardown (%s)", decision.reason)
    result = stop_lab(
        remove_volumes=policy.teardown_remove_volumes,
        project_dir=project_dir,
        backend=backend,
    )
    state.last_action = "teardown"
    state.last_action_at = now.isoformat()
    state.last_result = result.outcome.value
    state.last_error_label = redact(result.error) if result.error else ""
    if result.success:
        state.provisioned_at = None
    return LabResult(
        success=result.success,
        message=f"lifecycle: teardown ({decision.reason})",
        error=result.error,
        outcome=result.outcome,
        diagnostics=[_diag(f"teardown triggered by {decision.policy} policy")],
    )


def _resolve_schedule_scenario(project_dir: Path, scenario: Optional[str]) -> Optional[Path]:
    """Resolve an optional schedule scenario id to its SDL path."""
    if not scenario:
        return None
    from aptl.core.scenario_catalog import resolve_scenario_selection

    return resolve_scenario_selection(project_dir, scenario_id=scenario)


def _apply_provision(
    project_dir: Path,
    state: LifecycleState,
    decision: LifecycleDecision,
    now: datetime,
    backend: Optional["DeploymentBackend"],
) -> LabResult:
    """Provision a clean range via ``clean_boot_lab`` and record the outcome."""
    log.info("Lifecycle scheduled provisioning (%s)", decision.schedule_key)
    scenario_path = _resolve_schedule_scenario(project_dir, decision.scenario)
    # Scheduled provisioning is an ephemeral clean boot: guarantee fresh state
    # regardless of any residue from a prior run (RNG-001).
    result = clean_boot_lab(
        project_dir,
        remove_volumes=True,
        scenario_path=scenario_path,
        backend=backend,
    )
    state.last_action = "provision"
    state.last_action_at = now.isoformat()
    state.last_result = result.outcome.value
    state.last_error_label = redact(result.error) if result.error else ""
    if result.success:
        state.provisioned_at = now.isoformat()
        # Only consume the day's fire marker on success, so a failed provision
        # (transient backend/Docker/readiness fault) is retried by a later tick
        # while the grace window is still open.
        if decision.schedule_key:
            state.fired_schedules[decision.schedule_key] = now.date().isoformat()
    result.message = f"lifecycle: provision ({decision.reason})"
    return result


def _apply_decision(
    project_dir: Path,
    policy: LabLifecyclePolicyConfig,
    state: LifecycleState,
    decision: LifecycleDecision,
    now: datetime,
    backend: Optional["DeploymentBackend"],
) -> LabResult:
    """Dispatch a resolved decision to the matching action (or a no-op)."""
    if decision.action == "teardown":
        return _apply_teardown(project_dir, policy, state, decision, now, backend)
    if decision.action == "provision":
        return _apply_provision(project_dir, state, decision, now, backend)
    return LabResult(success=True, message=f"lifecycle: no action ({decision.reason})")


def _enforce_locked(
    project_dir: Path,
    policy: LabLifecyclePolicyConfig,
    now: datetime,
    backend: Optional["DeploymentBackend"],
    grace_minutes: float,
) -> LabResult:
    """Run one evaluate-and-act tick assuming the owner lock is already held."""
    state = load_state(project_dir)
    status = lab_status(project_dir=project_dir, backend=backend)
    running = status.running
    # Reconcile provisioning time against observed reality so TTL/idle behave
    # identically whether the lab was started manually or by a prior tick.
    if running and not state.provisioned_at:
        state.provisioned_at = now.isoformat()
    elif not running and state.provisioned_at:
        state.provisioned_at = None
    last_activity = _latest_activity_at(project_dir, state)
    decision = decide(policy, state, now, running, last_activity, grace_minutes)
    result = _apply_decision(project_dir, policy, state, decision, now, backend)
    save_state(project_dir, state)
    return result


# ---------------------------------------------------------------------------
# Public entrypoints
# ---------------------------------------------------------------------------


def enforce_once(
    project_dir: Path,
    *,
    now: Optional[datetime] = None,
    backend: Optional["DeploymentBackend"] = None,
    grace_minutes: float = 60.0,
) -> LabResult:
    """Run exactly one lifecycle evaluate-and-act cycle.

    Idempotent: at most one action (teardown or provision) per tick. A no-op
    when no ``lifecycle_policy`` is configured, and a FAILED result when
    ``aptl.json`` is malformed. Raises :class:`LifecycleBusyError` when another
    owner holds the project lock.
    """
    now = datetime.now(timezone.utc) if now is None else _to_utc(now)
    policy, failure = _policy_or_failure(project_dir)
    if failure is not None:
        return failure
    if policy is None:
        return LabResult(
            success=True, message="lifecycle: no policy configured; nothing to enforce"
        )
    with _single_owner_lock(project_dir):
        return _enforce_locked(project_dir, policy, now, backend, grace_minutes)


def run_monitor(
    project_dir: Path,
    *,
    interval_seconds: float,
    max_ticks: Optional[int] = None,
    backend: Optional["DeploymentBackend"] = None,
    grace_minutes: float = 60.0,
    sleep: Callable[[float], None] = time.sleep,
) -> list[LabResult]:
    """Run ``enforce`` in a single-owner loop until ``max_ticks`` (or forever).

    Holds the project lock for the whole loop so a second monitor — or a
    one-shot ``enforce`` — cannot interleave. Each tick reloads the policy so
    edits to ``aptl.json`` take effect without a restart.
    """
    policy, failure = _policy_or_failure(project_dir)
    if failure is not None:
        return [failure]
    if policy is None:
        log.info("No lifecycle_policy configured; monitor has nothing to do")
        return []
    results: list[LabResult] = []
    with _single_owner_lock(project_dir):
        tick = 0
        while max_ticks is None or tick < max_ticks:
            policy, failure = _policy_or_failure(project_dir)
            if failure is not None:
                results.append(failure)
                break
            if policy is None:
                break
            now = datetime.now(timezone.utc)
            results.append(
                _enforce_locked(project_dir, policy, now, backend, grace_minutes)
            )
            tick += 1
            if max_ticks is not None and tick >= max_ticks:
                break
            sleep(interval_seconds)
    return results
