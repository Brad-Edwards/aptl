"""Ephemeral lifecycle policy enforcement (DEP-003).

A control-plane decision layer *above* the existing on-demand lifecycle
(`orchestrate_lab_start` / `stop_lab` / `clean_boot_lab`, RNG-001). It does
not reimplement Docker, SSH, or config parsing — it reads the declarative
``lifecycle_policy`` from ``aptl.json`` and, on each enforcement tick, decides
whether to auto-teardown (TTL or idle) or provision (schedule) the single
project-scoped range, then acts through the same backend the manual commands
use (ADR-013/037).

Design (see ADR-045):

- **Single-shot, idempotent tick.** ``enforce_once`` performs exactly one
  evaluate-and-act cycle and returns; ``run_monitor`` is a thin loop over it.
  Cadence is owned by the operator (systemd timer / cron) — there is no
  long-lived daemon and the lab start path is not modified.
- **Pure core, thin shell.** ``evaluate_ttl`` / ``evaluate_idle`` /
  ``due_schedule_entries`` / ``decide`` are pure functions over timezone-aware
  UTC timestamps. The IO shell observes status, computes the activity signal,
  acts, and persists.
- **Single owner.** A ``flock`` on ``.aptl/lifecycle/.lock`` serializes ticks
  so a manual ``enforce`` and a running ``monitor`` cannot act concurrently.
- **Narrow, redacted state.** ``.aptl/lifecycle/state.json`` (mode 0600) holds
  only timestamps, the last action/result, a redacted error label, and the
  fired-schedule dates (ADR-029). Every value passes through :func:`redact`
  at the persist boundary.
"""

from __future__ import annotations

import fcntl
import json
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator, Optional

from aptl.core.config import (
    AptlConfig,
    LabLifecyclePolicyConfig,
    LifecycleScheduleEntry,
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
from aptl.core.runstore import resolve_active_run_dir
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

log = get_logger("lifecycle_policy")

_STATE_DIR = Path(".aptl") / "lifecycle"
_STATE_FILE = "state.json"
_LOCK_FILE = ".lock"
# Monday=0 .. Sunday=6, matching datetime.weekday().
_WEEKDAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


class LifecycleBusyError(RuntimeError):
    """Raised when another lifecycle owner already holds the project lock."""


@dataclass
class LifecycleState:
    """Persisted lifecycle state — narrow control-plane metadata only."""

    provisioned_at: Optional[str] = None
    last_action: str = "none"
    last_action_at: Optional[str] = None
    last_result: Optional[str] = None
    last_error_label: str = ""
    fired_schedules: dict[str, str] = field(default_factory=dict)


@dataclass
class LifecycleDecision:
    """The single action a tick resolved to."""

    action: str  # "none" | "teardown" | "provision"
    reason: str  # short, secret-free label
    policy: str = ""  # "ttl" | "idle" | "schedule" | ""
    scenario: Optional[str] = None
    schedule_key: Optional[str] = None


# ---------------------------------------------------------------------------
# Pure evaluators
# ---------------------------------------------------------------------------


def _minutes_between(later: datetime, earlier: datetime) -> float:
    return (later - earlier).total_seconds() / 60.0


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _to_utc(dt: datetime) -> datetime:
    """Normalize a datetime to UTC (treating a naive value as already UTC).

    Schedule times are an `HH:MM` UTC contract, so wall-clock comparisons,
    weekday filters, and fired-date bookkeeping must happen in UTC regardless
    of the timezone a caller's ``now`` carries.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def evaluate_ttl(
    policy: LabLifecyclePolicyConfig,
    provisioned_at: Optional[datetime],
    now: datetime,
) -> bool:
    """True when a TTL is set and the range has lived at least that long."""
    if policy.ttl_minutes is None or provisioned_at is None:
        return False
    return _minutes_between(now, provisioned_at) >= policy.ttl_minutes


def evaluate_idle(
    policy: LabLifecyclePolicyConfig,
    last_activity_at: Optional[datetime],
    now: datetime,
) -> bool:
    """True when an idle timeout is set and no activity within it."""
    if policy.idle_timeout_minutes is None or last_activity_at is None:
        return False
    return _minutes_between(now, last_activity_at) >= policy.idle_timeout_minutes


def schedule_entry_key(entry: LifecycleScheduleEntry) -> str:
    """Stable identity for a schedule entry (used to dedup per-day firing)."""
    return f"{entry.at}|{','.join(entry.days)}"


def _entry_due(
    entry: LifecycleScheduleEntry,
    state: LifecycleState,
    now: datetime,
    grace_minutes: float,
) -> bool:
    now = _to_utc(now)
    if entry.days and _WEEKDAY_NAMES[now.weekday()] not in entry.days:
        return False
    hour, minute = (int(p) for p in entry.at.split(":"))
    scheduled = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if now < scheduled or _minutes_between(now, scheduled) > grace_minutes:
        return False
    return state.fired_schedules.get(schedule_entry_key(entry)) != now.date().isoformat()


def due_schedule_entries(
    policy: LabLifecyclePolicyConfig,
    state: LifecycleState,
    now: datetime,
    grace_minutes: float,
) -> list[tuple[LifecycleScheduleEntry, str]]:
    """Schedule entries that should fire at ``now`` and have not fired today.

    An entry is due when ``now`` is on or after its time today (and within
    ``grace_minutes`` of it, so a tick hours late does not boot a stale
    window), its optional weekday filter matches, and it has not already
    fired on ``now``'s date.
    """
    return [
        (entry, schedule_entry_key(entry))
        for entry in policy.schedule
        if _entry_due(entry, state, now, grace_minutes)
    ]


def _decide_running(
    policy: LabLifecyclePolicyConfig,
    state: LifecycleState,
    now: datetime,
    last_activity_at: Optional[datetime],
) -> LifecycleDecision:
    if evaluate_ttl(policy, _parse_iso(state.provisioned_at), now):
        return LifecycleDecision("teardown", "ttl_exceeded", "ttl")
    if evaluate_idle(policy, last_activity_at, now):
        return LifecycleDecision("teardown", "idle_timeout", "idle")
    return LifecycleDecision("none", "running_within_policy")


def _decide_stopped(
    policy: LabLifecyclePolicyConfig,
    state: LifecycleState,
    now: datetime,
    grace_minutes: float,
) -> LifecycleDecision:
    due = due_schedule_entries(policy, state, now, grace_minutes)
    if not due:
        return LifecycleDecision("none", "stopped_no_schedule")
    entry, key = due[0]
    return LifecycleDecision(
        "provision", "scheduled", "schedule",
        scenario=entry.scenario, schedule_key=key,
    )


def decide(
    policy: LabLifecyclePolicyConfig,
    state: LifecycleState,
    now: datetime,
    running: bool,
    last_activity_at: Optional[datetime],
    grace_minutes: float,
) -> LifecycleDecision:
    """Resolve a tick to exactly one action.

    Running ranges are checked for TTL (first) then idle expiry; stopped
    ranges are checked for a due schedule entry. TTL takes precedence over
    idle because an expired range must go regardless of recent activity.
    """
    if running:
        return _decide_running(policy, state, now, last_activity_at)
    return _decide_stopped(policy, state, now, grace_minutes)


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------


def state_path(project_dir: Path) -> Path:
    return project_dir / _STATE_DIR / _STATE_FILE


def _read_state_file(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.warning("Unreadable lifecycle state at %s; starting fresh", path)
        return None
    return data if isinstance(data, dict) else None


def load_state(project_dir: Path) -> LifecycleState:
    """Load lifecycle state, returning a fresh default on absence/corruption."""
    data = _read_state_file(state_path(project_dir))
    if data is None:
        return LifecycleState()
    fired = data.get("fired_schedules")
    return LifecycleState(
        provisioned_at=data.get("provisioned_at"),
        last_action=data.get("last_action", "none"),
        last_action_at=data.get("last_action_at"),
        last_result=data.get("last_result"),
        last_error_label=data.get("last_error_label", ""),
        fired_schedules=fired if isinstance(fired, dict) else {},
    )


def save_state(project_dir: Path, state: LifecycleState) -> None:
    """Persist lifecycle state (mode 0600), redacted at the boundary."""
    path = state_path(project_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = redact(asdict(state))
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)


# ---------------------------------------------------------------------------
# Activity signal + single-owner lock
# ---------------------------------------------------------------------------


def _newest_mtime(directory: Optional[Path]) -> Optional[datetime]:
    if directory is None or not directory.exists():
        return None
    newest: Optional[float] = None
    for child in directory.rglob("*"):
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
    lock_path = project_dir / _STATE_DIR / _LOCK_FILE
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
# IO shell
# ---------------------------------------------------------------------------


def _load_policy(project_dir: Path) -> tuple[Optional[AptlConfig], Optional[LabLifecyclePolicyConfig]]:
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


def _diag(message: str) -> StartupDiagnostic:
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
    backend,
) -> LabResult:
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
    if not scenario:
        return None
    from aptl.core.scenario_catalog import resolve_scenario_selection

    return resolve_scenario_selection(project_dir, scenario_id=scenario)


def _apply_provision(
    project_dir: Path,
    state: LifecycleState,
    decision: LifecycleDecision,
    now: datetime,
    backend,
) -> LabResult:
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
    backend,
) -> LabResult:
    if decision.action == "teardown":
        return _apply_teardown(project_dir, policy, state, decision, now, backend)
    if decision.action == "provision":
        return _apply_provision(project_dir, state, decision, now, backend)
    return LabResult(success=True, message=f"lifecycle: no action ({decision.reason})")


def _enforce_locked(
    project_dir: Path,
    policy: LabLifecyclePolicyConfig,
    now: datetime,
    backend,
    grace_minutes: float,
) -> LabResult:
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


def enforce_once(
    project_dir: Path,
    *,
    now: Optional[datetime] = None,
    backend=None,
    grace_minutes: float = 60.0,
) -> LabResult:
    """Run exactly one lifecycle evaluate-and-act cycle.

    Idempotent: at most one action (teardown or provision) per tick. A no-op
    when no ``lifecycle_policy`` is configured. Raises
    :class:`LifecycleBusyError` when another owner holds the project lock.
    """
    now = _to_utc(now) if now is not None else datetime.now(timezone.utc)
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
    backend=None,
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
