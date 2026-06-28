"""Ephemeral lifecycle policy: model, pure evaluators, and state (DEP-003).

This module is the side-effect-free half of the lifecycle feature: the policy
decision model, the pure TTL/idle/schedule evaluators over timezone-aware UTC
timestamps, and the narrow persisted state. The enforcement runtime that
observes the lab and acts on a decision lives in
:mod:`aptl.core.lifecycle_enforce`.

See ADR-045 for the overall design (single-shot idempotent tick, UTC schedule
contract, capture-recency idle signal, single-owner lock, redacted state).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from aptl.core.config import LabLifecyclePolicyConfig, LifecycleScheduleEntry
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
    """The single action a tick resolved to.

    ``action`` is one of ``none`` / ``teardown`` / ``provision``; ``reason`` is
    a short, secret-free label; ``policy`` names the triggering policy
    (``ttl`` / ``idle`` / ``schedule`` / empty). ``scenario`` and
    ``schedule_key`` are populated only for a scheduled provision.
    """

    action: str
    reason: str
    policy: str = ""
    scenario: Optional[str] = None
    schedule_key: Optional[str] = None


# ---------------------------------------------------------------------------
# Pure evaluators
# ---------------------------------------------------------------------------


def _minutes_between(later: datetime, earlier: datetime) -> float:
    """Return the elapsed minutes from ``earlier`` to ``later``."""
    return (later - earlier).total_seconds() / 60.0


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp, returning None on absence or a bad value."""
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
    """True when a single schedule entry is due at ``now`` and not fired today."""
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
    """Resolve the action for a running range (TTL first, then idle)."""
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
    """Resolve the action for a stopped range (provision if a schedule is due)."""
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
    """Return the lifecycle state file path under the project's ``.aptl`` dir."""
    return project_dir / _STATE_DIR / _STATE_FILE


def _read_state_file(path: Path) -> Optional[dict[str, object]]:
    """Read and JSON-parse the state file, or None on absence/corruption."""
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
