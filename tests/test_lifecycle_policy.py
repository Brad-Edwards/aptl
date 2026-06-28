"""Tests for DEP-003 ephemeral lifecycle policy.

The pure evaluators (`evaluate_ttl`, `evaluate_idle`, `due_schedule_entries`,
`decide`) take timezone-aware UTC datetimes and are deterministic — no clock,
no Docker, no filesystem. The IO shell (`load_state`/`save_state`,
`enforce_once`, `run_monitor`) is exercised against a `tmp_path` project with
the lab functions monkeypatched, so the whole module runs in the fast
(non-integration) suite.
"""

import fcntl
import json
from datetime import datetime, timedelta, timezone

import pytest

from aptl.core import lifecycle_policy as lp
from aptl.core.config import (
    AptlConfig,
    LabLifecyclePolicyConfig,
    LifecycleScheduleEntry,
    load_config,
)
from aptl.core.lab_types import LabResult, LabStatus, StartupOutcome


UTC = timezone.utc


def _now(year=2026, month=6, day=28, hour=12, minute=0):
    return datetime(year, month, day, hour, minute, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Config model validation
# ---------------------------------------------------------------------------


class TestLifecyclePolicyConfig:
    def test_valid_policy_loads(self, tmp_path):
        payload = {
            "lab": {"name": "aptl"},
            "lifecycle_policy": {
                "ttl_minutes": 240,
                "idle_timeout_minutes": 60,
                "teardown_remove_volumes": True,
                "schedule": [
                    {"at": "08:00", "days": ["mon", "Fri"], "scenario": "techvault"}
                ],
            },
        }
        path = tmp_path / "aptl.json"
        path.write_text(json.dumps(payload))
        config = load_config(path)
        assert config.lifecycle_policy is not None
        assert config.lifecycle_policy.ttl_minutes == 240
        # weekday filter is normalized to lowercase
        assert config.lifecycle_policy.schedule[0].days == ["mon", "fri"]

    def test_absent_policy_is_none(self):
        assert AptlConfig().lifecycle_policy is None

    @pytest.mark.parametrize("bad", [0, -5])
    def test_rejects_non_positive_ttl(self, bad):
        with pytest.raises(ValueError):
            LabLifecyclePolicyConfig(ttl_minutes=bad)

    def test_rejects_non_positive_idle(self):
        with pytest.raises(ValueError):
            LabLifecyclePolicyConfig(idle_timeout_minutes=0)

    @pytest.mark.parametrize("bad", ["24:00", "8:00", "08:60", "noon", "0800"])
    def test_rejects_bad_schedule_time(self, bad):
        with pytest.raises(ValueError):
            LifecycleScheduleEntry(at=bad)

    def test_rejects_bad_weekday(self):
        with pytest.raises(ValueError):
            LifecycleScheduleEntry(at="08:00", days=["funday"])

    def test_rejects_unknown_key(self):
        with pytest.raises(ValueError):
            LabLifecyclePolicyConfig(ttl_min=10)


# ---------------------------------------------------------------------------
# Pure evaluators
# ---------------------------------------------------------------------------


class TestEvaluateTtl:
    def test_no_ttl_never_expires(self):
        policy = LabLifecyclePolicyConfig()
        assert lp.evaluate_ttl(policy, _now(hour=0), _now(hour=23)) is False

    def test_unset_provisioned_at_never_expires(self):
        policy = LabLifecyclePolicyConfig(ttl_minutes=10)
        assert lp.evaluate_ttl(policy, None, _now()) is False

    def test_expires_at_or_after_ttl(self):
        policy = LabLifecyclePolicyConfig(ttl_minutes=60)
        provisioned = _now(hour=12)
        assert lp.evaluate_ttl(policy, provisioned, _now(hour=13)) is True
        # boundary: exactly ttl minutes elapsed
        assert lp.evaluate_ttl(
            policy, provisioned, provisioned + timedelta(minutes=60)
        ) is True

    def test_not_expired_within_ttl(self):
        policy = LabLifecyclePolicyConfig(ttl_minutes=60)
        provisioned = _now(hour=12)
        assert lp.evaluate_ttl(policy, provisioned, _now(hour=12, minute=59)) is False


class TestEvaluateIdle:
    def test_no_idle_never_triggers(self):
        policy = LabLifecyclePolicyConfig()
        assert lp.evaluate_idle(policy, _now(hour=0), _now(hour=23)) is False

    def test_idle_triggers_after_timeout(self):
        policy = LabLifecyclePolicyConfig(idle_timeout_minutes=30)
        last = _now(hour=12)
        assert lp.evaluate_idle(policy, last, _now(hour=12, minute=30)) is True
        assert lp.evaluate_idle(policy, last, _now(hour=12, minute=29)) is False

    def test_unset_activity_never_triggers(self):
        policy = LabLifecyclePolicyConfig(idle_timeout_minutes=30)
        assert lp.evaluate_idle(policy, None, _now()) is False


class TestDueScheduleEntries:
    def test_due_when_past_time_same_day_and_not_fired(self):
        entry = LifecycleScheduleEntry(at="08:00")
        policy = LabLifecyclePolicyConfig(schedule=[entry])
        state = lp.LifecycleState()
        due = lp.due_schedule_entries(policy, state, _now(hour=8, minute=10), 60)
        assert [k for _, k in due] == [lp.schedule_entry_key(entry)]

    def test_not_due_before_time(self):
        policy = LabLifecyclePolicyConfig(schedule=[LifecycleScheduleEntry(at="08:00")])
        due = lp.due_schedule_entries(policy, lp.LifecycleState(), _now(hour=7), 60)
        assert due == []

    def test_not_due_outside_grace_window(self):
        policy = LabLifecyclePolicyConfig(schedule=[LifecycleScheduleEntry(at="08:00")])
        # 23:00 is hours past the 08:00 window — do not boot late
        due = lp.due_schedule_entries(policy, lp.LifecycleState(), _now(hour=23), 60)
        assert due == []

    def test_not_due_when_already_fired_today(self):
        entry = LifecycleScheduleEntry(at="08:00")
        policy = LabLifecyclePolicyConfig(schedule=[entry])
        state = lp.LifecycleState(
            fired_schedules={lp.schedule_entry_key(entry): "2026-06-28"}
        )
        due = lp.due_schedule_entries(policy, state, _now(hour=8, minute=5), 60)
        assert due == []

    def test_weekday_filter_excludes_other_days(self):
        # 2026-06-28 is a Sunday
        entry = LifecycleScheduleEntry(at="08:00", days=["mon"])
        policy = LabLifecyclePolicyConfig(schedule=[entry])
        due = lp.due_schedule_entries(policy, lp.LifecycleState(), _now(hour=8), 60)
        assert due == []

    def test_schedule_is_evaluated_in_utc_not_host_local(self):
        # 08:05+02:00 is 06:05 UTC, which is BEFORE the 08:00 UTC window —
        # a non-UTC `now` must not fire the schedule two hours early.
        plus2 = timezone(timedelta(hours=2))
        entry = LifecycleScheduleEntry(at="08:00")
        policy = LabLifecyclePolicyConfig(schedule=[entry])
        now = datetime(2026, 6, 28, 8, 5, tzinfo=plus2)
        assert lp.due_schedule_entries(policy, lp.LifecycleState(), now, 60) == []

    def test_weekday_filter_includes_matching_day(self):
        # 2026-06-28 is a Sunday
        entry = LifecycleScheduleEntry(at="08:00", days=["sun"])
        policy = LabLifecyclePolicyConfig(schedule=[entry])
        due = lp.due_schedule_entries(policy, lp.LifecycleState(), _now(hour=8), 60)
        assert len(due) == 1


class TestDecide:
    def test_running_within_policy_is_noop(self):
        policy = LabLifecyclePolicyConfig(ttl_minutes=240, idle_timeout_minutes=60)
        state = lp.LifecycleState(provisioned_at=_now(hour=11, minute=30).isoformat())
        decision = lp.decide(policy, state, _now(hour=12), True, _now(hour=11, minute=45), 60)
        assert decision.action == "none"

    def test_running_ttl_exceeded_tears_down(self):
        policy = LabLifecyclePolicyConfig(ttl_minutes=60)
        state = lp.LifecycleState(provisioned_at=_now(hour=10).isoformat())
        decision = lp.decide(policy, state, _now(hour=12), True, _now(hour=12), 60)
        assert decision.action == "teardown"
        assert decision.policy == "ttl"

    def test_running_idle_exceeded_tears_down(self):
        policy = LabLifecyclePolicyConfig(idle_timeout_minutes=30)
        state = lp.LifecycleState(provisioned_at=_now(hour=11).isoformat())
        decision = lp.decide(policy, state, _now(hour=12), True, _now(hour=11), 60)
        assert decision.action == "teardown"
        assert decision.policy == "idle"

    def test_ttl_takes_precedence_over_idle(self):
        policy = LabLifecyclePolicyConfig(ttl_minutes=60, idle_timeout_minutes=30)
        state = lp.LifecycleState(provisioned_at=_now(hour=10).isoformat())
        decision = lp.decide(policy, state, _now(hour=12), True, _now(hour=10), 60)
        assert decision.policy == "ttl"

    def test_not_running_due_schedule_provisions(self):
        entry = LifecycleScheduleEntry(at="08:00", scenario="techvault")
        policy = LabLifecyclePolicyConfig(schedule=[entry])
        decision = lp.decide(policy, lp.LifecycleState(), _now(hour=8, minute=5), False, None, 60)
        assert decision.action == "provision"
        assert decision.scenario == "techvault"

    def test_not_running_no_schedule_is_noop(self):
        policy = LabLifecyclePolicyConfig(ttl_minutes=60)
        decision = lp.decide(policy, lp.LifecycleState(), _now(), False, None, 60)
        assert decision.action == "none"


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------


class TestState:
    def test_load_missing_returns_default(self, tmp_path):
        state = lp.load_state(tmp_path)
        assert state == lp.LifecycleState()

    def test_round_trip(self, tmp_path):
        state = lp.LifecycleState(
            provisioned_at=_now().isoformat(),
            last_action="provision",
            last_action_at=_now().isoformat(),
            last_result="ready",
            fired_schedules={"08:00|": "2026-06-28"},
        )
        lp.save_state(tmp_path, state)
        assert lp.load_state(tmp_path) == state

    def test_state_file_is_owner_only(self, tmp_path):
        lp.save_state(tmp_path, lp.LifecycleState())
        mode = lp.state_path(tmp_path).stat().st_mode & 0o777
        assert mode == 0o600

    def test_corrupt_state_starts_fresh(self, tmp_path):
        path = lp.state_path(tmp_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json")
        assert lp.load_state(tmp_path) == lp.LifecycleState()

    def test_error_label_is_redacted_on_save(self, tmp_path):
        state = lp.LifecycleState(last_error_label="boom password=hunter2 done")
        lp.save_state(tmp_path, state)
        raw = lp.state_path(tmp_path).read_text()
        assert "hunter2" not in raw
        assert "[REDACTED]" in raw


# ---------------------------------------------------------------------------
# enforce_once IO shell
# ---------------------------------------------------------------------------


def _write_policy_config(tmp_path, policy_dict):
    payload = {"lab": {"name": "aptl"}, "lifecycle_policy": policy_dict}
    (tmp_path / "aptl.json").write_text(json.dumps(payload))


class TestEnforceOnce:
    def test_no_policy_is_noop(self, tmp_path):
        (tmp_path / "aptl.json").write_text(json.dumps({"lab": {"name": "aptl"}}))
        result = lp.enforce_once(tmp_path)
        assert result.success is True

    def test_no_config_is_noop(self, tmp_path):
        result = lp.enforce_once(tmp_path)
        assert result.success is True

    def test_running_within_policy_takes_no_action(self, tmp_path, monkeypatch):
        _write_policy_config(tmp_path, {"ttl_minutes": 240})
        monkeypatch.setattr(lp, "lab_status", lambda **k: LabStatus(running=True))
        calls = []
        monkeypatch.setattr(lp, "stop_lab", lambda **k: calls.append("stop") or LabResult(success=True))
        result = lp.enforce_once(tmp_path, now=_now())
        assert calls == []
        assert result.success is True
        # first observation of a running lab stamps provisioned_at
        assert lp.load_state(tmp_path).provisioned_at is not None

    def test_ttl_expired_calls_stop_lab(self, tmp_path, monkeypatch):
        _write_policy_config(tmp_path, {"ttl_minutes": 60, "teardown_remove_volumes": True})
        # seed state with an old provisioned_at so TTL is already exceeded
        lp.save_state(tmp_path, lp.LifecycleState(provisioned_at=_now(hour=10).isoformat()))
        monkeypatch.setattr(lp, "lab_status", lambda **k: LabStatus(running=True))
        seen = {}
        def fake_stop(**kwargs):
            seen.update(kwargs)
            return LabResult(success=True)
        monkeypatch.setattr(lp, "stop_lab", fake_stop)
        result = lp.enforce_once(tmp_path, now=_now(hour=12))
        assert seen.get("remove_volumes") is True
        assert result.success is True
        state = lp.load_state(tmp_path)
        assert state.last_action == "teardown"
        assert state.provisioned_at is None

    def test_idle_expired_calls_stop_lab(self, tmp_path, monkeypatch):
        _write_policy_config(tmp_path, {"idle_timeout_minutes": 30})
        lp.save_state(tmp_path, lp.LifecycleState(provisioned_at=_now(hour=10).isoformat()))
        monkeypatch.setattr(lp, "lab_status", lambda **k: LabStatus(running=True))
        called = []
        monkeypatch.setattr(lp, "stop_lab", lambda **k: called.append(True) or LabResult(success=True))
        result = lp.enforce_once(tmp_path, now=_now(hour=12))
        assert called == [True]
        assert result.success is True
        state = lp.load_state(tmp_path)
        assert state.last_action == "teardown"
        assert state.provisioned_at is None

    def test_scheduled_provision_calls_clean_boot(self, tmp_path, monkeypatch):
        _write_policy_config(tmp_path, {"schedule": [{"at": "08:00"}]})
        monkeypatch.setattr(lp, "lab_status", lambda **k: LabStatus(running=False))
        booted = []
        monkeypatch.setattr(
            lp, "clean_boot_lab",
            lambda *a, **k: booted.append(True) or LabResult(success=True, outcome=StartupOutcome.READY),
        )
        result = lp.enforce_once(tmp_path, now=_now(hour=8, minute=5))
        assert booted == [True]
        assert result.success is True
        state = lp.load_state(tmp_path)
        assert state.last_action == "provision"
        assert state.provisioned_at is not None
        # fired-today guard recorded
        assert state.fired_schedules

    def test_failed_scheduled_provision_is_not_marked_fired(self, tmp_path, monkeypatch):
        # A failed provision must NOT consume the day's fire marker, so a
        # later tick inside the grace window retries it.
        _write_policy_config(tmp_path, {"schedule": [{"at": "08:00"}]})
        monkeypatch.setattr(lp, "lab_status", lambda **k: LabStatus(running=False))
        monkeypatch.setattr(
            lp, "clean_boot_lab",
            lambda *a, **k: LabResult(
                success=False, error="boom", outcome=StartupOutcome.FAILED
            ),
        )
        result = lp.enforce_once(tmp_path, now=_now(hour=8, minute=5))
        assert result.success is False
        state = lp.load_state(tmp_path)
        assert state.fired_schedules == {}
        assert state.provisioned_at is None

    def test_invalid_config_fails_the_tick(self, tmp_path):
        # A malformed lifecycle policy must surface as a FAILED tick, not a
        # silent no-op that hides a broken unattended timer.
        (tmp_path / "aptl.json").write_text(
            json.dumps({"lab": {"name": "aptl"}, "lifecycle_policy": {"ttl_minutes": 0}})
        )
        result = lp.enforce_once(tmp_path, now=_now())
        assert result.success is False
        assert result.outcome is StartupOutcome.FAILED

    def test_not_running_no_schedule_is_noop(self, tmp_path, monkeypatch):
        _write_policy_config(tmp_path, {"ttl_minutes": 60})
        # Seed a stale provisioned_at from a range that has since gone down.
        lp.save_state(tmp_path, lp.LifecycleState(provisioned_at=_now(hour=1).isoformat()))
        monkeypatch.setattr(lp, "lab_status", lambda **k: LabStatus(running=False))
        monkeypatch.setattr(lp, "clean_boot_lab", lambda *a, **k: pytest.fail("should not boot"))
        result = lp.enforce_once(tmp_path, now=_now())
        assert result.success is True
        # stale provisioned_at is cleared when the lab is observed down
        assert lp.load_state(tmp_path).provisioned_at is None

    def test_raises_busy_when_lock_held(self, tmp_path, monkeypatch):
        _write_policy_config(tmp_path, {"ttl_minutes": 60})
        monkeypatch.setattr(lp, "lab_status", lambda **k: LabStatus(running=False))
        lock_path = lp.state_path(tmp_path).parent / ".lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        holder = open(lock_path, "w")
        try:
            fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with pytest.raises(lp.LifecycleBusyError):
                lp.enforce_once(tmp_path, now=_now())
        finally:
            fcntl.flock(holder, fcntl.LOCK_UN)
            holder.close()


class TestLatestActivity:
    def test_run_capture_recency_beats_provisioned_at(self, tmp_path, monkeypatch):
        # Active run dir with a recent file should win over an old provisioned_at.
        active = tmp_path / ".aptl" / "runs" / "trace1"
        active.mkdir(parents=True)
        marker = active / "mcp-side" / "ocsf.jsonl"
        marker.parent.mkdir(parents=True)
        marker.write_text("{}")
        recent = _now(hour=12).timestamp()
        import os
        os.utime(marker, (recent, recent))
        monkeypatch.setattr(lp, "resolve_active_run_dir", lambda state_dir: active)
        state = lp.LifecycleState(provisioned_at=_now(hour=1).isoformat())
        latest = lp._latest_activity_at(tmp_path, state)
        assert latest is not None
        assert abs((latest - _now(hour=12)).total_seconds()) < 2


class TestRunMonitor:
    def test_runs_bounded_ticks_without_sleeping_after_last(self, tmp_path, monkeypatch):
        _write_policy_config(tmp_path, {"ttl_minutes": 60})
        monkeypatch.setattr(lp, "lab_status", lambda **k: LabStatus(running=False))
        sleeps = []
        results = lp.run_monitor(
            tmp_path, interval_seconds=5, max_ticks=3, sleep=lambda s: sleeps.append(s)
        )
        assert len(results) == 3
        # sleeps between ticks only (not after the final tick)
        assert sleeps == [5, 5]

    def test_no_policy_returns_empty(self, tmp_path):
        (tmp_path / "aptl.json").write_text(json.dumps({"lab": {"name": "aptl"}}))
        assert lp.run_monitor(tmp_path, interval_seconds=5, max_ticks=2) == []

    def test_invalid_config_yields_failed_result(self, tmp_path):
        (tmp_path / "aptl.json").write_text(
            json.dumps({"lab": {"name": "aptl"}, "lifecycle_policy": {"ttl_minutes": 0}})
        )
        results = lp.run_monitor(tmp_path, interval_seconds=1, max_ticks=3)
        assert len(results) == 1
        assert results[0].success is False
