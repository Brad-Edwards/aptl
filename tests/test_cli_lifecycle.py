"""CLI tests for the DEP-003 lifecycle commands.

Wiring tests only — the lifecycle logic itself is covered by
``test_lifecycle_policy.py``. The core entrypoints (`enforce_once`,
`run_monitor`) are patched so no Docker or real lab is touched.
"""

import json

import pytest
from typer.testing import CliRunner

from aptl.cli.main import app
from aptl.core import lifecycle_enforce as le
from aptl.core.lab_types import LabResult, StartupOutcome


@pytest.fixture
def runner():
    return CliRunner()


def _write_config(tmp_path, lifecycle_policy=None):
    payload = {"lab": {"name": "aptl"}}
    if lifecycle_policy is not None:
        payload["lifecycle_policy"] = lifecycle_policy
    (tmp_path / "aptl.json").write_text(json.dumps(payload))


class TestEnforceCommand:
    def test_help(self, runner):
        result = runner.invoke(app, ["lab", "enforce", "--help"])
        assert result.exit_code == 0
        assert "idempotent" in result.stdout.lower()

    def test_success_prints_message(self, runner, monkeypatch):
        monkeypatch.setattr(
            le, "enforce_once",
            lambda *a, **k: LabResult(success=True, message="lifecycle: no action (x)"),
        )
        result = runner.invoke(app, ["lab", "enforce"])
        assert result.exit_code == 0
        assert "lifecycle: no action" in result.stdout

    def test_passes_grace_minutes(self, runner, monkeypatch):
        seen = {}

        def fake(project_dir, **kwargs):
            seen.update(kwargs)
            return LabResult(success=True, message="ok")

        monkeypatch.setattr(le, "enforce_once", fake)
        result = runner.invoke(app, ["lab", "enforce", "--grace-minutes", "15"])
        assert result.exit_code == 0
        assert seen["grace_minutes"] == 15

    def test_failure_exits_nonzero(self, runner, monkeypatch):
        monkeypatch.setattr(
            le, "enforce_once",
            lambda *a, **k: LabResult(
                success=False, message="lifecycle: teardown (ttl_exceeded)", error="boom"
            ),
        )
        result = runner.invoke(app, ["lab", "enforce"])
        assert result.exit_code == 1

    def test_busy_exits_nonzero(self, runner, monkeypatch):
        def raise_busy(*a, **k):
            raise le.LifecycleBusyError("locked")

        monkeypatch.setattr(le, "enforce_once", raise_busy)
        result = runner.invoke(app, ["lab", "enforce"])
        assert result.exit_code == 1
        assert "locked" in result.stdout + result.stderr


class TestMonitorCommand:
    def test_help(self, runner):
        result = runner.invoke(app, ["lab", "monitor", "--help"])
        assert result.exit_code == 0

    def test_wires_arguments(self, runner, monkeypatch):
        seen = {}

        def fake(project_dir, **kwargs):
            seen.update(kwargs)
            return [LabResult(success=True, message="tick")]

        monkeypatch.setattr(le, "run_monitor", fake)
        result = runner.invoke(
            app, ["lab", "monitor", "--interval", "30", "--max-ticks", "2"]
        )
        assert result.exit_code == 0
        assert seen["interval_seconds"] == 30
        assert seen["max_ticks"] == 2
        assert "tick" in result.stdout


class TestPolicyShowCommand:
    def test_no_policy(self, runner, tmp_path):
        _write_config(tmp_path)
        result = runner.invoke(
            app, ["lab", "policy", "show", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "No lifecycle_policy configured" in result.stdout

    def test_renders_policy_fields(self, runner, tmp_path):
        _write_config(
            tmp_path,
            {
                "ttl_minutes": 240,
                "schedule": [{"at": "08:00", "days": ["mon"], "scenario": "tv"}],
            },
        )
        result = runner.invoke(
            app, ["lab", "policy", "show", "--project-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "ttl_minutes: 240" in result.stdout
        assert "08:00 UTC [mon] scenario=tv" in result.stdout

    def test_json_output(self, runner, tmp_path):
        _write_config(tmp_path, {"ttl_minutes": 60})
        result = runner.invoke(
            app, ["lab", "policy", "show", "--project-dir", str(tmp_path), "--json"]
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["policy"]["ttl_minutes"] == 60
        assert payload["state"]["last_action"] == "none"
