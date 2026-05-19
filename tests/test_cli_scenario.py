"""Tests for ``aptl scenario`` CLI (#310 / SCN-010)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from aptl.cli.main import app
from aptl.cli.scenario import (
    _find_sdl_scenarios,
    _scenario_id_from_path,
    SDL_SUFFIX,
)

runner = CliRunner()


def test_find_sdl_scenarios_returns_only_dot_sdl_yaml(tmp_path: Path) -> None:
    """Discovery filters to ``*.sdl.yaml`` — plain ``*.yaml`` (legacy
    Pydantic scenarios) are intentionally excluded."""
    (tmp_path / "techvault.sdl.yaml").write_text("name: techvault")
    (tmp_path / "brute-force.sdl.yaml").write_text("name: brute")
    # Legacy Pydantic-style scenario; must NOT be picked up.
    (tmp_path / "legacy.yaml").write_text("metadata: {id: legacy}")
    # Unrelated file.
    (tmp_path / "README.md").write_text("docs")

    found = _find_sdl_scenarios(tmp_path)

    assert [p.name for p in found] == [
        "brute-force.sdl.yaml",
        "techvault.sdl.yaml",
    ]


def test_find_sdl_scenarios_returns_empty_for_missing_dir(tmp_path: Path) -> None:
    """A missing scenarios directory is not an error — just empty."""
    assert _find_sdl_scenarios(tmp_path / "nope") == []


def test_scenario_id_strips_double_suffix() -> None:
    """``Path.stem`` only strips one suffix; we strip the full
    ``.sdl.yaml`` so the user-visible id is just ``techvault``."""
    assert _scenario_id_from_path(Path("techvault.sdl.yaml")) == "techvault"
    assert _scenario_id_from_path(Path("nested/foo-bar.sdl.yaml")) == "foo-bar"


def test_aptl_scenario_list_prints_ids(tmp_path: Path) -> None:
    """``aptl scenario list`` prints one scenario id per line."""
    (tmp_path / "techvault.sdl.yaml").write_text("name: techvault")
    (tmp_path / "brute-force.sdl.yaml").write_text("name: brute")

    result = runner.invoke(
        app, ["scenario", "list", "--scenarios-dir", str(tmp_path)]
    )

    assert result.exit_code == 0
    lines = [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
    assert lines == ["brute-force", "techvault"]


def test_aptl_scenario_list_empty_exits_zero_with_message(
    tmp_path: Path,
) -> None:
    """No scenarios is not an error — exit 0 with a stderr note."""
    result = runner.invoke(
        app, ["scenario", "list", "--scenarios-dir", str(tmp_path / "absent")]
    )

    assert result.exit_code == 0
    # CliRunner mixes stderr into stdout via .output by default; use it.
    assert "No scenarios" in result.output


def test_aptl_scenario_start_missing_sdl_file_exit_1(tmp_path: Path) -> None:
    """``start <id>`` exits 1 with a clear message when the SDL file is
    absent — before touching the lab or session state."""
    result = runner.invoke(
        app,
        [
            "scenario", "start", "nope",
            "--project-dir", str(tmp_path),
            "--scenarios-dir", str(tmp_path),
        ],
    )
    assert result.exit_code == 1
    assert "nope" in result.output


def test_aptl_scenario_stop_no_active_scenario_exit_1(tmp_path: Path) -> None:
    """``stop`` exits 1 when no session file exists, BEFORE touching
    the lab. Prevents accidental docker-compose-down on a project that
    doesn't have an active scenario."""
    # Plausible aptl.json so config resolution doesn't fail first.
    (tmp_path / "aptl.json").write_text('{"deployment": {"provider": "docker-compose"}}')
    result = runner.invoke(
        app, ["scenario", "stop", "--project-dir", str(tmp_path)]
    )
    assert result.exit_code == 1
    assert "No active scenario" in result.output


def test_sdl_suffix_constant_matches_aces_convention() -> None:
    """``.sdl.yaml`` matches the suffix the ACES examples use
    (``examples/scenarios/*.sdl.yaml``). A drift here would silently
    break discovery once we adopt the ACES naming end-to-end."""
    assert SDL_SUFFIX == ".sdl.yaml"


def _minimal_sdl(name: str) -> str:
    """Two-node ACES SDL (Switch + VM) sufficient to drive a plan."""
    return f"""
name: {name}
description: Minimal SDL for the scenario CLI test
nodes:
  net0:
    type: Switch
    description: One segment
  victim:
    type: VM
    os: linux
    resources: {{ram: 1 gib, cpu: 1}}
    services:
      - {{port: 22, name: ssh}}
"""


def _project_with_config(tmp_path: Path) -> Path:
    """Drop a minimal valid aptl.json so config resolution succeeds."""
    (tmp_path / "aptl.json").write_text(
        '{"deployment": {"provider": "docker-compose"}}'
    )
    return tmp_path


def test_aptl_scenario_start_writes_session_on_apply_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A successful apply → session.start() writes session.json with the
    scenario id. Mock the DeploymentBackend so the test doesn't need
    Docker. The integration of SDL parse + RuntimeManager.plan + apply
    is real (aces-sdl is installed in the dev env)."""
    pytest.importorskip("aces_processor")

    project = _project_with_config(tmp_path)
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    (scenarios / "minimal.sdl.yaml").write_text(_minimal_sdl("minimal"))

    from unittest.mock import MagicMock
    from aptl.core.lab_types import LabResult, StartupOutcome

    mock_backend = MagicMock()
    mock_backend.start.return_value = LabResult(
        success=True, message="ok", outcome=StartupOutcome.READY
    )

    def fake_get_backend(_config, _project_dir):
        return mock_backend

    monkeypatch.setattr("aptl.cli.scenario.get_backend", fake_get_backend, raising=False)
    # The import in scenario.py is local; patch via the module the function
    # actually reads from.
    import aptl.cli.scenario as scenario_mod
    monkeypatch.setattr(scenario_mod, "get_backend", fake_get_backend, raising=False)
    monkeypatch.setattr(
        "aptl.core.deployment.get_backend", fake_get_backend, raising=False
    )

    result = runner.invoke(
        app,
        [
            "scenario", "start", "minimal",
            "--project-dir", str(project),
            "--scenarios-dir", str(scenarios),
        ],
    )

    if result.exit_code != 0:
        pytest.fail(f"start failed: rc={result.exit_code}\noutput:\n{result.output}")
    assert "Started scenario 'minimal'" in result.output

    session_file = project / ".aptl" / "session.json"
    assert session_file.exists()
    import json
    data = json.loads(session_file.read_text())
    assert data["scenario_id"] == "minimal"


def test_aptl_scenario_start_refuses_when_already_active(
    tmp_path: Path,
) -> None:
    """``start`` refuses when a session already exists — protects against
    accidentally double-applying a plan against a running lab."""
    project = _project_with_config(tmp_path)
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    (scenarios / "x.sdl.yaml").write_text(_minimal_sdl("x"))

    state_dir = project / ".aptl"
    state_dir.mkdir()
    (state_dir / "session.json").write_text(
        '{"scenario_id": "active-one", "state": "active", '
        '"started_at": "2026-05-19T00:00:00+00:00"}'
    )

    result = runner.invoke(
        app,
        [
            "scenario", "start", "x",
            "--project-dir", str(project),
            "--scenarios-dir", str(scenarios),
        ],
    )

    assert result.exit_code == 1
    assert "already active" in result.output


def test_aptl_scenario_stop_clears_session_on_backend_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A successful backend.stop → session.clear() removes session.json."""
    project = _project_with_config(tmp_path)
    state_dir = project / ".aptl"
    state_dir.mkdir()
    (state_dir / "session.json").write_text(
        '{"scenario_id": "minimal", "state": "active", '
        '"started_at": "2026-05-19T00:00:00+00:00"}'
    )

    from unittest.mock import MagicMock
    from aptl.core.lab_types import LabResult, StartupOutcome

    mock_backend = MagicMock()
    mock_backend.stop.return_value = LabResult(
        success=True, message="ok", outcome=StartupOutcome.READY
    )

    def fake_get_backend(_config, _project_dir):
        return mock_backend

    import aptl.cli.scenario as scenario_mod
    monkeypatch.setattr(scenario_mod, "get_backend", fake_get_backend, raising=False)
    monkeypatch.setattr(
        "aptl.core.deployment.get_backend", fake_get_backend, raising=False
    )

    result = runner.invoke(
        app, ["scenario", "stop", "--project-dir", str(project)]
    )

    if result.exit_code != 0:
        pytest.fail(f"stop failed: rc={result.exit_code}\noutput:\n{result.output}")
    assert "Scenario stopped" in result.output
    assert "minimal" in result.output
    assert not (state_dir / "session.json").exists()


def test_aptl_scenario_start_surfaces_apply_diagnostic_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When backend.start() reports failure, apply() returns
    ApplyResult(success=False) with diagnostics; the CLI prints each
    diagnostic on stderr and exits 1. session.json is NOT written."""
    pytest.importorskip("aces_processor")
    project = _project_with_config(tmp_path)
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    (scenarios / "x.sdl.yaml").write_text(_minimal_sdl("x"))

    from unittest.mock import MagicMock
    from aptl.core.lab_types import LabResult, StartupOutcome

    mock_backend = MagicMock()
    mock_backend.start.return_value = LabResult(
        success=False,
        error="container 'wazuh-manager' refused to start",
        outcome=StartupOutcome.FAILED,
    )

    def fake_get_backend(_config, _project_dir):
        return mock_backend

    import aptl.cli.scenario as scenario_mod
    monkeypatch.setattr(scenario_mod, "get_backend", fake_get_backend, raising=False)
    monkeypatch.setattr(
        "aptl.core.deployment.get_backend", fake_get_backend, raising=False
    )

    result = runner.invoke(
        app,
        [
            "scenario", "start", "x",
            "--project-dir", str(project),
            "--scenarios-dir", str(scenarios),
        ],
    )

    assert result.exit_code == 1
    assert "wazuh-manager" in result.output
    assert "aptl.lab-start-failed" in result.output
    assert not (project / ".aptl" / "session.json").exists()
