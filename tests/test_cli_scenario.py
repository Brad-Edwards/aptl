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


@pytest.mark.parametrize("subcommand", ["start", "stop"])
def test_aptl_scenario_start_stop_not_yet_wired_exit_2(
    tmp_path: Path, subcommand: str
) -> None:
    """``start``/``stop`` reserve exit code 2 + stderr message until
    the scenario engine lands. Pins the contract today so a regression
    that wires them to silently no-op fails this test."""
    args = ["scenario", subcommand]
    if subcommand == "start":
        args.append("techvault")
    args += ["--project-dir", str(tmp_path)]

    result = runner.invoke(app, args)

    assert result.exit_code == 2
    assert "not yet wired" in result.output


def test_sdl_suffix_constant_matches_aces_convention() -> None:
    """``.sdl.yaml`` matches the suffix the ACES examples use
    (``examples/scenarios/*.sdl.yaml``). A drift here would silently
    break discovery once we adopt the ACES naming end-to-end."""
    assert SDL_SUFFIX == ".sdl.yaml"
