"""CLI tests for ``aptl lab init`` (DEP-008, issue #659).

Materialization is redirected at a small synthetic bundle so the command is
exercised end-to-end without copying the real scenario tree.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from aptl.cli.main import app
from aptl.core import assets

runner = CliRunner()


@pytest.fixture
def fake_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bundle = tmp_path / "pkg" / "_labdata"
    (bundle / "config").mkdir(parents=True)
    (bundle / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (bundle / "config" / "certs.yml").write_text("x: 1\n", encoding="utf-8")
    monkeypatch.setattr(assets, "resolve_asset_source", lambda: (bundle, True))
    return bundle


def test_lab_init_success(fake_bundle: Path, tmp_path: Path) -> None:
    target = tmp_path / "lab"
    result = runner.invoke(app, ["lab", "init", str(target)])

    assert result.exit_code == 0, result.output
    assert "Initialized lab project" in result.output
    assert "aptl lab start" in result.output
    assert (target / "docker-compose.yml").is_file()
    assert (target / "aptl.json").is_file()


def test_lab_init_conflict_without_force(fake_bundle: Path, tmp_path: Path) -> None:
    target = tmp_path / "lab"
    runner.invoke(app, ["lab", "init", str(target)])
    result = runner.invoke(app, ["lab", "init", str(target)])

    assert result.exit_code == 1
    assert "already contains lab assets" in result.output


def test_lab_init_force_overwrites(fake_bundle: Path, tmp_path: Path) -> None:
    target = tmp_path / "lab"
    runner.invoke(app, ["lab", "init", str(target)])
    result = runner.invoke(app, ["lab", "init", str(target), "--force"])

    assert result.exit_code == 0, result.output
    assert (target / "docker-compose.yml").is_file()
