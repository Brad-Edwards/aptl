"""Tests for curated ACES startup scenario catalog resolution."""

import builtins
import importlib
from pathlib import Path
import sys

import pytest


def _write_catalog(project_dir: Path, body: str) -> None:
    scenarios_dir = project_dir / "scenarios"
    scenarios_dir.mkdir(exist_ok=True)
    (scenarios_dir / "catalog.json").write_text(body)


def _write_scenario(project_dir: Path, name: str = "custom.sdl.yaml") -> Path:
    (project_dir / "scenarios").mkdir(exist_ok=True)
    scenario = project_dir / "scenarios" / name
    scenario.write_text("name: custom\n")
    return scenario


class ParserFailure(Exception):
    """Synthetic parser exception used to exercise lazy loading."""


def _patch_parser(mocker, *, side_effect: Exception | None = None):
    parser = mocker.Mock(side_effect=side_effect)
    mocker.patch(
        "aptl.core.scenario_catalog._load_aces_sdl_parser",
        return_value=(ParserFailure, parser),
    )
    return parser


def test_import_does_not_require_aces_sdl(monkeypatch):
    sys.modules.pop("aptl.core.scenario_catalog", None)

    real_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "aces_sdl":
            raise ImportError("missing aces_sdl")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)

    module = importlib.import_module("aptl.core.scenario_catalog")

    assert module.CATALOG_RELATIVE_PATH == Path("scenarios") / "catalog.json"


def test_loads_curated_catalog_entries(mocker, tmp_path):
    from aptl.core.scenario_catalog import load_scenario_catalog

    _write_catalog(
        tmp_path,
        """
version: 1
scenarios:
  - id: custom
    name: Custom ACES
    description: Curated cutover input.
    path: scenarios/custom.sdl.yaml
""",
    )

    catalog = load_scenario_catalog(tmp_path)

    assert [entry.id for entry in catalog.scenarios] == ["custom"]
    assert catalog.scenarios[0].path == "scenarios/custom.sdl.yaml"


def test_repository_catalog_includes_paper_agent_loop():
    from aptl.core.scenario_catalog import load_scenario_catalog

    project_root = Path(__file__).resolve().parents[1]
    catalog = load_scenario_catalog(project_root)
    entries = {entry.id: entry for entry in catalog.scenarios}

    assert entries["paper-agent-loop"].path == "scenarios/paper-agent-loop.sdl.yaml"
    assert (project_root / entries["paper-agent-loop"].path).exists()


def test_resolves_catalog_id_to_project_contained_sdl(mocker, tmp_path):
    from aptl.core.scenario_catalog import resolve_scenario_selection

    selected = _write_scenario(tmp_path)
    _write_catalog(
        tmp_path,
        """
version: 1
scenarios:
  - id: custom
    name: Custom ACES
    path: scenarios/custom.sdl.yaml
""",
    )
    parser = _patch_parser(mocker)

    resolved = resolve_scenario_selection(tmp_path, scenario_id="custom")

    assert resolved == selected.resolve()
    parser.assert_called_once_with(selected.resolve())


def test_resolves_explicit_path_under_project(mocker, tmp_path):
    from aptl.core.scenario_catalog import resolve_scenario_selection

    selected = _write_scenario(tmp_path)
    parser = _patch_parser(mocker)

    resolved = resolve_scenario_selection(
        tmp_path,
        scenario_path=Path("scenarios/custom.sdl.yaml"),
    )

    assert resolved == selected.resolve()
    parser.assert_called_once_with(selected.resolve())


def test_rejects_catalog_path_outside_project(tmp_path):
    from aptl.core.scenario_catalog import resolve_scenario_selection

    _write_catalog(
        tmp_path,
        """
version: 1
scenarios:
  - id: escape
    name: Escape
    path: ../outside.sdl.yaml
""",
    )

    with pytest.raises(ValueError, match="outside project"):
        resolve_scenario_selection(tmp_path, scenario_id="escape")


def test_rejects_missing_catalog_sdl(tmp_path):
    from aptl.core.scenario_catalog import resolve_scenario_selection

    _write_catalog(
        tmp_path,
        """
version: 1
scenarios:
  - id: missing
    name: Missing
    path: scenarios/missing.sdl.yaml
""",
    )

    with pytest.raises(ValueError, match="does not exist"):
        resolve_scenario_selection(tmp_path, scenario_id="missing")


def test_rejects_aces_parser_failure(mocker, tmp_path):
    from aptl.core.scenario_catalog import resolve_scenario_selection

    _write_scenario(tmp_path)
    _write_catalog(
        tmp_path,
        """
version: 1
scenarios:
  - id: custom
    name: Custom ACES
    path: scenarios/custom.sdl.yaml
""",
    )
    _patch_parser(mocker, side_effect=ParserFailure("bad sdl"))

    with pytest.raises(ValueError, match="ACES SDL"):
        resolve_scenario_selection(tmp_path, scenario_id="custom")


def test_rejects_missing_aces_parser_dependency(monkeypatch, tmp_path):
    from aptl.core.scenario_catalog import resolve_scenario_selection

    _write_scenario(tmp_path)

    real_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "aces_sdl":
            raise ImportError("missing aces_sdl")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)

    with pytest.raises(ValueError, match="ACES runtime handoff unavailable"):
        resolve_scenario_selection(
            tmp_path,
            scenario_path=Path("scenarios/custom.sdl.yaml"),
        )


def test_rejects_duplicate_catalog_ids(tmp_path):
    from aptl.core.scenario_catalog import load_scenario_catalog

    _write_catalog(
        tmp_path,
        """
version: 1
scenarios:
  - id: custom
    name: One
    path: scenarios/one.sdl.yaml
  - id: custom
    name: Two
    path: scenarios/two.sdl.yaml
""",
    )

    with pytest.raises(ValueError, match="duplicate"):
        load_scenario_catalog(tmp_path)


def test_rejects_selecting_both_id_and_path(tmp_path):
    from aptl.core.scenario_catalog import resolve_scenario_selection

    with pytest.raises(ValueError, match="mutually exclusive"):
        resolve_scenario_selection(
            tmp_path,
            scenario_id="custom",
            scenario_path=Path("scenarios/custom.sdl.yaml"),
        )
