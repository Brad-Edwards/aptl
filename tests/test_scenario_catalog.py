"""Tests for acquired-pack catalog selection and the explicit dev escape hatch."""

import builtins
import importlib
from pathlib import Path
import sys

import pytest


class ParserFailure(Exception):
    pass


def _write_scenario(project_dir: Path, name: str = "custom.sdl.yaml") -> Path:
    scenario = project_dir / "dev-scenarios" / name
    scenario.parent.mkdir(exist_ok=True)
    scenario.write_text("name: custom\n")
    return scenario


def _patch_parser(mocker, *, side_effect: Exception | None = None):
    parser = mocker.Mock(side_effect=side_effect)
    mocker.patch(
        "aptl.core.scenario_catalog._load_raes_sdl_parser",
        return_value=(ParserFailure, parser),
    )
    return parser


def test_import_does_not_require_raes_sdl(monkeypatch):
    sys.modules.pop("aptl.core.scenario_catalog", None)
    real_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "raes":
            raise ImportError("missing raes")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    module = importlib.import_module("aptl.core.scenario_catalog")
    assert not hasattr(module, "CATALOG_RELATIVE_PATH")


def test_catalog_id_selects_configured_acquired_pack(tmp_path):
    from aptl.core.scenario_catalog import resolve_scenario_selection

    assert resolve_scenario_selection(tmp_path, scenario_id="techvault") is None


def test_unknown_catalog_id_lists_only_configured_pack(tmp_path):
    from aptl.core.scenario_catalog import resolve_scenario_selection

    with pytest.raises(ValueError, match="Available scenarios: techvault"):
        resolve_scenario_selection(tmp_path, scenario_id="local-shadow")


def test_repository_catalog_projects_validated_pack_identity():
    from aptl.core.scenario_catalog import load_scenario_catalog

    project_root = Path(__file__).resolve().parents[1]
    catalog = load_scenario_catalog(project_root)

    assert [entry.id for entry in catalog.scenarios] == ["techvault"]
    assert catalog.pack_identity.pack_id == "techvault"
    assert catalog.pack_identity.pack_version == "0.1.0"
    assert catalog.pack_identity.set_digest.startswith("sha256:")
    assert catalog.maturity == "built"
    assert not hasattr(catalog.scenarios[0], "path")


def test_rejected_pack_fails_closed_without_local_fallback(mocker, tmp_path):
    from aptl.core.scenario_bundle import EnvPackError
    from aptl.core.scenario_catalog import load_scenario_catalog

    mocker.patch(
        "aptl.core.scenario_catalog.resolve_scenario_bundle",
        side_effect=EnvPackError("digest mismatch"),
    )

    with pytest.raises(ValueError, match="Acquired scenario catalog unavailable"):
        load_scenario_catalog(tmp_path)


def test_resolves_explicit_path_under_project(mocker, tmp_path):
    from aptl.core.scenario_catalog import resolve_scenario_selection

    selected = _write_scenario(tmp_path)
    parser = _patch_parser(mocker)
    resolved = resolve_scenario_selection(
        tmp_path, scenario_path=Path("dev-scenarios/custom.sdl.yaml")
    )
    assert resolved == selected.resolve()
    parser.assert_called_once_with(selected.resolve())


def test_rejects_explicit_path_outside_project(tmp_path):
    from aptl.core.scenario_catalog import resolve_scenario_selection

    with pytest.raises(ValueError, match="outside project"):
        resolve_scenario_selection(tmp_path, scenario_path=Path("../escape.sdl.yaml"))


def test_rejects_symlinked_explicit_path(tmp_path):
    from aptl.core.scenario_catalog import resolve_scenario_selection

    target = _write_scenario(tmp_path, "real.sdl.yaml")
    (target.parent / "link.sdl.yaml").symlink_to(target)
    with pytest.raises(ValueError, match="does not exist"):
        resolve_scenario_selection(
            tmp_path, scenario_path=Path("dev-scenarios/link.sdl.yaml")
        )


def test_rejects_raes_parser_failure(mocker, tmp_path):
    from aptl.core.scenario_catalog import resolve_scenario_selection

    _write_scenario(tmp_path)
    _patch_parser(mocker, side_effect=ParserFailure("bad sdl"))
    with pytest.raises(ValueError, match="RAES SDL"):
        resolve_scenario_selection(
            tmp_path, scenario_path=Path("dev-scenarios/custom.sdl.yaml")
        )


def test_rejects_selecting_both_id_and_path(tmp_path):
    from aptl.core.scenario_catalog import resolve_scenario_selection

    with pytest.raises(ValueError, match="mutually exclusive"):
        resolve_scenario_selection(
            tmp_path,
            scenario_id="techvault",
            scenario_path=Path("dev-scenarios/custom.sdl.yaml"),
        )


def test_resolve_acquired_scenario_returns_same_validated_bundle():
    from aptl.core.scenario_catalog import (
        load_scenario_catalog,
        resolve_acquired_scenario,
    )

    project_root = Path(__file__).resolve().parents[1]
    catalog = load_scenario_catalog(project_root)
    resolved = resolve_acquired_scenario(project_root, "techvault", catalog=catalog)

    assert resolved.entry.id == "techvault"
    assert resolved.scenario.name == "techvault"
    assert resolved.bundle is catalog.bundle


def test_resolve_acquired_scenario_unknown_id_is_not_found():
    from aptl.core.scenario_catalog import resolve_acquired_scenario
    from aptl.core.scenarios import ScenarioNotFoundError

    with pytest.raises(ScenarioNotFoundError):
        resolve_acquired_scenario(Path(__file__).resolve().parents[1], "nope")
