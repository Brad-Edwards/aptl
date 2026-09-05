"""Regression tests for the ADR-035 scenario boundary."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class TestScenarioExceptions:
    """Shared exception types remain for session and continuity code."""

    def test_scenario_not_found_error(self):
        from aptl.core.scenarios import ScenarioError, ScenarioNotFoundError

        error = ScenarioNotFoundError("example")
        assert error.identifier == "example"
        assert isinstance(error, ScenarioError)

    def test_scenario_validation_error_without_path(self):
        from aptl.core.scenarios import ScenarioError, ScenarioValidationError

        error = ScenarioValidationError("bad field")
        assert error.path is None
        assert error.details == "bad field"
        assert isinstance(error, ScenarioError)


def test_local_scenario_loader_api_is_removed():
    """The deleted APTL-local loader must not survive as a runtime fallback."""
    import aptl.core.scenarios as scenarios

    assert not hasattr(scenarios, "load_scenario")
    assert not hasattr(scenarios, "find_scenarios")


def test_local_sdl_package_is_removed():
    """APTL must not expose its retired in-tree SDL parser package."""
    assert not list((PROJECT_ROOT / "src" / "aptl" / "core" / "sdl").glob("*.py"))
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("aptl.core.sdl.parser")


def test_startup_catalog_contains_only_acquired_pack_selectors():
    from aptl.core.scenario_catalog import load_scenario_catalog

    catalog = load_scenario_catalog(PROJECT_ROOT)

    assert [entry.id for entry in catalog.scenarios] == ["techvault"]
    assert catalog.pack_identity.pack_id == "techvault"
    assert not hasattr(catalog.scenarios[0], "path")


def test_repository_contains_no_scenario_content_tree():
    assert not (PROJECT_ROOT / "scenarios").exists()
