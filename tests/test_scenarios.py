"""Tests for the SDL scenario loading boundary."""

import pytest


VALID_SDL = """
name: test-scenario
description: Minimal SDL scenario
"""


class TestLoadScenario:
    """Tests for loading SDL scenarios from YAML files."""

    def test_load_valid_sdl(self, tmp_path):
        from aptl.core.scenarios import load_scenario

        path = tmp_path / "scenario.yaml"
        path.write_text(VALID_SDL, encoding="utf-8")

        scenario = load_scenario(path)
        assert scenario.name == "test-scenario"
        assert scenario.description == "Minimal SDL scenario"

    def test_load_nonexistent_file_raises(self, tmp_path):
        from aptl.core.scenarios import load_scenario

        with pytest.raises(FileNotFoundError):
            load_scenario(tmp_path / "missing.yaml")

    def test_load_empty_file_raises_validation_error(self, tmp_path):
        from aptl.core.scenarios import ScenarioValidationError, load_scenario

        path = tmp_path / "empty.yaml"
        path.write_text("", encoding="utf-8")

        with pytest.raises(ScenarioValidationError, match="empty"):
            load_scenario(path)

    def test_load_invalid_yaml_raises_validation_error(self, tmp_path):
        from aptl.core.scenarios import ScenarioValidationError, load_scenario

        path = tmp_path / "broken.yaml"
        path.write_text("{{not: valid: yaml: [}", encoding="utf-8")

        with pytest.raises(ScenarioValidationError, match="Invalid YAML"):
            load_scenario(path)

    def test_load_legacy_yaml_is_rejected(self, tmp_path):
        from aptl.core.scenarios import ScenarioValidationError, load_scenario

        path = tmp_path / "legacy.yaml"
        path.write_text(
            """
metadata:
  id: old-scenario
  name: Old Scenario
mode: red
            """.strip(),
            encoding="utf-8",
        )

        with pytest.raises(ScenarioValidationError):
            load_scenario(path)

    def test_validation_error_includes_path(self, tmp_path):
        from aptl.core.scenarios import ScenarioValidationError, load_scenario

        path = tmp_path / "empty.yaml"
        path.write_text("", encoding="utf-8")

        with pytest.raises(ScenarioValidationError) as exc_info:
            load_scenario(path)

        assert exc_info.value.path == path
        assert str(path) in str(exc_info.value)


class TestFindScenarios:
    """Tests for SDL scenario discovery."""

    def test_finds_yaml_files(self, tmp_path):
        from aptl.core.scenarios import find_scenarios

        (tmp_path / "a.yaml").write_text(VALID_SDL, encoding="utf-8")
        (tmp_path / "b.yaml").write_text(VALID_SDL, encoding="utf-8")

        paths = find_scenarios(tmp_path)
        assert [path.name for path in paths] == ["a.yaml", "b.yaml"]

    def test_ignores_non_yaml_files(self, tmp_path):
        from aptl.core.scenarios import find_scenarios

        (tmp_path / "a.yml").write_text(VALID_SDL, encoding="utf-8")
        (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")

        assert find_scenarios(tmp_path) == []

    def test_returns_empty_for_missing_directory(self, tmp_path):
        from aptl.core.scenarios import find_scenarios

        assert find_scenarios(tmp_path / "missing") == []


class TestScenarioExceptions:
    """Tests for shared scenario exception types."""

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
