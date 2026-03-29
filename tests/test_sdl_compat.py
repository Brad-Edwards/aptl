"""Tests for SDL backward compatibility with aptl.core.scenarios."""

from pathlib import Path

import pytest
import yaml


class TestImportCompatibility:
    """All names previously importable from scenarios continue to work."""

    def test_core_types(self):
        from aptl.core.scenarios import (
            ScenarioDefinition,
            ScenarioError,
            ScenarioNotFoundError,
            ScenarioStateError,
            ScenarioValidationError,
            ObserverError,
        )
        assert ScenarioDefinition is not None
        assert issubclass(ScenarioNotFoundError, ScenarioError)
        assert issubclass(ScenarioStateError, ScenarioError)

    def test_enums(self):
        from aptl.core.scenarios import (
            Difficulty,
            ScenarioMode,
            PreconditionType,
            ObjectiveType,
        )
        assert Difficulty.BEGINNER.value == "beginner"
        assert ScenarioMode.PURPLE.value == "purple"
        assert PreconditionType.EXEC.value == "exec"
        assert ObjectiveType.WAZUH_ALERT.value == "wazuh_alert"

    def test_models(self):
        from aptl.core.scenarios import (
            AttackStep,
            CommandOutputValidation,
            ContainerRequirements,
            ExpectedDetection,
            FileExistsValidation,
            Hint,
            MitreReference,
            Objective,
            ObjectiveSet,
            Precondition,
            ScenarioMetadata,
            ScoringConfig,
            TimeBonusConfig,
            WazuhAlertValidation,
        )
        # Verify they're constructible
        h = Hint(level=1, text="test", point_penalty=0)
        assert h.level == 1

    def test_functions(self):
        from aptl.core.scenarios import (
            find_scenarios,
            load_scenario,
            validate_scenario_containers,
        )
        assert callable(load_scenario)
        assert callable(find_scenarios)
        assert callable(validate_scenario_containers)


class TestScenarioDefinitionAlias:
    """ScenarioDefinition is a type alias for Scenario."""

    def test_alias_identity(self):
        from aptl.core.scenarios import ScenarioDefinition
        from aptl.core.sdl.scenario import Scenario
        assert ScenarioDefinition is Scenario

    def test_construct_via_alias(self):
        from aptl.core.scenarios import ScenarioDefinition
        s = ScenarioDefinition(
            metadata={
                "id": "test",
                "name": "Test",
                "description": "Desc",
                "difficulty": "beginner",
                "estimated_minutes": 10,
            },
            mode="red",
            containers={"required": ["kali"]},
            objectives={
                "red": [{"id": "obj", "description": "D", "type": "manual", "points": 10}],
                "blue": [],
            },
        )
        assert s.metadata.id == "test"


class TestLoadScenarioCompat:
    """load_scenario() works as a drop-in replacement."""

    @pytest.fixture
    def scenario_yaml(self, tmp_path):
        data = {
            "metadata": {
                "id": "compat-test",
                "name": "Compat",
                "description": "Compatibility test",
                "difficulty": "beginner",
                "estimated_minutes": 10,
            },
            "mode": "red",
            "containers": {"required": ["kali"]},
            "objectives": {
                "red": [{"id": "obj", "description": "D", "type": "manual", "points": 10}],
                "blue": [],
            },
        }
        path = tmp_path / "test.yaml"
        path.write_text(yaml.dump(data, default_flow_style=False))
        return path

    def test_load_scenario(self, scenario_yaml):
        from aptl.core.scenarios import load_scenario
        s = load_scenario(scenario_yaml)
        assert s.metadata.id == "compat-test"

    def test_load_missing_file(self):
        from aptl.core.scenarios import load_scenario
        with pytest.raises(FileNotFoundError):
            load_scenario(Path("/nonexistent/file.yaml"))

    def test_load_empty_file(self, tmp_path):
        from aptl.core.scenarios import ScenarioValidationError, load_scenario
        empty = tmp_path / "empty.yaml"
        empty.write_text("")
        with pytest.raises(ScenarioValidationError, match="empty"):
            load_scenario(empty)

    def test_load_invalid_yaml(self, tmp_path):
        from aptl.core.scenarios import ScenarioValidationError, load_scenario
        bad = tmp_path / "bad.yaml"
        bad.write_text(":::invalid")
        with pytest.raises(ScenarioValidationError):
            load_scenario(bad)


class TestFindScenariosCompat:
    def test_find_scenarios(self, tmp_path):
        from aptl.core.scenarios import find_scenarios
        (tmp_path / "a.yaml").touch()
        (tmp_path / "b.yaml").touch()
        (tmp_path / "c.txt").touch()
        paths = find_scenarios(tmp_path)
        assert len(paths) == 2

    def test_find_scenarios_missing_dir(self, tmp_path):
        from aptl.core.scenarios import find_scenarios
        paths = find_scenarios(tmp_path / "nonexistent")
        assert paths == []
