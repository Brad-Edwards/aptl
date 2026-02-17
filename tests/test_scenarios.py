"""Tests for scenario definition models, loading, and validation.

Tests exercise Pydantic model validation, YAML loading, file discovery,
and container requirement checking. All filesystem tests use tmp_path.
"""

import json
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError


# ---------------------------------------------------------------------------
# ScenarioMetadata validation
# ---------------------------------------------------------------------------


class TestScenarioMetadata:
    """Tests for the ScenarioMetadata Pydantic model."""

    def test_valid_minimal_metadata(self):
        """Metadata with required fields should parse successfully."""
        from aptl.core.scenarios import ScenarioMetadata

        meta = ScenarioMetadata(
            id="test-scan",
            name="Test Scan",
            description="A test scenario",
            difficulty="beginner",
            estimated_minutes=10,
        )
        assert meta.id == "test-scan"
        assert meta.name == "Test Scan"
        assert meta.version == "1.0.0"
        assert meta.author == ""
        assert meta.tags == []

    def test_valid_full_metadata(self):
        """Metadata with all optional fields should parse."""
        from aptl.core.scenarios import ScenarioMetadata

        meta = ScenarioMetadata(
            id="advanced-recon",
            name="Advanced Recon",
            description="An advanced scenario",
            version="2.0.0",
            author="APTL Team",
            difficulty="advanced",
            estimated_minutes=60,
            tags=["recon", "nmap"],
            mitre_attack={"tactics": ["TA0043"], "techniques": ["T1046"]},
        )
        assert meta.version == "2.0.0"
        assert meta.author == "APTL Team"
        assert meta.tags == ["recon", "nmap"]
        assert meta.mitre_attack.tactics == ["TA0043"]

    def test_rejects_invalid_id_with_uppercase(self):
        """Scenario ID must be lowercase slug."""
        from aptl.core.scenarios import ScenarioMetadata

        with pytest.raises(ValidationError, match="lowercase slug"):
            ScenarioMetadata(
                id="Test-Scan",
                name="Test",
                description="Desc",
                difficulty="beginner",
                estimated_minutes=10,
            )

    def test_rejects_invalid_id_with_spaces(self):
        """Scenario ID must not contain spaces."""
        from aptl.core.scenarios import ScenarioMetadata

        with pytest.raises(ValidationError, match="lowercase slug"):
            ScenarioMetadata(
                id="test scan",
                name="Test",
                description="Desc",
                difficulty="beginner",
                estimated_minutes=10,
            )

    def test_rejects_invalid_id_with_double_hyphens(self):
        """Scenario ID must not contain consecutive hyphens."""
        from aptl.core.scenarios import ScenarioMetadata

        with pytest.raises(ValidationError, match="lowercase slug"):
            ScenarioMetadata(
                id="test--scan",
                name="Test",
                description="Desc",
                difficulty="beginner",
                estimated_minutes=10,
            )

    def test_rejects_invalid_id_starting_with_hyphen(self):
        """Scenario ID must start with alphanumeric."""
        from aptl.core.scenarios import ScenarioMetadata

        with pytest.raises(ValidationError, match="lowercase slug"):
            ScenarioMetadata(
                id="-test-scan",
                name="Test",
                description="Desc",
                difficulty="beginner",
                estimated_minutes=10,
            )

    def test_rejects_empty_name(self):
        """Scenario name must not be empty."""
        from aptl.core.scenarios import ScenarioMetadata

        with pytest.raises(ValidationError, match="name"):
            ScenarioMetadata(
                id="test-scan",
                name="",
                description="Desc",
                difficulty="beginner",
                estimated_minutes=10,
            )

    def test_rejects_empty_description(self):
        """Scenario description must not be empty."""
        from aptl.core.scenarios import ScenarioMetadata

        with pytest.raises(ValidationError, match="description"):
            ScenarioMetadata(
                id="test-scan",
                name="Test",
                description="   ",
                difficulty="beginner",
                estimated_minutes=10,
            )

    def test_rejects_zero_estimated_minutes(self):
        """Estimated minutes must be greater than 0."""
        from aptl.core.scenarios import ScenarioMetadata

        with pytest.raises(ValidationError, match="estimated_minutes"):
            ScenarioMetadata(
                id="test-scan",
                name="Test",
                description="Desc",
                difficulty="beginner",
                estimated_minutes=0,
            )

    def test_rejects_estimated_minutes_over_480(self):
        """Estimated minutes must not exceed 480."""
        from aptl.core.scenarios import ScenarioMetadata

        with pytest.raises(ValidationError, match="estimated_minutes"):
            ScenarioMetadata(
                id="test-scan",
                name="Test",
                description="Desc",
                difficulty="beginner",
                estimated_minutes=481,
            )

    def test_rejects_invalid_difficulty(self):
        """Difficulty must be one of the enum values."""
        from aptl.core.scenarios import ScenarioMetadata

        with pytest.raises(ValidationError, match="difficulty"):
            ScenarioMetadata(
                id="test-scan",
                name="Test",
                description="Desc",
                difficulty="impossible",
                estimated_minutes=10,
            )

    def test_rejects_extra_fields(self):
        """Extra fields should be rejected (extra=forbid)."""
        from aptl.core.scenarios import ScenarioMetadata

        with pytest.raises(ValidationError, match="extra"):
            ScenarioMetadata(
                id="test-scan",
                name="Test",
                description="Desc",
                difficulty="beginner",
                estimated_minutes=10,
                unknown_field="value",
            )

    def test_single_char_id_is_valid(self):
        """A single character ID should be valid."""
        from aptl.core.scenarios import ScenarioMetadata

        meta = ScenarioMetadata(
            id="x",
            name="Test",
            description="Desc",
            difficulty="beginner",
            estimated_minutes=10,
        )
        assert meta.id == "x"


# ---------------------------------------------------------------------------
# Difficulty enum
# ---------------------------------------------------------------------------


class TestDifficulty:
    """Tests for the Difficulty enum."""

    def test_all_difficulty_levels(self):
        """All four difficulty levels should be available."""
        from aptl.core.scenarios import Difficulty

        assert Difficulty.BEGINNER == "beginner"
        assert Difficulty.INTERMEDIATE == "intermediate"
        assert Difficulty.ADVANCED == "advanced"
        assert Difficulty.EXPERT == "expert"


# ---------------------------------------------------------------------------
# Precondition validation
# ---------------------------------------------------------------------------


class TestPrecondition:
    """Tests for the Precondition model."""

    def test_valid_exec_precondition(self):
        """Exec precondition with command should be valid."""
        from aptl.core.scenarios import Precondition

        pre = Precondition(
            type="exec",
            container="victim",
            command="systemctl start apache2",
        )
        assert pre.command == "systemctl start apache2"

    def test_valid_file_precondition(self):
        """File precondition with path and content should be valid."""
        from aptl.core.scenarios import Precondition

        pre = Precondition(
            type="file",
            container="victim",
            path="/tmp/flag.txt",
            content="FLAG{test}",
        )
        assert pre.path == "/tmp/flag.txt"
        assert pre.content == "FLAG{test}"

    def test_exec_without_command_raises(self):
        """Exec precondition without command should fail validation."""
        from aptl.core.scenarios import Precondition

        with pytest.raises(ValidationError, match="command"):
            Precondition(type="exec", container="victim")

    def test_file_without_path_raises(self):
        """File precondition without path should fail validation."""
        from aptl.core.scenarios import Precondition

        with pytest.raises(ValidationError, match="path"):
            Precondition(type="file", container="victim", content="data")

    def test_file_without_content_raises(self):
        """File precondition without content should fail validation."""
        from aptl.core.scenarios import Precondition

        with pytest.raises(ValidationError, match="content"):
            Precondition(type="file", container="victim", path="/tmp/f.txt")

    def test_file_with_empty_string_content_is_valid(self):
        """File precondition with empty string content should be valid."""
        from aptl.core.scenarios import Precondition

        pre = Precondition(
            type="file",
            container="victim",
            path="/tmp/empty.txt",
            content="",
        )
        assert pre.content == ""


# ---------------------------------------------------------------------------
# ContainerRequirements validation
# ---------------------------------------------------------------------------


class TestContainerRequirements:
    """Tests for the ContainerRequirements model."""

    def test_valid_requirements(self):
        """Container requirements with at least one entry should be valid."""
        from aptl.core.scenarios import ContainerRequirements

        reqs = ContainerRequirements(required=["kali", "victim"])
        assert reqs.required == ["kali", "victim"]

    def test_rejects_empty_required_list(self):
        """Empty required list should fail validation."""
        from aptl.core.scenarios import ContainerRequirements

        with pytest.raises(ValidationError, match="at least one"):
            ContainerRequirements(required=[])


# ---------------------------------------------------------------------------
# Hint validation
# ---------------------------------------------------------------------------


class TestHint:
    """Tests for the Hint model."""

    def test_valid_hint(self):
        """A hint with level and text should be valid."""
        from aptl.core.scenarios import Hint

        hint = Hint(level=1, text="Use nmap", point_penalty=10)
        assert hint.level == 1
        assert hint.point_penalty == 10

    def test_rejects_level_zero(self):
        """Hint level must be >= 1."""
        from aptl.core.scenarios import Hint

        with pytest.raises(ValidationError, match="level"):
            Hint(level=0, text="Hint")

    def test_rejects_level_above_five(self):
        """Hint level must be <= 5."""
        from aptl.core.scenarios import Hint

        with pytest.raises(ValidationError, match="level"):
            Hint(level=6, text="Hint")

    def test_rejects_empty_text(self):
        """Hint text must not be empty."""
        from aptl.core.scenarios import Hint

        with pytest.raises(ValidationError, match="text"):
            Hint(level=1, text="")

    def test_rejects_negative_penalty(self):
        """Hint penalty must be >= 0."""
        from aptl.core.scenarios import Hint

        with pytest.raises(ValidationError, match="point_penalty"):
            Hint(level=1, text="Hint", point_penalty=-5)

    def test_default_penalty_is_zero(self):
        """Hint penalty defaults to 0."""
        from aptl.core.scenarios import Hint

        hint = Hint(level=1, text="Hint")
        assert hint.point_penalty == 0


# ---------------------------------------------------------------------------
# Objective validation
# ---------------------------------------------------------------------------


class TestObjective:
    """Tests for the Objective model."""

    def test_valid_manual_objective(self):
        """Manual objective without validation config should be valid."""
        from aptl.core.scenarios import Objective

        obj = Objective(
            id="test-obj",
            description="Do the thing",
            type="manual",
            points=100,
        )
        assert obj.type.value == "manual"
        assert obj.wazuh_alert is None

    def test_valid_wazuh_alert_objective(self):
        """Wazuh alert objective with validation config should be valid."""
        from aptl.core.scenarios import Objective

        obj = Objective(
            id="detect-scan",
            description="Detect the scan",
            type="wazuh_alert",
            points=75,
            wazuh_alert={
                "query": {"match_all": {}},
                "min_matches": 3,
                "time_window_seconds": 600,
            },
        )
        assert obj.wazuh_alert is not None
        assert obj.wazuh_alert.min_matches == 3

    def test_valid_command_output_objective(self):
        """Command output objective with validation config should be valid."""
        from aptl.core.scenarios import Objective

        obj = Objective(
            id="find-flag",
            description="Find the flag",
            type="command_output",
            points=50,
            command_output={
                "container": "kali",
                "command": "cat /tmp/flag.txt",
                "contains": ["FLAG{test}"],
            },
        )
        assert obj.command_output is not None
        assert obj.command_output.container == "kali"

    def test_valid_file_exists_objective(self):
        """File exists objective with validation config should be valid."""
        from aptl.core.scenarios import Objective

        obj = Objective(
            id="check-file",
            description="Check the file",
            type="file_exists",
            points=25,
            file_exists={
                "container": "victim",
                "path": "/tmp/result.txt",
            },
        )
        assert obj.file_exists is not None

    def test_wazuh_alert_without_validation_raises(self):
        """Wazuh alert objective without validation config should fail."""
        from aptl.core.scenarios import Objective

        with pytest.raises(ValidationError, match="wazuh_alert.*validation"):
            Objective(
                id="detect-scan",
                description="Detect the scan",
                type="wazuh_alert",
                points=75,
            )

    def test_command_output_without_validation_raises(self):
        """Command output objective without validation config should fail."""
        from aptl.core.scenarios import Objective

        with pytest.raises(ValidationError, match="command_output.*validation"):
            Objective(
                id="find-flag",
                description="Find the flag",
                type="command_output",
                points=50,
            )

    def test_file_exists_without_validation_raises(self):
        """File exists objective without validation config should fail."""
        from aptl.core.scenarios import Objective

        with pytest.raises(ValidationError, match="file_exists.*validation"):
            Objective(
                id="check-file",
                description="Check the file",
                type="file_exists",
                points=25,
            )

    def test_rejects_invalid_objective_id(self):
        """Objective ID must be a lowercase slug."""
        from aptl.core.scenarios import Objective

        with pytest.raises(ValidationError, match="lowercase slug"):
            Objective(
                id="Test_Obj",
                description="A test",
                type="manual",
                points=50,
            )

    def test_rejects_points_over_1000(self):
        """Objective points must be <= 1000."""
        from aptl.core.scenarios import Objective

        with pytest.raises(ValidationError, match="points"):
            Objective(
                id="test-obj",
                description="A test",
                type="manual",
                points=1001,
            )

    def test_rejects_negative_points(self):
        """Objective points must be >= 0."""
        from aptl.core.scenarios import Objective

        with pytest.raises(ValidationError, match="points"):
            Objective(
                id="test-obj",
                description="A test",
                type="manual",
                points=-10,
            )

    def test_rejects_duplicate_hint_levels(self):
        """Hint levels within an objective must be unique."""
        from aptl.core.scenarios import Objective

        with pytest.raises(ValidationError, match="unique"):
            Objective(
                id="test-obj",
                description="A test",
                type="manual",
                points=50,
                hints=[
                    {"level": 1, "text": "First hint"},
                    {"level": 1, "text": "Duplicate hint"},
                ],
            )

    def test_objective_with_ordered_hints(self):
        """Multiple hints with unique levels should be valid."""
        from aptl.core.scenarios import Objective

        obj = Objective(
            id="test-obj",
            description="A test",
            type="manual",
            points=50,
            hints=[
                {"level": 1, "text": "First hint"},
                {"level": 2, "text": "Second hint"},
                {"level": 3, "text": "Third hint"},
            ],
        )
        assert len(obj.hints) == 3


# ---------------------------------------------------------------------------
# ObjectiveSet validation
# ---------------------------------------------------------------------------


class TestObjectiveSet:
    """Tests for the ObjectiveSet model."""

    def test_valid_red_only(self):
        """ObjectiveSet with only red objectives should be valid."""
        from aptl.core.scenarios import ObjectiveSet

        obj_set = ObjectiveSet(
            red=[
                {"id": "obj-a", "description": "Do A", "type": "manual", "points": 50}
            ],
            blue=[],
        )
        assert len(obj_set.red) == 1
        assert len(obj_set.blue) == 0

    def test_valid_blue_only(self):
        """ObjectiveSet with only blue objectives should be valid."""
        from aptl.core.scenarios import ObjectiveSet

        obj_set = ObjectiveSet(
            red=[],
            blue=[
                {"id": "obj-b", "description": "Do B", "type": "manual", "points": 50}
            ],
        )
        assert len(obj_set.blue) == 1

    def test_valid_both_teams(self):
        """ObjectiveSet with both red and blue objectives should be valid."""
        from aptl.core.scenarios import ObjectiveSet

        obj_set = ObjectiveSet(
            red=[
                {"id": "obj-r", "description": "Red", "type": "manual", "points": 50}
            ],
            blue=[
                {"id": "obj-b", "description": "Blue", "type": "manual", "points": 50}
            ],
        )
        assert len(obj_set.all_objectives()) == 2

    def test_rejects_empty_both_teams(self):
        """ObjectiveSet with no objectives should fail validation."""
        from aptl.core.scenarios import ObjectiveSet

        with pytest.raises(ValidationError, match="at least one"):
            ObjectiveSet(red=[], blue=[])

    def test_rejects_duplicate_ids_across_teams(self):
        """Objective IDs must be unique across red and blue."""
        from aptl.core.scenarios import ObjectiveSet

        with pytest.raises(ValidationError, match="[Dd]uplicate"):
            ObjectiveSet(
                red=[
                    {"id": "same-id", "description": "Red", "type": "manual", "points": 50}
                ],
                blue=[
                    {"id": "same-id", "description": "Blue", "type": "manual", "points": 50}
                ],
            )


# ---------------------------------------------------------------------------
# ScoringConfig validation
# ---------------------------------------------------------------------------


class TestScoringConfig:
    """Tests for the ScoringConfig model."""

    def test_defaults(self):
        """Default scoring config should have time bonus disabled."""
        from aptl.core.scenarios import ScoringConfig

        config = ScoringConfig()
        assert config.time_bonus.enabled is False
        assert config.passing_score == 0
        assert config.max_score == 0

    def test_valid_time_bonus(self):
        """Time bonus config with valid values should parse."""
        from aptl.core.scenarios import ScoringConfig

        config = ScoringConfig(
            time_bonus={
                "enabled": True,
                "max_bonus": 50,
                "decay_after_minutes": 15,
            },
            passing_score=100,
            max_score=250,
        )
        assert config.time_bonus.enabled is True
        assert config.time_bonus.max_bonus == 50

    def test_rejects_negative_passing_score(self):
        """Passing score must be >= 0."""
        from aptl.core.scenarios import ScoringConfig

        with pytest.raises(ValidationError, match="passing_score"):
            ScoringConfig(passing_score=-1)


# ---------------------------------------------------------------------------
# ScenarioDefinition validation
# ---------------------------------------------------------------------------


class TestScenarioDefinition:
    """Tests for the full ScenarioDefinition model."""

    def test_valid_from_dict(self, sample_scenario_dict):
        """A valid scenario dict should parse into ScenarioDefinition."""
        from aptl.core.scenarios import ScenarioDefinition

        scenario = ScenarioDefinition(**sample_scenario_dict)
        assert scenario.metadata.id == "test-scenario"
        assert scenario.mode.value == "red"
        assert len(scenario.objectives.red) == 1

    def test_red_mode_requires_red_objectives(self):
        """Red mode scenario must have at least one red objective."""
        from aptl.core.scenarios import ScenarioDefinition

        with pytest.raises(ValidationError, match="[Rr]ed.*objectives"):
            ScenarioDefinition(
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
                    "red": [],
                    "blue": [
                        {"id": "obj-b", "description": "Blue", "type": "manual", "points": 50}
                    ],
                },
            )

    def test_blue_mode_requires_blue_objectives(self):
        """Blue mode scenario must have at least one blue objective."""
        from aptl.core.scenarios import ScenarioDefinition

        with pytest.raises(ValidationError, match="[Bb]lue.*objectives"):
            ScenarioDefinition(
                metadata={
                    "id": "test",
                    "name": "Test",
                    "description": "Desc",
                    "difficulty": "beginner",
                    "estimated_minutes": 10,
                },
                mode="blue",
                containers={"required": ["wazuh"]},
                objectives={
                    "red": [
                        {"id": "obj-r", "description": "Red", "type": "manual", "points": 50}
                    ],
                    "blue": [],
                },
            )

    def test_purple_mode_allows_either_team(self):
        """Purple mode scenario can have objectives from either team."""
        from aptl.core.scenarios import ScenarioDefinition

        scenario = ScenarioDefinition(
            metadata={
                "id": "test",
                "name": "Test",
                "description": "Desc",
                "difficulty": "beginner",
                "estimated_minutes": 10,
            },
            mode="purple",
            containers={"required": ["kali"]},
            objectives={
                "red": [
                    {"id": "obj-r", "description": "Red", "type": "manual", "points": 50}
                ],
                "blue": [],
            },
        )
        assert scenario.mode.value == "purple"

    def test_rejects_extra_top_level_fields(self):
        """Extra top-level fields should be rejected."""
        from aptl.core.scenarios import ScenarioDefinition

        with pytest.raises(ValidationError, match="extra"):
            ScenarioDefinition(
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
                    "red": [
                        {"id": "obj", "description": "Test", "type": "manual", "points": 50}
                    ],
                    "blue": [],
                },
                unknown_field="value",
            )

    def test_default_scoring_and_preconditions(self, sample_scenario_dict):
        """Scoring and preconditions should default to empty."""
        from aptl.core.scenarios import ScenarioDefinition

        scenario = ScenarioDefinition(**sample_scenario_dict)
        assert scenario.preconditions == []
        assert scenario.scoring.passing_score == 0


# ---------------------------------------------------------------------------
# Scenario loading (YAML)
# ---------------------------------------------------------------------------


class TestLoadScenario:
    """Tests for loading scenarios from YAML files."""

    def test_load_valid_yaml(self, sample_scenario_yaml):
        """Should load and parse a valid scenario YAML file."""
        from aptl.core.scenarios import load_scenario

        scenario = load_scenario(sample_scenario_yaml)
        assert scenario.metadata.id == "test-scenario"
        assert scenario.metadata.name == "Test Scenario"

    def test_load_nonexistent_file_raises(self, tmp_path):
        """Loading a missing file should raise FileNotFoundError."""
        from aptl.core.scenarios import load_scenario

        with pytest.raises(FileNotFoundError):
            load_scenario(tmp_path / "nonexistent.yaml")

    def test_load_empty_file_raises(self, tmp_path):
        """Loading an empty file should raise ScenarioValidationError."""
        from aptl.core.scenarios import ScenarioValidationError, load_scenario

        empty_file = tmp_path / "empty.yaml"
        empty_file.write_text("")
        with pytest.raises(ScenarioValidationError, match="empty"):
            load_scenario(empty_file)

    def test_load_invalid_yaml_raises(self, tmp_path):
        """Malformed YAML should raise ScenarioValidationError."""
        from aptl.core.scenarios import ScenarioValidationError, load_scenario

        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("{{not: valid: yaml: [}")
        with pytest.raises(ScenarioValidationError, match="[Ii]nvalid YAML"):
            load_scenario(bad_file)

    def test_load_yaml_scalar_raises(self, tmp_path):
        """A YAML file containing a scalar should raise ScenarioValidationError."""
        from aptl.core.scenarios import ScenarioValidationError, load_scenario

        scalar_file = tmp_path / "scalar.yaml"
        scalar_file.write_text("just a string")
        with pytest.raises(ScenarioValidationError, match="mapping"):
            load_scenario(scalar_file)

    def test_load_yaml_list_raises(self, tmp_path):
        """A YAML file containing a list should raise ScenarioValidationError."""
        from aptl.core.scenarios import ScenarioValidationError, load_scenario

        list_file = tmp_path / "list.yaml"
        list_file.write_text("- item1\n- item2\n")
        with pytest.raises(ScenarioValidationError, match="mapping"):
            load_scenario(list_file)

    def test_load_yaml_with_validation_error(self, tmp_path):
        """YAML that is valid but fails Pydantic validation should raise."""
        from aptl.core.scenarios import ScenarioValidationError, load_scenario

        bad_scenario = tmp_path / "bad-scenario.yaml"
        bad_scenario.write_text(yaml.dump({"metadata": {"id": "INVALID"}}))
        with pytest.raises(ScenarioValidationError):
            load_scenario(bad_scenario)

    def test_load_error_includes_file_path(self, tmp_path):
        """ScenarioValidationError should include the file path."""
        from aptl.core.scenarios import ScenarioValidationError, load_scenario

        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("")
        with pytest.raises(ScenarioValidationError) as exc_info:
            load_scenario(bad_file)
        assert exc_info.value.path == bad_file
        assert str(bad_file) in str(exc_info.value)

    def test_load_example_recon_scenario(self):
        """The bundled recon-nmap-scan.yaml example should load successfully."""
        from aptl.core.scenarios import load_scenario

        example = Path(__file__).parent.parent / "scenarios" / "recon-nmap-scan.yaml"
        if not example.exists():
            pytest.skip("Example scenario file not present")
        scenario = load_scenario(example)
        assert scenario.metadata.id == "recon-nmap-scan"
        assert scenario.mode.value == "red"
        assert len(scenario.objectives.red) == 3

    def test_load_example_brute_force_scenario(self):
        """The bundled detect-brute-force.yaml example should load successfully."""
        from aptl.core.scenarios import load_scenario

        example = Path(__file__).parent.parent / "scenarios" / "detect-brute-force.yaml"
        if not example.exists():
            pytest.skip("Example scenario file not present")
        scenario = load_scenario(example)
        assert scenario.metadata.id == "detect-brute-force"
        assert scenario.mode.value == "purple"
        assert len(scenario.objectives.red) == 1
        assert len(scenario.objectives.blue) == 2


# ---------------------------------------------------------------------------
# Scenario discovery
# ---------------------------------------------------------------------------


class TestFindScenarios:
    """Tests for discovering scenario files in a directory."""

    def test_finds_yaml_files(self, tmp_path, sample_scenario_dict):
        """Should find .yaml files in the given directory."""
        from aptl.core.scenarios import find_scenarios

        (tmp_path / "scenario-a.yaml").write_text(
            yaml.dump(sample_scenario_dict)
        )
        (tmp_path / "scenario-b.yaml").write_text(
            yaml.dump(sample_scenario_dict)
        )
        paths = find_scenarios(tmp_path)
        assert len(paths) == 2

    def test_returns_sorted_paths(self, tmp_path, sample_scenario_dict):
        """Found paths should be sorted alphabetically."""
        from aptl.core.scenarios import find_scenarios

        (tmp_path / "zzz.yaml").write_text(yaml.dump(sample_scenario_dict))
        (tmp_path / "aaa.yaml").write_text(yaml.dump(sample_scenario_dict))
        paths = find_scenarios(tmp_path)
        assert paths[0].name == "aaa.yaml"
        assert paths[1].name == "zzz.yaml"

    def test_ignores_non_yaml_files(self, tmp_path):
        """Should not return .json or .txt files."""
        from aptl.core.scenarios import find_scenarios

        (tmp_path / "config.json").write_text("{}")
        (tmp_path / "readme.txt").write_text("hello")
        paths = find_scenarios(tmp_path)
        assert len(paths) == 0

    def test_returns_empty_for_missing_directory(self, tmp_path):
        """Should return empty list if directory does not exist."""
        from aptl.core.scenarios import find_scenarios

        paths = find_scenarios(tmp_path / "nonexistent")
        assert paths == []

    def test_non_recursive(self, tmp_path, sample_scenario_dict):
        """Should not search subdirectories."""
        from aptl.core.scenarios import find_scenarios

        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "nested.yaml").write_text(yaml.dump(sample_scenario_dict))
        paths = find_scenarios(tmp_path)
        assert len(paths) == 0


# ---------------------------------------------------------------------------
# Container validation
# ---------------------------------------------------------------------------


class TestValidateScenarioContainers:
    """Tests for checking scenario container requirements against config."""

    def test_all_containers_enabled(self, sample_scenario_dict):
        """Should return empty list when all required containers are enabled."""
        from aptl.core.scenarios import (
            ScenarioDefinition,
            validate_scenario_containers,
        )
        from aptl.core.config import AptlConfig

        scenario = ScenarioDefinition(**sample_scenario_dict)
        config = AptlConfig(
            lab={"name": "test"},
            containers={"wazuh": True, "victim": True, "kali": True},
        )
        missing = validate_scenario_containers(scenario, config)
        assert missing == []

    def test_missing_containers(self, sample_scenario_dict):
        """Should return list of containers that are not enabled."""
        from aptl.core.scenarios import (
            ScenarioDefinition,
            validate_scenario_containers,
        )
        from aptl.core.config import AptlConfig

        scenario = ScenarioDefinition(**sample_scenario_dict)
        config = AptlConfig(
            lab={"name": "test"},
            containers={"wazuh": True, "victim": False, "kali": False},
        )
        missing = validate_scenario_containers(scenario, config)
        assert "kali" in missing
        assert "victim" in missing
        assert "wazuh" not in missing

    def test_missing_containers_sorted(self, sample_scenario_dict):
        """Missing container list should be sorted."""
        from aptl.core.scenarios import (
            ScenarioDefinition,
            validate_scenario_containers,
        )
        from aptl.core.config import AptlConfig

        scenario = ScenarioDefinition(**sample_scenario_dict)
        config = AptlConfig(
            lab={"name": "test"},
            containers={"wazuh": False, "victim": False, "kali": False},
        )
        missing = validate_scenario_containers(scenario, config)
        assert missing == sorted(missing)


# ---------------------------------------------------------------------------
# Exception classes
# ---------------------------------------------------------------------------


class TestExceptions:
    """Tests for the scenario exception hierarchy."""

    def test_scenario_not_found_error(self):
        """ScenarioNotFoundError should include the identifier."""
        from aptl.core.scenarios import ScenarioNotFoundError, ScenarioError

        err = ScenarioNotFoundError("my-scenario")
        assert err.identifier == "my-scenario"
        assert "my-scenario" in str(err)
        assert isinstance(err, ScenarioError)

    def test_scenario_validation_error_with_path(self, tmp_path):
        """ScenarioValidationError should include file path when provided."""
        from aptl.core.scenarios import ScenarioValidationError, ScenarioError

        path = tmp_path / "bad.yaml"
        err = ScenarioValidationError("bad field", path=path)
        assert err.path == path
        assert str(path) in str(err)
        assert "bad field" in err.details
        assert isinstance(err, ScenarioError)

    def test_scenario_validation_error_without_path(self):
        """ScenarioValidationError should work without a file path."""
        from aptl.core.scenarios import ScenarioValidationError

        err = ScenarioValidationError("something went wrong")
        assert err.path is None
        assert "something went wrong" in str(err)

    def test_scenario_state_error(self):
        """ScenarioStateError should be a ScenarioError."""
        from aptl.core.scenarios import ScenarioStateError, ScenarioError

        err = ScenarioStateError("not active")
        assert isinstance(err, ScenarioError)

    def test_observer_error(self):
        """ObserverError should be a ScenarioError."""
        from aptl.core.scenarios import ObserverError, ScenarioError

        err = ObserverError("connection failed")
        assert isinstance(err, ScenarioError)


# ---------------------------------------------------------------------------
# WazuhAlertValidation
# ---------------------------------------------------------------------------


class TestWazuhAlertValidation:
    """Tests for the WazuhAlertValidation model."""

    def test_valid_config(self):
        """Valid wazuh alert validation config should parse."""
        from aptl.core.scenarios import WazuhAlertValidation

        val = WazuhAlertValidation(
            query={"bool": {"must": [{"match": {"rule.groups": "auth"}}]}},
            min_matches=5,
            time_window_seconds=600,
        )
        assert val.min_matches == 5

    def test_defaults(self):
        """Defaults for min_matches and time_window_seconds."""
        from aptl.core.scenarios import WazuhAlertValidation

        val = WazuhAlertValidation(query={"match_all": {}})
        assert val.min_matches == 1
        assert val.time_window_seconds == 300

    def test_rejects_zero_min_matches(self):
        """min_matches must be >= 1."""
        from aptl.core.scenarios import WazuhAlertValidation

        with pytest.raises(ValidationError, match="min_matches"):
            WazuhAlertValidation(query={}, min_matches=0)

    def test_rejects_time_window_below_10(self):
        """time_window_seconds must be >= 10."""
        from aptl.core.scenarios import WazuhAlertValidation

        with pytest.raises(ValidationError, match="time_window"):
            WazuhAlertValidation(query={}, time_window_seconds=5)

    def test_rejects_time_window_above_3600(self):
        """time_window_seconds must be <= 3600."""
        from aptl.core.scenarios import WazuhAlertValidation

        with pytest.raises(ValidationError, match="time_window"):
            WazuhAlertValidation(query={}, time_window_seconds=7200)


# ---------------------------------------------------------------------------
# CommandOutputValidation
# ---------------------------------------------------------------------------


class TestCommandOutputValidation:
    """Tests for the CommandOutputValidation model."""

    def test_valid_with_contains(self):
        """Command output validation with contains list should parse."""
        from aptl.core.scenarios import CommandOutputValidation

        val = CommandOutputValidation(
            container="kali",
            command="cat /tmp/flag.txt",
            contains=["FLAG{test}"],
        )
        assert val.contains == ["FLAG{test}"]

    def test_valid_with_regex(self):
        """Command output validation with regex should parse."""
        from aptl.core.scenarios import CommandOutputValidation

        val = CommandOutputValidation(
            container="kali",
            command="nmap -sV target",
            regex=r"22/tcp\s+open\s+ssh",
        )
        assert val.regex is not None


# ---------------------------------------------------------------------------
# FileExistsValidation
# ---------------------------------------------------------------------------


class TestFileExistsValidation:
    """Tests for the FileExistsValidation model."""

    def test_valid_basic(self):
        """File exists validation with path should parse."""
        from aptl.core.scenarios import FileExistsValidation

        val = FileExistsValidation(container="victim", path="/tmp/result.txt")
        assert val.contains is None

    def test_valid_with_contains(self):
        """File exists validation with content check should parse."""
        from aptl.core.scenarios import FileExistsValidation

        val = FileExistsValidation(
            container="victim",
            path="/tmp/result.txt",
            contains="SUCCESS",
        )
        assert val.contains == "SUCCESS"
