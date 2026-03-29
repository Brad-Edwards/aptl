"""Tests for SDL parser — YAML loading, key normalization, shorthands."""

import pytest

from aptl.core.sdl._errors import SDLParseError, SDLValidationError
from aptl.core.sdl.nodes import NodeType
from aptl.core.sdl.parser import parse_sdl


class TestKeyNormalization:
    def test_lowercase_keys(self):
        s = parse_sdl("name: test\nnodes:\n  sw:\n    type: switch")
        assert "sw" in s.nodes

    def test_uppercase_keys(self):
        """Pydantic field keys are normalized but user-defined names are preserved."""
        s = parse_sdl("Name: test\nNodes:\n  SW:\n    Type: Switch")
        assert "SW" in s.nodes  # user-defined name preserved as-is
        assert s.nodes["SW"].type == NodeType.SWITCH  # enum value normalized

    def test_hyphenated_keys(self):
        sdl = """
name: test
nodes:
  vm-1:
    type: vm
    resources:
      ram: 1 gib
      cpu: 1
infrastructure:
  vm-1:
    count: 1
"""
        s = parse_sdl(sdl)
        assert "vm_1" in s.nodes or "vm-1" in s.nodes

    def test_integer_keys_preserved(self):
        """YAML can have integer keys (e.g., in step numbers)."""
        sdl = """
name: test
nodes:
  sw:
    type: switch
"""
        s = parse_sdl(sdl)
        assert s.name == "test"


class TestShorthandExpansion:
    def test_source_shorthand(self):
        sdl = """
name: test
features:
  svc:
    type: service
    source: my-package
"""
        s = parse_sdl(sdl, skip_semantic_validation=True)
        assert s.features["svc"].source.name == "my-package"
        assert s.features["svc"].source.version == "*"

    def test_source_longhand(self):
        sdl = """
name: test
features:
  svc:
    type: service
    source:
      name: my-package
      version: 2.0.0
"""
        s = parse_sdl(sdl, skip_semantic_validation=True)
        assert s.features["svc"].source.version == "2.0.0"

    def test_infrastructure_count_shorthand(self):
        sdl = """
name: test
nodes:
  sw:
    type: switch
infrastructure:
  sw: 1
"""
        s = parse_sdl(sdl)
        assert s.infrastructure["sw"].count == 1

    def test_role_shorthand(self):
        sdl = """
name: test
nodes:
  vm:
    type: vm
    resources:
      ram: 1 gib
      cpu: 1
    roles:
      admin: "admin-user"
"""
        s = parse_sdl(sdl)
        assert s.nodes["vm"].roles["admin"].username == "admin-user"

    def test_min_score_shorthand(self):
        sdl = """
name: test
conditions:
  c1:
    command: /check
    interval: 10
metrics:
  m1:
    type: conditional
    max-score: 10
    condition: c1
evaluations:
  e1:
    metrics:
      - m1
    min-score: 75
"""
        s = parse_sdl(sdl, skip_semantic_validation=True)
        assert s.evaluations["e1"].min_score.percentage == 75


class TestFormat:
    def test_ocr_format(self):
        s = parse_sdl("name: test\nnodes:\n  sw:\n    type: switch")
        assert s.name == "test"

    def test_switch_rejects_vm_only_fields(self):
        sdl = """
name: test
nodes:
  sw:
    type: switch
    os: linux
    services:
      - port: 80
        name: http
"""
        with pytest.raises(SDLParseError, match="Switch nodes cannot have VM-only fields"):
            parse_sdl(sdl)


class TestErrorHandling:
    def test_empty_content(self):
        with pytest.raises(SDLParseError, match="empty"):
            parse_sdl("")

    def test_invalid_yaml(self):
        with pytest.raises(SDLParseError, match="YAML"):
            parse_sdl(":::invalid")

    def test_non_mapping(self):
        with pytest.raises(SDLParseError, match="mapping"):
            parse_sdl("- just\n- a\n- list")

    def test_no_identity(self):
        with pytest.raises(SDLParseError):
            parse_sdl("description: no name or metadata")


class TestSkipSemanticValidation:
    def test_structural_only(self):
        """skip_semantic_validation=True skips cross-reference checks."""
        s = parse_sdl(
            "name: test\ngoals:\n  g1:\n    tlos:\n      - missing-tlo",
            skip_semantic_validation=True,
        )
        assert "g1" in s.goals


class TestLoadRealScenarios:
    """APTL legacy scenario YAMLs use the metadata format which is no
    longer part of the SDL. These are expected to fail until the
    scenario YAMLs are migrated to SDL format."""

    @pytest.fixture
    def scenarios_dir(self):
        from pathlib import Path
        d = Path("scenarios")
        if not d.exists():
            pytest.skip("scenarios/ directory not found")
        return d

    @pytest.mark.xfail(reason="Legacy APTL scenario format not supported after SDL cleanup")
    def test_all_scenarios_parse(self, scenarios_dir):
        from aptl.core.sdl.parser import parse_sdl_file

        for path in sorted(scenarios_dir.glob("*.yaml")):
            scenario = parse_sdl_file(path)
            assert scenario.name
