"""Tests for the APTL Scenario Creation MCP Server."""

import pytest

from mcp_scenario.server import (
    get_cross_reference_rules,
    get_enum_values,
    get_example_scenario,
    get_section_reference,
    list_enum_types,
    list_example_scenarios,
    scaffold_scenario,
    validate_scenario,
    validate_section,
)
from mcp_scenario.examples import EXAMPLES


# ── validate_scenario ──────────────────────────────────────────────────


class TestValidateScenario:
    def test_valid_minimal(self):
        result = validate_scenario("name: test\n")
        assert result.startswith("VALID scenario: test")

    def test_valid_with_nodes(self):
        sdl = """\
name: test
nodes:
  net: {type: Switch}
  vm:
    type: VM
    os: linux
    resources: {ram: 2 GiB, cpu: 1}
infrastructure:
  net:
    count: 1
    properties: {cidr: 10.0.0.0/24, gateway: 10.0.0.1}
  vm:
    count: 1
    links: [net]
"""
        result = validate_scenario(sdl)
        assert "VALID" in result
        assert "nodes: 2 entries" in result
        assert "infrastructure: 2 entries" in result

    def test_invalid_yaml(self):
        result = validate_scenario("{{{{not yaml")
        assert "STRUCTURAL ERROR" in result

    def test_empty_input(self):
        result = validate_scenario("")
        assert "STRUCTURAL ERROR" in result
        assert "empty" in result.lower()

    def test_structural_error_bad_type(self):
        result = validate_scenario("name: test\nnodes:\n  n: {type: BadType}\n")
        assert "STRUCTURAL ERROR" in result

    def test_semantic_error_undefined_feature(self):
        sdl = """\
name: test
nodes:
  vm:
    type: VM
    features: {nonexistent: admin}
    roles:
      admin: root
"""
        result = validate_scenario(sdl)
        assert "SEMANTIC VALIDATION" in result
        assert "nonexistent" in result

    def test_semantic_error_cycle(self):
        sdl = """\
name: test
features:
  a: {type: Service, dependencies: [b]}
  b: {type: Service, dependencies: [a]}
"""
        result = validate_scenario(sdl)
        assert "cycle" in result.lower()

    def test_advisories_shown(self):
        sdl = """\
name: test
nodes:
  vm:
    type: VM
    os: linux
"""
        result = validate_scenario(sdl)
        assert "VALID" in result
        assert "Advisories" in result or "advisory" in result.lower()

    def test_all_examples_valid(self):
        """Every embedded example must pass full validation."""
        for name, ex in EXAMPLES.items():
            result = validate_scenario(ex["sdl"])
            assert result.startswith("VALID"), (
                f"Example '{name}' failed validation:\n{result}"
            )


# ── validate_section ───────────────────────────────────────────────────


class TestValidateSection:
    def test_valid_nodes(self):
        result = validate_section(
            "nodes",
            "net: {type: Switch}\nvm: {type: VM, os: linux, resources: {ram: 1 GiB, cpu: 1}}"
        )
        assert "structurally valid" in result

    def test_invalid_section_name(self):
        result = validate_section("bogus", "foo: bar")
        assert "Unknown section" in result

    def test_bad_yaml(self):
        result = validate_section("nodes", "{{bad")
        assert "YAML parse error" in result

    def test_structural_error(self):
        result = validate_section("nodes", "n: {type: BadValue}")
        assert "STRUCTURAL ERROR" in result

    def test_empty_section(self):
        result = validate_section("nodes", "")
        assert "empty" in result.lower() or "None" in result


# ── get_example_scenario ───────────────────────────────────────────────


class TestGetExampleScenario:
    def test_get_minimal(self):
        result = get_example_scenario("minimal")
        assert "name: minimal-scenario" in result

    def test_get_nonexistent(self):
        result = get_example_scenario("nonexistent")
        assert "not found" in result

    def test_all_examples_exist(self):
        for name in EXAMPLES:
            result = get_example_scenario(name)
            assert "not found" not in result


# ── list_example_scenarios ─────────────────────────────────────────────


class TestListExampleScenarios:
    def test_lists_all(self):
        result = list_example_scenarios()
        for name in EXAMPLES:
            assert name in result


# ── scaffold_scenario ──────────────────────────────────────────────────


class TestScaffoldScenario:
    def test_basic_scaffold(self):
        result = scaffold_scenario("my-test", "A test", ["nodes"])
        assert "name: my-test" in result
        assert "nodes:" in result
        # The workflows section scaffold should not appear
        assert "workflows:" not in result

    def test_full_scaffold(self):
        result = scaffold_scenario("full-test")
        assert "nodes:" in result
        assert "workflows:" in result
        assert "variables:" in result

    def test_invalid_section(self):
        result = scaffold_scenario("test", sections=["bogus"])
        assert "Unknown sections" in result


# ── get_section_reference ──────────────────────────────────────────────


class TestGetSectionReference:
    def test_known_section(self):
        result = get_section_reference("nodes")
        assert "nodes" in result.lower()
        assert "type: Switch" in result or "VM" in result

    def test_unknown_section(self):
        result = get_section_reference("bogus")
        assert "Unknown section" in result


# ── get_enum_values ────────────────────────────────────────────────────


class TestGetEnumValues:
    def test_node_type(self):
        result = get_enum_values("NodeType")
        assert "vm" in result
        assert "switch" in result

    def test_unknown_enum(self):
        result = get_enum_values("FakeEnum")
        assert "Unknown enum" in result


# ── list_enum_types ────────────────────────────────────────────────────


class TestListEnumTypes:
    def test_lists_all(self):
        result = list_enum_types()
        assert "NodeType" in result
        assert "RelationshipType" in result
        assert "VariableType" in result


# ── get_cross_reference_rules ──────────────────────────────────────────


class TestGetCrossReferenceRules:
    def test_returns_rules(self):
        result = get_cross_reference_rules()
        assert "Cross-Reference Rules" in result
        assert "must exist" in result.lower() or "must reference" in result.lower()


# ── SDL parser smoke tests ─────────────────────────────────────────────


class TestSDLParser:
    def test_shorthand_source(self):
        sdl = """\
name: test
features:
  f: {type: Service, source: my-pkg}
"""
        result = validate_scenario(sdl)
        assert "VALID" in result

    def test_shorthand_infrastructure(self):
        sdl = """\
name: test
nodes:
  net: {type: Switch}
  vm: {type: VM, os: linux, resources: {ram: 1 GiB, cpu: 1}}
infrastructure:
  net:
    count: 1
    properties: {cidr: 10.0.0.0/24, gateway: 10.0.0.1}
  vm: 1
"""
        # vm: 1 is shorthand for {count: 1}
        # but vm needs links to be valid — let's just test it parses
        result = validate_scenario(sdl)
        # It should parse structurally, might have semantic warnings
        assert "VALID" in result or "SEMANTIC" in result

    def test_variable_references(self):
        sdl = """\
name: test
variables:
  speed:
    type: number
    default: 1.0
nodes:
  net: {type: Switch}
infrastructure:
  net:
    count: 1
    properties: {cidr: 10.0.0.0/24, gateway: 10.0.0.1}
conditions:
  check:
    command: "true"
    interval: 10
events:
  ev:
    conditions: [check]
scripts:
  s:
    start-time: 0
    end-time: 1 hour
    speed: ${speed}
    events:
      ev: 30 min
stories:
  st:
    speed: ${speed}
    scripts: [s]
"""
        result = validate_scenario(sdl)
        assert "VALID" in result

    def test_duration_parsing(self):
        sdl = """\
name: test
nodes:
  net: {type: Switch}
infrastructure:
  net:
    count: 1
    properties: {cidr: 10.0.0.0/24, gateway: 10.0.0.1}
conditions:
  c:
    command: "true"
    interval: 10
events:
  e:
    conditions: [c]
scripts:
  s:
    start-time: 0
    end-time: 1 week 2 days 3 hours
    speed: 1.0
    events:
      e: 10min 30sec
"""
        result = validate_scenario(sdl)
        assert "VALID" in result
