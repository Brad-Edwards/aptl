"""Tests for SDL semantic validation."""

import pytest

from aptl.core.sdl._errors import SDLValidationError
from aptl.core.sdl.scenario import Scenario
from aptl.core.sdl.validator import SemanticValidator


def _validate(scenario: Scenario) -> list[str]:
    """Run validation and return errors (empty list = valid)."""
    v = SemanticValidator(scenario)
    try:
        v.validate()
        return []
    except SDLValidationError as e:
        return e.errors


def _make_scenario(**kwargs) -> Scenario:
    """Build a minimal valid scenario with overrides."""
    defaults = {"name": "test-scenario"}
    defaults.update(kwargs)
    return Scenario(**defaults)


# ---------------------------------------------------------------------------
# OCR cross-reference validation
# ---------------------------------------------------------------------------


class TestVerifyNodes:
    def test_undefined_feature_reference(self):
        s = _make_scenario(
            nodes={
                "vm-1": {
                    "type": "vm",
                    "resources": {"ram": "1 gib", "cpu": 1},
                    "features": {"nonexistent": "admin"},
                    "roles": {"admin": {"username": "user"}},
                }
            },
        )
        errors = _validate(s)
        assert any("undefined feature" in e for e in errors)

    def test_undefined_vulnerability_on_node(self):
        s = _make_scenario(
            nodes={
                "vm-1": {
                    "type": "vm",
                    "resources": {"ram": "1 gib", "cpu": 1},
                    "vulnerabilities": ["nonexistent"],
                }
            },
        )
        errors = _validate(s)
        assert any("undefined vulnerability" in e for e in errors)

    def test_node_name_too_long(self):
        long_name = "a" * 36
        s = _make_scenario(
            nodes={
                long_name: {"type": "switch"},
            },
        )
        errors = _validate(s)
        assert any("35 characters" in e for e in errors)


class TestVerifyInfrastructure:
    def test_infra_without_matching_node(self):
        s = _make_scenario(
            infrastructure={"ghost": {"count": 1}},
        )
        errors = _validate(s)
        assert any("does not match" in e for e in errors)

    def test_link_to_undefined_infra(self):
        s = _make_scenario(
            nodes={"sw": {"type": "switch"}, "vm": {"type": "vm", "resources": {"ram": "1 gib", "cpu": 1}}},
            infrastructure={
                "sw": {"count": 1},
                "vm": {"count": 1, "links": ["nonexistent"]},
            },
        )
        errors = _validate(s)
        assert any("undefined" in e for e in errors)

    def test_switch_count_exceeds_one(self):
        s = _make_scenario(
            nodes={"sw": {"type": "switch"}},
            infrastructure={"sw": {"count": 2}},
        )
        errors = _validate(s)
        assert any("count > 1" in e for e in errors)


class TestVerifyFeatures:
    def test_feature_dependency_cycle(self):
        s = _make_scenario(
            features={
                "a": {"type": "service", "dependencies": ["b"]},
                "b": {"type": "service", "dependencies": ["a"]},
            },
        )
        errors = _validate(s)
        assert any("cycle" in e for e in errors)

    def test_feature_references_undefined_vuln(self):
        s = _make_scenario(
            features={
                "f": {"type": "service", "vulnerabilities": ["missing"]},
            },
        )
        errors = _validate(s)
        assert any("undefined vulnerability" in e for e in errors)

    def test_valid_feature_dependencies(self):
        s = _make_scenario(
            features={
                "a": {"type": "service"},
                "b": {"type": "configuration", "dependencies": ["a"]},
            },
        )
        errors = _validate(s)
        assert not errors


class TestVerifyMetrics:
    def test_conditional_metric_references_undefined_condition(self):
        s = _make_scenario(
            conditions={"c1": {"command": "/bin/check", "interval": 30}},
            metrics={
                "m1": {"type": "conditional", "max_score": 10, "condition": "missing"},
            },
        )
        errors = _validate(s)
        assert any("undefined condition" in e for e in errors)

    def test_duplicate_condition_reference(self):
        s = _make_scenario(
            conditions={"c1": {"command": "/bin/check", "interval": 30}},
            metrics={
                "m1": {"type": "conditional", "max_score": 10, "condition": "c1"},
                "m2": {"type": "conditional", "max_score": 10, "condition": "c1"},
            },
        )
        errors = _validate(s)
        assert any("multiple metrics" in e for e in errors)


class TestVerifyEvaluations:
    def test_references_undefined_metric(self):
        s = _make_scenario(
            evaluations={
                "e1": {"metrics": ["missing"], "min_score": {"percentage": 50}},
            },
        )
        errors = _validate(s)
        assert any("undefined metric" in e for e in errors)

    def test_absolute_min_score_exceeds_max(self):
        s = _make_scenario(
            conditions={"c1": {"command": "/check", "interval": 10}},
            metrics={"m1": {"type": "conditional", "max_score": 10, "condition": "c1"}},
            evaluations={
                "e1": {"metrics": ["m1"], "min_score": {"absolute": 100}},
            },
        )
        errors = _validate(s)
        assert any("exceeds" in e for e in errors)


class TestVerifyTLOs:
    def test_references_undefined_evaluation(self):
        s = _make_scenario(
            tlos={"t1": {"evaluation": "missing"}},
        )
        errors = _validate(s)
        assert any("undefined evaluation" in e for e in errors)


class TestVerifyGoals:
    def test_references_undefined_tlo(self):
        s = _make_scenario(
            goals={"g1": {"tlos": ["missing"]}},
        )
        errors = _validate(s)
        assert any("undefined TLO" in e for e in errors)


class TestVerifyEntities:
    def test_entity_references_undefined_tlo(self):
        s = _make_scenario(
            entities={"team": {"tlos": ["missing"]}},
        )
        errors = _validate(s)
        assert any("undefined TLO" in e for e in errors)


class TestVerifyInjects:
    def test_inject_references_undefined_entity(self):
        s = _make_scenario(
            entities={"red": {"role": "red"}},
            injects={
                "inj": {"from_entity": "red", "to_entities": ["missing"]},
            },
        )
        errors = _validate(s)
        assert any("not a defined entity" in e for e in errors)


class TestVerifyEvents:
    def test_event_references_undefined_condition(self):
        s = _make_scenario(
            events={"e1": {"conditions": ["missing"]}},
        )
        errors = _validate(s)
        assert any("undefined condition" in e for e in errors)


class TestVerifyScripts:
    def test_script_references_undefined_event(self):
        s = _make_scenario(
            scripts={
                "s1": {
                    "start_time": 0,
                    "end_time": 3600,
                    "speed": 1.0,
                    "events": {"missing": 600},
                }
            },
        )
        errors = _validate(s)
        assert any("undefined event" in e for e in errors)


class TestVerifyStories:
    def test_story_references_undefined_script(self):
        s = _make_scenario(
            stories={"st1": {"scripts": ["missing"]}},
        )
        errors = _validate(s)
        assert any("undefined script" in e for e in errors)


# ---------------------------------------------------------------------------
# APTL extension validation
# ---------------------------------------------------------------------------


class TestVerifyAttackSteps:
    def test_invalid_technique_id_format(self):
        s = _make_scenario(
            metadata={
                "id": "test",
                "name": "Test",
                "description": "Desc",
                "difficulty": "beginner",
                "estimated_minutes": 10,
            },
            mode="red",
            containers={"required": ["kali"]},
            objectives={"red": [{"id": "obj", "description": "D", "type": "manual", "points": 10}]},
            steps=[{
                "step_number": 1,
                "technique_id": "INVALID",
                "technique_name": "Test",
                "tactic": "Recon",
                "description": "Test",
                "target": "victim",
            }],
        )
        errors = _validate(s)
        assert any("ATT&CK format" in e for e in errors)


class TestVerifyMitreReferences:
    def test_invalid_technique_in_metadata(self):
        s = _make_scenario(
            metadata={
                "id": "test",
                "name": "Test",
                "description": "Desc",
                "difficulty": "beginner",
                "estimated_minutes": 10,
                "mitre_attack": {"techniques": ["INVALID"]},
            },
            mode="red",
            containers={"required": ["kali"]},
            objectives={"red": [{"id": "obj", "description": "D", "type": "manual", "points": 10}]},
        )
        errors = _validate(s)
        assert any("ATT&CK format" in e for e in errors)


class TestVerifyScenarioContent:
    def test_ocr_scenario_with_nodes_passes(self):
        """OCR-style scenario with just nodes is valid."""
        s = _make_scenario(
            nodes={"sw": {"type": "switch"}},
        )
        errors = _validate(s)
        assert not errors

    def test_empty_ocr_scenario_fails(self):
        """OCR-style scenario with no content fails."""
        s = _make_scenario()
        errors = _validate(s)
        assert any("at least one" in e.lower() for e in errors)


class TestErrorCollection:
    def test_multiple_errors_collected(self):
        """Validator collects all errors, not just the first."""
        s = _make_scenario(
            features={
                "f1": {"type": "service", "vulnerabilities": ["missing-1"]},
                "f2": {"type": "service", "vulnerabilities": ["missing-2"]},
            },
            goals={"g1": {"tlos": ["missing-tlo"]}},
        )
        errors = _validate(s)
        assert len(errors) >= 3


class TestVerifyContent:
    def test_content_targets_undefined_node(self):
        s = _make_scenario(
            nodes={"vm": {"type": "vm", "resources": {"ram": "1 gib", "cpu": 1}}},
            content={"data": {"type": "file", "target": "ghost-node", "path": "/tmp/x"}},
        )
        errors = _validate(s)
        assert any("undefined node" in e for e in errors)

    def test_valid_content_passes(self):
        s = _make_scenario(
            nodes={"vm": {"type": "vm", "resources": {"ram": "1 gib", "cpu": 1}}},
            content={"data": {"type": "file", "target": "vm", "path": "/tmp/flag"}},
        )
        errors = _validate(s)
        assert not errors


class TestVerifyAccounts:
    def test_account_references_undefined_node(self):
        s = _make_scenario(
            nodes={"vm": {"type": "vm", "resources": {"ram": "1 gib", "cpu": 1}}},
            accounts={"user": {"username": "admin", "node": "ghost-node"}},
        )
        errors = _validate(s)
        assert any("undefined node" in e for e in errors)

    def test_valid_account_passes(self):
        s = _make_scenario(
            nodes={"vm": {"type": "vm", "resources": {"ram": "1 gib", "cpu": 1}}},
            accounts={"user": {"username": "admin", "node": "vm"}},
        )
        errors = _validate(s)
        assert not errors


class TestVerifyACLs:
    def test_acl_references_undefined_network(self):
        s = _make_scenario(
            nodes={"sw": {"type": "switch"}},
            infrastructure={
                "sw": {
                    "count": 1,
                    "properties": {"cidr": "10.0.0.0/24", "gateway": "10.0.0.1"},
                    "acls": [{"direction": "in", "from_net": "ghost-net", "action": "deny"}],
                },
            },
        )
        errors = _validate(s)
        assert any("undefined network" in e for e in errors)


class TestFeatureListShorthand:
    def test_features_as_list_with_empty_role(self):
        """Nodes with features as list (no role) should validate."""
        from aptl.core.sdl import parse_sdl
        s = parse_sdl("""
name: shorthand-test
nodes:
  vm:
    type: VM
    resources: {ram: 1 gib, cpu: 1}
    features: [svc-a, svc-b]
features:
  svc-a: {type: Service, source: pkg-a}
  svc-b: {type: Service, source: pkg-b}
""")
        assert "svc-a" in s.nodes["vm"].features
        assert s.nodes["vm"].features["svc-a"] == ""


class TestValidFullScenario:
    def test_complete_ocr_scenario_validates(self):
        """A complete OCR-style scenario passes validation."""
        s = Scenario(
            name="full-test",
            nodes={
                "sw": {"type": "switch"},
                "vm": {
                    "type": "vm",
                    "resources": {"ram": "2 gib", "cpu": 1},
                    "features": {"svc": "admin"},
                    "conditions": {"check": "admin"},
                    "roles": {"admin": {"username": "user"}},
                },
            },
            infrastructure={
                "sw": {"count": 1, "properties": {"cidr": "10.0.0.0/24", "gateway": "10.0.0.1"}},
                "vm": {"count": 1, "links": ["sw"]},
            },
            features={"svc": {"type": "service", "source": {"name": "apache"}}},
            conditions={"check": {"command": "/bin/check", "interval": 30}},
            metrics={"m1": {"type": "conditional", "max_score": 10, "condition": "check"}},
            evaluations={"e1": {"metrics": ["m1"], "min_score": {"percentage": 50}}},
            tlos={"t1": {"evaluation": "e1"}},
            goals={"g1": {"tlos": ["t1"]}},
            entities={
                "blue": {"role": "blue", "tlos": ["t1"]},
            },
        )
        errors = _validate(s)
        assert not errors
