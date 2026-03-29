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


class TestVerifyRelationships:
    def test_undefined_source(self):
        s = _make_scenario(
            nodes={"vm": {"type": "vm", "resources": {"ram": "1 gib", "cpu": 1}}},
            features={"svc": {"type": "service"}},
            relationships={"r1": {"type": "connects_to", "source": "ghost", "target": "svc"}},
        )
        errors = _validate(s)
        assert any("does not reference" in e for e in errors)

    def test_undefined_target(self):
        s = _make_scenario(
            nodes={"vm": {"type": "vm", "resources": {"ram": "1 gib", "cpu": 1}}},
            features={"svc": {"type": "service"}},
            relationships={"r1": {"type": "connects_to", "source": "svc", "target": "ghost"}},
        )
        errors = _validate(s)
        assert any("does not reference" in e for e in errors)

    def test_valid_relationship(self):
        s = _make_scenario(
            features={
                "exchange": {"type": "service"},
                "ad-ds": {"type": "service"},
            },
            relationships={
                "auth": {"type": "authenticates_with", "source": "exchange", "target": "ad-ds"},
            },
        )
        errors = _validate(s)
        assert not errors


class TestVerifyAgents:
    def test_undefined_entity(self):
        s = _make_scenario(
            nodes={"vm": {"type": "vm", "resources": {"ram": "1 gib", "cpu": 1}}},
            agents={"a1": {"entity": "ghost-team", "actions": ["scan"]}},
        )
        errors = _validate(s)
        assert any("undefined entity" in e for e in errors)

    def test_undefined_starting_account(self):
        s = _make_scenario(
            nodes={"vm": {"type": "vm", "resources": {"ram": "1 gib", "cpu": 1}}},
            entities={"red": {"role": "red"}},
            agents={"a1": {"entity": "red", "starting_accounts": ["ghost-acct"]}},
        )
        errors = _validate(s)
        assert any("not in accounts" in e for e in errors)

    def test_undefined_allowed_subnet(self):
        s = _make_scenario(
            nodes={"vm": {"type": "vm", "resources": {"ram": "1 gib", "cpu": 1}}},
            entities={"red": {"role": "red"}},
            agents={"a1": {"entity": "red", "allowed_subnets": ["ghost-net"]}},
        )
        errors = _validate(s)
        assert any("not in infrastructure" in e for e in errors)

    def test_undefined_initial_knowledge_host(self):
        s = _make_scenario(
            nodes={"vm": {"type": "vm", "resources": {"ram": "1 gib", "cpu": 1}}},
            entities={"red": {"role": "red"}},
            agents={"a1": {
                "entity": "red",
                "initial_knowledge": {"hosts": ["ghost-host"]},
            }},
        )
        errors = _validate(s)
        assert any("not in nodes" in e for e in errors)

    def test_undefined_initial_knowledge_service(self):
        s = _make_scenario(
            nodes={
                "vm": {
                    "type": "vm",
                    "resources": {"ram": "1 gib", "cpu": 1},
                    "services": [{"port": 22, "name": "ssh"}],
                }
            },
            entities={"red": {"role": "red"}},
            agents={"a1": {
                "entity": "red",
                "initial_knowledge": {"services": ["ghost-service"]},
            }},
        )
        errors = _validate(s)
        assert any("not in node service names" in e for e in errors)

    def test_undefined_initial_knowledge_account(self):
        s = _make_scenario(
            nodes={"vm": {"type": "vm", "resources": {"ram": "1 gib", "cpu": 1}}},
            entities={"red": {"role": "red"}},
            accounts={"known-user": {"username": "user", "node": "vm"}},
            agents={"a1": {
                "entity": "red",
                "initial_knowledge": {"accounts": ["ghost-account"]},
            }},
        )
        errors = _validate(s)
        assert any("initial_knowledge account" in e for e in errors)

    def test_valid_agent(self):
        s = _make_scenario(
            nodes={
                "vm": {
                    "type": "vm",
                    "resources": {"ram": "1 gib", "cpu": 1},
                    "services": [{"port": 22, "name": "ssh"}],
                },
                "net": {"type": "switch"},
            },
            infrastructure={"net": {"count": 1, "properties": {"cidr": "10.0.0.0/24", "gateway": "10.0.0.1"}}},
            entities={"red": {"role": "red"}},
            accounts={"hacker": {"username": "h4x", "node": "vm"}},
            agents={"a1": {
                "entity": "red",
                "actions": ["scan", "exploit"],
                "starting_accounts": ["hacker"],
                "allowed_subnets": ["net"],
                "initial_knowledge": {
                    "hosts": ["vm"],
                    "subnets": ["net"],
                    "services": ["ssh"],
                    "accounts": ["hacker"],
                },
            }},
        )
        errors = _validate(s)
        assert not errors


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
