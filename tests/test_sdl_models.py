"""Tests for SDL structural models (Pydantic validation)."""

import pytest
from pydantic import ValidationError

from aptl.core.sdl._source import Source
from aptl.core.sdl.conditions import Condition
from aptl.core.sdl.entities import Entity, ExerciseRole, flatten_entities
from aptl.core.sdl.features import Feature, FeatureType
from aptl.core.sdl.infrastructure import InfraNode, SimpleProperties
from aptl.core.sdl.nodes import Node, NodeType, Resources, Role, parse_ram
from aptl.core.sdl.objectives import (
    Hint,
    Objective,
    ObjectiveSet,
    ObjectiveType,
    WazuhAlertValidation,
)
from aptl.core.sdl.orchestration import Event, Inject, Script, Story, parse_duration
from aptl.core.sdl.scoring import Evaluation, Goal, Metric, MetricType, MinScore, TLO
from aptl.core.sdl.vulnerabilities import Vulnerability


# ---------------------------------------------------------------------------
# Source
# ---------------------------------------------------------------------------


class TestSource:
    def test_basic(self):
        s = Source(name="pkg", version="1.0")
        assert s.name == "pkg"
        assert s.version == "1.0"

    def test_default_version(self):
        s = Source(name="pkg")
        assert s.version == "*"


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


class TestParseRam:
    def test_integer(self):
        assert parse_ram(4096) == 4096

    def test_gib_string(self):
        assert parse_ram("4 GiB") == 4 * 1073741824

    def test_mib_string(self):
        assert parse_ram("512 MiB") == 512 * 1048576

    def test_bare_digits(self):
        assert parse_ram("1024") == 1024

    def test_invalid_string(self):
        with pytest.raises(ValueError, match="Invalid RAM"):
            parse_ram("four gigabytes")


class TestResources:
    def test_human_readable_ram(self):
        r = Resources(ram="2 gib", cpu=2)
        assert r.ram == 2 * 1073741824

    def test_integer_ram(self):
        r = Resources(ram=1024, cpu=1)
        assert r.ram == 1024


class TestNode:
    def test_vm_node(self):
        n = Node(
            type="vm",
            source={"name": "ubuntu", "version": "22.04"},
            resources={"ram": "4 gib", "cpu": 2},
        )
        assert n.type == NodeType.VM

    def test_switch_node(self):
        n = Node(type="switch")
        assert n.type == NodeType.SWITCH

    def test_switch_rejects_source(self):
        with pytest.raises(ValidationError, match="Switch.*source"):
            Node(type="switch", source={"name": "pkg"})

    def test_switch_rejects_resources(self):
        with pytest.raises(ValidationError, match="Switch.*resources"):
            Node(type="switch", resources={"ram": "1 gib", "cpu": 1})


class TestRole:
    def test_basic_role(self):
        r = Role(username="admin")
        assert r.entities == []

    def test_role_with_entities(self):
        r = Role(username="user", entities=["blue-team.bob"])
        assert len(r.entities) == 1


# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------


class TestInfraNode:
    def test_defaults(self):
        n = InfraNode()
        assert n.count == 1
        assert n.links == []

    def test_with_count(self):
        n = InfraNode(count=3)
        assert n.count == 3

    def test_rejects_zero_count(self):
        with pytest.raises(ValidationError):
            InfraNode(count=0)

    def test_duplicate_links_rejected(self):
        with pytest.raises(ValidationError, match="unique"):
            InfraNode(links=["a", "a"])


class TestSimpleProperties:
    def test_valid(self):
        p = SimpleProperties(cidr="10.0.0.0/24", gateway="10.0.0.1")
        assert p.cidr == "10.0.0.0/24"

    def test_gateway_outside_cidr(self):
        with pytest.raises(ValidationError, match="not within CIDR"):
            SimpleProperties(cidr="10.0.0.0/24", gateway="192.168.1.1")

    def test_invalid_cidr(self):
        with pytest.raises(ValidationError):
            SimpleProperties(cidr="not-a-cidr", gateway="10.0.0.1")


# ---------------------------------------------------------------------------
# Features
# ---------------------------------------------------------------------------


class TestFeature:
    def test_service(self):
        f = Feature(type="service", source={"name": "apache"})
        assert f.type == FeatureType.SERVICE

    def test_with_dependencies(self):
        f = Feature(type="configuration", dependencies=["svc-a"])
        assert f.dependencies == ["svc-a"]


# ---------------------------------------------------------------------------
# Conditions
# ---------------------------------------------------------------------------


class TestCondition:
    def test_command_based(self):
        c = Condition(command="/usr/bin/check.sh", interval=30)
        assert c.command == "/usr/bin/check.sh"

    def test_source_based(self):
        c = Condition(source={"name": "checker-pkg"})
        assert c.source.name == "checker-pkg"

    def test_rejects_both(self):
        with pytest.raises(ValidationError, match="both"):
            Condition(command="/bin/check", interval=10, source={"name": "pkg"})

    def test_rejects_neither(self):
        with pytest.raises(ValidationError, match="must have"):
            Condition()

    def test_command_without_interval(self):
        with pytest.raises(ValidationError, match="interval"):
            Condition(command="/bin/check")


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------


class TestVulnerability:
    def test_valid(self):
        v = Vulnerability(
            name="SQLi", description="SQL injection", **{"class": "CWE-89"}
        )
        assert v.vuln_class == "CWE-89"

    def test_invalid_cwe(self):
        with pytest.raises(ValidationError, match="CWE"):
            Vulnerability(
                name="Test", description="Desc", **{"class": "INVALID"}
            )


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


class TestMetric:
    def test_manual(self):
        m = Metric(type="manual", max_score=10, artifact=True)
        assert m.type == MetricType.MANUAL

    def test_conditional(self):
        m = Metric(type="conditional", max_score=10, condition="cond-1")
        assert m.condition == "cond-1"

    def test_manual_rejects_condition(self):
        with pytest.raises(ValidationError, match="Manual.*condition"):
            Metric(type="manual", max_score=10, condition="cond-1")

    def test_conditional_requires_condition(self):
        with pytest.raises(ValidationError, match="requires.*condition"):
            Metric(type="conditional", max_score=10)


class TestMinScore:
    def test_percentage(self):
        ms = MinScore(percentage=75)
        assert ms.percentage == 75

    def test_absolute(self):
        ms = MinScore(absolute=50)
        assert ms.absolute == 50

    def test_rejects_both(self):
        with pytest.raises(ValidationError, match="both"):
            MinScore(absolute=50, percentage=75)

    def test_rejects_neither(self):
        with pytest.raises(ValidationError, match="either"):
            MinScore()


class TestEvaluation:
    def test_valid(self):
        e = Evaluation(
            metrics=["m-1"], min_score=MinScore(percentage=50)
        )
        assert len(e.metrics) == 1

    def test_empty_metrics_rejected(self):
        with pytest.raises(ValidationError):
            Evaluation(metrics=[], min_score=MinScore(percentage=50))


class TestTLO:
    def test_valid(self):
        t = TLO(evaluation="eval-1")
        assert t.evaluation == "eval-1"


class TestGoal:
    def test_valid(self):
        g = Goal(tlos=["tlo-1"])
        assert len(g.tlos) == 1


# ---------------------------------------------------------------------------
# Entities
# ---------------------------------------------------------------------------


class TestEntity:
    def test_basic(self):
        e = Entity(name="Team", role="blue")
        assert e.role == ExerciseRole.BLUE

    def test_nested_entities(self):
        e = Entity(
            name="Team",
            entities={"bob": Entity(name="Bob")},
        )
        assert "bob" in e.entities

    def test_flatten(self):
        entities = {
            "blue": Entity(
                name="Blue",
                entities={"bob": Entity(name="Bob")},
            ),
        }
        flat = flatten_entities(entities)
        assert "blue" in flat
        assert "blue.bob" in flat


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


class TestParseDuration:
    def test_integer(self):
        assert parse_duration(60) == 60

    def test_simple_string(self):
        assert parse_duration("10 min") == 600

    def test_compound(self):
        assert parse_duration("1h 30min") == 5400

    def test_zero(self):
        assert parse_duration("0") == 0

    def test_invalid(self):
        with pytest.raises(ValueError, match="Invalid duration"):
            parse_duration("not a duration")


class TestInject:
    def test_valid_pairing(self):
        i = Inject(from_entity="red", to_entities=["blue"])
        assert i.from_entity == "red"

    def test_rejects_partial_pairing(self):
        with pytest.raises(ValidationError, match="both"):
            Inject(from_entity="red")


class TestScript:
    def test_valid(self):
        s = Script(
            start_time="10 min",
            end_time="2 hour",
            speed=1.0,
            events={"evt-1": "30 min"},
        )
        assert s.start_time == 600
        assert s.end_time == 7200

    def test_end_before_start_rejected(self):
        with pytest.raises(ValidationError, match="end_time"):
            Script(
                start_time="2 hour",
                end_time="10 min",
                speed=1.0,
                events={"evt-1": "30 min"},
            )

    def test_event_outside_bounds_rejected(self):
        with pytest.raises(ValidationError, match="outside"):
            Script(
                start_time="10 min",
                end_time="20 min",
                speed=1.0,
                events={"evt-1": "30 min"},
            )


class TestStory:
    def test_valid(self):
        s = Story(scripts=["script-1"])
        assert s.speed == 1.0

    def test_speed_below_1_rejected(self):
        with pytest.raises(ValidationError):
            Story(scripts=["script-1"], speed=0.5)


# ---------------------------------------------------------------------------
# Objectives (APTL extensions)
# ---------------------------------------------------------------------------


class TestObjective:
    def test_manual(self):
        o = Objective(id="obj-a", description="Test", type="manual", points=50)
        assert o.type == ObjectiveType.MANUAL

    def test_wazuh_requires_config(self):
        with pytest.raises(ValidationError, match="wazuh_alert"):
            Objective(
                id="obj-b", description="Test", type="wazuh_alert", points=50
            )

    def test_wazuh_with_config(self):
        o = Objective(
            id="obj-b",
            description="Test",
            type="wazuh_alert",
            points=50,
            wazuh_alert=WazuhAlertValidation(
                query={"match_all": {}}, min_matches=1
            ),
        )
        assert o.wazuh_alert is not None


class TestObjectiveSet:
    def test_duplicate_ids_rejected(self):
        with pytest.raises(ValidationError, match="Duplicate"):
            ObjectiveSet(
                red=[
                    Objective(id="dup", description="A", type="manual", points=10),
                    Objective(id="dup", description="B", type="manual", points=10),
                ]
            )


# ---------------------------------------------------------------------------
# New extension models (G1-G9, G12-G13)
# ---------------------------------------------------------------------------

from aptl.core.sdl.accounts import Account, PasswordStrength
from aptl.core.sdl.attacks import PlatformCommand
from aptl.core.sdl.content import Content, ContentItem, ContentType
from aptl.core.sdl.infrastructure import ACLAction, ACLRule
from aptl.core.sdl.nodes import AssetValue, AssetValueLevel, OSFamily, ServicePort


class TestContent:
    def test_file_content(self):
        c = Content(type="file", target="victim", path="/tmp/flag.txt", text="FLAG{x}")
        assert c.type == ContentType.FILE
        assert c.text == "FLAG{x}"

    def test_dataset_content(self):
        c = Content(
            type="dataset",
            target="exchange",
            format="eml",
            items=[ContentItem(name="email.eml", tags=["phishing"])],
        )
        assert len(c.items) == 1
        assert c.items[0].tags == ["phishing"]

    def test_sensitive_flag(self):
        c = Content(type="file", target="fs", path="/keys/id_rsa", sensitive=True)
        assert c.sensitive is True


class TestAccount:
    def test_basic_account(self):
        a = Account(username="admin", node="dc")
        assert a.password_strength == PasswordStrength.MEDIUM

    def test_weak_account(self):
        a = Account(username="svc", node="dc", password_strength="weak")
        assert a.password_strength == PasswordStrength.WEAK

    def test_account_with_ad_fields(self):
        a = Account(
            username="svc_sql",
            node="dc",
            groups=["Domain Users"],
            spn="MSSQL/db.corp.local",
            password_strength="weak",
        )
        assert a.spn == "MSSQL/db.corp.local"

    def test_key_auth(self):
        a = Account(username="labadmin", node="victim", auth_method="key",
                     password_strength="none")
        assert a.auth_method == "key"


class TestACLRule:
    def test_allow_rule(self):
        r = ACLRule(direction="in", from_net="wan", protocol="tcp",
                    ports=[80, 443], action="allow")
        assert r.action == ACLAction.ALLOW
        assert r.ports == [80, 443]

    def test_deny_rule(self):
        r = ACLRule(direction="out", to_net="wan", action="deny")
        assert r.action == ACLAction.DENY


class TestOSFamily:
    def test_windows(self):
        n = Node(type="vm", os="windows", resources={"ram": "1 gib", "cpu": 1})
        assert n.os == OSFamily.WINDOWS

    def test_linux(self):
        n = Node(type="vm", os="linux", resources={"ram": "1 gib", "cpu": 1})
        assert n.os == OSFamily.LINUX

    def test_no_os(self):
        n = Node(type="vm", resources={"ram": "1 gib", "cpu": 1})
        assert n.os is None


class TestAssetValue:
    def test_defaults(self):
        av = AssetValue()
        assert av.confidentiality == AssetValueLevel.MEDIUM

    def test_custom(self):
        av = AssetValue(confidentiality="critical", availability="high")
        assert av.confidentiality == AssetValueLevel.CRITICAL

    def test_on_node(self):
        n = Node(
            type="vm",
            resources={"ram": "1 gib", "cpu": 1},
            asset_value={"confidentiality": "high", "availability": "critical"},
        )
        assert n.asset_value.confidentiality == AssetValueLevel.HIGH


class TestServicePort:
    def test_basic(self):
        sp = ServicePort(port=443, name="https")
        assert sp.protocol == "tcp"

    def test_on_node(self):
        n = Node(
            type="vm",
            resources={"ram": "1 gib", "cpu": 1},
            services=[{"port": 22, "name": "ssh"}, {"port": 80, "name": "http"}],
        )
        assert len(n.services) == 2


class TestPlatformCommand:
    def test_basic(self):
        pc = PlatformCommand(command="whoami")
        assert pc.shell == "sh"
        assert pc.cleanup == ""

    def test_with_cleanup(self):
        pc = PlatformCommand(shell="psh", command="procdump.exe", cleanup="del dump.bin")
        assert pc.cleanup == "del dump.bin"


class TestConditionExtensions:
    def test_timeout_and_retries(self):
        from aptl.core.sdl.conditions import Condition
        c = Condition(command="/check", interval=15, timeout=5, retries=3, start_period=10)
        assert c.timeout == 5
        assert c.retries == 3
        assert c.start_period == 10


class TestSimplePropertiesInternal:
    def test_internal_flag(self):
        from aptl.core.sdl.infrastructure import SimpleProperties
        p = SimpleProperties(cidr="10.0.0.0/24", gateway="10.0.0.1", internal=True)
        assert p.internal is True

    def test_default_not_internal(self):
        from aptl.core.sdl.infrastructure import SimpleProperties
        p = SimpleProperties(cidr="10.0.0.0/24", gateway="10.0.0.1")
        assert p.internal is False
