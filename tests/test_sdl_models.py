"""Tests for SDL structural models (Pydantic validation)."""

import pytest
from pydantic import ValidationError

from aptl.core.sdl._source import Source
from aptl.core.sdl.conditions import Condition
from aptl.core.sdl.entities import Entity, ExerciseRole, flatten_entities
from aptl.core.sdl.features import Feature, FeatureType
from aptl.core.sdl.infrastructure import InfraNode, SimpleProperties
from aptl.core.sdl.nodes import Node, NodeType, Resources, Role, parse_ram
from aptl.core.sdl.nodes import Node
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

    @pytest.mark.parametrize("value", [0, -1, True])
    def test_rejects_non_positive_or_bool_values(self, value):
        with pytest.raises(ValueError, match="RAM"):
            parse_ram(value)


class TestResources:
    def test_human_readable_ram(self):
        r = Resources(ram="2 gib", cpu=2)
        assert r.ram == 2 * 1073741824

    def test_integer_ram(self):
        r = Resources(ram=1024, cpu=1)
        assert r.ram == 1024

    def test_variable_placeholders(self):
        r = Resources(ram="${ram_bytes}", cpu="${cpu_cores}")
        assert r.ram == "${ram_bytes}"
        assert r.cpu == "${cpu_cores}"

    def test_rejects_non_positive_ram(self):
        with pytest.raises(ValidationError, match="RAM"):
            Resources(ram=0, cpu=1)


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

    @pytest.mark.parametrize(
        ("field_name", "value"),
        [
            ("os", "linux"),
            ("os_version", "22.04"),
            ("features", {"nginx": ""}),
            ("conditions", {"health-check": ""}),
            ("injects", {"email": ""}),
            ("vulnerabilities", ["sqli"]),
            ("roles", {"admin": {"username": "root"}}),
            ("services", [{"port": 80, "name": "http"}]),
            ("asset_value", {"confidentiality": "high"}),
        ],
    )
    def test_switch_rejects_other_vm_only_fields(self, field_name, value):
        with pytest.raises(ValidationError, match=field_name):
            Node(type="switch", **{field_name: value})


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

    def test_count_placeholder(self):
        n = InfraNode(count="${replicas}")
        assert n.count == "${replicas}"


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

    def test_variable_placeholders_skip_network_validation(self):
        p = SimpleProperties(
            cidr="${network_cidr}",
            gateway="${network_gateway}",
            internal="${is_internal}",
        )
        assert p.cidr == "${network_cidr}"
        assert p.gateway == "${network_gateway}"
        assert p.internal == "${is_internal}"


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

    def test_scalar_placeholders(self):
        c = Condition(
            command="/usr/bin/check.sh",
            interval="${check_interval}",
            timeout="${check_timeout}",
            retries="${check_retries}",
            start_period="${check_start_period}",
        )
        assert c.interval == "${check_interval}"
        assert c.timeout == "${check_timeout}"
        assert c.retries == "${check_retries}"
        assert c.start_period == "${check_start_period}"


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

    def test_variable_placeholders(self):
        m = Metric(type="manual", max_score="${max_score}", artifact="${needs_upload}")
        assert m.max_score == "${max_score}"
        assert m.artifact == "${needs_upload}"


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

    def test_placeholder_percentage(self):
        ms = MinScore(percentage="${pass_percentage}")
        assert ms.percentage == "${pass_percentage}"


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

    def test_facts_supported(self):
        e = Entity(name="Team", facts={"department": "SOC"})
        assert e.facts == {"department": "SOC"}

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

    def test_supports_months_and_years(self):
        assert parse_duration("1 mon") == 2_592_000
        assert parse_duration("1 y") == 31_536_000

    def test_supports_micro_and_nanoseconds(self):
        assert parse_duration("1 us") == 1
        assert parse_duration("1 ns") == 1

    def test_subsecond_values_round_up(self):
        assert parse_duration("1 ms") == 1
        assert parse_duration("1001 ms") == 2

    def test_supports_plus_syntax(self):
        assert parse_duration("1m+30") == 90

    def test_zero(self):
        assert parse_duration("0") == 0

    @pytest.mark.parametrize("value", [-1, -0.5, True, ""])
    def test_negative_or_blank_values_rejected(self, value):
        with pytest.raises(ValueError, match="Invalid duration"):
            parse_duration(value)

    def test_invalid(self):
        with pytest.raises(ValueError, match="Invalid duration"):
            parse_duration("not a duration")

    def test_rejects_garbage_suffix(self):
        with pytest.raises(ValueError, match="Invalid duration"):
            parse_duration("1h-nope")


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

    def test_variable_placeholders(self):
        s = Script(
            start_time="${script_start}",
            end_time="${script_end}",
            speed="${script_speed}",
            events={"evt-1": "${event_time}"},
        )
        assert s.start_time == "${script_start}"
        assert s.end_time == "${script_end}"
        assert s.speed == "${script_speed}"
        assert s.events["evt-1"] == "${event_time}"


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


# ---------------------------------------------------------------------------
# Extension models (G1-G9, G12-G13)
# ---------------------------------------------------------------------------

from aptl.core.sdl.accounts import Account, PasswordStrength
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

    def test_sensitive_placeholder(self):
        c = Content(
            type="file",
            target="fs",
            path="/tmp/flag.txt",
            sensitive="${contains_sensitive_data}",
        )
        assert c.sensitive == "${contains_sensitive_data}"

    def test_requires_target(self):
        with pytest.raises(ValidationError, match="Content requires 'target'"):
            Content(type="file", path="/tmp/flag.txt")

    def test_file_requires_path(self):
        with pytest.raises(ValidationError, match="File content requires 'path'"):
            Content(type="file", target="victim")

    def test_dataset_requires_source_or_items(self):
        with pytest.raises(
            ValidationError,
            match="Dataset content requires either 'source' or non-empty 'items'",
        ):
            Content(type="dataset", target="victim")

    def test_directory_requires_destination(self):
        with pytest.raises(
            ValidationError,
            match="Directory content requires 'destination'",
        ):
            Content(type="directory", target="victim")


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

    def test_disabled_placeholder(self):
        a = Account(username="svc", node="dc", disabled="${is_disabled}")
        assert a.disabled == "${is_disabled}"

    def test_requires_node(self):
        with pytest.raises(ValidationError, match="Account requires 'node'"):
            Account(username="admin")


class TestACLRule:
    def test_allow_rule(self):
        r = ACLRule(direction="in", from_net="wan", protocol="tcp",
                    ports=[80, 443], action="allow")
        assert r.action == ACLAction.ALLOW
        assert r.ports == [80, 443]

    def test_deny_rule(self):
        r = ACLRule(direction="out", to_net="wan", action="deny")
        assert r.action == ACLAction.DENY

    def test_port_placeholder(self):
        r = ACLRule(direction="in", from_net="wan", ports=["${https_port}"])
        assert r.ports == ["${https_port}"]


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

    def test_placeholder(self):
        sp = ServicePort(port="${service_port}", name="https")
        assert sp.port == "${service_port}"


class TestPlatformCommand:
    def test_basic(self):
        from aptl.core.attacks import PlatformCommand
        pc = PlatformCommand(command="whoami")
        assert pc.shell == "sh"
        assert pc.cleanup == ""

    def test_with_cleanup(self):
        from aptl.core.attacks import PlatformCommand
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


# ---------------------------------------------------------------------------
# Relationships, Agents, Variables (G10, G11, Identity)
# ---------------------------------------------------------------------------

from aptl.core.sdl.agents import Agent, InitialKnowledge
from aptl.core.sdl.relationships import Relationship, RelationshipType
from aptl.core.sdl.variables import Variable, VariableType


class TestRelationship:
    def test_authenticates_with(self):
        r = Relationship(type="authenticates_with", source="exchange", target="ad-ds")
        assert r.type == RelationshipType.AUTHENTICATES_WITH

    def test_trusts_with_properties(self):
        r = Relationship(
            type="trusts", source="child-domain", target="parent-domain",
            properties={"trust_type": "parent-child", "trust_direction": "bidirectional"},
        )
        assert r.properties["trust_type"] == "parent-child"

    def test_connects_to(self):
        r = Relationship(type="connects_to", source="webapp", target="db",
                         properties={"protocol": "tcp", "port": "5432"})
        assert r.source == "webapp"

    def test_federates_with(self):
        r = Relationship(type="federates_with", source="adfs", target="azure-ad",
                         properties={"protocol": "SAML"})
        assert r.type == RelationshipType.FEDERATES_WITH


class TestAgent:
    def test_basic_agent(self):
        a = Agent(entity="red-team", actions=["Scan", "Exploit"])
        assert len(a.actions) == 2

    def test_agent_with_starting_accounts(self):
        a = Agent(
            entity="red-team",
            starting_accounts=["phished-user"],
            allowed_subnets=["user-net"],
        )
        assert a.starting_accounts == ["phished-user"]

    def test_agent_with_initial_knowledge(self):
        a = Agent(
            entity="blue-team",
            initial_knowledge=InitialKnowledge(
                hosts=["defender", "server1"],
                subnets=["enterprise-net"],
            ),
        )
        assert len(a.initial_knowledge.hosts) == 2

    def test_initial_knowledge_defaults(self):
        ik = InitialKnowledge()
        assert ik.hosts == []
        assert ik.subnets == []
        assert ik.services == []
        assert ik.accounts == []

    def test_requires_entity(self):
        with pytest.raises(ValidationError, match="Agent requires 'entity'"):
            Agent(actions=["Scan"])


class TestVariable:
    def test_string_variable(self):
        v = Variable(type="string", default="techvault.local", description="Domain name")
        assert v.type == VariableType.STRING

    def test_integer_variable(self):
        v = Variable(type="integer", default=5)
        assert v.default == 5

    def test_variable_with_allowed_values(self):
        v = Variable(type="string", default="weak", allowed_values=["weak", "medium", "strong"])
        assert len(v.allowed_values) == 3

    def test_required_variable(self):
        v = Variable(type="string", required=True)
        assert v.required is True
        assert v.default is None

    def test_boolean_variable(self):
        v = Variable(type="boolean", default=True)
        assert v.type == VariableType.BOOLEAN

    def test_rejects_default_with_wrong_type(self):
        with pytest.raises(ValidationError, match="default must match"):
            Variable(type="integer", default="five")

    def test_rejects_allowed_values_with_wrong_type(self):
        with pytest.raises(ValidationError, match="allowed_values must match"):
            Variable(type="boolean", allowed_values=[True, "false"])

    def test_rejects_default_outside_allowed_values(self):
        with pytest.raises(ValidationError, match="default must be one of allowed_values"):
            Variable(type="string", default="critical", allowed_values=["low", "medium", "high"])

    def test_number_variable_accepts_int_and_float_allowed_values(self):
        v = Variable(type="number", default=1.5, allowed_values=[1, 1.5, 2.0])
        assert v.default == 1.5


class TestBooleanPlaceholders:
    def test_vulnerability_technical_placeholder(self):
        v = Vulnerability(
            name="SQLi",
            description="SQL injection",
            technical="${is_technical}",
            **{"class": "CWE-89"},
        )
        assert v.technical == "${is_technical}"
