"""Issue #912: the two released readiness demands decide honestly or not at all.

These sources are what stands between "the containers are up" and "the scenario
is ready". Their job is as much to refuse as to confirm, so most of what is
asserted here is what they reject.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from aptl.core.evidence.adapters.techvault_misp_readiness import (
    AdmittedMispState,
    MispAuthenticatedApiReadinessSource,
)
from aptl.core.evidence.adapters.techvault_wazuh_agent_readiness import (
    WazuhAgentReadinessSource,
)
from aptl.core.evidence.outcomes import CollectorStatus

_START = "2026-01-01T00:00:00Z"
_END = "2026-01-01T00:05:00Z"

_READY_MISP = {
    "canonical_url": "https://misp.techvault.local",
    "certificate_verified": True,
    "api_write_read_ok": True,
    "api_correlation_id": "aptl-readiness-0f1e",
    "database_identity": "misp",
    "database_role": "misp",
    "database_role_access_ok": True,
    "cache_authenticated": True,
    "cache_persistence_policy": "no",
    "cache_eviction_policy": "noeviction",
}

_NODES = ("db", "suricata")

_ADMITTED = AdmittedMispState(
    canonical_url="https://misp.techvault.local",
    database_identity="misp",
    database_role="misp",
    cache_persistence_policy="no",
    cache_eviction_policy="noeviction",
)


def _host(node: str, **overrides: object) -> dict[str, object]:
    row = {
        "node_ref": node,
        "enrollment_name": f"techvault-{node}-agent",
        "agent_id": f"00{_NODES.index(node) + 1}",
        "status": "active",
        "sources_readable": True,
        "telemetry_fresh": True,
        "telemetry_event_count": 3,
        "enrollment_preserved": True,
    }
    row.update(overrides)
    return row


def _misp_source(payload, admitted=_ADMITTED):
    return MispAuthenticatedApiReadinessSource(lambda _start, _end: payload, admitted)


def _wazuh_source(payload):
    return WazuhAgentReadinessSource(lambda _start, _end: payload, _NODES)


def _document(result):
    return json.loads(b"".join(result.chunks).decode())


# --------------------------------------------------------------------------
# MISP
# --------------------------------------------------------------------------


def test_misp_readiness_records_every_fact_the_demand_names():
    result = _misp_source(dict(_READY_MISP)).fetch(_START, _END)

    assert result.status is CollectorStatus.OK
    assert result.media_type == "application/json"
    document = _document(result)
    assert document["misp_authenticated_api_ready"] is True
    assert document["canonical_url"] == "https://misp.techvault.local"
    assert document["cache_eviction_policy"] == "noeviction"
    # The three declared subjects are each named, so the evidence cannot be
    # mistaken for a single-service observation.
    refs = {ref["ref_id"] for ref in result.source_pipeline["source_refs"]}
    assert refs == {
        "nodes.misp.runtime.platform_applications.misp-threat-intelligence",
        "nodes.misp-db.runtime.database_services.misp-db",
        "nodes.misp-redis.runtime.datastore_services.misp-redis",
    }


def test_an_unavailable_misp_probe_reports_no_evidence():
    result = _misp_source(None).fetch(_START, _END)

    assert result.status is CollectorStatus.SOURCE_UNAVAILABLE
    assert result.chunks == ()


def test_admitted_cache_policy_comes_from_misps_bound_cache_node():
    """An unrelated Redis node must not become MISP's admitted expectation."""

    from aptl.core.evidence.adapters.techvault_native_readiness import (
        admitted_misp_state,
    )

    def datastore(*, aof: bool, eviction: str):
        return SimpleNamespace(
            engine="redis",
            service="redis",
            persistence=SimpleNamespace(
                aof=aof, eviction=SimpleNamespace(value=eviction)
            ),
        )

    binding = SimpleNamespace(
        role="data_source", target_node_ref="misp-redis", target_service_ref="redis"
    )
    application = SimpleNamespace(upstream_bindings=(binding,))
    misp_runtime = SimpleNamespace(
        platform_applications=(application,),
        environment=(
            SimpleNamespace(name="BASE_URL", value="https://misp.techvault.local"),
            SimpleNamespace(name="MYSQL_DATABASE", value="misp"),
            SimpleNamespace(name="MYSQL_USER", value="misp"),
        ),
        datastore_services=(),
    )
    realization = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                name="unrelated-redis",
                runtime=SimpleNamespace(
                    platform_applications=(),
                    environment=(),
                    datastore_services=(
                        datastore(aof=True, eviction="allkeys-lru"),
                    ),
                ),
            ),
            SimpleNamespace(name="misp", runtime=misp_runtime),
            SimpleNamespace(
                name="misp-redis",
                runtime=SimpleNamespace(
                    platform_applications=(),
                    environment=(),
                    datastore_services=(
                        datastore(aof=False, eviction="noeviction"),
                    ),
                ),
            ),
        )
    )

    assert admitted_misp_state(realization) == _ADMITTED


@pytest.mark.parametrize(
    "field",
    ["certificate_verified", "api_write_read_ok", "database_role_access_ok", "cache_authenticated"],
)
def test_a_single_negative_fact_fails_readiness_closed(field):
    """Three of four proven is not readiness; each fact is load-bearing."""

    result = _misp_source({**_READY_MISP, field: False}).fetch(_START, _END)

    assert result.status is CollectorStatus.MID_RUN_LOSS
    assert result.chunks == ()


@pytest.mark.parametrize("field", sorted(_READY_MISP))
def test_a_missing_fact_is_not_treated_as_a_passing_one(field):
    payload = {name: value for name, value in _READY_MISP.items() if name != field}

    assert _misp_source(payload).fetch(_START, _END).chunks == ()


@pytest.mark.parametrize(
    ("field", "substituted"),
    [
        ("canonical_url", "https://misp.example.invalid"),
        ("database_identity", "someone_elses_database"),
        ("database_role", "root"),
        ("cache_persistence_policy", "yes"),
        ("cache_eviction_policy", "allkeys-lru"),
    ],
)
def test_a_substituted_value_is_rejected_even_though_it_answered(field, substituted):
    """A service that answers is not the service the plan admitted.

    Each of these is a live, non-empty observation. Accepting them on
    non-emptiness would let a swapped database role or a changed cache policy
    pass as readiness, which is exactly the drift this evidence exists to
    catch.
    """

    assert _misp_source({**_READY_MISP, field: substituted}).fetch(
        _START, _END
    ).chunks == ()


def test_an_anonymous_database_role_is_rejected():
    """Reaching the database as nobody in particular proves no role access."""

    assert _misp_source({**_READY_MISP, "database_role": "  "}).fetch(
        _START, _END
    ).chunks == ()


def test_a_boolean_cannot_stand_in_for_an_identity():
    """`True` is not a URL; a wrongly typed fact is contradictory, not ready."""

    assert _misp_source({**_READY_MISP, "canonical_url": True}).fetch(
        _START, _END
    ).chunks == ()


# --------------------------------------------------------------------------
# Wazuh endpoint agents
# --------------------------------------------------------------------------


def test_wazuh_readiness_records_one_identity_per_declared_host():
    result = _wazuh_source({"hosts": [_host("suricata"), _host("db")]}).fetch(
        _START, _END
    )

    assert result.status is CollectorStatus.OK
    document = _document(result)
    assert document["wazuh_agent_ready"] is True
    assert [row["node_ref"] for row in document["hosts"]] == ["db", "suricata"]
    assert all("enrollment_key" not in row for row in document["hosts"])


def test_a_host_the_pack_declares_may_not_be_silently_dropped():
    """A smaller passing fleet is a missing required identity."""

    assert _wazuh_source({"hosts": [_host("db")]}).fetch(_START, _END).chunks == ()


def test_an_undeclared_host_does_not_make_the_fleet_ready():
    payload = {"hosts": [_host("db"), _host("suricata"), _host("db")]}

    assert _wazuh_source(payload).fetch(_START, _END).chunks == ()


def test_two_members_answering_to_one_host_are_ambiguous():
    duplicate = _host("suricata", agent_id="001", enrollment_name="techvault-db-agent")

    assert _wazuh_source({"hosts": [_host("db"), duplicate]}).fetch(
        _START, _END
    ).chunks == ()


def test_an_inactive_member_is_not_a_ready_one():
    payload = {"hosts": [_host("db"), _host("suricata", status="disconnected")]}

    assert _wazuh_source(payload).fetch(_START, _END).chunks == ()


@pytest.mark.parametrize(
    "field", ["sources_readable", "telemetry_fresh", "enrollment_preserved"]
)
def test_each_per_host_fact_is_load_bearing(field):
    payload = {"hosts": [_host("db"), _host("suricata", **{field: False})]}

    assert _wazuh_source(payload).fetch(_START, _END).chunks == ()


def test_telemetry_freshness_must_agree_with_what_was_counted():
    """A row claiming fresh telemetry while counting none is contradictory."""

    payload = {
        "hosts": [
            _host("db"),
            _host("suricata", telemetry_fresh=True, telemetry_event_count=0),
        ]
    }

    assert _wazuh_source(payload).fetch(_START, _END).chunks == ()


def test_no_observed_events_is_not_fresh_telemetry():
    payload = {
        "hosts": [
            _host("db"),
            _host("suricata", telemetry_fresh=False, telemetry_event_count=0),
        ]
    }

    assert _wazuh_source(payload).fetch(_START, _END).chunks == ()


def test_a_boolean_cannot_stand_in_for_an_event_count():
    payload = {"hosts": [_host("db"), _host("suricata", telemetry_event_count=True)]}

    assert _wazuh_source(payload).fetch(_START, _END).chunks == ()


def test_a_malformed_roster_is_not_partially_accepted():
    assert _wazuh_source({"hosts": "everything is fine"}).fetch(
        _START, _END
    ).chunks == ()
    assert _wazuh_source({"hosts": [_host("db"), "suricata"]}).fetch(
        _START, _END
    ).chunks == ()
    assert _wazuh_source({}).fetch(_START, _END).chunks == ()


def test_an_unavailable_roster_reports_no_evidence():
    result = _wazuh_source(None).fetch(_START, _END)

    assert result.status is CollectorStatus.SOURCE_UNAVAILABLE


# --------------------------------------------------------------------------
# Construction of the facts, not just their acceptance.
# --------------------------------------------------------------------------


class _Result:
    def __init__(self, stdout: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode


def test_the_roster_parser_preserves_a_duplicate_name():
    """Collapsing duplicates here would hide them from the uniqueness check.

    A name-keyed mapping silently drops the earlier row, so the stale or
    duplicate member the released scope requires readiness to reject would
    never reach the code that rejects it.
    """

    from aptl.core.evidence.adapters.techvault_readiness_probes import _parse_roster

    rows = _parse_roster(
        "   ID: 001, Name: techvault-db-agent, IP: any, Active\n"
        "   ID: 007, Name: techvault-db-agent, IP: any, Disconnected\n"
    )

    assert rows == (
        ("techvault-db-agent", "001", "active"),
        ("techvault-db-agent", "007", "disconnected"),
    )


def test_an_unreadable_roster_yields_no_identities():
    from aptl.core.evidence.adapters.techvault_readiness_probes import _parse_roster

    assert _parse_roster("agent_control: permission denied\n") == ()


def test_telemetry_events_reports_what_the_manager_counted():
    from aptl.core.evidence.adapters.techvault_readiness_probes import telemetry_events

    def execute(_name, _cmd, _payload, timeout=None):
        return _Result("telemetry_event_count=4\n")

    assert telemetry_events(execute, "001", _START, _END) == 4


def test_an_unparseable_telemetry_count_is_not_read_as_zero_or_as_ready():
    from aptl.core.evidence.adapters.techvault_readiness_probes import telemetry_events

    def execute(_name, _cmd, _payload, timeout=None):
        return _Result("telemetry_event_count=lots\n")

    assert telemetry_events(execute, "001", _START, _END) is None


def test_a_duplicate_probe_field_is_ambiguous_not_last_value_wins():
    from aptl.core.evidence.adapters.techvault_readiness_probes import telemetry_events

    def execute(_name, _cmd, _payload, timeout=None):
        return _Result("telemetry_event_count=0\ntelemetry_event_count=4\n")

    assert telemetry_events(execute, "001", _START, _END) is None


def test_a_failed_telemetry_probe_is_not_read_as_no_events():
    from aptl.core.evidence.adapters.techvault_readiness_probes import telemetry_events

    def execute(_name, _cmd, _payload, timeout=None):
        return _Result("", returncode=1)

    assert telemetry_events(execute, "001", _START, _END) is None


def test_the_enrollment_baseline_is_recorded_once_and_not_overwritten(tmp_path):
    """Overwriting it would erase the evidence a later comparison depends on."""

    from aptl.core.evidence.adapters.techvault_enrollment_baseline import (
        enrollment_baseline,
        record_enrollment_baseline,
    )

    record_enrollment_baseline(tmp_path, {"db": "001"})
    assert enrollment_baseline(tmp_path) == {"db": "001"}

    # The agent re-enrolled and now reports a different id.
    record_enrollment_baseline(tmp_path, {"db": "009", "suricata": "002"})

    assert enrollment_baseline(tmp_path) == {"db": "001", "suricata": "002"}


def test_a_missing_baseline_reads_as_no_recorded_identity(tmp_path):
    from aptl.core.evidence.adapters.techvault_enrollment_baseline import (
        enrollment_baseline,
    )

    assert enrollment_baseline(tmp_path) == {}


def test_a_corrupt_baseline_is_not_replaced_with_a_fresh_identity(tmp_path):
    """Corruption is unknown state, not permission to bless the current id."""

    from aptl.core.evidence.adapters.techvault_enrollment_baseline import (
        ENROLLMENT_BASELINE_RELPATH,
        enrollment_baseline,
        record_enrollment_baseline,
    )

    path = tmp_path / ENROLLMENT_BASELINE_RELPATH
    path.parent.mkdir(parents=True)
    path.write_text("not-json\n", encoding="utf-8")

    assert enrollment_baseline(tmp_path) is None
    assert record_enrollment_baseline(tmp_path, {"db": "001"}) is False
    assert path.read_text(encoding="utf-8") == "not-json\n"


def test_a_re_enrolled_agent_does_not_pass_enrollment_preservation(tmp_path):
    """Delete the retained identity and both current views agree on a new id.

    That agreement is what made the previous check vacuous: only a baseline
    recorded before the restart distinguishes a preserved identity from a
    regenerated one.
    """

    from aptl.core.evidence.adapters.techvault_enrollment_baseline import (
        record_enrollment_baseline,
    )
    from aptl.core.evidence.adapters.techvault_native_readiness import (
        wazuh_agent_readiness,
    )

    record_enrollment_baseline(tmp_path, {"db": "001"})
    realization = _one_agent_realization()

    def execute(name, _cmd, _payload, timeout=None):
        if name == "aptl-wazuh-manager":
            if "agent_control" in _payload:
                return _Result("   ID: 009, Name: techvault-db-agent, IP: any, Active\n")
            return _Result("telemetry_event_count=2\n")
        return _Result("agent_id=009\nsources_readable=true\n")

    observed = wazuh_agent_readiness(execute, realization, tmp_path, _START, _END)

    assert observed is not None
    row = observed["hosts"][0]
    # The manager and the host agree with each other, and still disagree with
    # what was recorded before the restart.
    assert row["agent_id"] == "009"
    assert row["enrollment_preserved"] is False
    # So the source refuses it.
    assert WazuhAgentReadinessSource(
        lambda _s, _e: observed, ("db",)
    ).fetch(_START, _END).chunks == ()


def test_a_preserved_identity_passes_against_its_recorded_baseline(tmp_path):
    from aptl.core.evidence.adapters.techvault_enrollment_baseline import (
        record_enrollment_baseline,
    )
    from aptl.core.evidence.adapters.techvault_native_readiness import (
        wazuh_agent_readiness,
    )

    record_enrollment_baseline(tmp_path, {"db": "001"})
    realization = _one_agent_realization()

    def execute(name, _cmd, _payload, timeout=None):
        if name == "aptl-wazuh-manager":
            if "agent_control" in _payload:
                return _Result("   ID: 001, Name: techvault-db-agent, IP: any, Active\n")
            return _Result("telemetry_event_count=2\n")
        return _Result("agent_id=001\nsources_readable=true\n")

    observed = wazuh_agent_readiness(execute, realization, tmp_path, _START, _END)

    assert observed is not None
    row = observed["hosts"][0]
    assert row["enrollment_preserved"] is True
    assert row["telemetry_fresh"] is True
    assert row["telemetry_event_count"] == 2
    result = WazuhAgentReadinessSource(lambda _s, _e: observed, ("db",)).fetch(
        _START, _END
    )
    assert result.status is CollectorStatus.OK


def test_a_silent_agent_is_not_ready_even_while_connected(tmp_path):
    """`active` says it is talking to the manager, not that it shipped events."""

    from aptl.core.evidence.adapters.techvault_enrollment_baseline import (
        record_enrollment_baseline,
    )
    from aptl.core.evidence.adapters.techvault_native_readiness import (
        wazuh_agent_readiness,
    )

    record_enrollment_baseline(tmp_path, {"db": "001"})
    realization = _one_agent_realization()

    def execute(name, _cmd, _payload, timeout=None):
        if name == "aptl-wazuh-manager":
            if "agent_control" in _payload:
                return _Result("   ID: 001, Name: techvault-db-agent, IP: any, Active\n")
            return _Result("telemetry_event_count=0\n")
        return _Result("agent_id=001\nsources_readable=true\n")

    observed = wazuh_agent_readiness(execute, realization, tmp_path, _START, _END)

    assert observed["hosts"][0]["status"] == "active"
    assert observed["hosts"][0]["telemetry_fresh"] is False
    assert WazuhAgentReadinessSource(
        lambda _s, _e: observed, ("db",)
    ).fetch(_START, _END).chunks == ()


def test_a_duplicate_manager_member_stops_the_observation(tmp_path):
    from aptl.core.evidence.adapters.techvault_native_readiness import (
        wazuh_agent_readiness,
    )

    realization = _one_agent_realization()

    def execute(name, _cmd, _payload, timeout=None):
        if name == "aptl-wazuh-manager":
            if "agent_control" in _payload:
                return _Result(
                    "   ID: 001, Name: techvault-db-agent, IP: any, Active\n"
                    "   ID: 042, Name: techvault-db-agent, IP: any, Active\n"
                )
            return _Result("telemetry_event_count=2\n")
        return _Result("agent_id=001\nsources_readable=true\n")

    assert wazuh_agent_readiness(execute, realization, tmp_path, _START, _END) is None


class _Source:
    def __init__(self, kind: str, location: str) -> None:
        self.kind = kind
        self.location = location


class _Agent:
    implementation = "wazuh_agent"
    name = "techvault-db-agent"

    def __init__(self) -> None:
        self.sources = (_Source("tailed_path", "/var/log/postgresql/x.log"),)
        self.ship_targets = (type("T", (), {"enrollment_port": 1515})(),)


class _Runtime:
    def __init__(self) -> None:
        self.forwarding_agents = (_Agent(),)


class _Node:
    name = "db"

    def __init__(self) -> None:
        self.runtime = _Runtime()


class _Realization:
    def __init__(self) -> None:
        self.nodes = (_Node(),)


def _one_agent_realization() -> _Realization:
    return _Realization()


def test_duplicate_endpoint_agents_on_one_node_fail_declaration_closed():
    from aptl.core.evidence.adapters.techvault_native_readiness import (
        declared_endpoint_agents,
    )

    realization = _one_agent_realization()
    realization.nodes[0].runtime.forwarding_agents = (_Agent(), _Agent())

    assert declared_endpoint_agents(realization) == {}


def test_an_endpoint_agent_without_a_declared_tailed_source_is_not_ready():
    from aptl.core.evidence.adapters.techvault_native_readiness import (
        declared_endpoint_agents,
    )

    realization = _one_agent_realization()
    agent = _Agent()
    agent.sources = ()
    realization.nodes[0].runtime.forwarding_agents = (agent,)

    assert declared_endpoint_agents(realization) == {}


def test_the_first_capture_establishes_its_own_baseline(tmp_path):
    """A fresh installation has no identity to compare against yet.

    Reporting every host as re-enrolled on the first capture would mean
    readiness could never succeed once, so the first observation establishes
    the baseline. Every later capture is then compared against it.
    """

    from aptl.core.evidence.adapters.techvault_enrollment_baseline import (
        enrollment_baseline,
    )
    from aptl.core.evidence.adapters.techvault_native_readiness import (
        wazuh_agent_readiness,
    )

    realization = _one_agent_realization()

    def execute(name, _cmd, _payload, timeout=None):
        if name == "aptl-wazuh-manager":
            if "agent_control" in _payload:
                return _Result("   ID: 001, Name: techvault-db-agent, IP: any, Active\n")
            return _Result("telemetry_event_count=2\n")
        return _Result("agent_id=001\nsources_readable=true\n")

    assert enrollment_baseline(tmp_path) == {}

    observed = wazuh_agent_readiness(execute, realization, tmp_path, _START, _END)

    assert observed["hosts"][0]["enrollment_preserved"] is True
    assert enrollment_baseline(tmp_path) == {"db": "001"}
    result = WazuhAgentReadinessSource(lambda _s, _e: observed, ("db",)).fetch(
        _START, _END
    )
    assert result.status is CollectorStatus.OK


def test_the_explicit_reset_clears_the_baseline_it_owns(tmp_path):
    """Otherwise a legitimate `stop -v` leaves every host permanently failing."""

    from aptl.core.evidence.adapters.techvault_enrollment_baseline import (
        clear_enrollment_baseline,
        enrollment_baseline,
        record_enrollment_baseline,
    )

    record_enrollment_baseline(tmp_path, {"db": "001"})
    assert enrollment_baseline(tmp_path) == {"db": "001"}

    assert clear_enrollment_baseline(tmp_path) == []

    assert enrollment_baseline(tmp_path) == {}
    # Clearing what is already absent is not a failure; the reset is idempotent.
    assert clear_enrollment_baseline(tmp_path) == []
    assert clear_enrollment_baseline(None) == []
