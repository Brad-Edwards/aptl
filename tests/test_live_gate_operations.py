"""The scenario-neutral operations surface a verifier plugin drives (#879).

These exercise the framework capabilities core exposes to a plugin -- reach a
host from an origin, generate a representative event and grade whether the
defensive stack recorded it -- without a live lab, by patching the same leaf
collectors the live gate always did. The reachability and correlation logic is
the one the gate has always used; only its caller changed from an in-core check
to this seam-facing surface.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aptl.core.config import AptlConfig
from aptl.validation import _live_gate_operations as ops
from aptl.validation import _live_gate_probes as lgp
from aptl.validation import _live_gate_telemetry as lgt
from aptl.validation._live_gate_operations import LiveGateOperations
from aptl.validation.techvault_live_gate import LiveGateOptions, LiveGateState

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ATTACKER = "aptl-kali"


class _Backend:
    def __init__(self, returncode=0, stdout=""):
        self._returncode = returncode
        self._stdout = stdout
        self.calls = []

    def container_exec(self, name, cmd, timeout=None):
        import types

        self.calls.append((name, tuple(cmd), timeout))
        return types.SimpleNamespace(returncode=self._returncode, stdout=self._stdout)


def _config():
    return AptlConfig(lab={"name": "techvault"})


def _container(name, *, networks=None):
    return {"name": name, "status": "Up", "health": "", "networks": networks or {}}


def _state(containers):
    state = LiveGateState()
    state.snapshot = {"containers": containers}
    return state


def _operations(
    state,
    options=None,
    *,
    deadline_monotonic=float("inf"),
    monotonic_fn=None,
):
    kwargs = {}
    if monotonic_fn is not None:
        kwargs["monotonic_fn"] = monotonic_fn
    return LiveGateOperations(
        project_dir=PROJECT_ROOT,
        config=_config(),
        options=options or LiveGateOptions(),
        state=state,
        deadline_monotonic=deadline_monotonic,
        **kwargs,
    )


# --------------------------------------------------------------------------- #
# Reachability from the attacker node.
# --------------------------------------------------------------------------- #


def test_reachability_passes_when_shared_targets_reachable(monkeypatch):
    monkeypatch.setattr(ops, "get_backend", lambda c, p: _Backend(returncode=0))
    state = _state(
        [
            _container(ATTACKER, networks={"aptl-dmz-net": "172.20.1.30"}),
            _container("aptl-webapp", networks={"aptl-dmz-net": "172.20.1.10"}),
        ]
    )
    result = _operations(state).reachability_from(ATTACKER)
    assert result.reached
    assert result.tested == ("aptl-webapp",)
    assert state.evidence["reachability_targets"] == ["aptl-webapp"]


def test_reachability_fails_when_target_unreachable(monkeypatch):
    monkeypatch.setattr(ops, "get_backend", lambda c, p: _Backend(returncode=1))
    state = _state(
        [
            _container(ATTACKER, networks={"aptl-dmz-net": "172.20.1.30"}),
            _container("aptl-webapp", networks={"aptl-dmz-net": "172.20.1.10"}),
        ]
    )
    result = _operations(state).reachability_from(ATTACKER)
    assert not result.reached
    assert any("cannot reach" in d for d in result.diagnostics)


def test_reachability_fails_without_the_attacker():
    state = _state([_container("aptl-webapp", networks={"n": "1.2.3.4"})])
    result = _operations(state).reachability_from(ATTACKER)
    assert not result.reached
    assert any("not present" in d for d in result.diagnostics)


def test_reachability_fails_without_a_shared_network():
    state = _state(
        [
            _container(ATTACKER, networks={"aptl-redteam-net": "172.30.0.30"}),
            _container("aptl-webapp", networks={"aptl-dmz-net": "172.20.1.10"}),
        ]
    )
    result = _operations(state).reachability_from(ATTACKER)
    assert not result.reached
    assert any("shares a network" in d for d in result.diagnostics)


def test_generic_execution_targets_the_plugin_selected_node(monkeypatch):
    backend = _Backend(returncode=0)
    monkeypatch.setattr(ops, "get_backend", lambda c, p: backend)
    state = _state([_container("scenario-origin")])

    succeeded = _operations(state).execute_in_node(
        "scenario-origin", ("probe", "--safe-argument"), timeout_seconds=7
    )

    assert succeeded
    assert backend.calls == [("scenario-origin", ("probe", "--safe-argument"), 7)]


def test_generic_execution_clamps_to_the_framework_deadline(monkeypatch):
    backend = _Backend(returncode=0)
    monkeypatch.setattr(ops, "get_backend", lambda c, p: backend)
    state = _state([_container("scenario-origin")])
    operations = _operations(
        state,
        deadline_monotonic=10.0,
        monotonic_fn=lambda: 7.1,
    )

    succeeded = operations.execute_in_node(
        "scenario-origin", ("probe",), timeout_seconds=120
    )

    assert succeeded
    assert backend.calls == [("scenario-origin", ("probe",), 2)]


def test_expired_framework_deadline_prevents_container_activity(monkeypatch):
    backend = _Backend(returncode=0)
    monkeypatch.setattr(ops, "get_backend", lambda c, p: backend)
    state = _state([_container("scenario-origin")])
    operations = _operations(
        state,
        deadline_monotonic=10.0,
        monotonic_fn=lambda: 10.0,
    )

    succeeded = operations.execute_in_node(
        "scenario-origin", ("probe",), timeout_seconds=120
    )

    assert succeeded is False
    assert backend.calls == []


@pytest.mark.parametrize(
    ("origin", "argv", "timeout_seconds"),
    [
        ("", ("probe",), 10),
        ("x" * 129, ("probe",), 10),
        ("scenario-origin", (), 10),
        ("scenario-origin", ("probe",) * 65, 10),
        ("scenario-origin", ("probe", ""), 10),
        ("scenario-origin", ("probe",), 0),
        ("scenario-origin", ("probe",), 301),
        ("scenario-origin", ("probe",), True),
    ],
)
def test_generic_execution_rejects_unbounded_plugin_input(
    origin, argv, timeout_seconds
):
    with pytest.raises(ValueError, match="invalid-container-operation"):
        _operations(_state([])).execute_in_node(
            origin,
            argv,
            timeout_seconds=timeout_seconds,
        )


def test_tcp_probe_delegates_to_the_backend(monkeypatch):
    backend = _Backend(returncode=0)
    monkeypatch.setattr(ops, "get_backend", lambda c, p: backend)

    reached = _operations(_state([])).tcp_reachable_from(
        "scenario-origin", "192.0.2.10", 22
    )

    assert reached is True
    assert backend.calls == [
        ("scenario-origin", ("nc", "-z", "-w", "3", "192.0.2.10", "22"), 15)
    ]


def test_tcp_probe_clamps_to_the_framework_deadline(monkeypatch):
    backend = _Backend(returncode=0)
    monkeypatch.setattr(ops, "get_backend", lambda c, p: backend)
    operations = _operations(
        _state([]),
        deadline_monotonic=10.0,
        monotonic_fn=lambda: 7.1,
    )

    reached = operations.tcp_reachable_from("scenario-origin", "192.0.2.10", 22)

    assert reached is True
    assert backend.calls[0][-1] == 2


@pytest.mark.parametrize("port", [0, 65_536, True])
def test_tcp_probe_rejects_an_invalid_port(port):
    with pytest.raises(ValueError, match="invalid-port"):
        _operations(_state([])).tcp_reachable_from(
            "scenario-origin", "192.0.2.10", port
        )


@pytest.mark.parametrize(
    ("origin", "address"),
    [
        ("", "192.0.2.10"),
        ("x" * 129, "192.0.2.10"),
        ("scenario-origin", ""),
        ("scenario-origin", "x" * 256),
    ],
)
def test_tcp_probe_rejects_invalid_network_input(origin, address):
    with pytest.raises(ValueError, match="invalid-network-operation"):
        _operations(_state([])).tcp_reachable_from(origin, address, 22)


def test_generic_evidence_collection_uses_plugin_callbacks(monkeypatch):
    state = _state([_container("scenario-origin")])
    calls = []

    def collect(*args, **kwargs):
        calls.append(kwargs)
        kwargs["trigger"]()
        assert kwargs["alert_matches"]({"marker": "scenario-correlation"})
        return []

    monkeypatch.setattr(lgt, "collect_evidence_diagnostics", collect)
    trigger_calls = []

    result = _operations(state).collect_evidence(
        trigger=lambda: trigger_calls.append("triggered"),
        alert_matches=lambda alert: alert.get("marker") == "scenario-correlation",
        deadline_monotonic=100.0,
        poll_interval_seconds=2.0,
    )

    assert result.observed
    assert trigger_calls == ["triggered"]
    assert calls[0]["deadline_monotonic"] == 100.0
    assert calls[0]["poll_interval_seconds"] == 2.0


def test_expired_evidence_window_never_invokes_the_plugin_trigger(monkeypatch):
    state = _state([_container("scenario-origin")])
    trigger_calls = []
    monkeypatch.setattr(lgt, "get_backend", lambda c, p: _Backend())

    diagnostics = lgt.collect_evidence_diagnostics(
        _config(),
        PROJECT_ROOT,
        state,
        trigger=lambda: trigger_calls.append("triggered"),
        alert_matches=lambda _alert: False,
        deadline_monotonic=10.0,
        poll_interval_seconds=2.0,
        env_loader=_telemetry_env,
        monotonic_fn=lambda: 10.0,
    )

    assert trigger_calls == []
    assert diagnostics == ["verification deadline elapsed before evidence trigger"]


# --------------------------------------------------------------------------- #
# Detection evidence (telemetry traversal).
# --------------------------------------------------------------------------- #


def _telemetry_state():
    return _state(
        [
            _container(ATTACKER, networks={"aptl-dmz-net": "172.20.1.30"}),
            _container("aptl-webapp", networks={"aptl-dmz-net": "172.20.1.10"}),
        ]
    )


def _telemetry_env(_path):
    return {
        "INDEXER_USERNAME": "live-indexer-user",
        "INDEXER_PASSWORD": "live-indexer-password",
        "API_USERNAME": "live-api-user",
        "API_PASSWORD": "live-api-password",
        "APTL_HP_WAZUH_INDEXER_9200": "19200",
    }


def _wire_telemetry(monkeypatch):
    monkeypatch.setattr(ops, "get_backend", lambda c, p: _Backend())
    monkeypatch.setattr(lgt, "get_backend", lambda c, p: _Backend())
    monkeypatch.setattr(lgt, "load_dotenv", _telemetry_env)

    def collect_once(
        backend,
        start_iso,
        *,
        indexer_url,
        indexer_auth,
        alert_matches,
        regenerate,
        **_kwargs,
    ):
        regenerate()
        end_iso = "2026-07-17T10:00:00+00:00"
        return (
            lgp.collect_suricata_eve(start_iso, end_iso, backend),
            lgp.collect_wazuh_alerts(
                start_iso,
                end_iso,
                indexer_url=indexer_url,
                auth=indexer_auth,
            ),
        )

    monkeypatch.setattr(lgt, "_collect_until_evidence", collect_once)


def _matches_test_alert(alert):
    return "scenario-correlation" in str(alert)


def _collect(operations):
    return operations.collect_evidence(
        trigger=lambda: None,
        alert_matches=_matches_test_alert,
        deadline_monotonic=float("inf"),
        poll_interval_seconds=1.0,
    )


def test_detection_fails_when_only_suricata_traffic_is_collected(monkeypatch):
    _wire_telemetry(monkeypatch)
    monkeypatch.setattr(
        lgp,
        "collect_suricata_eve",
        lambda s, e, b: [{"event_type": "alert"}, {"event_type": "flow"}],
    )
    monkeypatch.setattr(lgp, "collect_wazuh_alerts", lambda s, e, **kwargs: [])
    state = _telemetry_state()
    result = _collect(_operations(state, LiveGateOptions(event_window_seconds=10)))
    assert not result.observed
    telemetry = state.evidence["telemetry"]
    assert telemetry["suricata_traffic_event_count"] == 2
    assert telemetry["wazuh_alert_count"] == 0


def test_detection_passes_when_a_correlated_wazuh_alert_is_collected(monkeypatch):
    _wire_telemetry(monkeypatch)
    monkeypatch.setattr(
        lgp, "collect_suricata_eve", lambda s, e, b: [{"event_type": "flow"}]
    )

    def collect_wazuh(start, end, **kwargs):
        return [
            {
                "rule": {"id": "5710"},
                "agent": {"name": "manager"},
                "@timestamp": "2026-07-17T10:00:00+00:00",
                "full_log": "scenario-correlation",
            }
        ]

    monkeypatch.setattr(lgp, "collect_wazuh_alerts", collect_wazuh)
    state = _telemetry_state()
    result = _collect(_operations(state, LiveGateOptions(event_window_seconds=10)))
    assert result.observed
    telemetry = state.evidence["telemetry"]
    assert telemetry["wazuh_correlated_alert_count"] == 1
    assert telemetry["matched_alert"]["rule_id"] == "5710"
    assert "full_log" not in telemetry["matched_alert"]


def test_detection_rejects_an_unrelated_wazuh_alert(monkeypatch):
    _wire_telemetry(monkeypatch)
    monkeypatch.setattr(lgp, "collect_suricata_eve", lambda s, e, b: [])
    monkeypatch.setattr(
        lgp,
        "collect_wazuh_alerts",
        lambda s, e, **kwargs: [
            {"rule": {"id": "1002"}, "full_log": "Unrelated event"}
        ],
    )
    state = _telemetry_state()
    result = _collect(_operations(state, LiveGateOptions(event_window_seconds=10)))
    assert not result.observed
    assert state.evidence["telemetry"]["wazuh_correlated_alert_count"] == 0


def test_detection_fails_on_stats_only_events(monkeypatch):
    _wire_telemetry(monkeypatch)
    monkeypatch.setattr(
        lgp,
        "collect_suricata_eve",
        lambda s, e, b: [{"event_type": "stats"}, {"event_type": "stats"}],
    )
    monkeypatch.setattr(lgp, "collect_wazuh_alerts", lambda s, e, **kwargs: [])
    state = _telemetry_state()
    result = _collect(_operations(state, LiveGateOptions(event_window_seconds=10)))
    assert not result.observed
    assert state.evidence["telemetry"]["suricata_traffic_event_count"] == 0
