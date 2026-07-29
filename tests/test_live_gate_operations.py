"""The scenario-neutral operations surface a verifier plugin drives (#879).

These exercise the framework capabilities core exposes to a plugin -- reach a
host from an origin, generate a representative event and grade whether the
defensive stack recorded it -- without a live lab, by patching the same leaf
collectors the live gate always did. The reachability and correlation logic is
the one the gate has always used; only its caller changed from an in-core check
to this seam-facing surface.
"""

from __future__ import annotations

import functools
from pathlib import Path

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

    def container_exec(self, name, cmd, timeout=None):
        import types

        return types.SimpleNamespace(returncode=self._returncode, stdout=self._stdout)


def _config():
    return AptlConfig(lab={"name": "techvault"})


def _container(name, *, networks=None):
    return {"name": name, "status": "Up", "health": "", "networks": networks or {}}


def _state(containers):
    state = LiveGateState()
    state.snapshot = {"containers": containers}
    return state


def _operations(state, options=None):
    return LiveGateOperations(
        project_dir=PROJECT_ROOT,
        config=_config(),
        options=options or LiveGateOptions(),
        state=state,
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
    monkeypatch.setattr(
        lgt,
        "_collect_until_evidence",
        functools.partial(lgp._collect_until_evidence, sleep_fn=lambda _: None),
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
    result = _operations(state, LiveGateOptions(event_window_seconds=10)).detection_evidence(
        ATTACKER, 10
    )
    assert not result.observed
    telemetry = state.evidence["telemetry"]
    assert telemetry["suricata_traffic_event_count"] == 2
    assert telemetry["wazuh_alert_count"] == 0


def test_detection_passes_when_a_correlated_wazuh_alert_is_collected(monkeypatch):
    _wire_telemetry(monkeypatch)
    monkeypatch.setattr(lgp, "collect_suricata_eve", lambda s, e, b: [{"event_type": "flow"}])

    def collect_wazuh(start, end, **kwargs):
        return [
            {
                "rule": {"id": "5710"},
                "agent": {"name": "manager"},
                "@timestamp": "2026-07-17T10:00:00+00:00",
                "full_log": "Invalid user aptl-live-gate-invalid from 172.20.4.30",
            }
        ]

    monkeypatch.setattr(lgp, "collect_wazuh_alerts", collect_wazuh)
    state = _telemetry_state()
    result = _operations(state, LiveGateOptions(event_window_seconds=10)).detection_evidence(
        ATTACKER, 10
    )
    assert result.observed
    telemetry = state.evidence["telemetry"]
    assert telemetry["wazuh_correlated_alert_count"] == 1
    assert telemetry["wazuh_correlation"]["rule_id"] == "5710"
    assert "full_log" not in telemetry["wazuh_correlation"]


def test_detection_rejects_an_unrelated_wazuh_alert(monkeypatch):
    _wire_telemetry(monkeypatch)
    monkeypatch.setattr(lgp, "collect_suricata_eve", lambda s, e, b: [])
    monkeypatch.setattr(
        lgp,
        "collect_wazuh_alerts",
        lambda s, e, **kwargs: [{"rule": {"id": "1002"}, "full_log": "Unrelated event"}],
    )
    state = _telemetry_state()
    result = _operations(state, LiveGateOptions(event_window_seconds=10)).detection_evidence(
        ATTACKER, 10
    )
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
    result = _operations(state, LiveGateOptions(event_window_seconds=10)).detection_evidence(
        ATTACKER, 10
    )
    assert not result.observed
    assert state.evidence["telemetry"]["suricata_traffic_event_count"] == 0


def test_detection_fails_without_a_reachable_target():
    state = _state([_container(ATTACKER, networks={"n": "1.1.1.1"})])
    result = _operations(state).detection_evidence(ATTACKER, 10)
    assert not result.observed
    assert any("no reachable target" in d for d in result.diagnostics)
