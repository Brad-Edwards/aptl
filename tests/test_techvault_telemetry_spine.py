"""The scenario states where detection telemetry comes from and where it goes (#866).

Declaring containers proves the range exists. It does not say that Suricata's EVE
output is what the Wazuh sidecar tails, that the sidecar ships to the manager, or
that MISP intelligence becomes live Suricata rules. Those facts are what make
TechVault a *purple-team* range rather than a set of processes, and RAES has typed
surfaces for all of them (ADR-040/042/044/050).

These tests assert the chain is joined end to end. A node declared with no
forwarding agent, or a ship target aimed at nothing, would leave the scenario
silent about the very behaviour the live gate verifies.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

SDL = Path(__file__).resolve().parent.parent / "scenarios" / "techvault-operational.sdl.yaml"


@pytest.fixture(scope="module")
def scenario() -> dict:
    return yaml.safe_load(SDL.read_text())


def _runtime(scenario: dict, node: str) -> dict:
    return scenario["nodes"][node].get("runtime") or {}


def test_suricata_eve_output_is_the_file_the_sidecar_tails(scenario):
    """The detection-to-SIEM hand-off is one declared path, stated on both ends."""

    engine = _runtime(scenario, "suricata")["network_detection_engines"][0]
    eve = next(s for s in engine["output_streams"] if s["format"] == "eve_json")

    agent = _runtime(scenario, "wazuh-sidecar-suricata")["forwarding_agents"][0]
    tailed = next(s for s in agent["sources"] if s["kind"] == "tailed_path")

    # Both sides name the same file, each through its own mount of the shared
    # suricata_logs volume: /var/log/suricata for the writer, /logs for the reader.
    assert eve["path"].endswith("/eve.json")
    assert tailed["location"].endswith("/eve.json")
    assert tailed["parse_format"] == "eve_json"


def test_both_wazuh_agents_ship_to_the_declared_manager(scenario):
    """A forwarder that ships nowhere is not a telemetry path."""

    for node in ("wazuh-sidecar-suricata", "wazuh-sidecar-db"):
        agent = _runtime(scenario, node)["forwarding_agents"][0]
        assert agent["agent_kind"] == "log_forwarder"
        targets = agent["ship_targets"]
        assert targets, node
        assert all(t["target_node_ref"] == "wazuh-manager" for t in targets), node
        # An ingestion endpoint is what ADR-050 requires of a log forwarder.
        assert all(t.get("ingestion_port") for t in targets), node


def test_the_manager_ingestion_port_is_a_listener_it_actually_declares(scenario):
    """Shipping to a port the manager does not listen on would be fiction."""

    manager = _runtime(scenario, "wazuh-manager")["security_monitoring_managers"][0]
    ingestion_roles = {
        listener["service"]
        for listener in manager["listeners"]
        if listener["role"] == "agent_event_ingestion"
    }
    services = {
        service["name"]: service["port"]
        for service in scenario["nodes"]["wazuh-manager"]["services"]
    }
    shipped_ports = {
        target["ingestion_port"]
        for node in ("wazuh-sidecar-suricata", "wazuh-sidecar-db")
        for target in _runtime(scenario, node)["forwarding_agents"][0]["ship_targets"]
    }

    assert shipped_ports == {services[name] for name in ingestion_roles}


def test_misp_intelligence_becomes_loadable_suricata_content(scenario):
    """content_sync must pull, transform to rules, and be able to make them live."""

    sync = _runtime(scenario, "misp-suricata-sync")["forwarding_agents"][0]
    assert sync["agent_kind"] == "content_sync"
    assert any(s["kind"] == "api_pull" for s in sync["sources"])
    assert any(t["kind"] == "ioc_to_rule" for t in sync["transforms"])

    reload_channel = sync["reload_channels"][0]
    assert reload_channel["target_ref"] == "suricata"

    # The engine must actually consume what the sync writes, and say so.
    engine = _runtime(scenario, "suricata")["network_detection_engines"][0]
    ioc_source = next(s for s in engine["rule_sources"] if s["kind"] == "ioc")
    assert "misp-ioc-to-suricata" in ioc_source["generated_by"]
    # And expose a reload capability for the channel to drive.
    channel = engine["control_channels"][0]
    assert "rule_reload" in channel["capabilities"]


def test_the_manager_declares_the_agents_that_ship_to_it(scenario):
    """Both directions agree on who is enrolled, so neither side can drift alone."""

    manager = _runtime(scenario, "wazuh-manager")["security_monitoring_managers"][0]
    enrolled = {agent["node_ref"] for agent in manager["agents"]}

    shippers = {
        node
        for node in scenario["nodes"]
        if any(
            agent.get("agent_kind") == "log_forwarder"
            for agent in (_runtime(scenario, node).get("forwarding_agents") or [])
        )
    }

    assert enrolled == shippers
