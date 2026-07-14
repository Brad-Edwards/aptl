"""Service-port and published-port extraction from compiled node payloads (#578).

These bindings used to be discarded down to the service name. The extraction
keeps container-facing services and host-facing published ports distinct, and
refuses ports it cannot realize (an unsubstituted ``${var}`` or an out-of-range
value) rather than inventing one.
"""

from __future__ import annotations

from aptl.backends.aces_realization_values import (
    _port_number,
    _protocol,
    published_ports,
    service_names,
    service_ports,
)
from aptl.core.deployment.realization import LOOPBACK_HOST_IP


def test_service_ports_extracts_name_port_protocol():
    spec = {
        "services": [
            {"name": "http", "port": 80, "protocol": "TCP"},
            {"name": "dns", "port": 53, "protocol": "udp"},
        ]
    }
    ports = service_ports(spec)
    assert [(p.name, p.port, p.protocol) for p in ports] == [
        ("http", 80, "tcp"),
        ("dns", 53, "udp"),
    ]
    # service_names is derived from the typed ports
    assert service_names(spec) == {"http", "dns"}


def test_service_ports_drops_unsubstituted_variable_port():
    spec = {"services": [{"name": "http", "port": "${http_port}"}, {"name": "ok", "port": 8080}]}
    ports = service_ports(spec)
    assert [(p.name, p.port) for p in ports] == [("ok", 8080)]


def test_service_ports_defaults_protocol_and_tolerates_missing_name():
    ports = service_ports({"services": [{"port": 22}]})
    assert ports == (type(ports[0])(name="", port=22, protocol="tcp"),)


def test_service_ports_handles_absent_or_malformed():
    assert service_ports(None) == ()
    assert service_ports({}) == ()
    assert service_ports({"services": "nope"}) == ()
    assert service_ports({"services": ["notamap", 5]}) == ()


def test_published_ports_extracts_and_defaults_loopback():
    spec = {
        "runtime": {
            "network": {
                "published_ports": [
                    {"container_port": 80, "host_port": 8080, "host_ip": "0.0.0.0"},
                    {"container_port": 443},  # no host_ip -> loopback, no host_port
                ]
            }
        }
    }
    bindings = published_ports(spec)
    assert (bindings[0].container_port, bindings[0].host_port, bindings[0].host_ip) == (
        80,
        8080,
        "0.0.0.0",
    )
    assert bindings[1].host_ip == LOOPBACK_HOST_IP
    assert bindings[1].host_port is None


def test_published_ports_drops_unrealizable_container_port():
    spec = {"runtime": {"network": {"published_ports": [{"container_port": "${p}"}]}}}
    assert published_ports(spec) == ()


def test_published_ports_handles_absent_or_malformed():
    assert published_ports(None) == ()
    assert published_ports({}) == ()
    assert published_ports({"runtime": {"network": {"published_ports": "nope"}}}) == ()
    assert published_ports({"runtime": "nope"}) == ()
    # non-mapping entries in the list are skipped, not fatal
    spec = {"runtime": {"network": {"published_ports": ["nope", {"container_port": 80}]}}}
    bindings = published_ports(spec)
    assert [b.container_port for b in bindings] == [80]


def test_port_number_edges():
    assert _port_number(80) == 80
    assert _port_number("443") == 443
    assert _port_number("${var}") is None  # unsubstituted variable
    assert _port_number(0) is None  # below range
    assert _port_number(70000) is None  # above range
    assert _port_number(True) is None  # bool is not a port
    assert _port_number(None) is None
    assert _port_number(1.5) is None


def test_protocol_normalizes_and_defaults():
    assert _protocol("UDP") == "udp"
    assert _protocol("") == "tcp"
    assert _protocol(None) == "tcp"
