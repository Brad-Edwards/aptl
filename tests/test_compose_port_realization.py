"""Host-port publishing for scenario-declared runtime ports (issue #578).

A scenario-declared host port is a realization requirement: it binds loopback
when no host address is given, fails closed on conflict rather than remapping,
and is refused when the node has no single compose service to attach it to.
"""

from __future__ import annotations

import socket

import yaml

from aptl.core.deployment._compose_port_realization import (
    compose_port_entry,
    published_port_conflicts,
    write_port_override,
)
from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentPublishedPort,
    DeploymentRealizationSpec,
)


def _spec(nodes):
    return DeploymentRealizationSpec(profiles=(), nodes=tuple(nodes), networks=())


def _node(name, service_name, ports):
    return DeploymentNodeRealization(
        address=f"provision.node.{name}",
        name=name,
        service_name=service_name,
        container_name=f"aptl-{name}",
        networks=(),
        published_ports=tuple(ports),
    )


def test_compose_port_entry_fixed_and_ephemeral():
    fixed = compose_port_entry(
        DeploymentPublishedPort(container_port=80, host_port=8080, host_ip="127.0.0.1")
    )
    assert fixed == {
        "target": 80,
        "protocol": "tcp",
        "host_ip": "127.0.0.1",
        "published": 8080,
    }
    ephemeral = compose_port_entry(DeploymentPublishedPort(container_port=80))
    assert "published" not in ephemeral
    assert ephemeral["host_ip"] == "127.0.0.1"  # loopback default, never all-interfaces


def test_no_conflict_for_ephemeral_or_free_port():
    spec = _spec([_node("web", "web", [DeploymentPublishedPort(container_port=80)])])
    assert published_port_conflicts(spec) == []


def test_conflict_when_declared_host_port_is_taken():
    # Bind a loopback port so the declared exact binding conflicts.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    taken = sock.getsockname()[1]
    try:
        spec = _spec(
            [
                _node(
                    "web",
                    "web",
                    [DeploymentPublishedPort(container_port=80, host_port=taken)],
                )
            ]
        )
        conflicts = published_port_conflicts(spec)
        assert conflicts
        assert "already in use" in conflicts[0]
        assert "will not silently publish it" in conflicts[0]
    finally:
        sock.close()


def test_conflict_when_node_has_no_resolvable_service():
    spec = _spec(
        [_node("web", None, [DeploymentPublishedPort(container_port=80, host_port=8080)])]
    )
    conflicts = published_port_conflicts(spec)
    assert conflicts
    assert "does not\n" not in conflicts[0]
    assert "single compose service" in conflicts[0]


def test_write_port_override_returns_none_without_ports(tmp_path):
    spec = _spec([_node("web", "web", [])])
    assert write_port_override(tmp_path, spec) is None


def test_write_port_override_emits_long_form_entries(tmp_path):
    spec = _spec(
        [
            _node(
                "web",
                "web-svc",
                [DeploymentPublishedPort(container_port=80, host_port=8080)],
            )
        ]
    )
    path = write_port_override(tmp_path, spec)
    assert path is not None and path.exists()
    doc = yaml.safe_load(path.read_text())
    entry = doc["services"]["web-svc"]["ports"][0]
    assert entry["target"] == 80
    assert entry["published"] == 8080
    assert entry["host_ip"] == "127.0.0.1"
