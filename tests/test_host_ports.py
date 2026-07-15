"""Tests for published host-port conflict detection, remap, and reporting.

The probe is exercised against real sockets; the resolver is driven with a
stubbed ``port_available`` so the remap/grouping/operator-override logic is
tested deterministically without depending on which host ports happen to be
free on the test machine.
"""

from __future__ import annotations

import errno
import socket

import pytest

from aptl.core import host_ports


# --------------------------------------------------------------------------- #
# _parse_entry — short-syntax port mappings, with and without ${VAR:-default}
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        (
            "127.0.0.1:${APTL_HP_WAZUH_DASHBOARD_5601:-443}:5601",
            ("wazuh.dashboard", "APTL_HP_WAZUH_DASHBOARD_5601", 443, 5601, "tcp", "127.0.0.1"),
        ),
        (
            "${APTL_DNS_HOST_PORT:-5353}:53/udp",
            ("dns", "APTL_DNS_HOST_PORT", 5353, 53, "udp", None),
        ),
        (
            "${APTL_HP_WEBAPP_8080:-8080}:8080",
            ("webapp", "APTL_HP_WEBAPP_8080", 8080, 8080, "tcp", None),
        ),
        (
            "127.0.0.1:9200:9200",  # unparameterized literal: no env var
            ("svc", None, 9200, 9200, "tcp", "127.0.0.1"),
        ),
    ],
)
def test_parse_entry(entry, expected):
    service = expected[0]
    spec = host_ports._parse_entry(service, entry)
    assert spec is not None
    assert expected == (
        spec.service,
        spec.env_var,
        spec.default_port,
        spec.container_port,
        spec.proto,
        spec.host_ip,
    )


def test_parse_entry_skips_varref_without_default():
    assert host_ports._parse_entry("svc", "${APTL_HP_X}:80") is None


def test_parse_entry_skips_non_string():
    assert host_ports._parse_entry("svc", {"target": 80, "published": 8080}) is None


def test_parse_published_ports_reads_all_services():
    compose = {
        "services": {
            "a": {"ports": ["127.0.0.1:${APTL_HP_A_1:-1000}:1"]},
            "b": {"ports": ["${APTL_HP_B_2:-2000}:2/udp", "3000:3"]},
            "c": {"image": "x"},  # no ports
        }
    }
    specs = host_ports.parse_published_ports(compose)
    assert {s.service for s in specs} == {"a", "b"}
    assert len(specs) == 3


def test_parse_published_ports_skips_inactive_profiles():
    compose = {
        "services": {
            "core": {"ports": ["${APTL_HP_CORE:-1000}:1"]},
            "soc": {
                "profiles": ["soc"],
                "ports": ["${APTL_HP_SOC:-2000}:2"],
            },
            "web": {
                "profiles": ["web"],
                "ports": ["${APTL_HP_WEB:-3000}:3"],
            },
        }
    }

    specs = host_ports.parse_published_ports(compose, {"soc"})

    assert {spec.service for spec in specs} == {"core", "soc"}


# --------------------------------------------------------------------------- #
# port_available — only EADDRINUSE counts as occupied (Linux/macOS safety)
# --------------------------------------------------------------------------- #
def test_port_available_true_for_free_high_port():
    # Bind a socket to grab a free port, release it, then probe it.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    free_port = s.getsockname()[1]
    s.close()
    assert host_ports.port_available(free_port, "tcp", "127.0.0.1") is True


def test_port_available_false_when_in_use():
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.bind(("127.0.0.1", 0))
    port = holder.getsockname()[1]
    holder.listen(1)
    try:
        assert host_ports.port_available(port, "tcp", "127.0.0.1") is False
    finally:
        holder.close()


def test_port_available_true_on_eacces(mocker):
    """A privileged-port EACCES must read as available, not occupied.

    Otherwise an unprivileged probe on Linux/macOS would falsely remap 443,
    514, 25, etc. and move the published ports off their documented defaults.
    """

    def fake_bind(self, addr):
        raise OSError(errno.EACCES, "permission denied")

    mocker.patch.object(socket.socket, "bind", fake_bind)
    assert host_ports.port_available(443, "tcp", "127.0.0.1") is True


# --------------------------------------------------------------------------- #
# resolve_host_ports — remap only conflicts, group shared vars, honor operator
# --------------------------------------------------------------------------- #
def _compose():
    return {
        "services": {
            "wazuh.dashboard": {
                "ports": ["127.0.0.1:${APTL_HP_WAZUH_DASHBOARD_5601:-443}:5601"]
            },
            "dns": {
                "ports": [
                    "${APTL_DNS_HOST_PORT:-5353}:53/tcp",
                    "${APTL_DNS_HOST_PORT:-5353}:53/udp",
                ]
            },
            "cortex": {"ports": ["127.0.0.1:${APTL_HP_CORTEX_9001:-9001}:9001"]},
        }
    }


@pytest.fixture
def _clean_env(monkeypatch):
    for var in (
        "APTL_HP_WAZUH_DASHBOARD_5601",
        "APTL_DNS_HOST_PORT",
        "APTL_HP_CORTEX_9001",
    ):
        monkeypatch.delenv(var, raising=False)


def test_no_remap_when_all_free(mocker, tmp_path, _clean_env):
    mocker.patch("aptl.core.host_ports._load_compose", return_value=_compose())
    mocker.patch("aptl.core.host_ports.port_available", return_value=True)

    resolved = host_ports.resolve_host_ports(tmp_path)

    assert all(not r.remapped for r in resolved)
    assert "APTL_HP_WAZUH_DASHBOARD_5601" not in __import__("os").environ


def test_remaps_only_the_occupied_port(mocker, tmp_path, _clean_env):
    import os

    mocker.patch("aptl.core.host_ports._load_compose", return_value=_compose())

    # 443 occupied, everything else free.
    def available(port, proto, host_ip):
        return port != 443

    mocker.patch("aptl.core.host_ports.port_available", side_effect=available)

    resolved = host_ports.resolve_host_ports(tmp_path)
    by_service = {r.service: r for r in resolved}

    assert by_service["wazuh.dashboard"].remapped is True
    assert by_service["wazuh.dashboard"].resolved_port != 443
    assert os.environ["APTL_HP_WAZUH_DASHBOARD_5601"] == str(
        by_service["wazuh.dashboard"].resolved_port
    )
    assert by_service["cortex"].remapped is False
    assert "APTL_HP_CORTEX_9001" not in os.environ


def test_dns_tcp_and_udp_remap_together(mocker, tmp_path, _clean_env):
    import os

    mocker.patch("aptl.core.host_ports._load_compose", return_value=_compose())

    # Only UDP 5353 is held (mDNS); the shared host port must still move as one.
    def available(port, proto, host_ip):
        return not (port == 5353 and proto == "udp")

    mocker.patch("aptl.core.host_ports.port_available", side_effect=available)

    resolved = host_ports.resolve_host_ports(tmp_path)
    dns = next(r for r in resolved if r.service == "dns")

    assert dns.remapped is True
    assert set(dns.protos) == {"tcp", "udp"}
    assert os.environ["APTL_DNS_HOST_PORT"] == str(dns.resolved_port)


def test_operator_pinned_value_is_honored(mocker, tmp_path, monkeypatch):
    monkeypatch.setenv("APTL_DNS_HOST_PORT", "15353")
    mocker.patch("aptl.core.host_ports._load_compose", return_value=_compose())
    # Even if the resolver were to probe, a reserved var must be left as-is.
    probe = mocker.patch("aptl.core.host_ports.port_available", return_value=False)

    resolved = host_ports.resolve_host_ports(
        tmp_path, reserved_env={"APTL_DNS_HOST_PORT"}
    )
    dns = next(r for r in resolved if r.service == "dns")

    assert dns.resolved_port == 15353
    assert not dns.remapped
    # The pinned port must not be probed/remapped.
    assert all(call.args[0] != 5353 for call in probe.call_args_list)


def test_existing_project_remap_is_reused(mocker, tmp_path, _clean_env):
    import os

    mocker.patch("aptl.core.host_ports._load_compose", return_value=_compose())
    probe = mocker.patch("aptl.core.host_ports.port_available", return_value=False)

    resolved = host_ports.resolve_host_ports(
        tmp_path,
        existing_bindings={
            ("dns", 53, "tcp"): 20000,
            ("dns", 53, "udp"): 20000,
        },
    )
    dns = next(r for r in resolved if r.service == "dns")

    assert dns.default_port == 5353
    assert dns.resolved_port == 20000
    assert dns.remapped is True
    assert os.environ["APTL_DNS_HOST_PORT"] == "20000"
    assert all(call.args[0] != 5353 for call in probe.call_args_list)


def test_incomplete_existing_group_falls_back_to_probe(
    mocker, tmp_path, _clean_env
):
    mocker.patch("aptl.core.host_ports._load_compose", return_value=_compose())
    mocker.patch("aptl.core.host_ports.port_available", return_value=True)

    resolved = host_ports.resolve_host_ports(
        tmp_path,
        existing_bindings={("dns", 53, "tcp"): 20000},
    )
    dns = next(r for r in resolved if r.service == "dns")

    assert dns.resolved_port == 5353
    assert dns.remapped is False


def test_project_port_bindings_deduplicates_address_families(mocker):
    backend = mocker.MagicMock()
    backend.container_list.return_value = [
        {"Name": "aptl-dns", "Service": "dns"},
    ]
    backend.container_inspect.return_value = {
        "NetworkSettings": {
            "Ports": {
                "53/tcp": [
                    {"HostIp": "0.0.0.0", "HostPort": "20000"},
                    {"HostIp": "::", "HostPort": "20000"},
                ],
                "53/udp": [
                    {"HostIp": "0.0.0.0", "HostPort": "20000"},
                    {"HostIp": "::", "HostPort": "20000"},
                ],
            }
        }
    }

    result = host_ports.project_port_bindings(backend)

    assert result == {
        ("dns", 53, "tcp"): 20000,
        ("dns", 53, "udp"): 20000,
    }


def test_project_port_bindings_returns_empty_when_list_fails(mocker):
    backend = mocker.MagicMock()
    backend.container_list.side_effect = OSError("daemon unavailable")

    assert host_ports.project_port_bindings(backend) == {}


def test_project_port_bindings_ignores_malformed_runtime_state(mocker):
    backend = mocker.MagicMock()
    backend.container_list.return_value = [
        "not-a-container",
        {"Service": "dns"},
        {"Name": "aptl-missing-service"},
        {"Name": "aptl-inspect-error", "Service": "dns"},
        {"Name": "aptl-invalid-info", "Service": "dns"},
        {"Name": "aptl-invalid-ports", "Service": "dns"},
        {"Name": "/aptl-dns", "Service": "dns"},
    ]

    def inspect(name):
        if name == "aptl-inspect-error":
            raise OSError("container disappeared")
        if name == "aptl-invalid-info":
            return []
        if name == "aptl-invalid-ports":
            return {"NetworkSettings": {"Ports": []}}
        return {
            "NetworkSettings": {
                "Ports": {
                    "not-a-port": [{"HostPort": "20000"}],
                    "53/tcp": [
                        None,
                        {},
                        {"HostPort": "invalid"},
                        {"HostPort": "0"},
                        {"HostPort": "20000"},
                        {"HostPort": "20001"},
                    ],
                    "54": [{"HostPort": "20002"}],
                    "55/tcp": None,
                }
            }
        }

    backend.container_inspect.side_effect = inspect

    assert host_ports.project_port_bindings(backend) == {
        ("dns", 54, "tcp"): 20002,
    }
