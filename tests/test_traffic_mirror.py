"""Scope-admitted host-boundary traffic mirror tests."""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

from aptl.core.deployment._compose_boundary import DEFAULT_BOUNDARY_HELPER_IMAGE
from aptl.core.deployment._compose_traffic_mirror import ComposeTrafficMirrorMixin
from aptl.core.deployment.errors import BackendTimeoutError


class _Apparatus:
    apparatus_id = "aptl.apparatus.suricata-traffic-mirror"

    @staticmethod
    def details():
        return {"apparatus_id": _Apparatus.apparatus_id}


class _Backend(ComposeTrafficMirrorMixin):
    supports_local_artifacts = True

    def __init__(self):
        self.commands: list[list[str]] = []

    def _traffic_mirror_binding(self, _realization):
        return "veth-source", "veth-sensor", "aptl-dmz"

    def _run(self, command, *, timeout=None):
        self.commands.append(command)
        output = ""
        if "filter" in command and "show" in command:
            output = (
                "filter protocol all pref 492 matchall chain 0\n"
                "action order 1: mirred (Egress Mirror to device veth-sensor) pipe\n"
            )
        return subprocess.CompletedProcess(command, 0, output, "")


class _DiscoveryBackend(ComposeTrafficMirrorMixin):
    _LINKS = {
        "aptl-kali": ("02:42:ac:14:01:0a", 10, "veth-kali"),
        "aptl-suricata": ("02:42:ac:14:01:0b", 11, "veth-sensor"),
        "aptl-webapp": ("02:42:ac:14:01:0c", 12, "veth-source"),
    }

    def container_inspect(self, container_name):
        mac, _index, _interface = self._LINKS[container_name]
        return {"NetworkSettings": {"Networks": {"aptl-dmz": {"MacAddress": mac}}}}

    def container_exec(self, container_name, _command, *, timeout=None):
        mac, index, _interface = self._LINKS[container_name]
        return subprocess.CompletedProcess([], 0, f"{mac} {index}\n", "")

    def _run(self, command, *, timeout=None):
        links = [
            {"ifindex": index, "ifname": interface}
            for _mac, index, interface in self._LINKS.values()
        ]
        return subprocess.CompletedProcess(command, 0, json.dumps(links), "")


def _realization():
    return SimpleNamespace(capture_apparatus=(_Apparatus(),))


def test_admitted_mirror_is_applied_in_both_directions_and_reported():
    backend = _Backend()
    realization = _realization()

    assert backend._realize_traffic_mirrors(realization) == []
    observed = backend._observe_traffic_mirror(realization, _Apparatus())

    assert any("ingress" in command for command in backend.commands)
    assert any("egress" in command for command in backend.commands)
    assert observed is not None
    assert observed["apparatus_kind"] == "host-veth-frame-mirror"
    assert observed["added_scenario_components"] == []
    assert observed["implementation_privileges"] == ["CAP_NET_ADMIN"]
    assert observed["implementation_helper_image"] == DEFAULT_BOUNDARY_HELPER_IMAGE
    assert observed["network"] == "aptl-dmz"
    assert all("sudo" not in command for command in backend.commands)
    assert all("--cap-add=NET_ADMIN" in command for command in backend.commands)


def test_traffic_mirror_discovers_exact_shared_network_host_veths():
    realization = SimpleNamespace(
        nodes=tuple(
            SimpleNamespace(name=name, container_name=f"aptl-{name}")
            for name in ("kali", "suricata", "webapp")
        )
    )

    assert _DiscoveryBackend()._traffic_mirror_binding(realization) == (
        "veth-source",
        "veth-sensor",
        "aptl-dmz",
    )


def test_traffic_mirror_allows_bounded_docker_startup_under_soc_load():
    class SlowHelperBackend(_Backend):
        def _run(self, command, *, timeout=None):
            if command[:2] == ["docker", "run"] and (timeout or 0) < 60:
                raise BackendTimeoutError("docker run timed out")
            return super()._run(command, timeout=timeout)

    backend = SlowHelperBackend()

    assert backend._realize_traffic_mirrors(_realization()) == []
    assert any(command[:2] == ["docker", "run"] for command in backend.commands)
