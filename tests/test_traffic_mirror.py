"""Scope-admitted host-boundary traffic mirror tests."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

from aptl.core.deployment._compose_traffic_mirror import ComposeTrafficMirrorMixin


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
    assert observed["implementation_helper_image"].endswith(":3")
    assert observed["network"] == "aptl-dmz"
    assert all("sudo" not in command for command in backend.commands)
    assert all("--cap-add=NET_ADMIN" in command for command in backend.commands)
