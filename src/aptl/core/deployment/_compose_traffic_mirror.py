"""Minimum-intrusion host-boundary traffic mirror for native IDS evidence."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping

from aptl.core.deployment._compose_capture_config import (
    TRAFFIC_MIRROR_APPARATUS_ID,
    traffic_mirror_requested,
)
from aptl.core.deployment._compose_boundary import (
    DEFAULT_BOUNDARY_HELPER_IMAGE,
    _ensure_helper,
)
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.lab_types import LabResult

_TC_PREFERENCE = "492"
_SAFE_INTERFACE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_UNAVAILABLE = "aptl.capture-apparatus.traffic-mirror-unavailable"


class ComposeTrafficMirrorMixin:
    """Realize an admitted frame copy without adding a scenario component."""

    def _traffic_mirror_preflight(
        self, realization: DeploymentRealizationSpec
    ) -> LabResult | None:
        result = None
        if (
            traffic_mirror_requested(realization)
            and not self._traffic_mirror_available()
        ):
            result = LabResult(success=False, error=_UNAVAILABLE)
        return result

    def _traffic_mirror_available(self) -> bool:
        """Return whether the host can realize the admitted minimum mirror."""

        return bool(
            getattr(self, "supports_local_artifacts", True)
            and _ensure_helper(self, DEFAULT_BOUNDARY_HELPER_IMAGE) is None
            and self._run(self._tc_command("-V"), timeout=5).returncode == 0
        )

    def _realize_traffic_mirrors(
        self, realization: DeploymentRealizationSpec
    ) -> list[str]:
        failures: list[str] = []
        if traffic_mirror_requested(realization):
            binding = self._traffic_mirror_binding(realization)
            if binding is None or not self._configure_traffic_mirror(*binding[:2]):
                failures.append(_UNAVAILABLE)
        return failures

    def _configure_traffic_mirror(self, source: str, sensor: str) -> bool:
        """Install and verify both frame-copy directions."""

        qdisc = self._run(
            self._tc_command("qdisc", "replace", "dev", source, "clsact"),
            timeout=10,
        )
        active = qdisc.returncode == 0
        for direction in ("ingress", "egress"):
            if not active:
                break
            # A retry may find our reserved preference pointing at a veth that
            # Compose has already replaced. tc cannot replace a matchall action
            # in place, so remove only APTL's preference and add the current
            # binding. A missing old filter is expected.
            self._run(
                self._tc_command(
                    "filter",
                    "del",
                    "dev",
                    source,
                    direction,
                    "pref",
                    _TC_PREFERENCE,
                ),
                timeout=10,
            )
            added = self._run(
                self._tc_command(
                    "filter",
                    "add",
                    "dev",
                    source,
                    direction,
                    "pref",
                    _TC_PREFERENCE,
                    "protocol",
                    "all",
                    "matchall",
                    "action",
                    "mirred",
                    "egress",
                    "mirror",
                    "dev",
                    sensor,
                ),
                timeout=10,
            )
            if added.returncode != 0:
                active = False
        return active and self._traffic_mirror_active(source, sensor)

    def _observe_traffic_mirror(
        self, realization: DeploymentRealizationSpec, item: object
    ) -> dict[str, object] | None:
        binding = self._traffic_mirror_binding(realization)
        if binding is None:
            return None
        source, sensor, network = binding
        if not self._traffic_mirror_active(source, sensor):
            return None
        return {
            **item.details(),
            "apparatus_kind": "host-veth-frame-mirror",
            "running": True,
            "source_container": "aptl-webapp",
            "sensor_container": "aptl-suricata",
            "network": network,
            "directions": ["ingress", "egress"],
            "published_ports": [],
            "added_scenario_components": [],
            "implementation_helper_image": DEFAULT_BOUNDARY_HELPER_IMAGE,
            "implementation_privileges": ["CAP_NET_ADMIN"],
        }

    @staticmethod
    def _tc_command(*args: str) -> list[str]:
        """Run tc in the fixed, capability-minimal host-network helper."""

        return [
            "docker",
            "run",
            "--pull=never",
            "--rm",
            "--network",
            "host",
            "--cap-drop=ALL",
            "--cap-add=NET_ADMIN",
            "--security-opt=no-new-privileges",
            "--read-only",
            "--entrypoint",
            "tc",
            DEFAULT_BOUNDARY_HELPER_IMAGE,
            *args,
        ]

    def _traffic_mirror_binding(
        self, realization: DeploymentRealizationSpec
    ) -> tuple[str, str, str] | None:
        nodes = {
            node.name: node
            for node in realization.nodes
            if node.name in {"kali", "suricata", "webapp"} and node.container_name
        }
        binding = None
        if set(nodes) == {"kali", "suricata", "webapp"}:
            inspected = {
                name: self.container_inspect(node.container_name)
                for name, node in nodes.items()
            }
            network = _shared_network(inspected)
            if network is not None:
                source = self._host_veth(
                    nodes["webapp"].container_name, inspected["webapp"], network
                )
                sensor = self._host_veth(
                    nodes["suricata"].container_name,
                    inspected["suricata"],
                    network,
                )
                if source is not None and sensor is not None and source != sensor:
                    binding = (source, sensor, network)
        return binding

    def _host_veth(
        self, container_name: str, inspected: Mapping[str, object], network: str
    ) -> str | None:
        mac = _network_mac(inspected, network)
        result = None
        if mac is not None:
            inside = self.container_exec(
                container_name,
                [
                    "sh",
                    "-c",
                    "for p in /sys/class/net/*; do "
                    'IFS= read -r mac < "$p/address"; '
                    'IFS= read -r peer < "$p/iflink"; '
                    'printf \'%s %s\\n\' "$mac" "$peer"; done',
                ],
                timeout=10,
            )
            host = self._run(["ip", "-j", "link", "show"], timeout=10)
            if inside.returncode == 0 and host.returncode == 0:
                result = _matching_host_interface(mac, inside.stdout, host.stdout)
        return result

    def _traffic_mirror_active(self, source: str, sensor: str) -> bool:
        for direction in ("ingress", "egress"):
            observed = self._run(
                self._tc_command("filter", "show", "dev", source, direction),
                timeout=10,
            )
            output = observed.stdout or ""
            if (
                observed.returncode != 0
                or f"pref {_TC_PREFERENCE} " not in output
                or f"Mirror to device {sensor}" not in output
            ):
                return False
        return True


def _shared_network(inspected: Mapping[str, object]) -> str | None:
    """Return the deterministic network shared by all three participants."""

    networks = {
        name: set(((value.get("NetworkSettings") or {}).get("Networks") or {}).keys())
        for name, value in inspected.items()
        if isinstance(value, Mapping)
    }
    shared = set.intersection(*networks.values()) if len(networks) == 3 else set()
    return min(shared) if shared else None


def _network_mac(inspected: Mapping[str, object], network: str) -> str | None:
    """Return a validated container MAC for one network attachment."""

    settings = inspected.get("NetworkSettings")
    attachments = settings.get("Networks") if isinstance(settings, Mapping) else None
    attachment = attachments.get(network) if isinstance(attachments, Mapping) else None
    mac = attachment.get("MacAddress") if isinstance(attachment, Mapping) else None
    return mac if isinstance(mac, str) and mac else None


def _matching_host_interface(mac: str, inside: str, host: str) -> str | None:
    """Map one container interface MAC to its unique safe host-veth name."""

    name = None
    try:
        peers = {
            int(line.rsplit(" ", 1)[1])
            for line in inside.splitlines()
            if line.rsplit(" ", 1)[0].lower() == mac.lower()
        }
        names = [
            item.get("ifname")
            for item in json.loads(host)
            if item.get("ifindex") in peers
        ]
        if (
            len(names) == 1
            and isinstance(names[0], str)
            and _SAFE_INTERFACE.fullmatch(names[0])
        ):
            name = names[0]
    except (IndexError, TypeError, ValueError):
        pass
    return name


__all__ = ("ComposeTrafficMirrorMixin", "TRAFFIC_MIRROR_APPARATUS_ID")
