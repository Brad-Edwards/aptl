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
        if not traffic_mirror_requested(realization):
            return None
        if not getattr(self, "supports_local_artifacts", True):
            return LabResult(success=False, error=_UNAVAILABLE)
        helper = _ensure_helper(self, DEFAULT_BOUNDARY_HELPER_IMAGE)
        if helper is not None:
            return LabResult(success=False, error=_UNAVAILABLE)
        probe = self._run(self._tc_command("-V"), timeout=5)
        return (
            None
            if probe.returncode == 0
            else LabResult(success=False, error=_UNAVAILABLE)
        )

    def _realize_traffic_mirrors(
        self, realization: DeploymentRealizationSpec
    ) -> list[str]:
        if not traffic_mirror_requested(realization):
            return []
        binding = self._traffic_mirror_binding(realization)
        if binding is None:
            return [_UNAVAILABLE]
        source, sensor, _network = binding
        qdisc = self._run(
            self._tc_command("qdisc", "replace", "dev", source, "clsact"),
            timeout=10,
        )
        if qdisc.returncode != 0:
            return [_UNAVAILABLE]
        for direction in ("ingress", "egress"):
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
                return [_UNAVAILABLE]
        return [] if self._traffic_mirror_active(source, sensor) else [_UNAVAILABLE]

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

    def _tc_command(self, *args: str) -> list[str]:
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
        if set(nodes) != {"kali", "suricata", "webapp"}:
            return None
        inspected = {
            name: self.container_inspect(node.container_name)
            for name, node in nodes.items()
        }
        networks = {
            name: set(
                ((value.get("NetworkSettings") or {}).get("Networks") or {}).keys()
            )
            for name, value in inspected.items()
            if isinstance(value, Mapping)
        }
        if len(networks) != 3:
            return None
        shared = set.intersection(*(networks[name] for name in sorted(networks)))
        if not shared:
            return None
        network = sorted(shared)[0]
        source = self._host_veth(
            nodes["webapp"].container_name, inspected["webapp"], network
        )
        sensor = self._host_veth(
            nodes["suricata"].container_name, inspected["suricata"], network
        )
        if source is None or sensor is None or source == sensor:
            return None
        return source, sensor, network

    def _host_veth(
        self, container_name: str, inspected: Mapping[str, object], network: str
    ) -> str | None:
        network_settings = inspected.get("NetworkSettings")
        attachments = (
            network_settings.get("Networks")
            if isinstance(network_settings, Mapping)
            else None
        )
        attachment = (
            attachments.get(network) if isinstance(attachments, Mapping) else None
        )
        mac = attachment.get("MacAddress") if isinstance(attachment, Mapping) else None
        if not isinstance(mac, str) or not mac:
            return None
        inside = self.container_exec(
            container_name,
            [
                "sh",
                "-c",
                "for p in /sys/class/net/*; do "
                "IFS= read -r mac < \"$p/address\"; "
                "IFS= read -r peer < \"$p/iflink\"; "
                "printf '%s %s\\n' \"$mac\" \"$peer\"; done",
            ],
            timeout=10,
        )
        host = self._run(["ip", "-j", "link", "show"], timeout=10)
        if inside.returncode != 0 or host.returncode != 0:
            return None
        try:
            peers = [
                int(line.rsplit(" ", 1)[1])
                for line in inside.stdout.splitlines()
                if line.rsplit(" ", 1)[0].lower() == mac.lower()
            ]
            names = [
                item.get("ifname")
                for item in json.loads(host.stdout)
                if item.get("ifindex") in peers
            ]
        except (IndexError, TypeError, ValueError, json.JSONDecodeError):
            return None
        return (
            names[0]
            if len(names) == 1
            and isinstance(names[0], str)
            and _SAFE_INTERFACE.fullmatch(names[0])
            else None
        )

    def _traffic_mirror_active(self, source: str, sensor: str) -> bool:
        for direction in ("ingress", "egress"):
            observed = self._run(
                self._tc_command(
                    "filter", "show", "dev", source, direction
                ),
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


__all__ = ("ComposeTrafficMirrorMixin", "TRAFFIC_MIRROR_APPARATUS_ID")
