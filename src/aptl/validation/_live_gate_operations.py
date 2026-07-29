"""The scenario-neutral operations a verification plugin drives (#878/#879).

A plugin decides *what* to check for one scenario; core owns *how* to observe a
live range. This surface is that boundary. It exposes only capability-oriented,
scenario-neutral operations -- reach a host from another host, generate a
representative event and see whether the defensive stack recorded it -- backed by
the same framework the live gate already used (bounded windows, re-driving a
trigger while its window is open, preferring probe targets that actually expose
the service). None of that machinery is duplicated into the plugin.

The surface deliberately carries no run store, destination paths, raw config,
``.env`` mapping, process environment, or unrestricted backend handle. A plugin
names an origin node and asks a question; the framework answers it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from aptl.core.deployment import get_backend
from aptl.validation._live_gate_probes import (
    _find_container,
    _ping_from_kali,
    _shared_network_targets,
)
from aptl.validation._live_gate_telemetry import telemetry_diagnostics

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aptl.core.config import AptlConfig
    from aptl.validation.techvault_live_gate import LiveGateOptions, LiveGateState


@dataclass(frozen=True)
class ReachabilityResult(object):
    """Whether an origin reached every host it shares a network with."""

    reached: bool
    tested: tuple[str, ...]
    diagnostics: tuple[str, ...]


@dataclass(frozen=True)
class DetectionResult(object):
    """Whether a representative event traversed the defensive stack."""

    observed: bool
    diagnostics: tuple[str, ...]


class LiveGateOperations(object):
    """Core-owned capabilities a scenario verifier drives against a live range.

    Constructed by the live gate after boot, from the run's project directory,
    config, options, and post-boot state. The plugin receives it as the context's
    ``operations`` and never sees the underlying config or backend.
    """

    def __init__(
        self,
        *,
        project_dir: Path,
        config: "AptlConfig",
        options: "LiveGateOptions",
        state: "LiveGateState",
    ) -> None:
        self._project_dir = project_dir
        self._config = config
        self._options = options
        self._state = state

    def reachability_from(self, origin: str) -> ReachabilityResult:
        """Return whether ``origin`` reaches every host on its shared networks.

        Targets are derived from live network co-membership, not a fixed list, so
        only the origin node is a scenario constant. The plugin supplies it.
        """

        containers = (self._state.snapshot or {}).get("containers", [])
        origin_container = _find_container(containers, origin)
        if origin_container is None:
            return ReachabilityResult(
                False, (), (f"origin {origin!r} not present in the booted range",)
            )
        networks = set((origin_container.get("networks") or {}).keys())
        if not networks:
            return ReachabilityResult(
                False, (), (f"origin {origin!r} has no network attachments",)
            )
        targets = _shared_network_targets(origin_container, containers, networks)
        if not targets:
            return ReachabilityResult(
                False, (), (f"no host shares a network with {origin!r} to test",)
            )
        backend = get_backend(self._config, self._project_dir)
        diagnostics = [
            f"{origin} cannot reach {name} ({ip}) on shared network"
            for name, ip in targets
            if not _ping_from_kali(backend, ip)
        ]
        tested = tuple(name for name, _ in targets)
        self._state.evidence = {"reachability_targets": list(tested)}
        return ReachabilityResult(not diagnostics, tested, tuple(diagnostics))

    def detection_evidence(self, origin: str, deadline_seconds: int) -> DetectionResult:
        """Generate one representative event from ``origin`` and grade traversal.

        Drives the existing bounded-window collection: the event is re-driven
        while the window is open rather than fired once, and probe targets that
        actually expose the service are preferred. Both are framework behaviour
        and stay here. The verdict on what the collected evidence means is the
        plugin's; this returns whether a correlated defensive-stack alert was
        observed at all.
        """

        containers = (self._state.snapshot or {}).get("containers", [])
        origin_container = _find_container(containers, origin)
        if origin_container is None:
            return DetectionResult(
                False, (f"origin {origin!r} not present; cannot generate an event",)
            )
        networks = set((origin_container.get("networks") or {}).keys())
        targets = _shared_network_targets(origin_container, containers, networks)
        if not targets:
            return DetectionResult(
                False, ("no reachable target to generate defensive-stack telemetry",)
            )
        diagnostics = telemetry_diagnostics(
            targets,
            self._config,
            self._project_dir,
            self._options,
            self._state,
        )
        return DetectionResult(not diagnostics, tuple(diagnostics))


__all__ = ["DetectionResult", "LiveGateOperations", "ReachabilityResult"]
