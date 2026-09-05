"""The scenario-neutral operations a verification plugin drives (#878/#879).

A plugin decides *what* to check for one scenario; core owns *how* to observe a
live range. This surface is that boundary. It exposes only capability-oriented,
scenario-neutral operations: enumerate admitted network peers, probe or execute
bounded argv inside a plugin-selected node, and poll existing evidence collectors
with a plugin-owned trigger and correlation predicate. The framework keeps the
deadline, polling, credentials, collectors, and evidence summary; the plugin
keeps every scenario/backend answer key.

The surface deliberately carries no run store, destination paths, raw config,
``.env`` mapping, process environment, or unrestricted backend handle. A plugin
names an origin node and asks a question; the framework answers it.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import floor, isfinite
from pathlib import Path
import time
from typing import TYPE_CHECKING, Callable

from aptl.core.deployment import get_backend
from aptl.validation import _live_gate_telemetry as telemetry
from aptl.validation._live_gate_probes import (
    _find_container,
    _ping_from_container,
    _shared_network_targets,
    _tcp_reachable_from_container,
)

if TYPE_CHECKING:
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
        deadline_monotonic: float = float("inf"),
        monotonic_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self._project_dir = project_dir
        self._config = config
        self._state = state
        self._deadline_monotonic = deadline_monotonic
        self._monotonic = monotonic_fn

    def _bounded_timeout(self, requested_seconds: int) -> int | None:
        """Clamp one backend operation to the remaining verification window."""

        if not isfinite(self._deadline_monotonic):
            return requested_seconds
        remaining = self._deadline_monotonic - self._monotonic()
        if remaining < 1:
            return None
        return min(requested_seconds, floor(remaining))

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
        targets = (
            _shared_network_targets(origin_container, containers, networks)
            if networks
            else []
        )
        if not targets:
            reason = (
                f"origin {origin!r} has no network attachments"
                if not networks
                else f"no host shares a network with {origin!r} to test"
            )
            return ReachabilityResult(False, (), (reason,))
        backend = get_backend(self._config, self._project_dir)
        diagnostics: list[str] = []
        for name, ip in targets:
            timeout = self._bounded_timeout(15)
            if timeout is None:
                diagnostics.append("verification deadline elapsed during reachability")
                break
            if not _ping_from_container(backend, origin, ip, timeout_seconds=timeout):
                diagnostics.append(
                    f"{origin} cannot reach {name} ({ip}) on shared network"
                )
        tested = tuple(name for name, _ in targets)
        self._state.evidence = {"reachability_targets": list(tested)}
        return ReachabilityResult(not diagnostics, tested, tuple(diagnostics))

    def shared_network_targets(self, origin: str) -> tuple[tuple[str, str], ...]:
        """Return admitted ``(node, address)`` peers sharing a network with origin."""

        containers = (self._state.snapshot or {}).get("containers", [])
        origin_container = _find_container(containers, origin)
        if origin_container is None:
            return ()
        networks = set((origin_container.get("networks") or {}).keys())
        return tuple(_shared_network_targets(origin_container, containers, networks))

    def tcp_reachable_from(self, origin: str, address: str, port: int) -> bool:
        """Return whether ``origin`` can open one bounded TCP endpoint."""

        if (
            not isinstance(origin, str)
            or not origin
            or len(origin) > 128
            or not isinstance(address, str)
            or not address
            or len(address) > 255
        ):
            raise ValueError("invalid-network-operation")
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ValueError("invalid-port")
        timeout = self._bounded_timeout(15)
        if timeout is None:
            return False
        backend = get_backend(self._config, self._project_dir)
        return _tcp_reachable_from_container(
            backend, origin, address, port, timeout_seconds=timeout
        )

    def execute_in_node(
        self,
        origin: str,
        argv: tuple[str, ...],
        *,
        timeout_seconds: int,
    ) -> bool:
        """Execute bounded argv inside one plugin-selected admitted node.

        This is container-scoped target activity, not a host shell: callers do
        not choose a host executable, working directory, environment, or backend.
        """

        if (
            not isinstance(origin, str)
            or not origin
            or len(origin) > 128
            or not isinstance(argv, tuple)
            or not argv
            or len(argv) > 64
            or any(
                not isinstance(item, str) or not item or len(item) > 4096
                for item in argv
            )
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or not 1 <= timeout_seconds <= 300
        ):
            raise ValueError("invalid-container-operation")
        bounded_timeout = self._bounded_timeout(timeout_seconds)
        if bounded_timeout is None:
            return False
        backend = get_backend(self._config, self._project_dir)
        try:
            result = backend.container_exec(origin, list(argv), timeout=bounded_timeout)
        except Exception:
            return False
        return result.returncode == 0

    def collect_evidence(
        self,
        *,
        trigger: Callable[[], None],
        alert_matches: Callable[[object], bool],
        deadline_monotonic: float,
        poll_interval_seconds: float,
    ) -> DetectionResult:
        """Poll core-owned collectors for one plugin-defined correlation rule."""

        effective_deadline = min(deadline_monotonic, self._deadline_monotonic)
        diagnostics = telemetry.collect_evidence_diagnostics(
            self._config,
            self._project_dir,
            self._state,
            trigger=trigger,
            alert_matches=alert_matches,
            deadline_monotonic=effective_deadline,
            poll_interval_seconds=poll_interval_seconds,
            monotonic_fn=self._monotonic,
        )
        return DetectionResult(not diagnostics, tuple(diagnostics))


__all__ = ["DetectionResult", "LiveGateOperations", "ReachabilityResult"]
