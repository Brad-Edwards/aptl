"""Wait for the service listeners a scenario declares to actually be listening.

``compose up -d`` proves a container was created, and a container health wait
proves whatever its own healthcheck claims — but a node realized from declared
facts carries no healthcheck of its own, so "healthy" is vacuously true the
moment it starts. Slow services (TheHive needs well over a minute to bind 9000)
were therefore observed before they listened, and the exact `service-listeners`
requirement failed nondeterministically: the same lab booted or failed on
timing alone (issue #1006).

The scenario already says what must be listening. That declaration is the
readiness signal: wait, bounded, for each declared listener to appear, then let
observation read the world. A listener that never appears still fails — this
waits for the truth rather than assuming it.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from aptl.core.deployment.errors import BackendTimeoutError
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from aptl.core.deployment.realization import DeploymentNodeRealization

log = get_logger("deployment.listener_readiness")

# TheHive is the slowest declared listener in the reference scenario: its own
# Compose healthcheck allows 120s of start period plus 5 retries at 30s, so it
# can legitimately take ~270s to bind. This is that bound plus margin, since a
# first boot also competes with every other service starting at once.
LISTENER_READY_TIMEOUT = 420
LISTENER_READY_INTERVAL = 5


def await_declared_listeners(
    backend: object,
    nodes: "tuple[DeploymentNodeRealization, ...]",
    *,
    timeout: int = LISTENER_READY_TIMEOUT,
    interval: int = LISTENER_READY_INTERVAL,
) -> list[str]:
    """Wait for every declared TCP/UDP listener to be bound; return failures."""

    pending = {
        node.container_name: _declared_ports(node)
        for node in nodes
        if node.container_name and _declared_ports(node)
    }
    if not pending:
        return []
    deadline = time.monotonic() + timeout
    unmet: dict[str, set[int]] = {}
    while True:
        unmet = {
            container: missing
            for container, ports in pending.items()
            if (missing := _missing_ports(backend, container, ports))
        }
        if not unmet or time.monotonic() >= deadline:
            break
        time.sleep(interval)
    if not unmet:
        return []
    detail = ", ".join(
        f"{container} (ports {sorted(ports)})"
        for container, ports in sorted(unmet.items())
    )
    log.warning("declared listeners did not bind within %ss: %s", timeout, detail)
    return [f"declared service listeners did not bind within {timeout}s: {detail}"]


def _declared_ports(node: "DeploymentNodeRealization") -> set[int]:
    """Return the ports a node's runtime declares as service listeners."""

    runtime = getattr(node, "runtime", None)
    listeners = getattr(runtime, "service_listeners", ()) or ()
    ports: set[int] = set()
    for listener in listeners:
        port = getattr(listener, "port", None)
        if isinstance(port, int) and 0 < port < 65536:
            ports.add(port)
    return ports


def _observe_listeners(backend: object, container: str) -> object | None:
    """Read the container's bound sockets, or None when they cannot be read."""

    observer = getattr(backend, "observe_container_listeners", None)
    if not callable(observer):
        return None
    try:
        return observer(container)
    except (BackendTimeoutError, OSError):
        return None


def _missing_ports(backend: object, container: str, ports: set[int]) -> set[int]:
    """Return declared ports not currently bound inside the container."""

    listeners = _observe_listeners(backend, container)
    if listeners is None:
        return set(ports)
    bound = {
        entry[2]
        for entry in getattr(listeners, "sockets", ())
        if isinstance(entry, tuple) and len(entry) == 3
    }
    return {port for port in ports if port not in bound}
