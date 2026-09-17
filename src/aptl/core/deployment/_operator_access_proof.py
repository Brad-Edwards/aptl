"""Proving a published operator endpoint actually reaches an SSH server.

A relay that starts is not access. After start the backend connects to the
published host port and requires an SSH identification banner from the far
side; a relay that starts but reaches nothing fails the realization.

Reporting lives here too, and says less than proving does on purpose: apply
details are written before lab start publishes and proves the relays, so they
record what was admitted and where it will be published, never that it is
reachable.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING

from aptl.core.deployment._operator_access_endpoints import (
    OPERATOR_ACCESS_ENDPOINTS,
    OperatorAccessEndpoint,
    resolved_host_port,
)
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from aptl.core.deployment.realization import DeploymentOperatorAccess

log = get_logger("deployment.operator_access")

OPERATOR_ACCESS_APPARATUS_ID = "aptl.apparatus.operator-interactive-access"
_LOOPBACK = "127.0.0.1"
_BANNER_PREFIX = b"SSH-2.0-"
# The relay is up within seconds, but the far side is an sshd that may still be
# settling behind the capture broker when the relay first answers. Bounded,
# generous relative to the observed few-second settle.
_READY_TIMEOUT_SECONDS = 120
_READY_INTERVAL_SECONDS = 2
_BANNER_READ_TIMEOUT_SECONDS = 5


def _log_published_access(
    accesses: Sequence["DeploymentOperatorAccess"],
) -> None:
    """Record where each proven access is reachable from the operator's host."""

    for access in accesses:
        endpoint = OPERATOR_ACCESS_ENDPOINTS[access.target_node]
        log.info(
            "Operator access %s (%s to %s) published on 127.0.0.1:%d",
            access.access_id,
            access.channel,
            access.target_node,
            resolved_host_port(endpoint),
        )


def _prove_endpoints(
    endpoints: Iterable[OperatorAccessEndpoint],
    *,
    timeout: float | None = None,
    interval: float | None = None,
) -> list[str]:
    """Require an SSH identification banner through every published endpoint."""

    timeout = _READY_TIMEOUT_SECONDS if timeout is None else timeout
    interval = _READY_INTERVAL_SECONDS if interval is None else interval

    pending = {endpoint.relay_container: endpoint for endpoint in endpoints}
    deadline = time.monotonic() + timeout
    while pending:
        for name, endpoint in list(pending.items()):
            if ssh_banner_reachable(_LOOPBACK, resolved_host_port(endpoint)):
                del pending[name]
        if not pending or time.monotonic() >= deadline:
            break
        time.sleep(interval)
    return [
        f"operator access through {endpoint.relay_container} "
        f"(127.0.0.1:{resolved_host_port(endpoint)}) did not reach an SSH server "
        f"within {int(timeout)}s"
        for endpoint in pending.values()
    ]


def ssh_banner_reachable(host: str, port: int) -> bool:
    """Return whether an SSH server identifies itself at host:port."""

    try:
        with socket.create_connection(
            (host, port), timeout=_BANNER_READ_TIMEOUT_SECONDS
        ) as conn:
            conn.settimeout(_BANNER_READ_TIMEOUT_SECONDS)
            return conn.recv(len(_BANNER_PREFIX)).startswith(_BANNER_PREFIX)
    except OSError:
        return False


def operator_access_details(
    accesses: Sequence["DeploymentOperatorAccess"],
) -> list[dict[str, object]]:
    """Report each admitted access and the endpoint planned for it.

    Apply details are written before lab start publishes and proves the relays,
    so this says what was admitted and where it will be published — not that it
    is reachable. Reachability is proven by `activate_operator_access`, and a
    failure there fails the start.
    """

    details: list[dict[str, object]] = []
    for access in accesses:
        endpoint = OPERATOR_ACCESS_ENDPOINTS.get(access.target_node)
        if endpoint is None:
            continue
        details.append(
            {
                **access.details(),
                "state": "admitted",
                "apparatus_id": OPERATOR_ACCESS_APPARATUS_ID,
                "relay_container": endpoint.relay_container,
                "planned_host_ip": _LOOPBACK,
                "planned_host_port": resolved_host_port(endpoint),
                "environment_visible": True,
            }
        )
    return details
