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

import shutil
import socket
import subprocess
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
    from pathlib import Path

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
# One key-only login attempt against a loopback relay; generous but bounded.
_LOGIN_CONNECT_TIMEOUT_SECONDS = 10
_LOGIN_TIMEOUT_SECONDS = 30
# ssh could not authenticate the operator: the declared access is not realized.
_AUTH_FAILURE_MARKERS = (
    "permission denied",
    "no supported authentication",
    "too many authentication failures",
)
# ssh never got far enough to authenticate, so nothing is proven either.
_TRANSPORT_FAILURE_MARKERS = (
    "connection refused",
    "connection timed out",
    "connection closed by",
    "connection reset",
    "no route to host",
    "network is unreachable",
    "kex_exchange_identification",
    "host key verification failed",
)


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
    key_path: Path | None = None,
    timeout: float | None = None,
    interval: float | None = None,
) -> list[str]:
    """Require an authenticated operator login through every published endpoint.

    A banner says the relay reaches an SSH server. It does not say the declared
    operator identity can log in, so disabled public-key authentication, a
    denied user, or a key installed where sshd never reads it all reported
    successful realization (issue #1105). The banner is still the cheap poll
    that tells us the far side is up; the access is only proven once a real
    login with the operator's key succeeds.
    """

    timeout = _READY_TIMEOUT_SECONDS if timeout is None else timeout
    interval = _READY_INTERVAL_SECONDS if interval is None else interval

    pending = {endpoint.relay_container: endpoint for endpoint in endpoints}
    reached: dict[str, OperatorAccessEndpoint] = {}
    deadline = time.monotonic() + timeout
    while pending:
        for name, endpoint in list(pending.items()):
            if ssh_banner_reachable(_LOOPBACK, resolved_host_port(endpoint)):
                reached[name] = pending.pop(name)
        if not pending or time.monotonic() >= deadline:
            break
        time.sleep(interval)
    failures = [
        f"operator access through {endpoint.relay_container} "
        f"(127.0.0.1:{resolved_host_port(endpoint)}) did not reach an SSH server "
        f"within {int(timeout)}s"
        for endpoint in pending.values()
    ]
    failures.extend(_unauthenticated(reached.values(), key_path))
    return failures


def _unauthenticated(
    endpoints: Iterable[OperatorAccessEndpoint], key_path: Path | None
) -> list[str]:
    """Return a failure for every endpoint the operator cannot actually log into."""

    endpoints = tuple(endpoints)
    if not endpoints:
        return []
    if key_path is None:
        return [
            "operator access cannot be proven: no operator private key was "
            "supplied to authenticate with"
        ]
    return [
        f"operator access to {endpoint.target_node} reached an SSH server but "
        f"{endpoint.login_user} could not authenticate with the operator key"
        for endpoint in endpoints
        if not ssh_login_succeeds(
            resolved_host_port(endpoint), endpoint.login_user, key_path
        )
    ]


def ssh_login_succeeds(port: int, user: str, key_path: Path) -> bool:
    """Return whether the operator's key authenticates as ``user`` on the port.

    What is proven is authentication, not a completed command. Kali's declared
    access terminates at the session-capture broker, a ``ForceCommand`` that
    deliberately refuses any session carrying no custody attribution — so
    reaching that refusal *is* the operator authenticating, and demanding a
    zero exit would fail every boot. Sending real attribution instead would
    mint a capture session on every start and write it into the run's own
    evidence, which a readiness probe has no business doing.

    ``BatchMode`` keeps it a key-only, non-interactive attempt: a server that
    falls back to a password prompt is not proof of the declared access. Host
    keys are deliberately not checked — the relay is a fresh loopback endpoint
    each run, and the identity that matters here is the operator's key.
    """

    completed = _run_login_attempt(port, user, key_path)
    if completed is None:
        return False
    if completed.returncode == 0:
        return True
    stderr = (completed.stderr or "").lower()
    return not any(
        marker in stderr
        for marker in (*_AUTH_FAILURE_MARKERS, *_TRANSPORT_FAILURE_MARKERS)
    )


def _run_login_attempt(
    port: int, user: str, key_path: Path
) -> "subprocess.CompletedProcess[str] | None":
    """Run one key-only login attempt, or None when it could not be made."""

    if not user or shutil.which("ssh") is None:
        return None
    try:
        return subprocess.run(
            [
                "ssh",
                "-i",
                str(key_path),
                "-p",
                str(port),
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                f"ConnectTimeout={_LOGIN_CONNECT_TIMEOUT_SECONDS}",
                f"{user}@{_LOOPBACK}",
                "true",
            ],
            capture_output=True,
            text=True,
            timeout=_LOGIN_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None


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
