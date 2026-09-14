"""Service readiness polling.

Provides a generic retry-poll loop and specific readiness checks for
Wazuh Indexer, Manager API, and SSH services.
"""

import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from aptl.utils.curl_safe import CurlOutcome, basic_auth_header, curl_request
from aptl.utils.logging import get_logger

log = get_logger("services")

ProgressCallback = Callable[[str], None]
_PROGRESS_INTERVAL_SECONDS = 30


@dataclass
class ServiceResult:
    """Result of a service readiness check."""

    ready: bool
    elapsed_seconds: float = 0.0
    error: str = ""


def wait_for_service(
    check_fn: Callable[[], bool],
    timeout: int,
    interval: int,
    service_name: str,
    *,
    time_source: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    progress: ProgressCallback | None = None,
) -> ServiceResult:
    """Poll a service until it becomes ready or timeout is exceeded.

    Args:
        check_fn: Callable that returns True when the service is ready.
                  May raise exceptions, which are treated as failures.
        timeout: Maximum seconds to wait.
        interval: Seconds between checks.
        service_name: Human-readable name for logging.
        time_source: Monotonic clock, injectable so tests drive the deadline
            with an explicit value sequence instead of patching the module.
        sleep: Sleep function, injectable so tests don't actually block.
        progress: Optional callback for participant-facing progress updates.

    Returns:
        ServiceResult indicating whether the service became ready and
        how long the wait took.
    """
    start = time_source()
    deadline = start + timeout
    next_progress_elapsed = 0.0
    bounded_progress_interval = max(_PROGRESS_INTERVAL_SECONDS, interval)

    log.info(
        "Waiting for %s (timeout=%ds, interval=%ds)", service_name, timeout, interval
    )

    while True:
        try:
            if check_fn():
                elapsed = time_source() - start
                log.info("%s is ready (%.1fs)", service_name, elapsed)
                return ServiceResult(ready=True, elapsed_seconds=elapsed)
        except Exception as exc:
            log.debug("%s check raised %s: %s", service_name, type(exc).__name__, exc)

        now = time_source()
        elapsed = max(0.0, now - start)
        if progress is not None and elapsed >= next_progress_elapsed:
            progress(
                f"Readiness: {service_name} still waiting ({int(elapsed)}/{timeout}s)."
            )
            next_progress_elapsed = elapsed + bounded_progress_interval
        if now >= deadline:
            log.warning("%s timed out after %.1fs", service_name, elapsed)
            return ServiceResult(
                ready=False,
                elapsed_seconds=elapsed,
                error=f"{service_name} timed out after {elapsed:.0f}s",
            )

        # Never sleep past the deadline: the last check runs at the deadline,
        # not an interval after it (#1002).
        sleep(min(interval, deadline - now))


@dataclass(frozen=True)
class WazuhApiProbe:
    """Secret-free outcome of one phased Wazuh indexer or manager API probe.

    ``phase`` is the phase that stopped the probe (``transport``,
    ``authentication``, ``manager_status``) or ``ready``. ``category`` is the
    normalized reason: a ``curl_safe`` transport category such as
    ``tls_handshake``, or ``credentials_rejected``, ``http_error``,
    ``invalid_response``, ``not_ready``. Only numeric curl and HTTP codes are
    kept -- never a URL, header, token, body, or curl stderr.
    """

    phase: str
    category: str
    curl_exit: int | None = None
    http_status: int | None = None

    @property
    def ready(self) -> bool:
        """Return whether every phase succeeded."""

        return self.phase == "ready"

    def describe(self) -> str:
        """Return a bounded, operator-facing summary of this outcome."""

        if self.ready:
            return "ready"
        if self.http_status is not None:
            code = f" (HTTP {self.http_status})"
        elif self.curl_exit is not None:
            code = f" (curl exit {self.curl_exit})"
        else:
            code = ""
        return f"{self.phase} phase failed: {self.category}{code}"


def probe_indexer_api(url: str, username: str, password: str) -> WazuhApiProbe:
    """Probe the Wazuh indexer API phase by phase and classify the outcome.

    Transport first, with a credential-free request: any HTTP status proves
    TCP, TLS, and HTTP completed. Only then does the probe authenticate, and
    ready means a 2xx for the configured credentials. A 401/403 is the
    retained-volume credential mismatch from #623. One attempt, no retries;
    the polling owner holds the deadline (#1002).
    """

    base = url.rstrip("/")
    transport = curl_request(f"{base}/", insecure=True, timeout=10)
    if transport.http_status is None:
        return _api_failure("transport", transport)
    auth = curl_request(
        f"{base}/",
        auth_header=basic_auth_header(username, password),
        insecure=True,
        timeout=10,
    )
    status = auth.http_status
    if status is not None and 200 <= status < 300:
        return WazuhApiProbe("ready", "ready", http_status=status)
    return _api_failure("authentication", auth)


def probe_manager_api(url: str, username: str, password: str) -> WazuhApiProbe:
    """Probe the Wazuh manager API phase by phase and classify the outcome.

    Transport comes first, with a credential-free request: any HTTP status
    proves TCP, TLS, and HTTP completed, so a listener that is still starting
    is observed without sending credentials to it. Only then does the probe
    authenticate and require a semantically successful manager status. It
    performs one attempt and never retries; the polling owner holds the
    deadline and decides whether a failure is warm-up or terminal (#1002).
    """

    base = url.rstrip("/")
    transport = curl_request(f"{base}/", insecure=True, timeout=10)
    if transport.http_status is None:
        return _api_failure("transport", transport)

    auth = curl_request(
        f"{base}/security/user/authenticate",
        auth_header=basic_auth_header(username, password),
        insecure=True,
        method="POST",
        timeout=10,
    )
    token = _manager_api_token(auth.payload) if auth.http_status == 200 else None
    if token is None:
        return _api_failure("authentication", auth)

    status = curl_request(
        f"{base}/manager/status",
        auth_header=f"Bearer {token}",
        insecure=True,
        timeout=10,
    )
    if status.http_status != 200:
        return _api_failure("manager_status", status)
    if not _manager_status_ready(status.payload):
        return WazuhApiProbe("manager_status", "not_ready", http_status=200)
    return WazuhApiProbe("ready", "ready", http_status=200)


def _api_failure(phase: str, outcome: CurlOutcome) -> WazuhApiProbe:
    """Classify a failed request in *phase* from its transport outcome."""

    if outcome.http_status is None:
        category = outcome.category
    elif outcome.http_status in (401, 403):
        category = "credentials_rejected"
    elif outcome.http_status == 200:
        category = "invalid_response"
    else:
        category = "http_error"
    return WazuhApiProbe(phase, category, outcome.exit_code, outcome.http_status)


def _manager_api_token(payload: object) -> str | None:
    """Extract a non-empty authentication token from a manager response."""

    if not isinstance(payload, Mapping) or payload.get("error") != 0:
        return None
    data = payload.get("data")
    token = data.get("token") if isinstance(data, Mapping) else None
    return token if isinstance(token, str) and token else None


def _manager_status_ready(payload: object) -> bool:
    """Return whether the manager status response contains affected items."""

    if not isinstance(payload, Mapping) or payload.get("error") != 0:
        return False
    data = payload.get("data")
    affected = data.get("affected_items") if isinstance(data, Mapping) else None
    return isinstance(affected, list) and bool(affected)


#: ssh(1) reserves this for its own failure -- no connection, no host key
#: agreement, or no accepted credential. Every other status came back from the
#: remote side, which means the session authenticated.
_SSH_TRANSPORT_FAILURE = 255


def test_ssh_connection(host: str, port: int, user: str, key_path: Path) -> bool:
    """Test SSH connectivity to a lab container.

    Reachability means the transport came up and the key authenticated, not
    that the probe obtained a shell. A capture-wrapped target refuses one on
    purpose: kali's sshd runs the capture wrapper as its ``ForceCommand``, and a
    session carrying no control-plane-issued capture capability is denied with
    exit 70, because an authenticated participant must never receive an
    unrecorded shell. Requiring exit 0 therefore reported every such target as
    unreachable, degrading a lab whose SSH was working.

    A remote exit status of any kind only exists because ssh connected and
    authenticated first, so only ssh's own ``255`` means the transport or the
    key failed. Whether a *wrapped* session works is a different question,
    answered by participant qualification rather than by a reachability probe.

    Args:
        host: SSH host (usually localhost).
        port: SSH port (mapped from container).
        user: SSH username.
        key_path: Path to the SSH private key.

    Returns:
        True if the target authenticated the key, False otherwise.
    """
    try:
        result = subprocess.run(
            [
                "ssh",
                "-i",
                str(key_path),
                "-o",
                "ConnectTimeout=5",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "BatchMode=yes",
                "-p",
                str(port),
                f"{user}@{host}",
                "echo",
                "SSH OK",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        return result.returncode != _SSH_TRANSPORT_FAILURE
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        log.debug("SSH connection test failed: %s", exc)
        return False
