"""Service readiness polling.

Provides a generic retry-poll loop and specific readiness checks for
Wazuh Indexer, Manager API, and SSH services.
"""

import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from aptl.utils.curl_safe import basic_auth_header, curl_json, curl_status
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

        sleep(interval)


def check_indexer_status(url: str, username: str, password: str) -> int | None:
    """Return the Wazuh Indexer's HTTP status, or ``None`` for no response.

    This is the classification probe: it distinguishes "not listening
    yet" (``None``) from "listening but rejecting the configured
    credentials" (401/403), which a plain readiness boolean cannot.
    Credentials are passed via a 0600 header temp file, never argv
    (ADR-029) — see ``aptl.utils.curl_safe.curl_status``.

    Args:
        url: The indexer URL (e.g., ``https://localhost:9200``).
        username: Authentication username.
        password: Authentication password.

    Returns:
        The HTTP status code, or ``None`` if the indexer gave no HTTP
        response at all (transport failure, timeout, connection refused).
    """
    return curl_status(url, auth=(username, password), insecure=True, timeout=10)


def check_indexer_ready(url: str, username: str, password: str) -> bool:
    """Check if the Wazuh Indexer is responding to HTTPS requests.

    Delegates to :func:`check_indexer_status`; ready means a 2xx status
    was returned for the given credentials.

    Args:
        url: The indexer URL (e.g., ``https://localhost:9200``).
        username: Authentication username.
        password: Authentication password.

    Returns:
        True if the indexer responds with a 2xx status, False otherwise.
    """
    status = check_indexer_status(url, username, password)
    return status is not None and 200 <= status < 300


def check_manager_api_ready(url: str, username: str, password: str) -> bool:
    """Authenticate and require a semantically successful manager status."""

    base = url.rstrip("/")
    auth = curl_json(
        f"{base}/security/user/authenticate",
        auth_header=basic_auth_header(username, password),
        insecure=True,
        method="POST",
        timeout=10,
    )
    token = _manager_api_token(auth)
    if token is None:
        return False
    status = curl_json(
        f"{base}/manager/status",
        auth_header=f"Bearer {token}",
        insecure=True,
        timeout=10,
    )
    return _manager_status_ready(status)


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


def test_ssh_connection(host: str, port: int, user: str, key_path: Path) -> bool:
    """Test SSH connectivity to a lab container.

    Args:
        host: SSH host (usually localhost).
        port: SSH port (mapped from container).
        user: SSH username.
        key_path: Path to the SSH private key.

    Returns:
        True if SSH connection succeeds, False otherwise.
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
        return result.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        log.debug("SSH connection test failed: %s", exc)
        return False
