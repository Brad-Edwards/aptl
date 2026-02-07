"""Service readiness polling.

Provides a generic retry-poll loop and specific readiness checks for
Wazuh Indexer, Manager API, and SSH services.
"""

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from aptl.utils.logging import get_logger

log = get_logger("services")


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
) -> ServiceResult:
    """Poll a service until it becomes ready or timeout is exceeded.

    Args:
        check_fn: Callable that returns True when the service is ready.
                  May raise exceptions, which are treated as failures.
        timeout: Maximum seconds to wait.
        interval: Seconds between checks.
        service_name: Human-readable name for logging.

    Returns:
        ServiceResult indicating whether the service became ready and
        how long the wait took.
    """
    start = time.monotonic()
    deadline = start + timeout

    log.info("Waiting for %s (timeout=%ds, interval=%ds)", service_name, timeout, interval)

    while True:
        try:
            if check_fn():
                elapsed = time.monotonic() - start
                log.info("%s is ready (%.1fs)", service_name, elapsed)
                return ServiceResult(ready=True, elapsed_seconds=elapsed)
        except Exception as exc:
            log.debug("%s check raised %s: %s", service_name, type(exc).__name__, exc)

        now = time.monotonic()
        if now >= deadline:
            elapsed = now - start
            log.warning("%s timed out after %.1fs", service_name, elapsed)
            return ServiceResult(
                ready=False,
                elapsed_seconds=elapsed,
                error=f"{service_name} timed out after {elapsed:.0f}s",
            )

        time.sleep(interval)


def check_indexer_ready(url: str, username: str, password: str) -> bool:
    """Check if the Wazuh Indexer is responding to HTTPS requests.

    Uses curl to make an insecure HTTPS request (self-signed certs).

    Args:
        url: The indexer URL (e.g., ``https://localhost:9200``).
        username: Authentication username.
        password: Authentication password.

    Returns:
        True if the indexer responds successfully, False otherwise.
    """
    try:
        result = subprocess.run(
            [
                "curl", "-k", "-s", "-f",
                url,
                "-u", f"{username}:{password}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        log.debug("Indexer check failed: %s", exc)
        return False


def check_manager_api_ready(
    container_name: str, username: str, password: str
) -> bool:
    """Check if the Wazuh Manager API is responding inside the container.

    Uses ``docker exec`` to run curl inside the manager container.

    Args:
        container_name: Docker container name for the manager.
        username: API authentication username.
        password: API authentication password.

    Returns:
        True if the API responds successfully, False otherwise.
    """
    try:
        result = subprocess.run(
            [
                "docker", "exec", container_name,
                "curl", "-k", "-s", "-f",
                "https://localhost:55000",
                "-u", f"{username}:{password}",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        log.debug("Manager API check failed: %s", exc)
        return False


def test_ssh_connection(
    host: str, port: int, user: str, key_path: Path
) -> bool:
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
                "-i", str(key_path),
                "-o", "ConnectTimeout=5",
                "-o", "StrictHostKeyChecking=no",
                "-o", "BatchMode=yes",
                "-p", str(port),
                f"{user}@{host}",
                "echo", "SSH OK",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        log.debug("SSH connection test failed: %s", exc)
        return False
