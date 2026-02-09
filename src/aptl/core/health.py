"""Container health checking and readiness polling."""

import time
from dataclasses import dataclass, field
from typing import Optional

from aptl.utils.logging import get_logger

log = get_logger("health")


class ContainerNotFoundError(Exception):
    """Raised when a Docker container cannot be found."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"Container not found: {name}")


@dataclass
class HealthResult:
    """Result of a single container health check."""

    container_name: str
    healthy: bool
    status: str = ""
    error: Optional[str] = None


@dataclass
class HealthSummary:
    """Aggregated health status across multiple containers."""

    all_healthy: bool
    healthy_count: int
    unhealthy_count: int
    results: list[HealthResult] = field(default_factory=list)


def check_container_health(
    container_name: str,
    *,
    client: object,
    retries: int = 1,
    retry_delay: float = 1.0,
) -> HealthResult:
    """Check the health of a single container.

    Supports retry logic for transient failures (e.g., container still starting).

    Args:
        container_name: Name of the Docker container.
        client: A Docker client (or mock) with containers.get().
        retries: Number of attempts before giving up.
        retry_delay: Seconds to wait between retries.

    Returns:
        HealthResult indicating container health status.
    """
    last_error: Optional[str] = None

    for attempt in range(retries):
        try:
            container = client.containers.get(container_name)
        except ContainerNotFoundError:
            last_error = f"Container '{container_name}' not found"
            log.warning(
                "Attempt %d/%d: %s", attempt + 1, retries, last_error
            )
            if attempt < retries - 1:
                time.sleep(retry_delay)
            continue

        container_status = container.status
        health_info = container.attrs.get("State", {}).get("Health", {})
        health_status = health_info.get("Status", "")

        if health_status:
            # Container has a healthcheck defined
            is_healthy = health_status == "healthy"
            log.debug(
                "Container %s health=%s status=%s",
                container_name,
                health_status,
                container_status,
            )
            return HealthResult(
                container_name=container_name,
                healthy=is_healthy,
                status=health_status,
            )
        else:
            # No healthcheck: fall back to container running status
            is_healthy = container_status == "running"
            log.debug(
                "Container %s (no healthcheck) status=%s",
                container_name,
                container_status,
            )
            return HealthResult(
                container_name=container_name,
                healthy=is_healthy,
                status=container_status,
            )

    return HealthResult(
        container_name=container_name,
        healthy=False,
        status="not_found",
        error=last_error,
    )


def aggregate_health(results: list[HealthResult]) -> HealthSummary:
    """Aggregate multiple container health results into a summary.

    Args:
        results: List of individual health check results.

    Returns:
        HealthSummary with counts and overall status.
    """
    if not results:
        return HealthSummary(
            all_healthy=False,
            healthy_count=0,
            unhealthy_count=0,
            results=[],
        )

    healthy_count = sum(1 for r in results if r.healthy)
    unhealthy_count = len(results) - healthy_count

    return HealthSummary(
        all_healthy=unhealthy_count == 0,
        healthy_count=healthy_count,
        unhealthy_count=unhealthy_count,
        results=results,
    )
