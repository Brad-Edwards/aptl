"""Backend-observed service health for realized scenario nodes (issue #578).

``docker compose up -d`` returns as soon as the daemon has *created* the
containers. It says nothing about whether the declared services actually came
up, so treating its exit code as "the scenario is realized" is the vacuous
realization ADR-046's runtime addendum forbids: a resource counts as realized
only once the backend has started it *and* observed it.

Health here is observed, never declared. aces-sdl 0.21.0 removed
``runtime.health`` from the authored SDL contract (ACES #761) precisely because
observed health is evidence, not an author declaration — so there is no declared
status to compare against and nothing to fabricate one from. The container
carries its own expectation instead: it reports a health state only when its
image or Compose service defines a healthcheck, so a non-empty health state is
that check's own claim and must reach ``healthy``. A container with no
healthcheck reports nothing and only has to be running.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

from aptl.core.services import wait_for_service
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

log = get_logger("realization-health")

# The SOC stack sets the floor here: `lab.py` already allows the Wazuh indexer
# and manager APIs 120s each to come up, and a realized scenario waits on the
# whole selected topology at once (indexer, manager, dashboard, and the victim
# services) rather than one service. The budget must cover the slowest observed
# *first-boot* path, not just a warm restart: on a fresh machine TheHive's
# initial Cassandra schema + Elasticsearch index creation and MISP's first-boot
# database load run well past 300s (observed ~8 minutes on a loaded host while
# every other service was already healthy — issue #677). Timing out early is
# not fail-safe here: the timeout hands control to the admitted-plan retry,
# whose `compose up` recreates services mid-initialization and can tear
# Cassandra's commit log. 900s keeps a generous margin over that observed
# worst case; a genuinely stuck service still fails closed, just after the
# budget rather than before it.
REALIZATION_HEALTH_TIMEOUT = 900
REALIZATION_HEALTH_INTERVAL = 5


def container_health(info: dict[str, Any]) -> str:
    """Return a container's observed health, or ``""`` when it has no healthcheck.

    Reads ``docker inspect`` ``State.Health.Status``. Docker omits ``Health``
    entirely for a container whose image and Compose service define no
    healthcheck, which is exactly the "nothing was claimed" case.
    """

    state = info.get("State")
    if not isinstance(state, dict):
        return ""
    health = state.get("Health")
    if not isinstance(health, dict):
        return ""
    status = health.get("Status")
    return status if isinstance(status, str) else ""


def container_running(info: dict[str, Any]) -> bool:
    """Return whether ``docker inspect`` reports the container as running."""

    state = info.get("State")
    return bool(state.get("Running")) if isinstance(state, dict) else False


def container_settled(info: dict[str, Any]) -> bool:
    """Return whether a container has reached its final, realized state."""

    if not container_running(info):
        return False
    health = container_health(info)
    return not health or health == "healthy"


def unhealthy_container_reasons(
    backend: "DeploymentBackend",
    container_names: Sequence[str],
) -> list[str]:
    """Return one operator-facing reason per container that is not realized."""

    reasons: list[str] = []
    for name in container_names:
        info = backend.container_inspect(name)
        if not info:
            reasons.append(f"container {name!r} was never created")
        elif not container_running(info):
            reasons.append(f"container {name!r} is not running")
        else:
            health = container_health(info)
            if health and health != "healthy":
                reasons.append(
                    f"container {name!r} defines a healthcheck but reports "
                    f"health {health!r}, not 'healthy'"
                )
    return reasons


def wait_for_realized_health(
    backend: "DeploymentBackend",
    container_names: Sequence[str],
    *,
    timeout: int = REALIZATION_HEALTH_TIMEOUT,
    interval: int = REALIZATION_HEALTH_INTERVAL,
    time_source: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> list[str]:
    """Wait for every realized container to settle; return failures, if any.

    Returns an empty list once all containers are running and every container
    carrying a healthcheck reports ``healthy``. On timeout, returns one reason
    per container that did not get there, so the caller fails closed with an
    operator-actionable message instead of reporting a lab that never came up as
    realized.
    """

    names = [name for name in container_names if name]
    if not names:
        return []

    # `compose up` has already returned, so every service it was asked to start
    # exists by now. A container that is still absent is never going to appear,
    # and polling for it would burn the whole budget before reporting a failure
    # we can already prove. Waiting is only for containers that exist and have
    # yet to settle.
    missing = [
        f"container {name!r} was never created"
        for name in names
        if not backend.container_inspect(name)
    ]
    if missing:
        return missing

    return _await_all_settled(
        backend,
        names,
        timeout=timeout,
        interval=interval,
        time_source=time_source,
        sleep=sleep,
    )


def _await_all_settled(
    backend: "DeploymentBackend",
    names: Sequence[str],
    *,
    timeout: int,
    interval: int,
    time_source: Callable[[], float],
    sleep: Callable[[float], None],
) -> list[str]:
    """Poll existing containers until all settle; return reasons on timeout."""

    def all_settled() -> bool:
        """Return whether every awaited container is running and healthy."""
        return all(
            container_settled(backend.container_inspect(name)) for name in names
        )

    result = wait_for_service(
        check_fn=all_settled,
        timeout=timeout,
        interval=interval,
        service_name=f"{len(names)} realized service(s)",
        time_source=time_source,
        sleep=sleep,
    )
    if result.ready:
        return []
    reasons = unhealthy_container_reasons(backend, names) or [
        f"realized services did not become healthy within {timeout}s",
    ]
    log.warning(
        "realized services did not become healthy within %ss: %s",
        timeout,
        "; ".join(reasons[:5]),
    )
    return reasons
