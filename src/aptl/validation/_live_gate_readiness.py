"""Node-readiness / health-conformance comparison for the live validation gate.

Extracted from ``_live_gate_probes`` (SCN-010F / #323) to keep both modules
under the file-size budget. These helpers compare the realized ACES node
surface against the booted range's container snapshot: every realized node in a
started profile must map to a live container, and any container carrying a
healthcheck must actually report healthy.
``_live_gate_checks.check_defensive_stack_readiness`` imports
``_node_readiness_diagnostics`` and ``_warn_unhealthy_infra`` from here.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from aptl.backends.aces_profiles import normalize_identifier
from aptl.utils.logging import get_logger

log = get_logger("live-gate")


def _node_readiness_diagnostics(
    nodes: Sequence[Mapping[str, Any]],
    containers: Sequence[Mapping[str, Any]],
    selected: set[str],
) -> tuple[list[str], set[str]]:
    """Return (hard-failure diagnostics, matched container names) for realized nodes."""
    diagnostics: list[str] = []
    matched_names: set[str] = set()
    for node in nodes:
        # Only nodes whose profile is in the started subset get a container; a
        # declared node in a non-selected profile (e.g. mail/reverse when those
        # profiles are disabled) is correctly absent and not a readiness gap.
        if selected and not (set(node.get("profiles", ())) & selected):
            continue
        container = _live_container_for_node(node, containers)
        if container is None:
            diagnostics.append(
                f"realized node {node.get('name', '?')!r} has no live container"
            )
            continue
        matched_names.add(container.get("name", ""))
        diagnostics.extend(
            _container_health_diagnostics(node.get("name", "?"), container)
        )
    return diagnostics, matched_names


def _warn_unhealthy_infra(
    containers: Sequence[Mapping[str, Any]], matched_names: set[str]
) -> None:
    """Log unhealthy non-node infra containers as informational notes only."""
    for container in containers:
        if container.get("name", "") in matched_names:
            continue
        if container.get("health") == "unhealthy":
            log.warning(
                "non-node infra container unhealthy: %s", container.get("name", "?")
            )


def _container_health_diagnostics(
    node_name: str,
    container: Mapping[str, Any],
) -> list[str]:
    """Return hard-failure diagnostics for one realized node's container.

    Health is observed, never declared. aces-sdl 0.21.0 removed ``runtime.health``
    from the authored SDL contract (ACES #761): observed health is evidence, so
    there is no author-supplied expectation left to compare against — and nothing
    to fabricate one from.

    The container itself carries the expectation instead. A container reports a
    health state only when its image or Compose service defines a healthcheck, so
    a non-empty health field *is* the declaration that this service is meant to
    become healthy: it must reach ``healthy``. A container with no healthcheck
    reports nothing, and only has to be running.
    """
    status = str(container.get("status", ""))
    health = str(container.get("health", ""))
    if not status.startswith("Up"):
        diag = f"node {node_name!r} container not running (status={status!r})"
    elif health and health != "healthy":
        diag = (
            f"node {node_name!r} container defines a healthcheck but reports "
            f"health {health!r}, not 'healthy'"
        )
    else:
        diag = ""
    return [diag] if diag else []


def _live_container_for_node(
    node: Mapping[str, Any], containers: Sequence[Mapping[str, Any]]
) -> Mapping[str, Any] | None:
    """Match a realized node to a live container by normalized alias."""
    node_keys: set[str] = set()
    raw_values = [node.get("name", ""), *node.get("aliases", ())]
    for raw in raw_values:
        norm = normalize_identifier(str(raw))
        if norm:
            node_keys.add(norm)
            node_keys.add(norm.removeprefix("aptl-"))
    for container in containers:
        cname = normalize_identifier(str(container.get("name", "")))
        if cname in node_keys or cname.removeprefix("aptl-") in node_keys:
            return container
    return None
