"""Evidence-sized range snapshot summaries."""

from __future__ import annotations

from collections.abc import Mapping, Sequence


def summarize_snapshot(snapshot: Mapping[str, object]) -> dict[str, object]:
    """Return an evidence-sized view of a range snapshot.

    Keeps the operationally meaningful container and network fields (identity,
    health, attachments, published ports) and drops the verbose Compose label
    block, so a committed proof artifact stays reviewable. The source snapshot is
    already redacted by ``capture_snapshot`` (ADR-029); this only trims noise.
    """

    containers = [
        {
            "name": container.get("name"),
            "image": container.get("image"),
            "status": container.get("status"),
            "health": container.get("health"),
            "networks": container.get("networks"),
            "ports": container.get("ports"),
        }
        for container in _as_sequence(snapshot.get("containers"))
        if isinstance(container, Mapping)
    ]
    networks = [
        {
            "name": network.get("name"),
            "subnet": network.get("subnet"),
            "gateway": network.get("gateway"),
            "containers": network.get("containers"),
        }
        for network in _as_sequence(snapshot.get("networks"))
        if isinstance(network, Mapping)
    ]
    return {
        "timestamp": snapshot.get("timestamp"),
        "containers": containers,
        "networks": networks,
    }


def _as_sequence(value: object) -> Sequence[object]:
    """Return a list/tuple value as a sequence, or an empty tuple otherwise."""

    if isinstance(value, list | tuple):
        return value
    return ()
