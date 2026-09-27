"""Small authored-value readers used by stateful realization."""

from __future__ import annotations

from collections.abc import Mapping

from raes_contracts.planning import PlannedResource


def resource_name(resource: PlannedResource) -> str:
    """Return the authored resource name or its address suffix."""

    return text(resource.payload.get("name")) or resource.address.rsplit(".", 1)[-1]


def choice(
    mapping: Mapping[str, object],
    key: str,
    allowed: frozenset[str],
) -> str | None:
    """Return a non-empty string only when it belongs to the allowed vocabulary."""

    value = text(mapping.get(key))
    return value if value in allowed else None


def text(value: object) -> str | None:
    """Return a non-empty string value without altering authored whitespace."""

    return value if isinstance(value, str) and value.strip() else None


def only(values: tuple[str, ...]) -> str | None:
    """Return the sole tuple member, rejecting absent or ambiguous bindings."""

    return values[0] if len(values) == 1 else None


__all__ = ("choice", "only", "resource_name", "text")
