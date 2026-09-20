"""Bounded invocation of one already-selected scenario startup provider."""

from __future__ import annotations

from aptl.core.scenario_bundle import PackIdentity
from aptl.utils.logging import get_logger

log = get_logger("scenario-runtime-hooks")


def invoke_runtime_provider(
    provider: object,
    identity: PackIdentity | None,
    backend: object,
    nodes: tuple[object, ...],
) -> list[str]:
    """Invoke post-start work and normalize its bounded failure list."""

    runner = getattr(provider, "realize_runtime", None)
    if runner is None:
        return []
    if not callable(runner):
        return ["scenario runtime provider is malformed"]
    try:
        failures = runner(backend, nodes)
    except Exception as exc:
        log.warning(
            "scenario runtime provider failed: selector=%s exception=%s",
            getattr(identity, "pack_id", ""),
            type(exc).__name__,
        )
        return ["scenario runtime provider failed"]
    if not isinstance(failures, list) or any(
        not isinstance(item, str) or not item for item in failures
    ):
        return ["scenario runtime provider returned an invalid result"]
    return failures


def invoke_runtime_observer(
    provider: object | None,
    identity: PackIdentity | None,
    backend: object,
    node: object,
) -> object | None:
    """Read one qualified adapter result, leaving projection to the caller."""

    try:
        observer = getattr(provider, "observe_runtime", None) if provider else None
        if observer is None:
            return None
        if not callable(observer):
            raise TypeError("scenario runtime observer is malformed")
        return observer(backend, node)
    except Exception as exc:
        log.warning(
            "scenario runtime observation failed: selector=%s exception=%s",
            getattr(identity, "pack_id", ""),
            type(exc).__name__,
        )
        return None
