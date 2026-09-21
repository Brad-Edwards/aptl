"""Exact discovery for bounded pack planning compatibility decisions."""

from __future__ import annotations

import re
from importlib import metadata

from aptl.backends.scenario_planning_compatibility import (
    ENTRY_POINT_GROUP,
    EXTENSION_API_VERSION,
    PERMITTED_DAEMON_READBACK_CONCERNS,
    PERMITTED_MINIMUM_INTRUSION_EXACT_CONCERNS,
    PERMITTED_OPEN_DEFAULT_CONCERNS,
    PlanningCompatibilityDecision,
    ResolvedPlanningCompatibility,
    ScenarioPlanningCompatibilityContext,
)
from aptl.utils.logging import get_logger

log = get_logger("scenario-planning-compatibility")
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SAFE_CONCERN = re.compile(r"[a-z][a-z0-9-]{0,127}")


class ScenarioPlanningCompatibilityError(RuntimeError):
    """Stable fail-closed diagnostic from planning-provider discovery."""


def _entry_points() -> list[metadata.EntryPoint]:
    """List planning providers without importing their targets."""

    return list(metadata.entry_points(group=ENTRY_POINT_GROUP))


def _sequence(provider: object, name: str) -> tuple[str, ...]:
    """Read one required provider identity tuple."""

    value = getattr(provider, name, None)
    if not isinstance(value, tuple) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ScenarioPlanningCompatibilityError("provider-malformed")
    return value


def _compatible(
    provider: object, context: ScenarioPlanningCompatibilityContext
) -> bool:
    """Check exact pack and backend compatibility."""

    provider_id = getattr(provider, "provider_id", "")
    if (
        not isinstance(provider_id, str)
        or _SAFE_ID.fullmatch(provider_id) is None
        or not isinstance(getattr(provider, "extension_api_version", None), str)
        or not isinstance(getattr(provider, "supported_pack_id", None), str)
        or not isinstance(getattr(provider, "backend_target_name", None), str)
        or not callable(getattr(provider, "resolve", None))
    ):
        raise ScenarioPlanningCompatibilityError("provider-malformed")
    transports = _sequence(provider, "backend_transports")
    return all(
        (
            provider.extension_api_version == EXTENSION_API_VERSION,
            provider.supported_pack_id == context.pack.pack_id,
            provider.backend_target_name == context.backend.target_name,
            context.pack.pack_version in _sequence(provider, "supported_pack_versions"),
            context.pack.set_digest
            in _sequence(provider, "supported_pack_set_digests"),
            context.backend.target_version
            in _sequence(provider, "backend_target_versions"),
            context.backend.profile in _sequence(provider, "backend_profiles"),
            not transports or context.backend.transport in transports,
        )
    )


def _load(entry_point: metadata.EntryPoint) -> object:
    """Load one provider while redacting implementation failures."""

    try:
        target = entry_point.load()
        return target() if isinstance(target, type) else target
    except Exception as exc:
        log.warning(
            "planning compatibility provider load failed: selector=%s exception=%s",
            entry_point.name,
            type(exc).__name__,
        )
        raise ScenarioPlanningCompatibilityError("provider-load-failed") from None


def _validated_decision(value: object) -> PlanningCompatibilityDecision:
    """Validate the provider's finite, core-enforced decision."""

    if not isinstance(value, PlanningCompatibilityDecision):
        raise ScenarioPlanningCompatibilityError("provider-result-invalid")
    concern_sets = (
        (value.daemon_readback_concerns, PERMITTED_DAEMON_READBACK_CONCERNS),
        (value.open_default_concerns, PERMITTED_OPEN_DEFAULT_CONCERNS),
        (
            value.minimum_intrusion_exact_concerns,
            PERMITTED_MINIMUM_INTRUSION_EXACT_CONCERNS,
        ),
    )
    if not all(
        _valid_concern_set(items, permitted) for items, permitted in concern_sets
    ):
        raise ScenarioPlanningCompatibilityError("provider-result-invalid")
    if not _valid_runtime_max_nodes(value.runtime_max_nodes):
        raise ScenarioPlanningCompatibilityError("provider-result-invalid")
    return value


def _valid_concern_set(items: object, permitted: frozenset[str]) -> bool:
    """Return whether a concern set is finite, well formed, and authorized."""

    return (
        isinstance(items, frozenset)
        and len(items) <= 256
        and all(
            isinstance(item, str) and _SAFE_CONCERN.fullmatch(item) is not None
            for item in items
        )
        and items.issubset(permitted)
    )


def _valid_runtime_max_nodes(value: object) -> bool:
    """Return whether the optional node budget is a bounded integer."""

    return value is None or (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= 1_048_576
    )


def resolve_scenario_planning_compatibility(
    context: ScenarioPlanningCompatibilityContext,
) -> ResolvedPlanningCompatibility | None:
    """Return the one compatible decision; absence means no compatibility."""

    selector = f"{context.pack.pack_id}.{context.backend.target_name}"
    compatible: list[tuple[metadata.EntryPoint, object]] = []
    for entry_point in _entry_points():
        if entry_point.name != selector:
            continue
        provider = _load(entry_point)
        if _compatible(provider, context):
            compatible.append((entry_point, provider))
    if not compatible:
        return None
    if len(compatible) != 1:
        raise ScenarioPlanningCompatibilityError("provider-ambiguous")
    entry_point, provider = compatible[0]
    try:
        decision = _validated_decision(provider.resolve(context))
    except ScenarioPlanningCompatibilityError:
        raise
    except Exception as exc:
        log.warning(
            "planning compatibility provider resolve failed: selector=%s exception=%s",
            selector,
            type(exc).__name__,
        )
        raise ScenarioPlanningCompatibilityError("provider-resolve-failed") from None
    dist = getattr(entry_point, "dist", None)
    return ResolvedPlanningCompatibility(
        decision=decision,
        provider_id=provider.provider_id,
        extension_api_version=EXTENSION_API_VERSION,
        distribution=str(getattr(dist, "name", "") or ""),
        distribution_version=str(getattr(dist, "version", "") or ""),
        entry_point=selector,
    )


__all__ = [
    "ScenarioPlanningCompatibilityError",
    "resolve_scenario_planning_compatibility",
]
