"""Exact, lazy discovery for scenario capture providers."""

from __future__ import annotations

import re
from importlib import metadata

from aptl.backends.scenario_capture import (
    ENTRY_POINT_GROUP,
    EXTENSION_API_VERSION,
    ResolvedScenarioCapture,
    ScenarioCaptureContext,
    ScenarioCaptureContribution,
)
from aptl.core.experiment.capture_registry import CollectorRegistry
from aptl.utils.logging import get_logger

log = get_logger("scenario-capture")
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SAFE_ENV_KEY = re.compile(r"[A-Z][A-Z0-9_]{0,127}")


class ScenarioCaptureProviderError(RuntimeError):
    """Stable fail-closed diagnostic from capture-provider discovery."""


def _entry_points() -> list[metadata.EntryPoint]:
    """List capture providers without importing their targets."""

    return list(metadata.entry_points(group=ENTRY_POINT_GROUP))


def _sequence(provider: object, name: str) -> tuple[str, ...]:
    """Read one required provider identity tuple."""

    value = getattr(provider, name, None)
    if not isinstance(value, tuple) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ScenarioCaptureProviderError("provider-malformed")
    return value


def _compatible(provider: object, context: ScenarioCaptureContext) -> bool:
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
        raise ScenarioCaptureProviderError("provider-malformed")
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
            "capture provider load failed: selector=%s exception=%s",
            entry_point.name,
            type(exc).__name__,
        )
        raise ScenarioCaptureProviderError("provider-load-failed") from None


def _validate_contribution(value: object) -> ScenarioCaptureContribution:
    """Validate the bounded declaration returned by one provider."""

    if not isinstance(value, ScenarioCaptureContribution):
        raise ScenarioCaptureProviderError("provider-result-invalid")
    try:
        registry = CollectorRegistry(value.registrations)
    except (TypeError, ValueError):
        raise ScenarioCaptureProviderError("provider-result-invalid") from None
    ids = frozenset(item.registration_id for item in registry.registrations)
    if (
        not isinstance(value.native_registration_ids, frozenset)
        or not value.native_registration_ids.issubset(ids)
        or not isinstance(value.runtime_environment_keys, tuple)
        or len(set(value.runtime_environment_keys))
        != len(value.runtime_environment_keys)
        or any(
            not isinstance(key, str) or _SAFE_ENV_KEY.fullmatch(key) is None
            for key in value.runtime_environment_keys
        )
        or (
            value.transcript_registration_id is not None
            and value.transcript_registration_id not in ids
        )
    ):
        raise ScenarioCaptureProviderError("provider-result-invalid")
    return value


def resolve_scenario_capture(
    context: ScenarioCaptureContext,
) -> ResolvedScenarioCapture:
    """Resolve exactly one compatible installed capture provider."""

    selector = f"{context.pack.pack_id}.{context.backend.target_name}"
    compatible: list[tuple[metadata.EntryPoint, object]] = []
    for entry_point in _entry_points():
        if entry_point.name != selector:
            continue
        provider = _load(entry_point)
        if _compatible(provider, context):
            compatible.append((entry_point, provider))
    if len(compatible) != 1:
        code = "provider-missing" if not compatible else "provider-ambiguous"
        raise ScenarioCaptureProviderError(code)
    entry_point, provider = compatible[0]
    try:
        contribution = _validate_contribution(provider.resolve(context))
    except ScenarioCaptureProviderError:
        raise
    except Exception as exc:
        log.warning(
            "capture provider resolve failed: selector=%s exception=%s",
            selector,
            type(exc).__name__,
        )
        raise ScenarioCaptureProviderError("provider-resolve-failed") from None
    dist = getattr(entry_point, "dist", None)
    return ResolvedScenarioCapture(
        registry=CollectorRegistry(contribution.registrations),
        contribution=contribution,
        context=context,
        provider_id=provider.provider_id,
        extension_api_version=EXTENSION_API_VERSION,
        distribution=str(getattr(dist, "name", "") or ""),
        distribution_version=str(getattr(dist, "version", "") or ""),
        entry_point=selector,
    )


__all__ = ["ScenarioCaptureProviderError", "resolve_scenario_capture"]
