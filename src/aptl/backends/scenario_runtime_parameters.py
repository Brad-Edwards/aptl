"""Lazy adapter discovery for scenario-owned runtime parameter bindings."""

from __future__ import annotations

from collections.abc import Mapping
from importlib import metadata

from aptl.core.scenario_bundle import ScenarioBundle
from aptl.utils.logging import get_logger

log = get_logger("scenario-runtime-parameters")

ENTRY_POINT_GROUP = "aptl.scenario_runtime_parameters"
EXTENSION_API_VERSION = "1"


class RuntimeParameterProviderError(RuntimeError):
    """Stable fail-closed diagnostic for the runtime-parameter adapter seam."""


def _entry_points() -> list[metadata.EntryPoint]:
    return list(metadata.entry_points(group=ENTRY_POINT_GROUP))


def _load(entry_point: metadata.EntryPoint) -> object:
    try:
        provider = entry_point.load()
        if isinstance(provider, type):
            provider = provider()
    except Exception as exc:
        log.warning(
            "runtime parameter provider load failed: selector=%s exception=%s",
            entry_point.name,
            type(exc).__name__,
        )
        raise RuntimeParameterProviderError("provider-load-failed") from None
    return provider


def _compatible(provider: object, bundle: ScenarioBundle) -> bool:
    identity = bundle.pack_identity
    if identity is None:
        return False
    versions = getattr(provider, "supported_pack_versions", None)
    digests = getattr(provider, "supported_pack_set_digests", None)
    if (
        getattr(provider, "extension_api_version", None) != EXTENSION_API_VERSION
        or getattr(provider, "supported_pack_id", None) != identity.pack_id
        or not isinstance(versions, tuple)
        or not isinstance(digests, tuple)
        or any(
            not isinstance(value, str) or not value for value in (*versions, *digests)
        )
        or not callable(getattr(provider, "resolve", None))
    ):
        raise RuntimeParameterProviderError("provider-malformed")
    return identity.pack_version in versions and identity.set_digest in digests


def _validated_parameters(value: object) -> Mapping[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or any(
        not isinstance(name, str) or not name for name in value
    ):
        raise RuntimeParameterProviderError("provider-result-invalid")
    return dict(value)


def resolve_runtime_parameters(
    bundle: ScenarioBundle,
) -> Mapping[str, object] | None:
    """Resolve exact pack bindings without importing scenario code in core."""

    identity = bundle.pack_identity
    if identity is None:
        return None
    candidates = [
        entry_point
        for entry_point in _entry_points()
        if entry_point.name == identity.pack_id
    ]
    compatible: list[object] = []
    for entry_point in candidates:
        provider = _load(entry_point)
        if _compatible(provider, bundle):
            compatible.append(provider)
    if len(compatible) > 1:
        raise RuntimeParameterProviderError("provider-ambiguous")
    if not compatible:
        return None
    try:
        return _validated_parameters(compatible[0].resolve(bundle))
    except RuntimeParameterProviderError:
        raise
    except Exception as exc:
        log.warning(
            "runtime parameter provider resolve failed: selector=%s exception=%s",
            identity.pack_id,
            type(exc).__name__,
        )
        raise RuntimeParameterProviderError("provider-resolve-failed") from None


__all__ = [
    "ENTRY_POINT_GROUP",
    "EXTENSION_API_VERSION",
    "RuntimeParameterProviderError",
    "resolve_runtime_parameters",
]
