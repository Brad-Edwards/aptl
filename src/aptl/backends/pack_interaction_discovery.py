"""Exact, lazy discovery for deployment-serving interaction providers."""

from __future__ import annotations

import re
from importlib import metadata
from time import monotonic

from aptl.backends.pack_interaction import (
    ENTRY_POINT_GROUP,
    EXTENSION_API_VERSION,
    ComponentGroupMembership,
    PackBackendInteractionContext,
    PackBackendInteractionResult,
    ResolvedPackBackendInteraction,
)
from aptl.core.provenance.identity import derive_identity
from aptl.utils.logging import get_logger

log = get_logger("pack-backend-interaction")

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_DEFAULT_PROVIDER_ID = "aptl.core.unprofiled-default"


class PackBackendInteractionError(RuntimeError):
    """A stable fail-closed diagnostic from the serving interaction seam."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _entry_points() -> list[metadata.EntryPoint]:
    """Return installed deployment-serving interaction entry points."""

    return list(metadata.entry_points(group=ENTRY_POINT_GROUP))


def _selector(context: PackBackendInteractionContext) -> str:
    """Return the exact pack/backend family selector for ``context``."""

    return f"{context.pack.pack_id}.{context.backend.target_name}"


def _mapping_digest(
    memberships: tuple[ComponentGroupMembership, ...],
) -> str:
    """Derive the stable identity of a validated membership mapping."""

    return derive_identity(
        "pack-serving",
        {
            "memberships": [
                {
                    "component_address": membership.component_address,
                    "groups": list(membership.groups),
                }
                for membership in memberships
            ]
        },
    )


def _validate_context(context: PackBackendInteractionContext) -> None:
    """Reject contexts whose bounded collections are not canonical."""

    addresses = context.component_addresses
    groups = context.operator_groups
    if (
        any(not isinstance(value, str) or not value for value in addresses)
        or tuple(sorted(addresses)) != addresses
        or len(set(addresses)) != len(addresses)
        or any(not isinstance(value, str) or not value for value in groups)
        or len(set(groups)) != len(groups)
    ):
        raise PackBackendInteractionError("context-invalid")


def _sequence(provider: object, name: str) -> tuple[str, ...]:
    """Read one required tuple-of-strings provider metadata field."""

    value = getattr(provider, name, None)
    if not isinstance(value, tuple) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise PackBackendInteractionError("provider-malformed")
    return value


def _provider_id(provider: object) -> str:
    """Return a provider's validated, evidence-safe identifier."""

    provider_id = getattr(provider, "provider_id", "")
    if not isinstance(provider_id, str) or _SAFE_ID.fullmatch(provider_id) is None:
        raise PackBackendInteractionError("provider-malformed")
    return provider_id


def _extension_api_version(provider: object) -> str:
    """Return a provider's required extension API version."""

    value = getattr(provider, "extension_api_version", None)
    if not isinstance(value, str) or not value:
        raise PackBackendInteractionError("provider-malformed")
    return value


def _scalar_claim_matches(
    provider: object,
    context: PackBackendInteractionContext,
    extension_api_version: str,
) -> bool:
    """Return whether scalar provider metadata claims this context."""

    observed = (
        extension_api_version,
        getattr(provider, "supported_pack_id", None),
        getattr(provider, "backend_target_name", None),
    )
    expected = (
        EXTENSION_API_VERSION,
        context.pack.pack_id,
        context.backend.target_name,
    )
    return observed == expected


def _sequence_claim_matches(
    provider: object, context: PackBackendInteractionContext
) -> bool:
    """Return whether bounded version, digest, profile, and transport claims match."""

    checks = (
        context.pack.pack_version in _sequence(provider, "supported_pack_versions"),
        context.pack.set_digest in _sequence(provider, "supported_pack_set_digests"),
        context.backend.target_version in _sequence(provider, "backend_target_versions"),
        context.backend.profile in _sequence(provider, "backend_profiles"),
    )
    transports = _sequence(provider, "backend_transports")
    transport_matches = not transports or context.backend.transport in transports
    return all(checks) and transport_matches


def _compatible_provider_id(
    provider: object, context: PackBackendInteractionContext
) -> str | None:
    """Return a compatible provider id, or ``None`` for a different claim.

    Entry-point names narrow discovery to one pack/backend family. Version,
    digest, profile, and transport metadata decide whether each installed
    candidate claims this exact validated context; stale or differently scoped
    providers can therefore coexist without suppressing the default.
    """

    provider_id = _provider_id(provider)
    extension_api_version = _extension_api_version(provider)
    if not _scalar_claim_matches(provider, context, extension_api_version):
        return None
    if not _sequence_claim_matches(provider, context):
        return None
    if not callable(getattr(provider, "resolve", None)):
        raise PackBackendInteractionError("provider-malformed")
    return provider_id


def _load(entry_point: metadata.EntryPoint) -> object:
    """Load one selector candidate and contain all provider exceptions."""

    try:
        target = entry_point.load()
        if isinstance(target, type) or (
            callable(target) and not callable(getattr(target, "resolve", None))
        ):
            target = target()
    except Exception as exc:
        log.warning(
            "pack interaction provider load failed: selector=%s exception=%s",
            entry_point.name,
            type(exc).__name__,
        )
        raise PackBackendInteractionError("provider-load-failed") from None
    return target


def _validated_membership(
    membership: ComponentGroupMembership,
    expected: set[str],
    seen: set[str],
    allowed_groups: set[str],
) -> ComponentGroupMembership:
    """Copy one exact membership after validating address and group bounds."""

    address = membership.component_address
    groups = membership.groups
    if address not in expected or address in seen:
        raise PackBackendInteractionError("mapping-invalid")
    if (
        not isinstance(groups, tuple)
        or any(
            not isinstance(group, str) or group not in allowed_groups
            for group in groups
        )
        or len(set(groups)) != len(groups)
    ):
        raise PackBackendInteractionError("mapping-invalid")
    seen.add(address)
    return ComponentGroupMembership(
        component_address=address,
        groups=tuple(sorted(groups)),
    )


def _validate_result(
    result: object, context: PackBackendInteractionContext
) -> tuple[ComponentGroupMembership, ...]:
    """Validate and immutably copy one provider's total mapping."""

    if not isinstance(result, PackBackendInteractionResult):
        raise PackBackendInteractionError("mapping-invalid")
    memberships = result.memberships
    if not isinstance(memberships, tuple) or any(
        not isinstance(item, ComponentGroupMembership) for item in memberships
    ):
        raise PackBackendInteractionError("mapping-invalid")

    expected = set(context.component_addresses)
    seen: set[str] = set()
    copied: list[ComponentGroupMembership] = []
    allowed_groups = set(context.operator_groups)
    for membership in memberships:
        copied.append(_validated_membership(membership, expected, seen, allowed_groups))
    if seen != expected:
        raise PackBackendInteractionError("mapping-invalid")
    return tuple(sorted(copied))


def _default(context: PackBackendInteractionContext) -> ResolvedPackBackendInteraction:
    """Return the pack-agnostic all-unprofiled total mapping."""

    memberships = tuple(
        ComponentGroupMembership(address, ()) for address in context.component_addresses
    )
    return ResolvedPackBackendInteraction(
        memberships=memberships,
        mapping_digest=_mapping_digest(memberships),
        provider_id=_DEFAULT_PROVIDER_ID,
        extension_api_version=EXTENSION_API_VERSION,
    )


def resolve_pack_backend_interaction(
    context: PackBackendInteractionContext,
) -> ResolvedPackBackendInteraction:
    """Resolve one exact provider, or the core unprofiled default when absent."""

    started = monotonic()
    _validate_context(context)
    selector = _selector(context)
    matches = [
        entry_point
        for entry_point in _entry_points()
        if entry_point.name == selector
    ]
    if not matches:
        resolved = _default(context)
        log.info(
            "pack interaction resolved: entry_point=%s outcome=unprofiled-default "
            "components=%d duration_ms=%d",
            selector,
            len(context.component_addresses),
            round((monotonic() - started) * 1000),
        )
        return resolved
    compatible: list[tuple[metadata.EntryPoint, object, str]] = []
    for entry_point in matches:
        provider = _load(entry_point)
        provider_id = _compatible_provider_id(provider, context)
        if provider_id is not None:
            compatible.append((entry_point, provider, provider_id))

    if not compatible:
        resolved = _default(context)
        log.info(
            "pack interaction resolved: entry_point=%s outcome=unprofiled-default "
            "selector_candidates=%d components=%d duration_ms=%d",
            selector,
            len(matches),
            len(context.component_addresses),
            round((monotonic() - started) * 1000),
        )
        return resolved
    if len(compatible) != 1:
        log.warning(
            "pack interaction discovery failed: entry_point=%s "
            "outcome=provider-ambiguous candidates=%d duration_ms=%d",
            selector,
            len(compatible),
            round((monotonic() - started) * 1000),
        )
        raise PackBackendInteractionError("provider-ambiguous")

    entry_point, provider, provider_id = compatible[0]
    try:
        result = provider.resolve(context)
    except PackBackendInteractionError:
        raise
    except Exception as exc:
        log.warning(
            "pack interaction provider resolve failed: selector=%s exception=%s",
            selector,
            type(exc).__name__,
        )
        raise PackBackendInteractionError("provider-resolve-failed") from None
    memberships = _validate_result(result, context)
    dist = getattr(entry_point, "dist", None)
    resolved = ResolvedPackBackendInteraction(
        memberships=memberships,
        mapping_digest=_mapping_digest(memberships),
        provider_id=provider_id,
        extension_api_version=EXTENSION_API_VERSION,
        distribution=str(getattr(dist, "name", "") or ""),
        distribution_version=str(getattr(dist, "version", "") or ""),
        entry_point=selector,
    )
    log.info(
        "pack interaction resolved: provider=%s distribution=%s "
        "distribution_version=%s entry_point=%s outcome=resolved "
        "components=%d duration_ms=%d",
        provider_id,
        resolved.distribution,
        resolved.distribution_version,
        selector,
        len(memberships),
        round((monotonic() - started) * 1000),
    )
    return resolved


__all__ = ["PackBackendInteractionError", "resolve_pack_backend_interaction"]
