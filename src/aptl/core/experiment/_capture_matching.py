"""Pure matching predicates for the trusted collector registry."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol

from raes_contracts.contracts import (
    ExperimentCaptureRequirementModel,
    ExperimentCaptureSpecModel,
)


class RegistrationView(Protocol):
    """Registration fields consumed by the pure coverage predicate."""

    contract_version: str
    capture_kind: str
    capture_scope: str
    window_kinds: frozenset[str]
    media_types: frozenset[str]
    required_artifact_roles: frozenset[str]
    supported_sensitivities: frozenset[str]
    integrity_modes: frozenset[str]
    supports_redaction: bool
    redaction_policies: frozenset[str]
    supports_retention: bool
    retention_policies: frozenset[str]
    supports_loss_disclosure: bool


def window_kinds_by_ref(spec: ExperimentCaptureSpecModel) -> Mapping[str, str]:
    """Return a map from each capture-window ID to its window kind for spec."""

    return {window.window_id: window.window_kind for window in spec.capture_windows}


def _windows_supported(
    window_refs: Sequence[str],
    kinds_by_ref: Mapping[str, str],
    supported_window_kinds: frozenset[str],
) -> bool:
    """Return whether every reference resolves to a supported window kind."""

    return all(
        (kind := kinds_by_ref.get(window_ref)) is not None
        and kind in supported_window_kinds
        for window_ref in window_refs
    )


def registration_covers(
    registration: RegistrationView,
    requirement: ExperimentCaptureRequirementModel,
    *,
    contract_version: str,
    kinds_by_ref: Mapping[str, str],
) -> bool:
    """Return whether a registration covers every authored requirement axis."""

    checks = (
        registration.contract_version == contract_version,
        registration.capture_kind == requirement.capture_kind,
        registration.capture_scope == requirement.capture_scope,
        _windows_supported(
            requirement.window_refs, kinds_by_ref, registration.window_kinds
        ),
        frozenset(requirement.expected_media_types) <= registration.media_types,
        frozenset(requirement.required_artifact_roles)
        <= registration.required_artifact_roles,
        requirement.sensitivity in registration.supported_sensitivities,
        frozenset(requirement.integrity_requirements) <= registration.integrity_modes,
        requirement.redaction_policy is None
        or (
            registration.supports_redaction
            and requirement.redaction_policy in registration.redaction_policies
        ),
        requirement.retention_policy is None
        or (
            registration.supports_retention
            and requirement.retention_policy in registration.retention_policies
        ),
        registration.supports_loss_disclosure
        or not requirement.loss_disclosure_required,
    )
    return all(checks)


__all__ = ("registration_covers", "window_kinds_by_ref")
