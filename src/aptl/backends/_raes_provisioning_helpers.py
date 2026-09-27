"""Focused validation helpers used by the RAES provisioner."""

from __future__ import annotations

from typing import TYPE_CHECKING

from raes_contracts.diagnostics import Diagnostic
from raes_contracts.planning import ProvisioningPlan
from raes_contracts.runtime_state import RuntimeSnapshot

from aptl.backends.raes_artifact_mechanisms import dynamic_composition_provenance_ref
from aptl.backends.raes_diagnostics import PROVISIONING_ADDRESS, diagnostic
from aptl.backends.raes_profiles import load_compose_profile_index
from aptl.utils.redaction import redact

if TYPE_CHECKING:
    from raes_contracts.contracts import ArtifactAvailabilityContext

_ASYNC_READBACK_CONCERNS = frozenset(
    {
        "forwarding-agents",
        "generated-artifact",
        "runtime-app-authorizations",
        "runtime-applications",
        "runtime-database-services",
        "runtime-datastore-services",
        "runtime-dns-services",
        "runtime-file-services",
        "runtime-filesystem-inventory",
        "runtime-identity-authorities",
        "runtime-local-identity",
        "runtime-network-detection-engines",
        "runtime-platform-applications",
        "runtime-security-monitoring-managers",
        "runtime-service-manager-units",
        "service-listeners",
    }
)


def retryable_readback_gaps(
    plan: ProvisioningPlan,
    snapshot: RuntimeSnapshot,
    diagnostics: list[Diagnostic],
) -> bool:
    """Return whether every authority failure can be transient native readback."""

    return bool(diagnostics) and all(
        _retryable_readback_gap(plan, snapshot, item) for item in diagnostics
    )


def _retryable_readback_gap(
    plan: ProvisioningPlan, snapshot: RuntimeSnapshot, item: Diagnostic
) -> bool:
    """Classify one realization-authority failure as retryable or terminal."""

    authorities = [
        authority
        for authority in plan.realization_authority
        if authority.address == item.address
        and f"'{authority.requirement_kind}'" in item.message
    ]
    if len(authorities) != 1:
        return False
    authority = authorities[0]
    eligible = bool(
        authority.requirement_kind in _ASYNC_READBACK_CONCERNS
        and str(getattr(authority.mode, "value", authority.mode)) != "closed"
    )
    if not eligible:
        return False
    resource = plan.resources.get(authority.address)
    entry = snapshot.entries.get(authority.address)
    resource_type = getattr(resource, "resource_type", "")
    return bool(
        resource_type == "generated-artifact"
        if entry is None
        else resource_type in {"node", "generated-artifact"}
    )


def availability_substrate_digests(
    availability: ArtifactAvailabilityContext | None,
) -> dict[str, str]:
    """Return exact address-scoped substrate config ids verified by availability."""

    if availability is None:
        return {}
    provenance = dynamic_composition_provenance_ref()
    digests: dict[str, str] = {}
    for requirement in getattr(availability, "requirements", ()):
        verified = getattr(requirement, "verified_provenance_refs", ())
        refs = getattr(requirement, "verified_integrity_refs", ())
        if provenance in verified and len(refs) == 1:
            digests[requirement.address] = refs[0]
    return digests


def compose_validity_diagnostics(
    scenario_root: object, selected_profiles: list[str]
) -> list[Diagnostic]:
    """Return diagnostics for cross-profile gaps in the selected Compose project."""

    try:
        profile_index = load_compose_profile_index(scenario_root)
    except (OSError, ValueError) as exc:
        return [
            diagnostic(
                "aptl.provisioner.compose-profile-index-failed",
                PROVISIONING_ADDRESS,
                redact(str(exc)),
            )
        ]
    gaps = profile_index.cross_profile_dependency_gaps(set(selected_profiles))
    return [
        diagnostic(
            "aptl.provisioner.compose-project-invalid",
            PROVISIONING_ADDRESS,
            (
                "Selected APTL compose profiles form an invalid project: "
                f"service '{service_name}' depends on {', '.join(dependencies)}, "
                "which the profile selection excludes. Declare the dependency's "
                "node or enable its profile."
            ),
        )
        for service_name, dependencies in sorted(gaps.items())
    ]


__all__ = (
    "availability_substrate_digests",
    "compose_validity_diagnostics",
    "retryable_readback_gaps",
)
