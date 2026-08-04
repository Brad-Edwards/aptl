"""Fail-closed diagnostics for provisioning-plan realization.

Split out of :mod:`aptl.backends.raes_realization`, which keeps the lowering
itself. These are the three ways a plan is refused rather than realized: a node
that maps to no APTL compose profile, a plan whose profile set is empty or
misses every public-start profile, and a supported resource whose payload is not
a mapping. Every one of them is reported, never silently dropped.
"""

from __future__ import annotations

from collections.abc import Mapping

from raes_contracts.diagnostics import Diagnostic
from raes_contracts.planning import PlannedResource

from aptl.backends.raes_diagnostics import PROVISIONING_ADDRESS, diagnostic
from aptl.backends.raes_profiles import public_start_profiles
from aptl.core.config import AptlConfig


def _append_node_profile_diagnostic(
    resource: PlannedResource,
    diagnostics: list[Diagnostic],
) -> None:
    """Record a diagnostic for a node without an APTL profile mapping."""

    diagnostics.append(
        diagnostic(
            "aptl.provisioner.node-profile-unresolved",
            resource.address,
            (
                "RAES node resource does not declare content that "
                "maps to an APTL compose profile."
            ),
        )
    )


def _append_profile_diagnostics(
    profiles: set[str],
    config: AptlConfig,
    diagnostics: list[Diagnostic],
) -> None:
    """Record diagnostics for missing or disabled compose-profile matches."""

    if not profiles:
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.profile-resolution-failed",
                PROVISIONING_ADDRESS,
                (
                    "RAES provisioning plan contained no node resources "
                    "that map to APTL compose profiles."
                ),
            )
        )

    start_profiles = public_start_profiles(config)
    if start_profiles and not (set(start_profiles) & profiles):
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.no-configured-profile-matches",
                PROVISIONING_ADDRESS,
                (
                    "RAES provisioning plan did not declare any node "
                    "that maps to a public-start APTL compose profile."
                ),
            )
        )


def _invalid_payload_diagnostics(
    resources: list[PlannedResource],
) -> list[Diagnostic]:
    """Report supported resources whose payload cannot be interpreted."""

    diagnostics: list[Diagnostic] = []
    for resource in resources:
        if isinstance(resource.payload, Mapping):
            continue
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.invalid-resource-payload",
                resource.address,
                (
                    "APTL provisioner expected RAES resource payload "
                    f"'{resource.resource_type}' to be a mapping."
                ),
            )
        )
    return diagnostics
