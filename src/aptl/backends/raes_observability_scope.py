"""Choose optional apparatus using RAE's public lexical scope semantics."""

from dataclasses import dataclass

from raes.realization_designation import (
    designation_records,
    resolve_realization_designation,
)
from raes_contracts.vocabulary import Closure

from aptl.core.deployment._compose_observability import (
    OBSERVABILITY_NETWORK,
    OBSERVABILITY_SERVICES,
    OBSERVABILITY_VOLUMES,
)
from aptl.core.experiment.errors import AdmissionRejection, diagnostic

_FOOTPRINT = (
    *(f"/nodes/{name}" for name in sorted(OBSERVABILITY_SERVICES)),
    f"/infrastructure/{OBSERVABILITY_NETWORK}",
    *(f"/persistent_volumes/{name}" for name in sorted(OBSERVABILITY_VOLUMES)),
    "/content/backend-otel-config",
    "/content/backend-tempo-config",
    "/content/backend-grafana-config",
)


def reject_scenario_observability_ownership(scenario: object) -> None:
    """Reject obsolete/duplicate owners before artifact availability can build."""
    nodes = getattr(scenario, "nodes", None) or {}
    if any(
        {name, f"aptl-{name}"}.intersection(OBSERVABILITY_SERVICES) for name in nodes
    ):
        raise AdmissionRejection(
            (
                diagnostic(
                    "aptl.observability-ownership-conflict",
                    "scenario.nodes",
                    "The scenario declares reserved backend observability resources; use a compatible pack.",
                ),
            )
        )


@dataclass(frozen=True)
class ObservabilityScopeDecision:
    """Internal plan decision; it grants no exemption from an authored scope."""

    enabled: bool = False
    environment_visible: bool = False
    governing_scopes: tuple[str, ...] = ()
    reason: str = "minimum-intrusion"

    def select_profiles(self, profiles: list[str]) -> list[str]:
        selected = [profile for profile in profiles if profile != "otel"]
        if self.enabled:
            selected.append("otel")
        return selected


def observability_scope_decision(scenario: object) -> ObservabilityScopeDecision:
    """Select minimum intrusion after all required evidence has been admitted.

    The ordinary private network has no scenario attachment or non-loopback
    publication. A scenario's host-root Docker authority defeats that isolation:
    it can enumerate same-daemon resources regardless of network membership.
    Every added node/network/volume/config then needs an open governing scope,
    but permission alone does not establish a need for the addition. The SDL
    capture adapter currently admits only existing native readback, which does
    not depend on this stack. Omit visible optional apparatus even in an open
    scope. A future intrusive collector must establish necessity and select the
    least intrusive compliant candidate, not simply enable this whole stack.
    Required evidence is admitted separately before this selection; a missing
    optional dashboard never waives an unsupported evidence requirement.
    """
    nodes = getattr(scenario, "nodes", None) or {}
    visible = any(
        node.runtime is not None and node.runtime.orchestration_authorities
        for node in nodes.values()
    )
    if not visible:
        return ObservabilityScopeDecision(environment_visible=False)
    provenance = getattr(scenario, "instantiation_provenance", None)
    designation = getattr(scenario, "realization", None)
    if provenance is not None:
        records = provenance.realization_designations
    elif designation is not None:
        records = designation_records(designation)
    else:
        records = ()
    resolutions = tuple(
        resolve_realization_designation(records, field_pointer=pointer)
        for pointer in _FOOTPRINT
    )
    allowed = all(
        resolution.closure is Closure.OPEN_WORLD for resolution in resolutions
    )
    reason = "minimum-intrusion" if allowed else "closed-realization-scope"
    return ObservabilityScopeDecision(
        enabled=False,
        environment_visible=True,
        governing_scopes=tuple(
            sorted(
                {
                    resolution.governing_scope
                    for resolution in resolutions
                    if resolution.governing_scope
                }
            )
        ),
        reason=reason,
    )
