"""One qualification/start gate over the ADR-049 trust inputs."""

from __future__ import annotations

from pathlib import Path
from typing import Literal, Protocol

from aptl.core.appliance_boundary import (
    ApplianceBoundaryBinding,
    ApplianceBoundaryPolicy,
    load_boundary_policy,
)
from aptl.core.appliance_boundary_inventory import (
    BoundaryQualificationResult,
    GuestBoundaryObservation,
    HostBoundaryObservation,
    qualify_appliance_boundary,
)

BoundaryPhase = Literal["image-qualification", "start"]


class BoundaryObservationAdapter(Protocol):
    """Narrow guest adapter implemented by a supported appliance backend."""

    def materialize_and_observe_boundary(
        self,
        policy: ApplianceBoundaryPolicy,
        binding: ApplianceBoundaryBinding,
        *,
        phase: BoundaryPhase,
    ) -> GuestBoundaryObservation: ...


def run_appliance_boundary_gate(
    *,
    policy_path: Path,
    binding: ApplianceBoundaryBinding,
    host_observation: HostBoundaryObservation | None,
    adapter: BoundaryObservationAdapter,
    phase: BoundaryPhase,
) -> BoundaryQualificationResult:
    """Use the same fatal verifier for image qualification and every start.

    The binding and host observation are trusted projections supplied by the
    signed envelope/launcher work. This function does not manufacture either
    input and cannot downgrade a missing outer observation to a warning.
    """

    policy = load_boundary_policy(policy_path, binding)
    guest = adapter.materialize_and_observe_boundary(
        policy,
        binding,
        phase=phase,
    )
    return qualify_appliance_boundary(
        policy,
        binding,
        host_observation,
        guest,
        phase=phase,
    )
