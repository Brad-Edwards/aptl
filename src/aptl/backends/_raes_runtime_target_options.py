"""Optional authorities and evidence bound into one RAES runtime target."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from raes_contracts.contracts import ArtifactAvailabilityContext

from aptl.backends.raes_observability_scope import ObservabilityScopeDecision
from aptl.backends.raes_operator_access import OperatorAccessDecision
from aptl.backends.raes_participant_actions import ParticipantActionSpec
from aptl.backends.raes_participant_driver import ParticipantPlanAuthority
from aptl.core.experiment.capture_plan import CapturePlan


@dataclass(frozen=True)
class RuntimeTargetOptions:
    """Optional authorities and evidence state bound into one runtime target."""

    participant_action_specs: Mapping[str, ParticipantActionSpec] | None = None
    participant_plan_authority: ParticipantPlanAuthority | None = None
    artifact_availability: ArtifactAvailabilityContext | None = None
    capture_plan: CapturePlan | None = None
    observability_scope: ObservabilityScopeDecision | None = None
    operator_access: OperatorAccessDecision | None = None
