"""Typed contracts for SDL-authored participant inject delivery."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from aptl.core.experiment.capture_registry import CaptureBinding
from aptl.workbench.profiles import ProfileId

CLAUDE_CODE_REALIZATION_PROFILE = "participant-implementation-manifest:claude-code"


@dataclass(frozen=True)
class ParticipantInjectTurn:
    """One fully resolved SDL-authored delivery, with no inferred behavior."""

    address: str
    behavior_specification_address: str
    participant_address: str
    profile: ProfileId
    realization_profile_ref: str
    instruction: str
    source_item_ref: str
    inject_address: str
    event_address: str
    script_address: str
    story_address: str
    observation_boundary_address: str
    policy_ref: str
    policy_revision: str
    exposure_policy_ref: str
    audience_scope_ref: str
    visibility_basis_ref: str
    disclosure_basis_ref: str
    temporal_constraint_address: str
    clock_address: str
    tick: int
    control_transition_address: str
    control_policy_revision: str
    control_expected_state_revision: int
    control_effective_order: int
    control_valid_from_order: int
    control_valid_until_order: int
    controller_address: str
    control_authority_scope_addresses: tuple[str, ...]
    proposal_transition_address: str
    proposal_expected_state_revision: int
    proposal_id: str
    proposal_revision: int
    control_evidence_addresses: tuple[str, ...]
    evidence_requirement_addresses: tuple[str, ...]
    failure_disposition: str
    capture_binding: CaptureBinding | None = None


@dataclass(frozen=True)
class ParticipantDeliveryPlan:
    """Closed ordered set of participant deliveries for one admitted scenario."""

    turns: tuple[ParticipantInjectTurn, ...] = ()
    behavior_specifications: Mapping[str, object] | None = None


@dataclass(frozen=True)
class ParticipantTurnResult:
    """One provider result retained as participant delivery evidence."""

    session_id: str
    response: str
    provider_payload: Mapping[str, object]
