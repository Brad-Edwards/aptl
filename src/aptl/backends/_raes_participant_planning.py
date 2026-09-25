"""Plan SDL-authored participant inject deliveries."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace

from aptl.backends._raes_participant_models import (
    CLAUDE_CODE_REALIZATION_PROFILE,
    ParticipantDeliveryPlan,
    ParticipantInjectTurn,
)
from aptl.core.experiment.capture_plan import CapturePlan
from aptl.workbench.profiles import ProfileId, profile_for


def has_participant_inject_deliveries(scenario: object) -> bool:
    """Return whether the authored scenario requests the delivery capability."""

    return any(
        bool(getattr(specification, "participant_inject_deliveries", {}))
        for specification in getattr(scenario, "behavior_specifications", {}).values()
    )


def build_participant_delivery_plan(
    scenario: object,
    runtime_model: object,
) -> ParticipantDeliveryPlan:
    """Resolve the exact participant-directed orchestration slice APTL supports."""

    compiled = getattr(runtime_model, "participant_inject_deliveries", {})
    if not compiled:
        return ParticipantDeliveryPlan()
    if not isinstance(compiled, dict):
        raise ValueError("compiled participant inject deliveries are invalid")
    _require_closed_participant_orchestration(scenario, compiled)
    constraints = {
        item.address: item
        for item in getattr(
            getattr(runtime_model, "time_model", None), "constraints", ()
        )
    }
    turns = [
        _build_participant_turn(address, delivery, scenario, runtime_model, constraints)
        for address, delivery in compiled.items()
    ]
    return ParticipantDeliveryPlan(
        _ordered_participant_turns(turns),
        behavior_specifications=dict(runtime_model.behavior_specifications),
    )


def _build_participant_turn(
    address: str,
    delivery: object,
    scenario: object,
    runtime_model: object,
    constraints: Mapping[str, object],
) -> ParticipantInjectTurn:
    """Resolve one compiled delivery only from its authored coordinates."""

    behavior, behavior_address, compiled_behavior, profile = _resolved_behavior(
        address, delivery, scenario, runtime_model
    )
    constraint, tick = _exact_temporal_constraint(address, delivery, constraints)
    _require_occurrence_tick(scenario, delivery, getattr(scenario, "scripts", {}), tick)
    direct_transition, proposal_transition, proposal_revision = (
        _resolved_control_transitions(delivery, compiled_behavior)
    )
    source_ref, instruction = _literal_instruction(scenario, delivery)
    return ParticipantInjectTurn(
        address=address,
        behavior_specification_address=behavior_address,
        participant_address=delivery.participant_address,
        profile=profile,
        realization_profile_ref=behavior.realization_profile_ref,
        instruction=instruction,
        source_item_ref=source_ref,
        inject_address=delivery.inject_address,
        event_address=delivery.event_address,
        script_address=delivery.script_address,
        story_address=delivery.story_address,
        observation_boundary_address=delivery.observation_boundary_address,
        policy_ref=delivery.policy_ref,
        policy_revision=delivery.policy_revision,
        exposure_policy_ref=delivery.exposure_policy_ref,
        audience_scope_ref=delivery.audience_scope_ref,
        visibility_basis_ref=delivery.visibility_basis_ref,
        disclosure_basis_ref=delivery.disclosure_basis_ref,
        temporal_constraint_address=constraint.address,
        clock_address=constraint.clock_address,
        tick=tick,
        control_transition_address=delivery.control_transition_address,
        control_policy_revision=direct_transition.policy_revision,
        control_expected_state_revision=direct_transition.expected_state_revision,
        control_effective_order=delivery.control_effective_order,
        control_valid_from_order=delivery.control_valid_from_order,
        control_valid_until_order=delivery.control_valid_until_order,
        controller_address=delivery.controller_address,
        control_authority_scope_addresses=tuple(
            delivery.control_authority_scope_addresses
        ),
        proposal_transition_address=proposal_transition.address,
        proposal_expected_state_revision=proposal_transition.expected_state_revision,
        proposal_id=direct_transition.proposal_address,
        proposal_revision=proposal_revision,
        control_evidence_addresses=tuple(
            getattr(delivery, "control_evidence_addresses", ())
        ),
        evidence_requirement_addresses=tuple(delivery.evidence_requirement_addresses),
        failure_disposition=delivery.failure_disposition,
    )


def _resolved_behavior(
    address: str,
    delivery: object,
    scenario: object,
    runtime_model: object,
) -> tuple[object, str, object, ProfileId]:
    """Resolve and validate one authored and compiled participant behavior."""

    spec_name = _behavior_specification_name(address)
    behavior = getattr(scenario, "behavior_specifications", {}).get(spec_name)
    if behavior is None:
        raise ValueError(
            "participant inject delivery has no authored behavior specification"
        )
    behavior_address = getattr(delivery, "behavior_specification_address", "")
    compiled_behavior = getattr(runtime_model, "behavior_specifications", {}).get(
        behavior_address
    )
    if compiled_behavior is None:
        raise ValueError("participant delivery has no compiled behavior specification")
    roles = tuple(getattr(behavior, "participant_role_refs", ()))
    if len(roles) != 1:
        raise ValueError(
            "participant inject delivery requires exactly one participant role"
        )
    try:
        profile = ProfileId(roles[0])
        profile_for(profile)
    except (TypeError, ValueError) as exc:
        raise ValueError("participant role has no installed APTL profile") from exc
    if getattr(behavior, "realization_profile_ref", None) != (
        CLAUDE_CODE_REALIZATION_PROFILE
    ):
        raise ValueError("participant realization profile is unsupported")
    if getattr(delivery, "failure_disposition", None) != "reject-no-delivery":
        raise ValueError("participant delivery must fail closed")
    return behavior, behavior_address, compiled_behavior, profile


def _exact_temporal_constraint(
    address: str,
    delivery: object,
    constraints: Mapping[str, object],
) -> tuple[object, int]:
    """Resolve the one exact logical tick authored for a delivery."""

    addresses = tuple(getattr(delivery, "temporal_constraint_addresses", ()))
    if len(addresses) != 1:
        raise ValueError("participant delivery requires one exact temporal window")
    constraint = constraints.get(addresses[0])
    exact = (
        constraint is not None
        and getattr(constraint, "kind", None) == "window"
        and getattr(constraint, "start_tick", None)
        == getattr(constraint, "end_tick", None)
        and getattr(constraint, "start_microstep", None) == 0
        and getattr(constraint, "end_microstep", None) == 0
        and tuple(getattr(constraint, "subject_addresses", ())) == (address,)
    )
    if not exact:
        raise ValueError("participant delivery temporal window is not exact")
    return constraint, int(constraint.start_tick)


def _resolved_control_transitions(
    delivery: object,
    compiled_behavior: object,
) -> tuple[object, object, int]:
    """Resolve the proposal/direction pair and validate policy coordinates."""

    direct = _control_transition(
        compiled_behavior, getattr(delivery, "control_transition_address", "")
    )
    proposal = _control_transition(
        compiled_behavior, getattr(direct, "proposal_address", "")
    )
    revision = getattr(direct, "proposal_revision", None)
    policy_values = (
        getattr(delivery, "policy_ref", None),
        getattr(delivery, "policy_revision", None),
        getattr(delivery, "exposure_policy_ref", None),
        getattr(delivery, "audience_scope_ref", None),
        getattr(delivery, "visibility_basis_ref", None),
        getattr(delivery, "disclosure_basis_ref", None),
    )
    control_orders = (
        getattr(delivery, "control_effective_order", None),
        getattr(delivery, "control_valid_from_order", None),
        getattr(delivery, "control_valid_until_order", None),
    )
    valid = (
        getattr(direct, "transition_kind", None) == "external-direction"
        and getattr(proposal, "transition_kind", None) == "proposal"
        and isinstance(revision, int)
        and all(isinstance(value, str) and value for value in policy_values)
        and all(
            isinstance(value, int) and not isinstance(value, bool)
            for value in control_orders
        )
    )
    if not valid:
        raise ValueError(
            "participant delivery requires authored control and policy coordinates"
        )
    return direct, proposal, revision


def _literal_instruction(
    scenario: object,
    delivery: object,
) -> tuple[str, str]:
    """Resolve the authored literal instruction named by one delivery."""

    source_ref = getattr(delivery, "source_item_ref", "")
    source_name = _section_ref_name(source_ref, "content")
    source = getattr(scenario, "content", {}).get(source_name)
    instruction = getattr(source, "text", None)
    if not isinstance(instruction, str) or not instruction.strip():
        raise ValueError(
            "participant delivery source must contain literal instruction text"
        )
    return source_ref, instruction


def _ordered_participant_turns(
    turns: list[ParticipantInjectTurn],
) -> tuple[ParticipantInjectTurn, ...]:
    """Return the closed delivery sequence after validating its global order."""

    ordered = tuple(
        sorted(turns, key=lambda turn: (turn.tick, turn.control_effective_order))
    )
    if len({turn.tick for turn in ordered}) != len(ordered):
        raise ValueError("participant delivery ticks must be unique")
    if any(
        current.control_effective_order >= following.control_effective_order
        for current, following in zip(ordered, ordered[1:], strict=False)
    ):
        raise ValueError(
            "participant delivery control order must be strictly increasing"
        )
    return ordered


def bind_participant_delivery_capture(
    plan: ParticipantDeliveryPlan,
    capture_plan: CapturePlan,
) -> ParticipantDeliveryPlan:
    """Bind each authored delivery to its admitted evidence requirement."""

    by_requirement = {
        binding.requirement_id: binding for binding in capture_plan.runtime_bindings()
    }
    turns: list[ParticipantInjectTurn] = []
    for turn in plan.turns:
        if len(turn.evidence_requirement_addresses) != 1:
            raise ValueError("participant delivery requires one evidence requirement")
        requirement_id = turn.evidence_requirement_addresses[0].removeprefix(
            "sdl.evidence-requirements."
        )
        binding = by_requirement.get(requirement_id)
        if binding is None or not binding.registration_id.startswith(
            "aptl.collector.participant-delivery."
        ):
            raise ValueError("participant delivery evidence is not admitted")
        turns.append(replace(turn, capture_binding=binding))
    return ParticipantDeliveryPlan(tuple(turns), plan.behavior_specifications)


def _control_transition(behavior: object, address: str) -> object:
    """Resolve exactly one compiled control transition by address."""

    matches = [
        transition
        for transition in getattr(behavior, "control_transitions", ())
        if getattr(transition, "address", None) == address
    ]
    if len(matches) != 1:
        raise ValueError("participant delivery control transition is unresolved")
    return matches[0]


def _require_closed_participant_orchestration(
    scenario: object,
    compiled: Mapping[str, object],
) -> None:
    """Reject orchestration that the participant delivery runner would omit."""

    deliveries = tuple(compiled.values())
    inject_refs = {
        getattr(item, "inject_address", "").removeprefix("orchestration.inject.")
        for item in deliveries
    }
    event_refs = {
        getattr(item, "event_address", "").removeprefix("orchestration.event.")
        for item in deliveries
    }
    script_refs = {
        getattr(item, "script_address", "").removeprefix("orchestration.script.")
        for item in deliveries
    }
    story_refs = {
        getattr(item, "story_address", "").removeprefix("orchestration.story.")
        for item in deliveries
    }
    if inject_refs != set(getattr(scenario, "injects", {})):
        raise ValueError("every authored inject must have one participant delivery")
    if event_refs != set(getattr(scenario, "events", {})):
        raise ValueError("every authored event must have one participant delivery")
    if script_refs != set(getattr(scenario, "scripts", {})):
        raise ValueError(
            "every authored script must be covered by participant deliveries"
        )
    if story_refs != set(getattr(scenario, "stories", {})):
        raise ValueError(
            "every authored story must be covered by participant deliveries"
        )
    for event in getattr(scenario, "events", {}).values():
        if len(getattr(event, "injects", ())) != 1:
            raise ValueError(
                "participant delivery events must contain exactly one inject"
            )
    for inject in getattr(scenario, "injects", {}).values():
        if getattr(inject, "environment", ()):
            raise ValueError(
                "participant delivery injects cannot carry environment effects"
            )


def _require_occurrence_tick(
    scenario: object,
    delivery: object,
    scripts: Mapping[str, object],
    tick: int,
) -> None:
    """Require the delivery tick to match its story/script occurrence."""

    spec = getattr(delivery, "spec", {})
    occurrence = spec.get("occurrence", {}) if isinstance(spec, dict) else {}
    script_name = occurrence.get("script_ref")
    event_name = occurrence.get("event_ref")
    story_name = occurrence.get("story_ref")
    script = scripts.get(script_name)
    event_tick = getattr(script, "events", {}).get(event_name) if script else None
    story = getattr(scenario, "stories", {}).get(story_name)
    if event_tick != tick or script_name not in tuple(getattr(story, "scripts", ())):
        raise ValueError(
            "participant delivery time does not match its authored occurrence"
        )


def _behavior_specification_name(address: str) -> str:
    """Extract the behavior specification name from a delivery address."""

    prefix = "participant.behavior-specification."
    suffix = ".inject-delivery."
    if not address.startswith(prefix) or suffix not in address:
        raise ValueError("participant inject delivery address is invalid")
    return address[len(prefix) :].split(suffix, 1)[0]


def _section_ref_name(reference: str, section: str) -> str:
    """Extract a named SDL section member from an exact reference."""

    prefix = f"{section}."
    if not reference.startswith(prefix) or len(reference) == len(prefix):
        raise ValueError(f"participant delivery {section} reference is invalid")
    return reference[len(prefix) :]
