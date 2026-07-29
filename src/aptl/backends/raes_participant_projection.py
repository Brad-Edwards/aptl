"""Exact-cut RAES projection and delivery for bounded participants."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace

from raes_contracts.contracts import (
    ParticipantDecisionSurfaceDerivationAnchorV2Model,
)
from raes_processor.models import (
    ParticipantBehaviorHistoryEvent,
    ParticipantBehaviorProjectionAnchorRequestV2,
    ParticipantBehaviorSpecificationRuntime,
    ParticipantDecisionSurfaceActionAssessment,
    ParticipantDecisionSurfaceProjectionInputV2,
    ParticipantExposureAssessment,
    project_participant_decision_surface_v2,
    resolve_participant_behavior_projection_anchor_v2,
    resolve_participant_episode_readiness_anchor_v2,
)

from aptl.backends.raes_participant_apparatus_models import (
    ParticipantApparatus,
    ParticipantDecisionTurn,
    reference_token,
)
from aptl.backends.raes_participant_candidates import candidate_selections
from aptl.backends.raes_participant_exposure import (
    deliver_surface,
    exposure_resolvers as build_exposure_resolvers,
)
from aptl.backends.raes_participant_realizations import BPA_ACTION_REALIZATIONS

_PARTICIPANT_SURFACE_PROVENANCE = "provenance.aptl-participant-surface"
_PARTICIPANT_VISIBLE_MARKING = "markings.participant-visible"


@dataclass(frozen=True)
class _TurnProjectionContext:
    """Resolved exact-cut coordinates for one participant decision."""

    behavior: ParticipantBehaviorSpecificationRuntime
    behavior_specification_address: str
    participant_address: str
    boundary_address: str
    episode_id: str
    decision_epoch: int
    history: tuple[ParticipantBehaviorHistoryEvent, ...]
    visible_context_refs: tuple[str, ...]


def project_participant_turn(
    *,
    runtime_model: object,
    runtime_snapshot: object,
    behavior_specification_address: str,
    apparatus: ParticipantApparatus,
) -> ParticipantDecisionTurn:
    """Project and deliver one exact-cut candidate set from trusted state."""

    context = _resolve_turn_context(
        runtime_model,
        runtime_snapshot,
        behavior_specification_address,
        apparatus,
    )
    assessments = _action_assessments(runtime_model, context.behavior)
    emitted_refs = tuple(dict.fromkeys((*context.visible_context_refs, *assessments)))
    projection = _projection_input(
        context,
        apparatus,
        assessments,
        emitted_refs,
        _projection_anchor(runtime_model, runtime_snapshot, context),
    )
    exposure_resolvers, exact_selection = build_exposure_resolvers(
        projection,
        apparatus,
        emitted_refs,
    )
    projected = project_participant_decision_surface_v2(
        runtime_model,
        runtime_snapshot,
        history_events=context.history,
        projection=projection,
        exposure_resolvers=exposure_resolvers,
    )
    delivered = deliver_surface(projected)
    return ParticipantDecisionTurn(
        behavior_specification_address=behavior_specification_address,
        observation_boundary_address=context.boundary_address,
        surface=delivered,
        rendered_context=_render_visible_context(
            runtime_model,
            context.visible_context_refs,
        ),
        observation_history=_render_observation_history(context.history),
        candidates=candidate_selections(
            delivered,
            runtime_model,
            completed_action_sequence=_completed_action_sequence(context.history),
        ),
        apparatus=replace(apparatus, selection=exact_selection),
    )


def _resolve_turn_context(
    runtime_model: object,
    runtime_snapshot: object,
    behavior_specification_address: str,
    apparatus: ParticipantApparatus,
) -> _TurnProjectionContext:
    """Resolve participant, episode, boundary, history, and visible context."""

    behavior = runtime_model.behavior_specifications[behavior_specification_address]
    participant_address = apparatus.selection.participant_address
    if participant_address not in behavior.participant_addresses:
        raise ValueError(
            "participant apparatus is outside the selected behavior specification"
        )
    if len(behavior.observation_boundary_addresses) != 1:
        raise ValueError(
            "bounded participant behaviors require exactly one observation boundary"
        )
    boundary_address = behavior.observation_boundary_addresses[0]
    state = runtime_snapshot.participant_episode_results.get(participant_address)
    if not isinstance(state, Mapping):
        raise ValueError("participant episode is not initialized")
    episode_id = state.get("episode_id")
    if not isinstance(episode_id, str) or not episode_id:
        raise ValueError("participant episode identity is unavailable")
    history = tuple(
        ParticipantBehaviorHistoryEvent.from_payload(payload)
        for payload in runtime_snapshot.participant_behavior_history.get(
            participant_address, []
        )
        if payload.get("episode_id") == episode_id
    )
    decision_epoch = sum(
        event.event_type.value == "observation_emitted" for event in history
    )
    boundary = runtime_model.observation_boundaries[boundary_address]
    initial_relation = boundary.view_relation_timeline[0]
    initial_visible_refs = (
        initial_relation.get("visible_refs", ())
        if isinstance(initial_relation, Mapping)
        else initial_relation.visible_refs
    )
    visible_context_refs = tuple(
        ref for ref in initial_visible_refs if ref.startswith("content.")
    )
    if not visible_context_refs:
        raise ValueError("participant behavior has no visible task context")
    return _TurnProjectionContext(
        behavior=behavior,
        behavior_specification_address=behavior_specification_address,
        participant_address=participant_address,
        boundary_address=boundary_address,
        episode_id=episode_id,
        decision_epoch=decision_epoch,
        history=history,
        visible_context_refs=visible_context_refs,
    )


def _projection_anchor(
    runtime_model: object,
    runtime_snapshot: object,
    context: _TurnProjectionContext,
) -> ParticipantDecisionSurfaceDerivationAnchorV2Model:
    """Resolve the RAES anchor for the current initial or continued cut."""

    evidence_refs = (
        f"participant-evidence.{context.episode_id}."
        f"decision-epoch-{context.decision_epoch}",
    )
    provenance_refs = ("provenance.aptl-raes-runtime-control-plane",)
    if context.decision_epoch == 0:
        return resolve_participant_episode_readiness_anchor_v2(
            runtime_snapshot,
            participant_address=context.participant_address,
            decision_epoch=0,
            evidence_refs=evidence_refs,
            provenance_refs=provenance_refs,
        )
    return resolve_participant_behavior_projection_anchor_v2(
        runtime_snapshot,
        runtime_model=runtime_model,
        request=ParticipantBehaviorProjectionAnchorRequestV2(
            participant_address=context.participant_address,
            episode_id=context.episode_id,
            decision_epoch=context.decision_epoch,
            behavior_history_order=len(context.history) - 1,
            evidence_refs=evidence_refs,
            provenance_refs=provenance_refs,
        ),
    )


def _action_assessments(
    runtime_model: object,
    behavior: object,
) -> dict[str, ParticipantDecisionSurfaceActionAssessment]:
    """Build and completeness-check the realizable action assessments."""

    assessments = {
        address: ParticipantDecisionSurfaceActionAssessment(
            entry_id=f"candidate.{address.removeprefix('participant.action-contract.')}",
            action_contract_address=address,
            presentation_basis_ref=f"presentation-basis.{address}",
            eligibility="eligible",
            eligibility_reason_refs=(),
            constraint_refs=(
                runtime_model.action_contracts[address].argument_shape_ref,
            ),
            selection_shape_ref=runtime_model.action_contracts[
                address
            ].argument_shape_ref,
            support="supported",
            support_refs=(f"backend-support.aptl.{address}",),
            realization_refs=(f"aptl-realization.{address}",),
        )
        for address in behavior.action_contract_addresses
        if address in BPA_ACTION_REALIZATIONS
    }
    if set(assessments) != set(behavior.action_contract_addresses):
        raise ValueError(
            "selected behavior contains an action without an APTL realization"
        )
    return assessments


def _projection_input(
    context: _TurnProjectionContext,
    apparatus: ParticipantApparatus,
    assessments: Mapping[str, ParticipantDecisionSurfaceActionAssessment],
    emitted_refs: tuple[str, ...],
    anchor: ParticipantDecisionSurfaceDerivationAnchorV2Model,
) -> ParticipantDecisionSurfaceProjectionInputV2:
    """Build the versioned exact-cut projection input."""

    episode_id = context.episode_id
    decision_epoch = context.decision_epoch
    participant_address = context.participant_address
    behavior_address = context.behavior_specification_address
    return ParticipantDecisionSurfaceProjectionInputV2(
        surface_id=(
            f"participant-decision-surfaces.{episode_id}."
            f"epoch-{decision_epoch}.{context.behavior.spec_name}"
        ),
        participant_address=participant_address,
        episode_id=episode_id,
        decision_epoch=decision_epoch,
        information_state_ref=(
            f"participant-information-states.{episode_id}.epoch-{decision_epoch}"
        ),
        behavior_specification_address=behavior_address,
        observation_boundary_address=context.boundary_address,
        context_view_ref=(
            f"participant-context-views.{episode_id}.epoch-{decision_epoch}"
        ),
        implementation_selection_ref=apparatus.implementation_selection_ref,
        decision_control_mode=apparatus.selection.selected_decision_surface_mode,
        audience_scope_ref=f"audience.{participant_address}",
        projection_policy_ref=(f"participant-projection-policy.{participant_address}"),
        projection_policy_revision="1",
        projection_policy_decision_ref=(
            f"participant-projection-decisions.{episode_id}.epoch-{decision_epoch}"
        ),
        exposure_policy_ref=apparatus.selection.exposure_policy.policy_id,
        visibility_projection_ref=(
            f"participant-visibility-projections.{episode_id}.epoch-{decision_epoch}"
        ),
        # The managed providers are deliberately one-shot: Claude runs with
        # persistence disabled and Codex runs ephemeral in a fresh home.  The
        # backend therefore declares episode-local memory and names the
        # authority responsible for that reset instead of claiming persistence
        # it does not provide.
        participant_memory_scope="episode_local_reset",
        memory_reset_authority_ref=(
            "participant-memory-reset-authority.aptl-one-shot-provider"
        ),
        visible_context_refs=context.visible_context_refs,
        action_assessments=assessments,
        exposure_assessments={
            item_ref: ParticipantExposureAssessment(
                item_ref=item_ref,
                authorization_record_ref=(
                    f"participant-exposure-authorizations.{episode_id}."
                    f"epoch-{decision_epoch}.{reference_token(item_ref)}"
                ),
            )
            for item_ref in emitted_refs
        },
        form={
            "surface_form": "candidate_action_set",
            "selection_meaning_ref": (
                f"participant-selection-meaning.{behavior_address}"
            ),
            "candidate_entry_ids": [
                assessment.entry_id for assessment in assessments.values()
            ],
        },
        evidence_refs=tuple(
            dict.fromkeys(
                (
                    *anchor.evidence_refs,
                    "evidence.aptl-projection-policy",
                    "evidence.aptl-participant-surface",
                )
            )
        ),
        provenance_refs=tuple(
            dict.fromkeys(
                (
                    *anchor.provenance_refs,
                    "provenance.aptl-projection-policy",
                    _PARTICIPANT_SURFACE_PROVENANCE,
                )
            )
        ),
        marking_definition_refs=(_PARTICIPANT_VISIBLE_MARKING,),
        redaction_policy_ref="redaction-policy.aptl-participant-view",
        semantic_limitations=(
            "Projection and delivery do not imply admission, execution, or outcome",
            "The participant receives no evaluator state or backend capability",
        ),
        derivation_anchor=anchor,
    )


def _render_visible_context(
    runtime_model: object,
    visible_context_refs: tuple[str, ...],
) -> tuple[Mapping[str, object], ...]:
    """Resolve only authorized participant-visible content references.

    RAES keeps the canonical participant view referential so its digest remains
    stable and exact-cut verifiable.  APTL's delivery adapter resolves those
    references into provider-readable text without modifying that canonical
    view.  Sensitive, untagged, missing, or non-text content fails closed.
    """

    placements = getattr(runtime_model, "content_placements", None)
    if not isinstance(placements, Mapping):
        raise ValueError("compiled model has no content placements")
    rendered: list[Mapping[str, object]] = []
    for item_ref in visible_context_refs:
        placement = placements.get(f"provision.{item_ref}")
        spec = getattr(placement, "spec", None)
        if not isinstance(spec, Mapping):
            raise ValueError(f"visible context is not resolvable: {item_ref}")
        tags = spec.get("tags", ())
        text = spec.get("text")
        if (
            spec.get("sensitive") is True
            or not isinstance(tags, Sequence)
            or isinstance(tags, (str, bytes))
            or "participant-visible" not in tags
            or not isinstance(text, str)
            or not text.strip()
        ):
            raise ValueError(
                f"visible context is not authorized for rendering: {item_ref}"
            )
        rendered.append(
            {
                "information_ref": item_ref,
                "media_type": "text/plain",
                "sha256": hashlib.sha256(text.encode()).hexdigest(),
                "text": text,
            }
        )
    return tuple(rendered)


def _render_observation_history(
    history: tuple[ParticipantBehaviorHistoryEvent, ...],
) -> tuple[Mapping[str, object], ...]:
    """Render the participant-owned terminal results at the same state cut."""

    rendered: list[Mapping[str, object]] = []
    for event in history:
        if event.event_type.value != "observation_emitted":
            continue
        result = event.action_result
        if result is None:
            continue
        payload = result.to_payload()
        rendered.append(
            {
                "action_instance_id": event.action_instance_id,
                "action_contract_address": event.action_contract_address,
                "status": payload["status"],
                "failure_class": payload.get("failure_class"),
                "observations": list(payload.get("observations", ())),
            }
        )
    return tuple(rendered)


def _completed_action_sequence(
    history: tuple[ParticipantBehaviorHistoryEvent, ...],
) -> tuple[str, ...]:
    """Return successful observed actions in episode order."""

    return tuple(
        event.action_contract_address
        for event in history
        if event.event_type.value == "observation_emitted"
        and event.action_result is not None
        and event.action_result.to_payload()["status"] == "succeeded"
    )
