"""Exposure authorization and delivery for participant projections."""

from __future__ import annotations

from raes_contracts.contracts import (
    ParticipantDecisionSurfaceDeliveryV2Model,
    ParticipantDecisionSurfaceV2Model,
    ParticipantImplementationSelectionModel,
)
from raes_contracts.participant_decision_surface_delivery import (
    deliver_participant_decision_surface_v2,
)
from raes_processor.models import (
    ParticipantDecisionSurfaceProjectionInputV2,
    ParticipantExposureAuthorizationRecordV2,
    ParticipantExposurePolicyDecisionV2,
    ParticipantExposureResolversV2,
)

from aptl.backends.raes_participant_apparatus_models import (
    ParticipantApparatus,
    reference_token,
)

_PARTICIPANT_SURFACE_PROVENANCE = "provenance.aptl-participant-surface"
_PARTICIPANT_VISIBLE_MARKING = "markings.participant-visible"


def exposure_resolvers(
    projection: ParticipantDecisionSurfaceProjectionInputV2,
    apparatus: ParticipantApparatus,
    emitted_refs: tuple[str, ...],
) -> tuple[
    ParticipantExposureResolversV2,
    ParticipantImplementationSelectionModel,
]:
    """Handle resolvers for the bounded participant workflow."""
    policy = apparatus.selection.exposure_policy.model_copy(
        update={"disclosed_refs": list(emitted_refs)}
    )
    selection = apparatus.selection.model_copy(update={"exposure_policy": policy})
    authorizations = {
        item_ref: ParticipantExposureAuthorizationRecordV2(
            authorization_record_ref=projection.exposure_assessments[
                item_ref
            ].authorization_record_ref,
            item_ref=item_ref,
            source_ref=item_ref,
            source_layer_ref=f"source-layer.{reference_token(item_ref)}",
            participant_address=projection.participant_address,
            episode_id=projection.episode_id,
            audience_scope_ref=projection.audience_scope_ref,
            decision_epoch=projection.decision_epoch,
            decision_cut_ref=projection.decision_cut_ref,
            implementation_selection_ref=projection.implementation_selection_ref,
            projection_policy_ref=projection.projection_policy_ref,
            projection_policy_revision=projection.projection_policy_revision,
            projection_policy_decision_ref=projection.projection_policy_decision_ref,
            exposure_policy_ref=projection.exposure_policy_ref,
            exposure_policy_version=policy.policy_version,
            exposure_policy_digest=policy.policy_digest,
            visibility_basis_ref=f"visibility-basis.{reference_token(item_ref)}",
            operation="disclosure",
            operation_basis_ref=f"disclosure.{reference_token(item_ref)}",
            actor_ref="actors.aptl-runtime-projector",
            controller_ref="controllers.aptl-participant-control-plane",
            authority_basis_ref="authority.raes-exact-cut-projection",
            backend_support_ref="backend-support.aptl-participant-runtime",
            source_marking_definition_refs=(_PARTICIPANT_VISIBLE_MARKING,),
            result_marking_definition_refs=(_PARTICIPANT_VISIBLE_MARKING,),
            source_provenance_refs=(_PARTICIPANT_SURFACE_PROVENANCE,),
            result_provenance_refs=(_PARTICIPANT_SURFACE_PROVENANCE,),
            evidence_refs=("evidence.aptl-participant-surface",),
            provenance_refs=(_PARTICIPANT_SURFACE_PROVENANCE,),
            loss_and_limitations=("No hidden or evaluator refs are disclosed",),
        )
        for item_ref in emitted_refs
    }
    policy_decision = ParticipantExposurePolicyDecisionV2(
        policy_ref=projection.projection_policy_ref,
        revision=projection.projection_policy_revision,
        decision_ref=projection.projection_policy_decision_ref,
        decision_cut_ref=projection.decision_cut_ref,
        evidence_refs=("evidence.aptl-projection-policy",),
        provenance_refs=("provenance.aptl-projection-policy",),
        limitations=("Policy decision is scoped to this exact state cut",),
    )
    return (
        ParticipantExposureResolversV2(
            apparatus=lambda **coordinates: (
                selection
                if coordinates.get("implementation_selection_ref")
                == projection.implementation_selection_ref
                and coordinates.get("exposure_policy_ref")
                == projection.exposure_policy_ref
                and coordinates.get("decision_cut_ref") == projection.decision_cut_ref
                else None
            ),
            projection_policy=lambda **coordinates: (
                policy_decision
                if coordinates.get("projection_policy_ref")
                == projection.projection_policy_ref
                and coordinates.get("decision_cut_ref") == projection.decision_cut_ref
                else None
            ),
            authorization=lambda **coordinates: (
                authorizations.get(str(coordinates.get("item_ref")))
                if coordinates.get("decision_cut_ref") == projection.decision_cut_ref
                and authorizations.get(str(coordinates.get("item_ref"))) is not None
                and authorizations[
                    str(coordinates.get("item_ref"))
                ].authorization_record_ref
                == coordinates.get("authorization_record_ref")
                else None
            ),
        ),
        selection,
    )


def _delivery_record(
    surface: ParticipantDecisionSurfaceV2Model,
) -> ParticipantDecisionSurfaceDeliveryV2Model:
    """Handle the internal operation for the bounded participant workflow."""
    view = surface.participant_view
    delivery_ref = f"participant-decision-surface-deliveries.{view.surface_id}"
    return ParticipantDecisionSurfaceDeliveryV2Model(
        delivery_ref=delivery_ref,
        surface_id=view.surface_id,
        participant_address=view.participant_address,
        episode_id=view.episode_id,
        decision_epoch=view.decision_epoch,
        participant_view_digest=surface.assurance.participant_view_digest,
        delivery_basis="emission_is_delivery",
        delivery_cut_ref=surface.assurance.derivation_anchor.state_cut.cut_ref,
        delivery_authorization_ref=f"{delivery_ref}.authorization",
        delivery_policy_decision_ref=f"{delivery_ref}.policy-decision",
        observation_ref=f"{delivery_ref}.observation",
        evidence_refs=("evidence.aptl-surface-delivery",),
        provenance_refs=("provenance.aptl-participant-control-plane",),
        limitations=("Synchronous management-plane delivery",),
    )


def deliver_surface(
    projected: ParticipantDecisionSurfaceV2Model,
) -> ParticipantDecisionSurfaceV2Model:
    """Attach and validate the synchronous delivery record."""

    delivery = _delivery_record(projected)
    return deliver_participant_decision_surface_v2(
        projected,
        delivery_ref=delivery.delivery_ref,
        resolver=lambda **coordinates: (
            delivery
            if coordinates.get("delivery_ref") == delivery.delivery_ref
            else None
        ),
    )
