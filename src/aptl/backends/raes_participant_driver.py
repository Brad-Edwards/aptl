"""RAES-owned authority retained by APTL's bounded participant driver."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from raes_contracts.contracts import ParticipantDecisionSurfaceSelectionV2Model
from raes_contracts.participant_binding import ParticipantActionAdmissionRequest
from raes_contracts.participant_binding_v2 import (
    ParticipantDecisionSurfaceBindingResolversV2,
)
from raes_contracts.planning import RuntimeDomain
from raes_contracts.runtime_state import OperationReceipt, OperationState
from raes_processor.models import resolve_participant_action_arguments
from raes_runtime.control_plane import RuntimeControlPlane
from raes_runtime.control_plane_execution import execute_participant_action

from aptl.backends.raes_participant_apparatus import (
    ParticipantApparatus,
    ParticipantDecisionTurn,
    project_participant_turn,
)
from aptl.backends.raes_participant_provider import (
    ParticipantDecisionSolicitation,
    ParticipantSelectionProvider,
    candidate_payloads,
)
from aptl.backends.raes_participant_control_evidence import (
    ParticipantControlEvidence,
    persist_control_evidence,
    selection_fingerprint,
    solicitation_fingerprint,
)
from aptl.backends.raes_participant_realizations import (
    BPA_ACTION_REALIZATIONS,
    ParticipantRealizationReadiness,
    validate_participant_realizations,
)
from aptl.backends.raes_runtime_model_artifact import (
    compiled_runtime_model_sha256,
)

if TYPE_CHECKING:
    from raes_processor.models import ExecutionPlan, RuntimeModel

    from aptl.core.runstore import RunStorageBackend

BOUNDED_PARTICIPANT_AGENCY_SCENARIO = "bounded-participant-agency-techvault"
BOUNDED_PARTICIPANT_AGENCY_SOURCE_SHA256 = (
    "9683f2539bdefbd99635924d2a6fce27b144e12f382cd74d2f3e10d10ecb7616"
)
BOUNDED_PARTICIPANT_AGENCY_COMPILED_SHA256 = (
    "099209f578da193ce88e201cc86887ae8ca4587a6b9c6b1a570ed195047d4c8c"
)
MAX_PARTICIPANT_PROPOSALS = 12
MAX_ADMITTED_PARTICIPANT_ACTIONS = 8
MAX_PARTICIPANT_DECISION_SECONDS = 90
MAX_PARTICIPANT_EPISODE_SECONDS = 600
_RUNTIME_UNAVAILABLE = "APTL participant runtime is unavailable"


@dataclass
class ParticipantPlanAuthority:
    """One admitted plan and the concrete runtime context authorized to use it."""

    execution_plan: ExecutionPlan
    scenario_path: Path
    runtime_model: RuntimeModel = field(init=False)
    scenario_source_sha256: str = field(init=False)
    compiled_model_sha256: str = field(init=False)
    realization_details: dict[str, Any] = field(default_factory=dict, init=False)
    readiness: ParticipantRealizationReadiness | None = field(default=None, init=False)
    run_store: RunStorageBackend | None = field(default=None, init=False)
    run_id: str | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        """Resolve and fingerprint the exact authored and compiled authorities."""

        self.scenario_path = self.scenario_path.resolve(strict=True)
        self.scenario_source_sha256 = hashlib.sha256(
            self.scenario_path.read_bytes()
        ).hexdigest()
        self.runtime_model = self.execution_plan.model
        try:
            self.compiled_model_sha256 = compiled_runtime_model_sha256(
                self.runtime_model
            )
        except TypeError:
            if self.is_bounded_participant_agency:
                raise
            # Generic scenario startup does not use this issue-557 privileged
            # registry. Test doubles and older non-participant plans need not
            # implement the bounded model-artifact contract.
            self.compiled_model_sha256 = "unavailable"

    @property
    def is_bounded_participant_agency(self) -> bool:
        """Whether this authority names the selected evaluation scenario."""

        return (
            getattr(self.runtime_model, "scenario_name", None)
            == BOUNDED_PARTICIPANT_AGENCY_SCENARIO
        )

    @property
    def is_approved_bounded_participant_agency(self) -> bool:
        """Whether both authored and compiled authorities match the freeze."""

        return (
            self.is_bounded_participant_agency
            and self.scenario_source_sha256 == BOUNDED_PARTICIPANT_AGENCY_SOURCE_SHA256
            and self.compiled_model_sha256 == BOUNDED_PARTICIPANT_AGENCY_COMPILED_SHA256
        )

    def bind_runtime_context(
        self,
        realization_details: dict[str, Any],
        *,
        run_store: RunStorageBackend | None,
        run_id: str | None,
    ) -> None:
        """Bind realized targets and evidence destination after interpretation."""

        self.realization_details = dict(realization_details)
        self.run_store = run_store
        self.run_id = run_id
        if self.is_bounded_participant_agency:
            if not self.is_approved_bounded_participant_agency:
                raise ValueError(
                    "bounded participant realization requires the approved "
                    "authored and compiled scenario identities"
                )
            self.readiness = validate_participant_realizations(
                self.runtime_model,
                self.realization_details,
                registry=BPA_ACTION_REALIZATIONS,
            )


@dataclass(frozen=True)
class ParticipantTurnOutcome:
    """One mediated provider choice and its RAES admission operation."""

    turn: ParticipantDecisionTurn
    solicitation_receipt: OperationReceipt
    admission_receipt: OperationReceipt
    selected_action_contract_address: str


@dataclass(frozen=True)
class ParticipantAdmissionAttempt:
    """One direct RAES v2 admission at an already-delivered state cut."""

    receipt: OperationReceipt
    request: ParticipantActionAdmissionRequest


@dataclass(frozen=True)
class _SolicitationEvidenceContext:
    """Shared evidence coordinates for one provider solicitation."""

    authority: ParticipantPlanAuthority
    turn: ParticipantDecisionTurn
    provider: ParticipantSelectionProvider
    solicitation: ParticipantDecisionSolicitation
    receipt: OperationReceipt
    status: object
    fingerprint: str


class AptlParticipantControlPlane(RuntimeControlPlane):
    """RAES control plane with one backend-owned provider-solicitation method.

    The method reuses RAES's participant operation executor.  This means the
    provider child is invoked only after a RUNNING participant operation is
    durable, and timeout/malformed-output failures become FAILED operations
    rather than pre-control-plane side effects.
    """

    def solicit_participant_selection(
        self,
        request: ParticipantDecisionSolicitation,
    ) -> OperationReceipt:
        """Execute provider solicitation as one durable participant operation."""

        runtime = self._target.participant_runtime
        from aptl.backends.raes_participant_runtime import (
            AptlParticipantRuntime,
        )

        if not isinstance(runtime, AptlParticipantRuntime):
            return self._reject_submission(
                domain=RuntimeDomain.PARTICIPANT,
                message="target does not provide the APTL participant runtime",
                idempotency_key=request.solicitation_id,
                request_fingerprint=solicitation_fingerprint(request),
            )
        return execute_participant_action(
            self,
            method=runtime.solicit_selection,
            request=request,
            address=(
                "runtime.control-plane.participant."
                f"{request.participant_address}.solicit-selection"
            ),
            idempotency_key=request.solicitation_id,
            request_fingerprint=solicitation_fingerprint(request),
        )


def run_participant_turn(
    control_plane: AptlParticipantControlPlane,
    *,
    behavior_specification_address: str,
    apparatus: ParticipantApparatus,
    provider: ParticipantSelectionProvider,
) -> ParticipantTurnOutcome:
    """Run projection → provider operation → RAES v2 admission for one turn."""

    runtime = control_plane._target.participant_runtime
    from aptl.backends.raes_participant_runtime import AptlParticipantRuntime

    if not isinstance(runtime, AptlParticipantRuntime):
        raise ValueError(_RUNTIME_UNAVAILABLE)
    authority = runtime.plan_authority
    if authority is None or authority.readiness is None:
        raise ValueError("participant plan authority is not ready")
    turn = project_participant_turn(
        runtime_model=authority.runtime_model,
        runtime_snapshot=control_plane.snapshot,
        behavior_specification_address=behavior_specification_address,
        apparatus=apparatus,
    )
    solicitation = _build_solicitation(runtime, turn)
    solicitation_digest = solicitation_fingerprint(solicitation)
    runtime.bind_selection_provider(provider)
    solicitation_receipt = control_plane.solicit_participant_selection(solicitation)
    solicitation_status = control_plane.get_operation(solicitation_receipt.operation_id)
    evidence_context = _SolicitationEvidenceContext(
        authority=authority,
        turn=turn,
        provider=provider,
        solicitation=solicitation,
        receipt=solicitation_receipt,
        status=solicitation_status,
        fingerprint=solicitation_digest,
    )
    if (
        solicitation_status is None
        or solicitation_status.state is not OperationState.SUCCEEDED
    ):
        _persist_solicitation_failure(evidence_context)
        raise ValueError("participant selection operation failed")
    selection = runtime.consume_selection(solicitation.solicitation_id)
    admission = admit_projected_participant_selection(
        control_plane,
        turn=turn,
        selection=selection,
    )
    admission_receipt = admission.receipt
    admission_status = control_plane.get_operation(admission_receipt.operation_id)
    _persist_admission_evidence(
        evidence_context,
        selection,
        admission,
        admission_status,
    )
    return ParticipantTurnOutcome(
        turn=turn,
        solicitation_receipt=solicitation_receipt,
        admission_receipt=admission_receipt,
        selected_action_contract_address=selection.action_contract_address,
    )


def _build_solicitation(
    runtime: object,
    turn: ParticipantDecisionTurn,
) -> ParticipantDecisionSolicitation:
    """Build the exact provider payload for one projected decision turn."""

    from aptl.backends.raes_participant_runtime import AptlParticipantRuntime

    if not isinstance(runtime, AptlParticipantRuntime):
        raise TypeError(_RUNTIME_UNAVAILABLE)
    view = turn.surface.participant_view
    ordinal = runtime.next_solicitation_ordinal(
        view.participant_address,
        view.episode_id,
    )
    solicitation_id = (
        f"participant-selection-solicitations.{view.surface_id}.proposal-{ordinal}"
    )
    return ParticipantDecisionSolicitation(
        participant_address=view.participant_address,
        episode_id=view.episode_id,
        solicitation_id=solicitation_id,
        participant_view=view.model_dump(mode="json"),
        rendered_context=turn.rendered_context,
        observation_history=turn.observation_history,
        candidate_selections=candidate_payloads(turn.candidates),
    )


def _persist_solicitation_failure(
    context: _SolicitationEvidenceContext,
) -> None:
    """Persist a failed provider operation without constructing an admission."""

    state = getattr(context.status, "state", None)
    diagnostics = getattr(context.status, "diagnostics", ())
    persist_control_evidence(
        context.authority,
        ParticipantControlEvidence(
            turn=context.turn,
            provider=context.provider,
            solicitation=context.solicitation,
            solicitation_receipt=context.receipt,
            solicitation_state=(
                state.value if isinstance(state, OperationState) else "unavailable"
            ),
            solicitation_diagnostics=tuple(
                diagnostic.message for diagnostic in diagnostics
            ),
            solicitation_fingerprint=context.fingerprint,
        ),
    )


def _persist_admission_evidence(
    context: _SolicitationEvidenceContext,
    selection: ParticipantDecisionSurfaceSelectionV2Model,
    admission: ParticipantAdmissionAttempt,
    admission_status: object,
) -> None:
    """Persist provider selection and the resulting RAES admission operation."""

    admission_state = getattr(admission_status, "state", None)
    admission_diagnostics = getattr(admission_status, "diagnostics", ())
    solicitation_diagnostics = getattr(context.status, "diagnostics", ())
    persist_control_evidence(
        context.authority,
        ParticipantControlEvidence(
            turn=context.turn,
            provider=context.provider,
            solicitation=context.solicitation,
            solicitation_receipt=context.receipt,
            solicitation_state=OperationState.SUCCEEDED.value,
            solicitation_diagnostics=tuple(
                diagnostic.message for diagnostic in solicitation_diagnostics
            ),
            solicitation_fingerprint=context.fingerprint,
            selection=selection.model_dump(mode="json"),
            action_instance_id=admission.request.action_instance_id,
            admission_receipt=admission.receipt,
            admission_state=(
                admission_state.value
                if isinstance(admission_state, OperationState)
                else "unavailable"
            ),
            admission_diagnostics=tuple(
                diagnostic.message for diagnostic in admission_diagnostics
            ),
        ),
    )


def admit_projected_participant_selection(
    control_plane: AptlParticipantControlPlane,
    *,
    turn: ParticipantDecisionTurn,
    selection: object,
    admission_apparatus: ParticipantApparatus | None = None,
    action_instance_id: str | None = None,
    idempotency_key: str | None = None,
    request_fingerprint: str | None = None,
) -> ParticipantAdmissionAttempt:
    """Bind and admit one selection from an exact delivered RAES v2 surface.

    The optional overrides exist for controlled conformance challenges. They
    still traverse the public RAES binder and control plane; they do not grant
    another action path.
    """

    if not isinstance(selection, ParticipantDecisionSurfaceSelectionV2Model):
        raise TypeError("selection must be a RAES v2 decision-surface selection")
    runtime = control_plane._target.participant_runtime
    from aptl.backends.raes_participant_runtime import AptlParticipantRuntime

    if not isinstance(runtime, AptlParticipantRuntime):
        raise ValueError(_RUNTIME_UNAVAILABLE)
    authority = runtime.plan_authority
    if authority is None:
        raise ValueError("participant plan authority is unavailable")
    view = turn.surface.participant_view
    delivery = turn.surface.delivery
    if delivery is None:
        raise ValueError("participant decision surface was not delivered")
    request_apparatus = admission_apparatus or turn.apparatus
    request = _build_admission_request(
        turn,
        selection,
        request_apparatus,
        action_instance_id,
    )
    resolvers = _build_binding_resolvers(authority, turn, delivery)
    participant_behavior = authority.runtime_model.participant_behaviors[
        view.participant_address
    ]
    fingerprint = request_fingerprint or selection_fingerprint(
        selection.model_dump(mode="json")
    )
    receipt = control_plane.admit_participant_decision_surface_selection_v2(
        participant_behavior,
        surface=turn.surface,
        selection=selection,
        admission_request=request,
        resolvers=resolvers,
        idempotency_key=idempotency_key
        or f"participant-admission.{selection.proposal_ref}",
        request_fingerprint=fingerprint,
    )
    return ParticipantAdmissionAttempt(receipt=receipt, request=request)


def _build_admission_request(
    turn: ParticipantDecisionTurn,
    selection: ParticipantDecisionSurfaceSelectionV2Model,
    apparatus: ParticipantApparatus,
    action_instance_id: str | None,
) -> ParticipantActionAdmissionRequest:
    """Bind one selected candidate to the delivered participant state cut."""

    view = turn.surface.participant_view
    return ParticipantActionAdmissionRequest(
        participant_address=view.participant_address,
        action_contract_address=selection.action_contract_address,
        observation_boundary_address=turn.observation_boundary_address,
        action_instance_id=action_instance_id
        or (
            f"{view.episode_id}.epoch-{view.decision_epoch}."
            f"{selection.action_contract_address.removeprefix('participant.action-contract.')}"
        ),
        implementation_manifest=apparatus.manifest,
        implementation_selection=apparatus.selection,
        evidence_refs=("content.participant-observations",),
        visible_refs=tuple(view.visible_context_refs),
        disclosed_refs=(),
        observation_boundary_evidence_refs=("content.participant-observations",),
        requires_terminal_outcome=True,
    )


def _build_binding_resolvers(
    authority: ParticipantPlanAuthority,
    turn: ParticipantDecisionTurn,
    delivery: object,
) -> ParticipantDecisionSurfaceBindingResolversV2:
    """Build closed resolvers for the exact delivered selection coordinates."""

    def resolve_arguments(**coordinates: object) -> object:
        """Resolve arguments only through the admitted runtime action contract."""
        address = coordinates.get("action_contract_address")
        contract = authority.runtime_model.action_contracts.get(address)
        if contract is None:
            return None
        return resolve_participant_action_arguments(
            contract,
            action_contract_address=str(address),
            argument_shape_ref=str(coordinates.get("argument_shape_ref")),
            proposal_ref=str(coordinates.get("proposal_ref")),
            proposed_arguments=coordinates.get("proposed_arguments", {}),
        )

    return ParticipantDecisionSurfaceBindingResolversV2(
        argument_shape=resolve_arguments,
        apparatus=lambda **coordinates: (
            turn.apparatus.selection
            if coordinates.get("implementation_selection_ref")
            == turn.apparatus.implementation_selection_ref
            and coordinates.get("exposure_policy_ref")
            == turn.apparatus.selection.exposure_policy.policy_id
            and coordinates.get("decision_cut_ref")
            == turn.surface.assurance.derivation_anchor.state_cut.cut_ref
            else None
        ),
        delivery=lambda **coordinates: (
            delivery
            if coordinates.get("delivery_ref") == delivery.delivery_ref
            else None
        ),
    )
