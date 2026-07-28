"""Secret-free control evidence for participant selection and admission."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from raes_contracts.runtime_state import OperationReceipt

from aptl.backends.raes_participant_apparatus_models import ParticipantDecisionTurn
from aptl.backends.raes_participant_provider import (
    ParticipantDecisionSolicitation,
    ParticipantSelectionProvider,
)

if TYPE_CHECKING:
    from aptl.backends.raes_participant_driver import ParticipantPlanAuthority


@dataclass(frozen=True)
class ParticipantControlEvidence:
    """One participant selection operation and optional admission result."""

    turn: ParticipantDecisionTurn
    provider: ParticipantSelectionProvider
    solicitation: ParticipantDecisionSolicitation
    solicitation_receipt: OperationReceipt
    solicitation_state: str
    solicitation_diagnostics: tuple[str, ...]
    solicitation_fingerprint: str
    selection: Mapping[str, object] | None = None
    action_instance_id: str | None = None
    admission_receipt: OperationReceipt | None = None
    admission_state: str | None = None
    admission_diagnostics: tuple[str, ...] = ()


def persist_control_evidence(
    authority: ParticipantPlanAuthority,
    evidence: ParticipantControlEvidence,
) -> None:
    """Persist the joins between provider, RAES, and native realization."""

    if authority.run_store is None or authority.run_id is None:
        return
    record = _control_evidence_payload(authority, evidence)
    authority.run_store.append_jsonl(
        authority.run_id,
        "evaluator/participant-control-evidence.jsonl",
        [record],
    )


def _control_evidence_payload(
    authority: ParticipantPlanAuthority,
    evidence: ParticipantControlEvidence,
) -> dict[str, object]:
    """Build the canonical secret-free participant control record."""

    turn = evidence.turn
    view = turn.surface.participant_view
    delivery = turn.surface.delivery
    selection = evidence.selection
    return {
        "schema": "aptl.participant-control-evidence/v2",
        "run_id": authority.run_id,
        "participant_address": view.participant_address,
        "episode_id": view.episode_id,
        "decision_epoch": view.decision_epoch,
        "behavior_specification_address": turn.behavior_specification_address,
        "observation_boundary_address": turn.observation_boundary_address,
        "surface_id": view.surface_id,
        "participant_view_digest": turn.surface.assurance.participant_view_digest,
        "delivery_ref": delivery.delivery_ref if delivery is not None else None,
        "implementation_name": evidence.provider.implementation_name,
        "implementation_version": evidence.provider.implementation_version,
        "provider": turn.apparatus.provider,
        "model": turn.apparatus.model,
        "implementation_manifest_ref": turn.apparatus.manifest_ref,
        "implementation_manifest_digest": turn.apparatus.selection.manifest_digest,
        "implementation_selection_ref": turn.apparatus.implementation_selection_ref,
        "implementation_configuration_ref": (
            turn.apparatus.selection.configuration_ref
        ),
        "implementation_configuration_digest": (
            turn.apparatus.selection.configuration_digest
        ),
        "exposure_policy_ref": turn.apparatus.selection.exposure_policy.policy_id,
        "solicitation_id": evidence.solicitation.solicitation_id,
        "solicitation_operation_id": evidence.solicitation_receipt.operation_id,
        "solicitation_state": evidence.solicitation_state,
        "solicitation_diagnostics": list(evidence.solicitation_diagnostics),
        "solicitation_fingerprint": evidence.solicitation_fingerprint,
        "rendered_context_digest": selection_fingerprint(
            {"items": list(evidence.solicitation.rendered_context)}
        ),
        "observation_history_digest": selection_fingerprint(
            {"items": list(evidence.solicitation.observation_history)}
        ),
        "selected_action_contract_address": (
            selection.get("action_contract_address") if selection is not None else None
        ),
        "selected_proposal_ref": (
            selection.get("proposal_ref") if selection is not None else None
        ),
        "selected_payload_digest": (
            selection_fingerprint(selection) if selection is not None else None
        ),
        "action_instance_id": evidence.action_instance_id,
        "admission_operation_id": (
            evidence.admission_receipt.operation_id
            if evidence.admission_receipt is not None
            else None
        ),
        "admission_state": evidence.admission_state,
        "admission_diagnostics": list(evidence.admission_diagnostics),
        "scenario_source_sha256": authority.scenario_source_sha256,
        "compiled_model_sha256": authority.compiled_model_sha256,
        "official_capture_started": False,
    }


def solicitation_fingerprint(
    request: ParticipantDecisionSolicitation,
) -> str:
    """Digest one complete participant decision solicitation."""

    return selection_fingerprint(
        {
            "participant_address": request.participant_address,
            "episode_id": request.episode_id,
            "solicitation_id": request.solicitation_id,
            "participant_view": dict(request.participant_view),
            "rendered_context": [dict(item) for item in request.rendered_context],
            "observation_history": [dict(item) for item in request.observation_history],
            "candidate_selections": [
                dict(candidate) for candidate in request.candidate_selections
            ],
        }
    )


def selection_fingerprint(payload: Mapping[str, object]) -> str:
    """Digest one canonical participant selection payload."""

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"
