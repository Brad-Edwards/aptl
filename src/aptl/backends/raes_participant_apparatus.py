"""RAES v2 apparatus construction for APTL participants."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

import rfc8785
from raes_contracts.contracts import (
    ParticipantImplementationManifestModel,
    ParticipantImplementationSelectionModel,
)
from raes_contracts.satisfiability import canonical_contract_digest

from aptl.backends.raes_participant_apparatus_models import (
    ParticipantApparatus,
    ParticipantDecisionTurn,
)
from aptl.backends.raes_participant_projection import project_participant_turn

__all__ = [
    "ParticipantApparatus",
    "ParticipantDecisionTurn",
    "build_participant_apparatus",
    "project_participant_turn",
]

_PARTICIPANT_CONTRACTS = (
    "participant-implementation-manifest-v1",
    "participant-implementation-provenance-v1",
    "participant-episode-state-envelope-v1",
    "participant-episode-history-event-stream-v1",
    "participant-behavior-history-event-stream-v1",
    "participant-decision-surface-v2",
)
_PARTICIPANT_SELECTION_CONTRACTS = (
    "participant-episode-state-envelope-v1",
    "participant-episode-history-event-stream-v1",
    "participant-behavior-history-event-stream-v1",
    "participant-decision-surface-v2",
)
_CONCEPT_BINDINGS = (
    {"scope": "implementation_kind", "family": "apparatus-declarations"},
    {
        "scope": "capabilities.supported_participant_contracts",
        "family": "apparatus-declarations",
    },
    {
        "scope": "capabilities.supported_decision_surface_modes",
        "family": "apparatus-declarations",
    },
    {
        "scope": "capabilities.tool_affordance_expectations",
        "family": "tools-and-artifacts",
    },
    {
        "scope": "capabilities.exposure_policy_kinds",
        "family": "provenance-and-evidence",
    },
)


def build_participant_apparatus(
    *,
    participant_address: str,
    implementation_name: str,
    implementation_version: str,
    run_id: str,
) -> ParticipantApparatus:
    """Build the manifest and exact run selection for one installed agent."""

    manifest_ref = (
        "participant-implementation-manifests."
        f"{implementation_name}.{implementation_version}"
    )
    selection_ref = (
        f"participant-implementation-selections.{run_id}."
        f"{participant_address.removeprefix('participant.behavior.')}"
    )
    policy_id = (
        f"participant-exposure-policies.{run_id}."
        f"{participant_address.removeprefix('participant.behavior.')}"
    )
    manifest = ParticipantImplementationManifestModel.model_validate(
        {
            "identity": {
                "name": implementation_name,
                "version": implementation_version,
            },
            "implementation_kind": "agent",
            "supported_contract_versions": list(_PARTICIPANT_CONTRACTS),
            "compatibility": {
                "participant_runtimes": ["aptl"],
                "processors": ["raes-reference-processor"],
                "backends": ["aptl"],
            },
            "concept_bindings": list(_CONCEPT_BINDINGS),
            "constraints": {
                "max_parallel_episodes": "1",
                "action_execution": "none; decision source only",
                "decision_payload": "RAES participant-decision-surface-v2 view",
            },
            "capabilities": {
                "supported_participant_contracts": list(
                    _PARTICIPANT_SELECTION_CONTRACTS
                ),
                "supported_decision_surface_modes": ["autonomous"],
                # The installed CLI is a decision source only.  It is never
                # given participant action, shell, browser, filesystem,
                # network, or MCP affordances.
                "tool_affordance_expectations": ["x-aptl:no-action-tools"],
                "exposure_policy_kinds": [
                    "task-statement",
                    "observation-stream",
                ],
            },
        }
    )
    policy_digest = canonical_mapping_digest(
        {
            "policy_id": policy_id,
            "version": "1",
            "participant_address": participant_address,
            "disclosed_classes": ["task-statement", "observation-stream"],
            "withheld_classes": ["hidden-truth", "evaluator-state"],
        }
    )
    selection = ParticipantImplementationSelectionModel.model_validate(
        {
            "participant_address": participant_address,
            "implementation_identity": manifest.identity.model_dump(mode="json"),
            "manifest_ref": manifest_ref,
            "manifest_digest": canonical_contract_digest(manifest),
            "selected_decision_surface_mode": "autonomous",
            "participant_contract_versions": list(_PARTICIPANT_SELECTION_CONTRACTS),
            "exposure_policy": {
                "policy_id": policy_id,
                "policy_version": "1",
                "policy_digest": policy_digest,
                "exposure_policy_kinds": [
                    "task-statement",
                    "observation-stream",
                ],
                "disclosed_refs": [],
                "withheld_refs": [
                    "content.study-hidden-truth",
                    "content.study-evaluator-evidence",
                ],
                "tool_affordance_refs": [],
                "visibility_scope_refs": [
                    f"audience.{participant_address}",
                ],
            },
        }
    )
    return ParticipantApparatus(
        implementation_selection_ref=selection_ref,
        manifest_ref=manifest_ref,
        manifest=manifest,
        selection=selection,
    )


def canonical_mapping_digest(value: Mapping[str, object]) -> str:
    """Return the canonical digest for one apparatus mapping."""

    return f"sha256:{hashlib.sha256(rfc8785.dumps(dict(value))).hexdigest()}"
