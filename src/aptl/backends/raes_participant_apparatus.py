"""RAES v2 apparatus construction for APTL participants."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass

import rfc8785
from raes_contracts.contracts import (
    BindingOwnerModel,
    BindingScalarType,
    ConfigurationTargetDeclarationModel,
    ConfigurationTargetRegistryModel,
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
    "experiment-binding-descriptors-v1",
    "participant-configuration-result-v1",
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
_MODEL_CONFIGURATION_TARGET = "model.identifier"


@dataclass(frozen=True)
class _ApparatusRefs:
    """Stable contract references for one participant run."""

    manifest: str
    selection: str
    policy: str


@dataclass(frozen=True)
class _ManifestAssembly:
    """Manifest payload plus its optional bound model configuration."""

    payload: dict[str, object]
    configuration_ref: str | None
    configuration_digest: str | None


def build_participant_apparatus(
    *,
    participant_address: str,
    implementation_name: str,
    implementation_version: str,
    provider_name: str,
    model: str | None,
    run_id: str,
) -> ParticipantApparatus:
    """Build the manifest and exact run selection for one installed agent."""

    refs = _apparatus_refs(
        participant_address,
        implementation_name,
        implementation_version,
        run_id,
    )
    assembly = _manifest_assembly(
        implementation_name,
        implementation_version,
        provider_name,
        model,
    )
    manifest = ParticipantImplementationManifestModel.model_validate(assembly.payload)
    selection = _implementation_selection(
        participant_address,
        refs,
        manifest,
        assembly,
    )
    return ParticipantApparatus(
        implementation_selection_ref=refs.selection,
        manifest_ref=refs.manifest,
        manifest=manifest,
        selection=selection,
        provider=provider_name,
        model=model,
    )


def _apparatus_refs(
    participant_address: str,
    implementation_name: str,
    implementation_version: str,
    run_id: str,
) -> _ApparatusRefs:
    """Derive stable references for one participant apparatus."""

    participant_suffix = participant_address.removeprefix("participant.behavior.")
    return _ApparatusRefs(
        manifest=(
            "participant-implementation-manifests."
            f"{implementation_name}.{implementation_version}"
        ),
        selection=f"participant-implementation-selections.{run_id}.{participant_suffix}",
        policy=f"participant-exposure-policies.{run_id}.{participant_suffix}",
    )


def _manifest_assembly(
    implementation_name: str,
    implementation_version: str,
    provider_name: str,
    model: str | None,
) -> _ManifestAssembly:
    """Build one manifest payload and optional model configuration binding."""

    payload: dict[str, object] = {
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
            "supported_participant_contracts": list(_PARTICIPANT_SELECTION_CONTRACTS),
            "supported_decision_surface_modes": ["autonomous"],
            # The installed CLI is a decision source only. It is never
            # given participant action, shell, browser, filesystem,
            # network, or MCP affordances.
            "tool_affordance_expectations": ["x-aptl:no-action-tools"],
            "exposure_policy_kinds": [
                "task-statement",
                "observation-stream",
            ],
        },
    }
    if model is None:
        return _ManifestAssembly(payload, None, None)
    configuration_payload = {
        "schema": "aptl.installed-participant-model-configuration/v1",
        "provider": provider_name,
        "model": model,
    }
    configuration_digest = canonical_mapping_digest(configuration_payload)
    configuration_ref = (
        "participant-implementation-configurations."
        f"{provider_name}.{configuration_digest.removeprefix('sha256:')[:16]}"
    )
    payload["configuration_registry"] = _model_configuration_registry()
    return _ManifestAssembly(payload, configuration_ref, configuration_digest)


def _model_configuration_registry() -> dict[str, object]:
    """Declare the literal internal model identifier binding."""

    registry = ConfigurationTargetRegistryModel(
        owner=BindingOwnerModel(
            contract_id="participant-implementation-manifest/v1",
            contract_version="1",
            validator_id="aptl-installed-participant-model",
            validator_version="1",
        ),
        targets={
            _MODEL_CONFIGURATION_TARGET: ConfigurationTargetDeclarationModel(
                target_id=_MODEL_CONFIGURATION_TARGET,
                value_type=BindingScalarType.STRING,
                allowed_value_kinds=["literal"],
                sensitivity="internal",
            )
        },
    )
    return registry.model_dump(mode="json")


def _implementation_selection(
    participant_address: str,
    refs: _ApparatusRefs,
    manifest: ParticipantImplementationManifestModel,
    assembly: _ManifestAssembly,
) -> ParticipantImplementationSelectionModel:
    """Bind one exact manifest, model configuration, and exposure policy."""

    policy_digest = canonical_mapping_digest(
        {
            "policy_id": refs.policy,
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
            "manifest_ref": refs.manifest,
            "manifest_digest": canonical_contract_digest(manifest),
            "configuration_ref": assembly.configuration_ref,
            "configuration_digest": assembly.configuration_digest,
            "selected_decision_surface_mode": "autonomous",
            "participant_contract_versions": list(_PARTICIPANT_SELECTION_CONTRACTS),
            "exposure_policy": {
                "policy_id": refs.policy,
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
    return selection


def canonical_mapping_digest(value: Mapping[str, object]) -> str:
    """Return the canonical digest for one apparatus mapping."""

    return f"sha256:{hashlib.sha256(rfc8785.dumps(dict(value))).hexdigest()}"
