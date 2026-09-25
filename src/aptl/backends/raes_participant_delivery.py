"""Execute SDL-authored participant inject deliveries through installed agents.

The scenario owns every behavioral fact: participant identity, role, instruction
content, occurrence, order, control transition, evidence references, and logical
time.  This module supplies only the backend mechanism selected by the authored
``realization_profile_ref``.  It deliberately contains no study prompt and no
scenario-specific resource name.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping
from uuid import NAMESPACE_URL, uuid5

from raes_contracts.contracts.participant_crossing import (
    ParticipantCrossingGateDisposition,
    ParticipantCrossingPolicyReferenceModel,
)
from raes_contracts.runtime_state import OperationState
from raes_runtime.control_plane import RuntimeControlPlane
from raes_runtime.control_plane_security import (
    ControlPlaneIdentity,
    ControlPlaneRole,
    ParticipantControlSubjectBinding,
)
from raes_runtime.participant_control_intents import (
    ParticipantExternalDirectionControlIntent,
    ParticipantProposalControlIntent,
)
from raes_runtime.participant_crossing_mediation import (
    ParticipantCrossingEvidence,
    ParticipantCrossingIntent,
    ParticipantCrossingPolicyResolution,
    ParticipantCrossingSemanticGates,
    ParticipantCrossingValidationContext,
)

from aptl.core.runstore import RunStorageBackend
from aptl.core.correlation.clock import SystemClockProvider
from aptl.core.evidence._persist import EvidenceRef
from aptl.core.evidence.coordinator import acquire_evidence
from aptl.core.evidence.outcomes import AcquisitionDisposition, CollectorStatus
from aptl.core.evidence.protocol import CollectorContext, CollectorOutcome, RunScope
from aptl.core.experiment.capture_plan import CapturePlan
from aptl.core.experiment.capture_registry import CaptureBinding
from aptl.utils.pathsafe import create_exclusive_nofollow
from aptl.utils.logging import get_logger
from aptl.workbench.agent import (
    _admitted_executable,
    _parse_agent_result,
    _read_private_config,
)
from aptl.workbench.process import (
    AgentExecutionError,
    BoundedProcessRunner,
    ProcessRunner,
)
from aptl.workbench.profiles import ProfileId, profile_for

CLAUDE_CODE_REALIZATION_PROFILE = "participant-implementation-manifest:claude-code"
_EVIDENCE_PATH = "participant/inject-deliveries.jsonl"
log = get_logger("raes-participant-delivery")

_PROVIDER_AUTH_ENVIRONMENT = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "CLAUDE_CODE_USE_VERTEX",
        "ANTHROPIC_VERTEX_PROJECT_ID",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "CLOUDSDK_CONFIG",
        "SHIFTER_GOOGLE_APPLICATION_CREDENTIALS",
        "CLAUDE_CODE_USE_BEDROCK",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
    }
)

_MCP_COMMON_RUNTIME_ENVIRONMENT = frozenset({"APTL_MCP_DISABLE_DOTENV"})

_MCP_RUNTIME_ENVIRONMENT = {
    "aptl-red": frozenset(
        {
            "APTL_HP_KALI_SSH_PROXY_2023",
            "APTL_MCP_ADMITTED_RUN_ID",
            "APTL_MCP_KALI_HOST",
            "APTL_MCP_RUN_STORE_BASE",
            "APTL_STATE_DIR",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        }
    ),
    "aptl-casemgmt": frozenset(
        {
            "APTL_HP_THEHIVE_9000",
            "APTL_MCP_ADMITTED_RUN_ID",
            "APTL_MCP_RUN_STORE_BASE",
            "APTL_STATE_DIR",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        }
    ),
    "aptl-indexer": frozenset(
        {
            "APTL_HP_WAZUH_INDEXER_9200",
            "APTL_HP_WAZUH_MANAGER_55000",
            "APTL_MCP_ADMITTED_RUN_ID",
            "APTL_MCP_RUN_STORE_BASE",
            "APTL_STATE_DIR",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        }
    ),
    "aptl-network": frozenset(
        {
            "APTL_HP_WAZUH_INDEXER_9200",
            "APTL_MCP_ADMITTED_RUN_ID",
            "APTL_MCP_RUN_STORE_BASE",
            "APTL_STATE_DIR",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        }
    ),
    "aptl-soar": frozenset(
        {
            "APTL_HP_SHUFFLE_FRONTEND_443",
            "APTL_MCP_ADMITTED_RUN_ID",
            "APTL_MCP_RUN_STORE_BASE",
            "APTL_STATE_DIR",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        }
    ),
    "aptl-threatintel": frozenset(
        {
            "APTL_HP_MISP_443",
            "APTL_MCP_ADMITTED_RUN_ID",
            "APTL_MCP_RUN_STORE_BASE",
            "APTL_STATE_DIR",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        }
    ),
    "aptl-wazuh": frozenset(
        {
            "APTL_HP_WAZUH_INDEXER_9200",
            "APTL_HP_WAZUH_MANAGER_55000",
            "APTL_MCP_ADMITTED_RUN_ID",
            "APTL_MCP_RUN_STORE_BASE",
            "APTL_STATE_DIR",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        }
    ),
}


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


class _ParticipantDeliveryCrossingPolicyResolver:
    """Resolve API-423 ingress policy from compiled delivery declarations."""

    def __init__(
        self,
        turns: tuple[ParticipantInjectTurn, ...],
        target: object,
        behavior_specifications: Mapping[str, object],
    ) -> None:
        self._policies = _delivery_crossing_policies(turns)
        self._subjects: list[object] = []
        behavior_evidence, behavior_authority = _participant_behavior_policy_refs(
            turns,
            behavior_specifications,
        )
        self._evidence_refs = frozenset(
            {
                *(
                    ref
                    for turn in turns
                    for ref in (
                        *turn.evidence_requirement_addresses,
                        *turn.control_evidence_addresses,
                    )
                ),
                *behavior_evidence,
                *_target_participant_policy_evidence_refs(target),
            }
        )
        self._authority_refs = (
            frozenset(
                ref
                for turn in turns
                for ref in (
                    turn.controller_address,
                    *turn.control_evidence_addresses,
                )
            )
            | behavior_authority
        )

    def resolve(
        self,
        intent: ParticipantCrossingIntent,
        _snapshot: object,
    ) -> ParticipantCrossingPolicyResolution:
        policy = self._policies.get(intent.participant_address)
        if policy is None:
            raise ValueError("participant delivery crossing policy is unavailable")
        if intent.subject not in self._subjects:
            self._subjects.append(intent.subject)
        return ParticipantCrossingPolicyResolution(
            policy=policy,
            gates=ParticipantCrossingSemanticGates(
                participant_authority=ParticipantCrossingGateDisposition.PERMIT,
                action_admission=ParticipantCrossingGateDisposition.PERMIT,
                visibility=ParticipantCrossingGateDisposition.NOT_APPLICABLE,
                marking_authorization=ParticipantCrossingGateDisposition.PERMIT,
                declassification=ParticipantCrossingGateDisposition.NOT_APPLICABLE,
                transformation_validity=(
                    ParticipantCrossingGateDisposition.NOT_APPLICABLE
                ),
            ),
            reason_code="authored-participant-delivery-policy-satisfied",
        )

    def validation_context(
        self,
        _snapshot: object,
        _participant_address: str,
    ) -> ParticipantCrossingValidationContext:
        return ParticipantCrossingValidationContext(
            known_subjects=tuple(self._subjects),
            policies=tuple(self._policies.values()),
            known_evidence_refs=self._evidence_refs,
            known_authority_basis_refs=self._authority_refs,
        )


def _target_participant_policy_evidence_refs(target: object) -> tuple[str, ...]:
    """Return the target's own evidence for supported participant policy."""

    manifest = getattr(target, "manifest", None)
    capabilities = getattr(manifest, "participant_runtime", None)
    return tuple(
        ref
        for support in getattr(capabilities, "feature_support", ()) or ()
        for ref in getattr(support, "evidence_refs", ()) or ()
    )


def _participant_behavior_policy_refs(
    turns: tuple[ParticipantInjectTurn, ...],
    behavior_specifications: Mapping[str, object],
) -> tuple[frozenset[str], frozenset[str]]:
    """Collect compiled state and transition evidence for delivered participants."""

    admitted = {turn.behavior_specification_address for turn in turns}
    evidence: set[str] = set()
    authority: set[str] = set()
    for address in admitted:
        behavior = behavior_specifications.get(address)
        if behavior is None:
            continue
        for state in getattr(behavior, "controller_states", ()):
            evidence.update(getattr(state, "evidence_addresses", ()) or ())
            authority.update(
                getattr(state, "authority_basis_addresses", ())
                or getattr(state, "authority_basis_refs", ())
                or ()
            )
        for transition in getattr(behavior, "control_transitions", ()):
            evidence.update(getattr(transition, "evidence_addresses", ()) or ())
            evidence.update(
                getattr(transition, "completion_evidence_addresses", ()) or ()
            )
    return frozenset(evidence), frozenset(authority)


def _delivery_crossing_policies(
    turns: tuple[ParticipantInjectTurn, ...],
) -> dict[str, ParticipantCrossingPolicyReferenceModel]:
    """Build one stable authored policy interval for each participant."""

    grouped: dict[str, list[ParticipantInjectTurn]] = {}
    for turn in turns:
        grouped.setdefault(turn.participant_address, []).append(turn)
    policies: dict[str, ParticipantCrossingPolicyReferenceModel] = {}
    for participant, participant_turns in grouped.items():
        coordinates = {
            (
                turn.policy_ref,
                turn.policy_revision,
                turn.exposure_policy_ref,
                turn.audience_scope_ref,
                turn.visibility_basis_ref,
                turn.disclosure_basis_ref,
                turn.observation_boundary_address,
            )
            for turn in participant_turns
        }
        if len(coordinates) != 1:
            raise AgentExecutionError(
                "participant delivery policy changes within one participant sequence"
            )
        (
            policy_ref,
            policy_revision,
            exposure_policy_ref,
            audience_scope_ref,
            visibility_basis_ref,
            disclosure_basis_ref,
            observation_boundary_address,
        ) = coordinates.pop()
        policy_payload = json.dumps(
            {
                "audience_scope_ref": audience_scope_ref,
                "disclosure_basis_ref": disclosure_basis_ref,
                "exposure_policy_ref": exposure_policy_ref,
                "observation_boundary_address": observation_boundary_address,
                "policy_ref": policy_ref,
                "policy_revision": policy_revision,
                "visibility_basis_ref": visibility_basis_ref,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        valid_from = min(turn.control_valid_from_order for turn in participant_turns)
        # API-423 records a request at the control transition's logical order
        # and its decision at the following order.  The authored control window
        # therefore supplies the policy's request interval; extend the policy
        # by one order so the terminal decision remains inside that policy.
        valid_until = (
            max(turn.control_valid_until_order for turn in participant_turns) + 1
        )
        policies[participant] = ParticipantCrossingPolicyReferenceModel(
            policy_id=policy_ref,
            policy_revision=policy_revision,
            policy_digest=f"sha256:{hashlib.sha256(policy_payload).hexdigest()}",
            policy_decision_ref=disclosure_basis_ref,
            decision_cut_ref=observation_boundary_address,
            effective_order=valid_from,
            valid_from_order=valid_from,
            valid_until_order=valid_until,
        )
    return policies


class _ParticipantDeliveryCollector:
    """Run one provider turn inside the public evidence lifecycle."""

    def __init__(self, registration_id: str) -> None:
        self._registration_id = registration_id
        self._context: CollectorContext | None = None
        self._started_at = ""
        self._payload: dict[str, object] = {}
        self.result: ParticipantTurnResult | None = None
        self._failed = False

    @property
    def registration_id(self) -> str:
        return self._registration_id

    def start(self, context: CollectorContext) -> object:
        self._context = context
        self._started_at = context.clock.now()
        return self

    def deliver(
        self,
        adapter: "ClaudeCodeHostParticipantAdapter",
        **kwargs: object,
    ) -> None:
        try:
            self.result = adapter.deliver(**kwargs)  # type: ignore[arg-type]
        except Exception:
            self._failed = True
            raise

    def mark_failed(self) -> None:
        self._failed = True

    def stop(self, handle: object) -> CollectorOutcome:
        if handle is not self or self._context is None:
            raise AgentExecutionError("participant delivery collector handle is invalid")
        now = self._context.clock.now()
        if self._failed or self.result is None:
            return CollectorOutcome(
                status=CollectorStatus.MID_RUN_LOSS,
                started_at=self._started_at,
                finished_at=now,
                detail="participant provider delivery failed",
            )
        result = self.result
        provider_metadata = {
            key: value
            for key, value in result.provider_payload.items()
            if key != "result"
        }
        payload = {
            "delivery_address": self._payload["delivery_address"],
            "participant_address": self._payload["participant_address"],
            "realization_profile_ref": self._payload["realization_profile_ref"],
            "instruction": self._payload["instruction"],
            "response": result.response,
            "provider_metadata": provider_metadata,
            "model": self._payload["model"],
            "session_id": result.session_id,
            "delivery_status": "delivered",
            "observation_status": "not-asserted",
        }
        return CollectorOutcome(
            status=CollectorStatus.OK,
            started_at=self._started_at,
            finished_at=now,
            chunks=(json.dumps(payload, sort_keys=True).encode("utf-8"),),
            media_type="application/json",
            event_count=1,
            observer_effect="participant instruction delivered through installed provider",
            source_pipeline={
                "realization_profile_ref": payload["realization_profile_ref"],
                "delivery_address": payload["delivery_address"],
            },
        )

    def bind_payload(self, turn: ParticipantInjectTurn, model: str) -> None:
        self._payload = {
            "delivery_address": turn.address,
            "participant_address": turn.participant_address,
            "realization_profile_ref": turn.realization_profile_ref,
            "instruction": turn.instruction,
            "model": model,
        }


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
        for item in getattr(getattr(runtime_model, "time_model", None), "constraints", ())
    }
    behavior_specs = getattr(scenario, "behavior_specifications", {})
    content = getattr(scenario, "content", {})
    scripts = getattr(scenario, "scripts", {})
    turns: list[ParticipantInjectTurn] = []

    for address, delivery in compiled.items():
        spec_name = _behavior_specification_name(address)
        behavior = behavior_specs.get(spec_name)
        if behavior is None:
            raise ValueError("participant inject delivery has no authored behavior specification")
        behavior_address = getattr(delivery, "behavior_specification_address", "")
        compiled_behavior = getattr(runtime_model, "behavior_specifications", {}).get(
            behavior_address
        )
        if compiled_behavior is None:
            raise ValueError("participant delivery has no compiled behavior specification")
        roles = tuple(getattr(behavior, "participant_role_refs", ()))
        if len(roles) != 1:
            raise ValueError("participant inject delivery requires exactly one participant role")
        try:
            profile = ProfileId(roles[0])
            profile_for(profile)
        except (TypeError, ValueError) as exc:
            raise ValueError("participant role has no installed APTL profile") from exc

        realization_profile = getattr(behavior, "realization_profile_ref", None)
        if realization_profile != CLAUDE_CODE_REALIZATION_PROFILE:
            raise ValueError("participant realization profile is unsupported")
        if getattr(delivery, "failure_disposition", None) != "reject-no-delivery":
            raise ValueError("participant delivery must fail closed")

        constraint_addresses = tuple(
            getattr(delivery, "temporal_constraint_addresses", ())
        )
        if len(constraint_addresses) != 1:
            raise ValueError("participant delivery requires one exact temporal window")
        constraint = constraints.get(constraint_addresses[0])
        if (
            constraint is None
            or getattr(constraint, "kind", None) != "window"
            or getattr(constraint, "start_tick", None)
            != getattr(constraint, "end_tick", None)
            or getattr(constraint, "start_microstep", None) != 0
            or getattr(constraint, "end_microstep", None) != 0
            or tuple(getattr(constraint, "subject_addresses", ())) != (address,)
        ):
            raise ValueError("participant delivery temporal window is not exact")
        tick = int(constraint.start_tick)
        _require_occurrence_tick(scenario, delivery, scripts, tick)
        direct_transition = _control_transition(
            compiled_behavior,
            getattr(delivery, "control_transition_address", ""),
        )
        proposal_transition = _control_transition(
            compiled_behavior,
            getattr(direct_transition, "proposal_address", ""),
        )
        proposal_revision = getattr(direct_transition, "proposal_revision", None)
        delivery_policy_values = (
            getattr(delivery, "policy_ref", None),
            getattr(delivery, "policy_revision", None),
            getattr(delivery, "exposure_policy_ref", None),
            getattr(delivery, "audience_scope_ref", None),
            getattr(delivery, "visibility_basis_ref", None),
            getattr(delivery, "disclosure_basis_ref", None),
        )
        delivery_control_orders = (
            getattr(delivery, "control_effective_order", None),
            getattr(delivery, "control_valid_from_order", None),
            getattr(delivery, "control_valid_until_order", None),
        )
        if (
            getattr(direct_transition, "transition_kind", None)
            != "external-direction"
            or getattr(proposal_transition, "transition_kind", None) != "proposal"
            or not isinstance(proposal_revision, int)
            or any(
                not isinstance(value, str) or not value
                for value in delivery_policy_values
            )
            or any(
                not isinstance(value, int) or isinstance(value, bool)
                for value in delivery_control_orders
            )
        ):
            raise ValueError(
                "participant delivery requires authored control and policy coordinates"
            )

        source_ref = getattr(delivery, "source_item_ref", "")
        source_name = _section_ref_name(source_ref, "content")
        source = content.get(source_name)
        instruction = getattr(source, "text", None)
        if not isinstance(instruction, str) or not instruction.strip():
            raise ValueError("participant delivery source must contain literal instruction text")

        turns.append(
            ParticipantInjectTurn(
                address=address,
                behavior_specification_address=behavior_address,
                participant_address=delivery.participant_address,
                profile=profile,
                realization_profile_ref=realization_profile,
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
                proposal_expected_state_revision=(
                    proposal_transition.expected_state_revision
                ),
                proposal_id=direct_transition.proposal_address,
                proposal_revision=proposal_revision,
                control_evidence_addresses=tuple(
                    getattr(delivery, "control_evidence_addresses", ())
                ),
                evidence_requirement_addresses=tuple(
                    delivery.evidence_requirement_addresses
                ),
                failure_disposition=delivery.failure_disposition,
            )
        )

    ordered = _ordered_participant_turns(turns)
    return ParticipantDeliveryPlan(
        ordered,
        behavior_specifications=dict(runtime_model.behavior_specifications),
    )


def _ordered_participant_turns(
    turns: list[ParticipantInjectTurn],
) -> tuple[ParticipantInjectTurn, ...]:
    """Return the closed delivery sequence after validating its global order."""

    ordered = tuple(sorted(turns, key=lambda turn: (turn.tick, turn.control_effective_order)))
    if len({turn.tick for turn in ordered}) != len(ordered):
        raise ValueError("participant delivery ticks must be unique")
    if any(
        current.control_effective_order >= following.control_effective_order
        for current, following in zip(ordered, ordered[1:], strict=False)
    ):
        raise ValueError("participant delivery control order must be strictly increasing")
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
        if (
            binding is None
            or not binding.registration_id.startswith(
                "aptl.collector.participant-delivery."
            )
        ):
            raise ValueError("participant delivery evidence is not admitted")
        turns.append(replace(turn, capture_binding=binding))
    return ParticipantDeliveryPlan(tuple(turns), plan.behavior_specifications)


def _control_transition(behavior: object, address: str) -> object:
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
        raise ValueError("every authored script must be covered by participant deliveries")
    if story_refs != set(getattr(scenario, "stories", {})):
        raise ValueError("every authored story must be covered by participant deliveries")
    for event in getattr(scenario, "events", {}).values():
        if len(getattr(event, "injects", ())) != 1:
            raise ValueError("participant delivery events must contain exactly one inject")
    for inject in getattr(scenario, "injects", {}).values():
        if getattr(inject, "environment", ()):
            raise ValueError("participant delivery injects cannot carry environment effects")


def _require_occurrence_tick(
    scenario: object,
    delivery: object,
    scripts: Mapping[str, object],
    tick: int,
) -> None:
    spec = getattr(delivery, "spec", {})
    occurrence = spec.get("occurrence", {}) if isinstance(spec, dict) else {}
    script_name = occurrence.get("script_ref")
    event_name = occurrence.get("event_ref")
    story_name = occurrence.get("story_ref")
    script = scripts.get(script_name)
    event_tick = getattr(script, "events", {}).get(event_name) if script else None
    story = getattr(scenario, "stories", {}).get(story_name)
    if event_tick != tick or script_name not in tuple(getattr(story, "scripts", ())):
        raise ValueError("participant delivery time does not match its authored occurrence")


def _behavior_specification_name(address: str) -> str:
    prefix = "participant.behavior-specification."
    suffix = ".inject-delivery."
    if not address.startswith(prefix) or suffix not in address:
        raise ValueError("participant inject delivery address is invalid")
    return address[len(prefix) :].split(suffix, 1)[0]


def _section_ref_name(reference: str, section: str) -> str:
    prefix = f"{section}."
    if not reference.startswith(prefix) or len(reference) == len(prefix):
        raise ValueError(f"participant delivery {section} reference is invalid")
    return reference[len(prefix) :]


class ClaudeCodeHostParticipantAdapter:
    """Use the operator's authenticated Claude Code CLI for one bounded turn."""

    def __init__(
        self,
        executable: Path,
        work_dir: Path,
        *,
        runner: ProcessRunner | None = None,
        timeout_seconds: float = 600.0,
        max_output_bytes: int = 2_000_000,
    ) -> None:
        self._executable = _admitted_executable(executable)
        self._work_dir = work_dir.resolve()
        self._host_home = _host_home()
        self._runner = runner or BoundedProcessRunner()
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes

    def deliver(
        self,
        *,
        instruction: str,
        model: str,
        config_path: Path,
        allowed_tools: tuple[str, ...],
        session_id: str,
        resume: bool,
    ) -> ParticipantTurnResult:
        if not instruction.strip():
            raise AgentExecutionError("participant instruction is empty")
        config_digest = _private_file_sha256(config_path)
        argv = self._argv(
            model=model,
            config_path=config_path,
            allowed_tools=allowed_tools,
            session_id=session_id,
            resume=resume,
        )
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            # The host participant is the operator's installed, authenticated
            # Claude CLI. Its login can depend on provider state below HOME
            # (for example Google ADC), so retain that one host coordinate.
            "HOME": str(self._host_home),
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
            "NO_COLOR": "1",
            **{
                name: os.environ[name]
                for name in (
                    *_PROVIDER_AUTH_ENVIRONMENT,
                    "XDG_CONFIG_HOME",
                    "CLAUDE_CONFIG_DIR",
                )
                if os.environ.get(name)
            },
        }
        result = self._runner.run(
            argv,
            env=environment,
            cwd=self._work_dir,
            stdin=instruction.encode("utf-8"),
            timeout_seconds=self._timeout_seconds,
            max_output_bytes=self._max_output_bytes,
        )
        if not hmac.compare_digest(config_digest, _private_file_sha256(config_path)):
            raise AgentExecutionError("participant MCP configuration changed during delivery")
        if result.returncode != 0:
            raise AgentExecutionError("participant instruction delivery failed")
        response = _parse_agent_result(result.stdout)
        payload = json.loads(result.stdout)
        return ParticipantTurnResult(
            session_id=session_id,
            response=response,
            provider_payload=payload,
        )

    def _argv(
        self,
        *,
        model: str,
        config_path: Path,
        allowed_tools: tuple[str, ...],
        session_id: str,
        resume: bool,
    ) -> tuple[str, ...]:
        session_args = ("--resume", session_id) if resume else ("--session-id", session_id)
        return (
            str(self._executable),
            "--print",
            "--bare",
            "--disable-slash-commands",
            "--no-chrome",
            "--output-format",
            "json",
            "--permission-mode",
            "dontAsk",
            "--tools",
            "",
            "--model",
            model,
            "--allowedTools",
            ",".join(allowed_tools),
            "--mcp-config",
            str(config_path),
            "--strict-mcp-config",
            *session_args,
        )


def execute_participant_delivery_plan(
    plan: ParticipantDeliveryPlan,
    *,
    project_dir: Path,
    model: str,
    run_store: RunStorageBackend,
    run_id: str,
    target: object,
    runtime_manager: object | None,
    initial_snapshot: object,
    claude_executable: Path | None = None,
    runner: ProcessRunner | None = None,
) -> object:
    """Deliver an admitted sequence and return its advanced RAES snapshot."""

    if not plan.turns:
        return initial_snapshot
    if runtime_manager is None:
        raise AgentExecutionError("participant delivery runtime manager is unavailable")
    behavior_specifications = plan.behavior_specifications
    if not behavior_specifications:
        raise AgentExecutionError(
            "participant delivery behavior specifications are unavailable"
        )
    executable = claude_executable or _which_executable("claude")
    node_executable = _which_executable("node")
    source_config = project_dir / ".mcp.json"
    if not source_config.is_file():
        raise AgentExecutionError("synchronized MCP configuration is unavailable")
    run_store.create_run(run_id)

    root = Path(tempfile.mkdtemp(prefix=f"aptl-participant-{run_id}-"))
    root.chmod(0o700)
    work_dir = root / "work"
    work_dir.mkdir(mode=0o700)
    adapter = ClaudeCodeHostParticipantAdapter(
        executable,
        work_dir,
        runner=runner,
    )
    session_ids: dict[str, str] = {}
    configured_profiles: dict[ProfileId, tuple[Path, tuple[str, ...]]] = {}
    snapshot = initial_snapshot
    current_ticks: dict[str, int] = {}
    crossing_policy_resolver = _ParticipantDeliveryCrossingPolicyResolver(
        plan.turns,
        target,
        behavior_specifications,
    )
    try:
        for sequence, turn in enumerate(plan.turns, start=1):
            log.info(
                "Delivering participant inject %d/%d: %s at logical tick %d",
                sequence,
                len(plan.turns),
                turn.address,
                turn.tick,
            )
            config_path, tools = configured_profiles.get(turn.profile, (None, ()))
            if config_path is None:
                config_path, tools = _render_runtime_profile_config(
                    profile=turn.profile,
                    project_dir=project_dir,
                    source_config=source_config,
                    output_dir=root,
                    node_executable=node_executable,
                )
                configured_profiles[turn.profile] = (config_path, tools)
            current_tick = current_ticks.get(turn.clock_address, 0)
            if turn.tick <= current_tick:
                raise AgentExecutionError("participant delivery time is not monotonic")
            advanced = runtime_manager.advance_time(
                turn.clock_address,
                ticks=turn.tick - current_tick,
                microstep=0,
            )
            if not advanced.success:
                raise AgentExecutionError("participant delivery clock advance failed")
            snapshot = advanced.snapshot
            current_ticks[turn.clock_address] = turn.tick

            session_id = session_ids.setdefault(
                turn.participant_address,
                str(uuid5(NAMESPACE_URL, f"aptl:{run_id}:{turn.participant_address}")),
            )
            binding = turn.capture_binding
            if binding is None:
                raise AgentExecutionError(
                    "participant delivery evidence binding is unavailable"
                )
            collector = _ParticipantDeliveryCollector(binding.registration_id)
            collector.bind_payload(turn, model)
            control_plane = RuntimeControlPlane(
                target,
                initial_snapshot=snapshot,
                behavior_specifications=behavior_specifications,
                crossing_policy_resolver=crossing_policy_resolver,
                # The delivery declarations carry API-423 crossing policy.
                # They do not claim the separate SEM-233 flow-control model.
                enforce_final_sink_flow_control=False,
            )
            identity = _participant_control_identity(turn, target)
            trial_failure: Exception | None = None

            def deliver_turn() -> None:
                nonlocal trial_failure
                try:
                    _deliver_controlled_turn(
                        control_plane=control_plane,
                        identity=identity,
                        collector=collector,
                        adapter=adapter,
                        turn=turn,
                        model=model,
                        config_path=config_path,
                        allowed_tools=tools,
                        session_id=session_id,
                        resume=sum(
                            prior.participant_address == turn.participant_address
                            for prior in plan.turns[: sequence - 1]
                        )
                        > 0,
                        run_id=run_id,
                    )
                except Exception as exc:
                    # acquire_evidence intentionally converts trial exceptions
                    # into typed capture failure. Retain the original exception
                    # here because the trial remains this caller's concern.
                    trial_failure = exc
                    raise

            try:
                acquisition = acquire_evidence(
                    bindings=(binding,),
                    collectors={binding.registration_id: collector},
                    run_store=run_store,
                    scope=RunScope(
                        run_id=run_id,
                        planned_trial_id=f"{run_id}:participant-deliveries",
                        attempt_id=f"{run_id}:participant-delivery:{sequence}",
                    ),
                    clock=SystemClockProvider(),
                    trial_body=deliver_turn,
                )
                controlled_snapshot = control_plane.snapshot
            finally:
                control_plane.close()
            if (
                acquisition.disposition is not AcquisitionDisposition.SEALED_READY
                or len(acquisition.refs) != 1
                or collector.result is None
            ):
                if trial_failure is not None:
                    raise AgentExecutionError(
                        "participant delivery attempt failed"
                    ) from trial_failure
                raise AgentExecutionError(
                    "participant delivery evidence acquisition did not complete"
                )
            result = collector.result
            evidence_ref = acquisition.refs[0]
            snapshot = runtime_manager.adopt_participant_delivery_snapshot(
                controlled_snapshot
            )
            run_store.append_jsonl(
                run_id,
                _EVIDENCE_PATH,
                [_delivery_record(sequence, turn, result, model, evidence_ref)],
            )
        return snapshot
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _participant_control_identity(
    turn: ParticipantInjectTurn,
    target: object,
) -> ControlPlaneIdentity:
    return ControlPlaneIdentity(
        identity="aptl-participant-delivery-controller",
        roles=frozenset({ControlPlaneRole.OPERATOR}),
        target_name=str(getattr(target, "name", "")),
        participant_control_subjects=(
            ParticipantControlSubjectBinding(
                turn.participant_address,
                turn.controller_address,
            ),
        ),
    )


def _control_intent_fields(
    turn: ParticipantInjectTurn,
    *,
    run_id: str,
    suffix: str,
    expected_state_revision: int,
) -> dict[str, object]:
    evidence_refs = list(
        turn.control_evidence_addresses or turn.evidence_requirement_addresses
    )
    return {
        "episode_id": str(
            uuid5(NAMESPACE_URL, f"aptl:{run_id}:{turn.participant_address}:episode")
        ),
        "client_correlation_id": f"{turn.address}:{suffix}",
        "policy_revision": turn.control_policy_revision,
        "expected_state_revision": expected_state_revision,
        "provenance_refs": [turn.event_address, turn.script_address, turn.story_address],
        "evidence_refs": evidence_refs,
        "object_marking_refs": [turn.source_item_ref],
        "limitation_refs": [turn.failure_disposition],
    }


def _require_control_success(
    control_plane: RuntimeControlPlane,
    receipt: object,
    participant_address: str,
) -> None:
    operation_id = getattr(receipt, "operation_id", "")
    status = control_plane.get_operation(operation_id)
    history = control_plane.snapshot.participant_control_history.get(
        participant_address, ()
    )
    occurrence = history[-1].get("occurrence", {}) if history else {}
    if (
        status is None
        or status.state is not OperationState.SUCCEEDED
        or occurrence.get("disposition") != "accepted"
    ):
        raise AgentExecutionError("participant delivery control operation was rejected")


def _participant_crossing_evidence(
    turn: ParticipantInjectTurn,
) -> ParticipantCrossingEvidence:
    """Project one delivery's authored API-423 evidence coordinates."""

    provenance_refs = (
        turn.source_item_ref,
        turn.inject_address,
        turn.event_address,
        turn.script_address,
        turn.story_address,
        turn.temporal_constraint_address,
    )
    marking_refs = (
        turn.exposure_policy_ref,
        turn.visibility_basis_ref,
        turn.disclosure_basis_ref,
    )
    return ParticipantCrossingEvidence(
        audience_scope_ref=turn.audience_scope_ref,
        required_evidence_refs=list(turn.evidence_requirement_addresses),
        provenance_refs=list(dict.fromkeys(provenance_refs)),
        evidence_refs=list(
            turn.control_evidence_addresses
            or turn.evidence_requirement_addresses
        ),
        object_marking_refs=list(dict.fromkeys(marking_refs)),
        authorization_scope=turn.controller_address,
        loss_and_limitations=[
            f"failure-disposition:{turn.failure_disposition}",
        ],
    )


def _deliver_controlled_turn(
    *,
    control_plane: RuntimeControlPlane,
    identity: ControlPlaneIdentity,
    collector: _ParticipantDeliveryCollector,
    adapter: ClaudeCodeHostParticipantAdapter,
    turn: ParticipantInjectTurn,
    model: str,
    config_path: Path,
    allowed_tools: tuple[str, ...],
    session_id: str,
    resume: bool,
    run_id: str,
) -> None:
    try:
        proposal = ParticipantProposalControlIntent(
            declaration_ref=turn.proposal_transition_address,
            **_control_intent_fields(
                turn,
                run_id=run_id,
                suffix="proposal",
                expected_state_revision=turn.proposal_expected_state_revision,
            ),
            proposal_id=turn.proposal_id,
            proposal_revision=turn.proposal_revision,
            action_contract_ref=turn.inject_address,
            payload_ref=turn.source_item_ref,
        )
        proposal_receipt = control_plane.record_participant_control(
            turn.participant_address,
            proposal,
            identity=identity,
            idempotency_key=f"{run_id}:{turn.address}:proposal",
            crossing_evidence=_participant_crossing_evidence(turn),
        )
        _require_control_success(
            control_plane,
            proposal_receipt,
            turn.participant_address,
        )
        collector.deliver(
            adapter,
            instruction=turn.instruction,
            model=model,
            config_path=config_path,
            allowed_tools=allowed_tools,
            session_id=session_id,
            resume=resume,
        )
        direction = ParticipantExternalDirectionControlIntent(
            declaration_ref=turn.control_transition_address,
            **_control_intent_fields(
                turn,
                run_id=run_id,
                suffix="external-direction",
                expected_state_revision=turn.control_expected_state_revision,
            ),
            target_kind="proposal",
            target_ref=turn.proposal_id,
            target_revision=turn.proposal_revision,
        )
        direction_receipt = control_plane.record_participant_control(
            turn.participant_address,
            direction,
            identity=identity,
            idempotency_key=f"{run_id}:{turn.address}:external-direction",
            crossing_evidence=_participant_crossing_evidence(turn),
        )
        _require_control_success(
            control_plane,
            direction_receipt,
            turn.participant_address,
        )
    except Exception:
        collector.mark_failed()
        raise


def _render_runtime_profile_config(
    *,
    profile: ProfileId,
    project_dir: Path,
    source_config: Path,
    output_dir: Path,
    node_executable: Path,
) -> tuple[Path, tuple[str, ...]]:
    try:
        document = json.loads(source_config.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AgentExecutionError("synchronized MCP configuration is unreadable") from exc
    source_servers = document.get("mcpServers") if isinstance(document, dict) else None
    if not isinstance(source_servers, dict):
        raise AgentExecutionError("synchronized MCP configuration is invalid")
    servers: dict[str, object] = {}
    allowed: list[str] = []
    for server in profile_for(profile).servers:
        source = source_servers.get(server.server_id)
        if not isinstance(source, dict) or not isinstance(source.get("env"), dict):
            raise AgentExecutionError("participant profile MCP server is unavailable")
        source_environment = source["env"]
        admitted_environment = _MCP_RUNTIME_ENVIRONMENT.get(server.server_id)
        if admitted_environment is None:
            raise AgentExecutionError("participant profile MCP environment is unsupported")
        allowed_environment = (
            _MCP_COMMON_RUNTIME_ENVIRONMENT
            | admitted_environment
            | frozenset(server.credential_aliases)
        )
        if set(source_environment) - allowed_environment:
            raise AgentExecutionError("participant profile MCP environment is not admitted")
        if set(server.credential_aliases) - set(source_environment):
            raise AgentExecutionError(
                "participant profile MCP credential environment is incomplete"
            )
        artifact = (project_dir / server.artifact_ref).resolve()
        if not artifact.is_file() or not artifact.is_relative_to(project_dir.resolve()):
            raise AgentExecutionError("participant profile MCP artifact is unavailable")
        servers[server.server_id] = {
            "command": str(node_executable),
            "args": [str(artifact)],
            "env": {
                name: value
                for name, value in source_environment.items()
                if name in allowed_environment
            },
        }
        allowed.extend(f"mcp__{server.server_id}__{tool}" for tool in server.tool_names)
    path = output_dir / f"{profile.value}.mcp.json"
    create_exclusive_nofollow(
        output_dir,
        path.name,
        (json.dumps({"mcpServers": servers}, sort_keys=True) + "\n").encode(),
    )
    return path, tuple(allowed)


def _delivery_record(
    sequence: int,
    turn: ParticipantInjectTurn,
    result: ParticipantTurnResult,
    model: str,
    evidence_ref: EvidenceRef,
) -> dict[str, object]:
    instruction_sha256 = hashlib.sha256(turn.instruction.encode()).hexdigest()
    response_sha256 = hashlib.sha256(result.response.encode()).hexdigest()
    return {
        "schema_version": "aptl-participant-inject-delivery/v1",
        "sequence": sequence,
        "delivery_address": turn.address,
        "participant_address": turn.participant_address,
        "profile": turn.profile.value,
        "realization_profile_ref": turn.realization_profile_ref,
        "source_item_ref": turn.source_item_ref,
        "instruction_sha256": f"sha256:{instruction_sha256}",
        "response_sha256": f"sha256:{response_sha256}",
        "model": model,
        "conversation_continuity_sha256": (
            "sha256:" + hashlib.sha256(result.session_id.encode()).hexdigest()
        ),
        "inject_address": turn.inject_address,
        "event_address": turn.event_address,
        "script_address": turn.script_address,
        "story_address": turn.story_address,
        "observation_boundary_address": turn.observation_boundary_address,
        "temporal_constraint_address": turn.temporal_constraint_address,
        "clock_address": turn.clock_address,
        "tick": turn.tick,
        "control_transition_address": turn.control_transition_address,
        "control_effective_order": turn.control_effective_order,
        "controller_address": turn.controller_address,
        "evidence_requirement_addresses": list(turn.evidence_requirement_addresses),
        "failure_disposition": turn.failure_disposition,
        "delivery_status": "delivered",
        "observation_status": "not-asserted",
        "evidence_record_id": evidence_ref.evidence_record_id,
        "evidence_content_digest": evidence_ref.content_digest,
        "capture_spec_id": evidence_ref.capture_spec_id,
        "capture_requirement_id": evidence_ref.requirement_id,
        "capture_registration_id": evidence_ref.registration_id,
    }


def _private_file_sha256(path: Path) -> str:
    return hashlib.sha256(_read_private_config(path)).hexdigest()


def _host_home() -> Path:
    """Return the authenticated host CLI home without reading its contents."""

    value = os.environ.get("HOME", "")
    path = Path(value)
    if not value or not path.is_absolute() or not path.is_dir():
        raise AgentExecutionError("authenticated participant CLI home is unavailable")
    return path.resolve()


def _which_executable(name: str) -> Path:
    candidate = shutil.which(name)
    if candidate is None:
        raise AgentExecutionError(f"required participant executable is unavailable: {name}")
    return Path(candidate)


__all__ = [
    "CLAUDE_CODE_REALIZATION_PROFILE",
    "ClaudeCodeHostParticipantAdapter",
    "ParticipantDeliveryPlan",
    "ParticipantInjectTurn",
    "ParticipantTurnResult",
    "bind_participant_delivery_capture",
    "build_participant_delivery_plan",
    "execute_participant_delivery_plan",
]
