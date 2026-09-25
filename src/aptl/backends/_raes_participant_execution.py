"""Governed execution of admitted participant delivery plans."""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

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
from raes_runtime.participant_crossing_mediation import ParticipantCrossingEvidence

from aptl.backends._raes_participant_crossing import (
    _ParticipantDeliveryCrossingPolicyResolver,
)
from aptl.backends._raes_participant_evidence import (
    _ParticipantDeliveryCollector,
    _delivery_record,
)
from aptl.backends._raes_participant_models import (
    ParticipantDeliveryPlan,
    ParticipantInjectTurn,
)
from aptl.backends._raes_participant_transport import (
    ClaudeCodeHostParticipantAdapter,
    _render_runtime_profile_config,
    _which_executable,
)
from aptl.core.correlation.clock import SystemClockProvider
from aptl.core.evidence.coordinator import acquire_evidence
from aptl.core.evidence.outcomes import AcquisitionDisposition
from aptl.core.evidence.protocol import RunScope
from aptl.core.runstore import RunStorageBackend
from aptl.utils.logging import get_logger
from aptl.workbench.process import AgentExecutionError, ProcessRunner
from aptl.workbench.profiles import ProfileId

_EVIDENCE_PATH = "participant/inject-deliveries.jsonl"
log = get_logger("raes-participant-delivery")


@dataclass(frozen=True)
class ParticipantDeliveryExecutionContext:
    """Runtime dependencies for one admitted participant delivery sequence."""

    project_dir: Path
    model: str
    run_store: RunStorageBackend
    run_id: str
    target: object
    runtime_manager: object | None
    initial_snapshot: object
    claude_executable: Path | None = None
    runner: ProcessRunner | None = None


@dataclass
class _ControlledTurn:
    """One evidence-wrapped participant control transaction."""

    control_plane: RuntimeControlPlane
    identity: ControlPlaneIdentity
    collector: _ParticipantDeliveryCollector
    adapter: ClaudeCodeHostParticipantAdapter
    turn: ParticipantInjectTurn
    model: str
    config_path: Path
    allowed_tools: tuple[str, ...]
    session_id: str
    resume: bool
    run_id: str
    failure: Exception | None = field(default=None, init=False)

    def __call__(self) -> None:
        """Run the controlled turn while retaining its exact failure."""

        try:
            _deliver_controlled_turn(self)
        except Exception as exc:
            self.failure = exc
            raise


class _ParticipantDeliveryExecutor:
    """Coordinate logical time, profiles, sessions, control, and evidence."""

    def __init__(
        self,
        plan: ParticipantDeliveryPlan,
        context: ParticipantDeliveryExecutionContext,
    ) -> None:
        """Validate dependencies and create private per-run transport state."""

        if context.runtime_manager is None:
            raise AgentExecutionError(
                "participant delivery runtime manager is unavailable"
            )
        if not plan.behavior_specifications:
            raise AgentExecutionError(
                "participant delivery behavior specifications are unavailable"
            )
        source_config = context.project_dir / ".mcp.json"
        if not source_config.is_file():
            raise AgentExecutionError("synchronized MCP configuration is unavailable")
        context.run_store.create_run(context.run_id)
        self.plan = plan
        self.context = context
        self.source_config = source_config
        self.root = Path(tempfile.mkdtemp(prefix=f"aptl-participant-{context.run_id}-"))
        self.root.chmod(0o700)
        work_dir = self.root / "work"
        work_dir.mkdir(mode=0o700)
        executable = context.claude_executable or _which_executable("claude")
        self.node_executable = _which_executable("node")
        self.adapter = ClaudeCodeHostParticipantAdapter(
            executable, work_dir, runner=context.runner
        )
        self.sessions: dict[str, str] = {}
        self.profiles: dict[ProfileId, tuple[Path, tuple[str, ...]]] = {}
        self.current_ticks: dict[str, int] = {}
        self.snapshot = context.initial_snapshot
        self.crossing_policy = _ParticipantDeliveryCrossingPolicyResolver(
            plan.turns, context.target, plan.behavior_specifications
        )

    def execute(self) -> object:
        """Deliver every admitted turn and remove private transient state."""

        try:
            for sequence, turn in enumerate(self.plan.turns, start=1):
                self._execute_turn(sequence, turn)
            return self.snapshot
        finally:
            shutil.rmtree(self.root, ignore_errors=True)

    def _execute_turn(self, sequence: int, turn: ParticipantInjectTurn) -> None:
        """Advance time and acquire one governed delivery record."""

        log.info(
            "Delivering participant inject %d/%d: %s at logical tick %d",
            sequence,
            len(self.plan.turns),
            turn.address,
            turn.tick,
        )
        config_path, tools = self._profile(turn.profile)
        self._advance_time(turn)
        binding = turn.capture_binding
        if binding is None:
            raise AgentExecutionError(
                "participant delivery evidence binding is unavailable"
            )
        collector = _ParticipantDeliveryCollector(binding.registration_id)
        collector.bind_payload(turn, self.context.model)
        control_plane = RuntimeControlPlane(
            self.context.target,
            initial_snapshot=self.snapshot,
            behavior_specifications=self.plan.behavior_specifications,
            crossing_policy_resolver=self.crossing_policy,
            enforce_final_sink_flow_control=False,
        )
        trial = _ControlledTurn(
            control_plane=control_plane,
            identity=_participant_control_identity(turn, self.context.target),
            collector=collector,
            adapter=self.adapter,
            turn=turn,
            model=self.context.model,
            config_path=config_path,
            allowed_tools=tools,
            session_id=self._session_id(turn),
            resume=self._has_prior_turn(turn, sequence),
            run_id=self.context.run_id,
        )
        acquisition, controlled_snapshot = self._acquire(
            sequence, binding, collector, control_plane, trial
        )
        result = collector.result
        if result is None:
            raise AgentExecutionError(
                "participant delivery evidence acquisition did not complete"
            )
        self.snapshot = (
            self.context.runtime_manager.adopt_participant_delivery_snapshot(
                controlled_snapshot
            )
        )
        self.context.run_store.append_jsonl(
            self.context.run_id,
            _EVIDENCE_PATH,
            [
                _delivery_record(
                    sequence,
                    turn,
                    result,
                    self.context.model,
                    acquisition.refs[0],
                )
            ],
        )

    def _profile(self, profile: ProfileId) -> tuple[Path, tuple[str, ...]]:
        """Materialize and cache one role-scoped MCP profile."""

        configured = self.profiles.get(profile)
        if configured is None:
            configured = _render_runtime_profile_config(
                profile=profile,
                project_dir=self.context.project_dir,
                source_config=self.source_config,
                output_dir=self.root,
                node_executable=self.node_executable,
            )
            self.profiles[profile] = configured
        return configured

    def _advance_time(self, turn: ParticipantInjectTurn) -> None:
        """Advance the authored logical clock to one exact delivery tick."""

        current = self.current_ticks.get(turn.clock_address, 0)
        if turn.tick <= current:
            raise AgentExecutionError("participant delivery time is not monotonic")
        advanced = self.context.runtime_manager.advance_time(
            turn.clock_address, ticks=turn.tick - current, microstep=0
        )
        if not advanced.success:
            raise AgentExecutionError("participant delivery clock advance failed")
        self.snapshot = advanced.snapshot
        self.current_ticks[turn.clock_address] = turn.tick

    def _session_id(self, turn: ParticipantInjectTurn) -> str:
        """Return the stable role session for conversation continuity."""

        return self.sessions.setdefault(
            turn.participant_address,
            str(
                uuid5(
                    NAMESPACE_URL,
                    f"aptl:{self.context.run_id}:{turn.participant_address}",
                )
            ),
        )

    def _has_prior_turn(self, turn: ParticipantInjectTurn, sequence: int) -> bool:
        """Return whether this participant already received an earlier turn."""

        return any(
            prior.participant_address == turn.participant_address
            for prior in self.plan.turns[: sequence - 1]
        )

    def _acquire(
        self,
        sequence: int,
        binding: object,
        collector: _ParticipantDeliveryCollector,
        control_plane: RuntimeControlPlane,
        trial: _ControlledTurn,
    ) -> tuple[object, object]:
        """Acquire evidence around one controlled participant turn."""

        try:
            acquisition = acquire_evidence(
                bindings=(binding,),
                collectors={binding.registration_id: collector},
                run_store=self.context.run_store,
                scope=RunScope(
                    run_id=self.context.run_id,
                    planned_trial_id=(f"{self.context.run_id}:participant-deliveries"),
                    attempt_id=(
                        f"{self.context.run_id}:participant-delivery:{sequence}"
                    ),
                ),
                clock=SystemClockProvider(),
                trial_body=trial,
            )
            controlled_snapshot = control_plane.snapshot
        finally:
            control_plane.close()
        complete = (
            acquisition.disposition is AcquisitionDisposition.SEALED_READY
            and len(acquisition.refs) == 1
            and collector.result is not None
        )
        if complete:
            return acquisition, controlled_snapshot
        failure = trial.failure
        if failure is not None:
            raise AgentExecutionError(
                "participant delivery attempt failed"
            ) from failure
        raise AgentExecutionError(
            "participant delivery evidence acquisition did not complete"
        )


def execute_participant_delivery_plan(
    plan: ParticipantDeliveryPlan,
    *,
    context: ParticipantDeliveryExecutionContext,
) -> object:
    """Deliver an admitted sequence and return its advanced RAES snapshot."""

    if not plan.turns:
        return context.initial_snapshot
    return _ParticipantDeliveryExecutor(plan, context).execute()


def _participant_control_identity(
    turn: ParticipantInjectTurn,
    target: object,
) -> ControlPlaneIdentity:
    """Build the least-privilege identity for one participant subject."""

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
    """Return shared authored coordinates for a participant control intent."""

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
        "provenance_refs": [
            turn.event_address,
            turn.script_address,
            turn.story_address,
        ],
        "evidence_refs": evidence_refs,
        "object_marking_refs": [turn.source_item_ref],
        "limitation_refs": [turn.failure_disposition],
    }


def _require_control_success(
    control_plane: RuntimeControlPlane,
    receipt: object,
    participant_address: str,
) -> None:
    """Require an accepted terminal control occurrence."""

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
            turn.control_evidence_addresses or turn.evidence_requirement_addresses
        ),
        object_marking_refs=list(dict.fromkeys(marking_refs)),
        authorization_scope=turn.controller_address,
        loss_and_limitations=[
            f"failure-disposition:{turn.failure_disposition}",
        ],
    )


def _deliver_controlled_turn(trial: _ControlledTurn) -> None:
    """Record proposal and direction around one provider delivery."""

    turn = trial.turn
    try:
        proposal = ParticipantProposalControlIntent(
            declaration_ref=turn.proposal_transition_address,
            **_control_intent_fields(
                turn,
                run_id=trial.run_id,
                suffix="proposal",
                expected_state_revision=turn.proposal_expected_state_revision,
            ),
            proposal_id=turn.proposal_id,
            proposal_revision=turn.proposal_revision,
            action_contract_ref=turn.inject_address,
            payload_ref=turn.source_item_ref,
        )
        proposal_receipt = trial.control_plane.record_participant_control(
            turn.participant_address,
            proposal,
            identity=trial.identity,
            idempotency_key=f"{trial.run_id}:{turn.address}:proposal",
            crossing_evidence=_participant_crossing_evidence(turn),
        )
        _require_control_success(
            trial.control_plane, proposal_receipt, turn.participant_address
        )
        trial.collector.deliver(
            trial.adapter,
            instruction=turn.instruction,
            model=trial.model,
            config_path=trial.config_path,
            allowed_tools=trial.allowed_tools,
            session_id=trial.session_id,
            resume=trial.resume,
        )
        direction = ParticipantExternalDirectionControlIntent(
            declaration_ref=turn.control_transition_address,
            **_control_intent_fields(
                turn,
                run_id=trial.run_id,
                suffix="external-direction",
                expected_state_revision=turn.control_expected_state_revision,
            ),
            target_kind="proposal",
            target_ref=turn.proposal_id,
            target_revision=turn.proposal_revision,
        )
        direction_receipt = trial.control_plane.record_participant_control(
            turn.participant_address,
            direction,
            identity=trial.identity,
            idempotency_key=(f"{trial.run_id}:{turn.address}:external-direction"),
            crossing_evidence=_participant_crossing_evidence(turn),
        )
        _require_control_success(
            trial.control_plane, direction_receipt, turn.participant_address
        )
    except Exception:
        trial.collector.mark_failed()
        raise
