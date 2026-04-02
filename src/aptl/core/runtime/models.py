"""Runtime data models for the SDL-native execution layer.

The runtime is split into three domains:

- provisioning: desired deployed state
- orchestration: resolved exercise control graph
- evaluation: resolved monitoring/scoring graph

The compiler produces a ``RuntimeModel`` with reusable templates separated
from bound runtime instances. The planner reconciles those instances against
the current ``RuntimeSnapshot`` and emits a composite ``ExecutionPlan``.
"""

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from aptl.core.semantics.workflow import (
    WORKFLOW_STATE_SCHEMA_VERSION,
    WorkflowStepSemanticContract,
)
from aptl.core.runtime.capabilities import (
    BackendManifest,
    WorkflowFeature,
    WorkflowStatePredicateFeature,
)


class RuntimeDomain(str, Enum):
    """Top-level runtime concern."""

    PROVISIONING = "provisioning"
    ORCHESTRATION = "orchestration"
    EVALUATION = "evaluation"


RUNTIME_SNAPSHOT_SCHEMA_VERSION = "runtime-snapshot/v1"
OPERATION_SCHEMA_VERSION = "runtime-operation/v1"
EVALUATION_STATE_SCHEMA_VERSION = "evaluation-result-state/v1"


class ChangeAction(str, Enum):
    """Planner reconciliation result for a resource."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    UNCHANGED = "unchanged"


class Severity(str, Enum):
    """Diagnostic severity level."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class OperationState(str, Enum):
    """Lifecycle for async control-plane operations."""

    ACCEPTED = "accepted"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class WorkflowStepLifecycle(str, Enum):
    """Portable execution lifecycle for workflow-visible step state."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"


class WorkflowStepOutcome(str, Enum):
    """Portable execution outcomes for workflow-visible step state."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    EXHAUSTED = "exhausted"


class WorkflowStatus(str, Enum):
    """Portable workflow-level execution status."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class WorkflowHistoryEventType(str, Enum):
    """Portable workflow history event kinds."""

    WORKFLOW_STARTED = "workflow_started"
    STEP_STARTED = "step_started"
    STEP_COMPLETED = "step_completed"
    BRANCH_ENTERED = "branch_entered"
    BRANCH_CONVERGED = "branch_converged"
    WORKFLOW_COMPLETED = "workflow_completed"
    WORKFLOW_FAILED = "workflow_failed"
    WORKFLOW_CANCELLED = "workflow_cancelled"
    WORKFLOW_TIMED_OUT = "workflow_timed_out"


class EvaluationResultStatus(str, Enum):
    """Portable lifecycle for evaluator-observable results."""

    PENDING = "pending"
    RUNNING = "running"
    READY = "ready"
    FAILED = "failed"


class EvaluationHistoryEventType(str, Enum):
    """Portable evaluator history event kinds."""

    EVALUATION_STARTED = "evaluation_started"
    EVALUATION_UPDATED = "evaluation_updated"
    EVALUATION_READY = "evaluation_ready"
    EVALUATION_FAILED = "evaluation_failed"


@dataclass(frozen=True)
class Diagnostic:
    """Structured planner/runtime message."""

    code: str
    domain: str
    address: str
    message: str
    severity: Severity = Severity.ERROR

    @property
    def is_error(self) -> bool:
        return self.severity == Severity.ERROR


@dataclass(frozen=True)
class RuntimeTemplate:
    """Reusable SDL definition preserved in compiled form."""

    address: str
    name: str
    spec: dict[str, Any]


@dataclass(frozen=True)
class ResolvedResource:
    """Base class for bound runtime resources."""

    address: str
    name: str
    spec: dict[str, Any]
    ordering_dependencies: tuple[str, ...] = ()
    refresh_dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class NetworkRuntime(ResolvedResource):
    """Compiled switch/network deployment."""

    node_name: str = ""


@dataclass(frozen=True)
class NodeRuntime(ResolvedResource):
    """Compiled VM deployment."""

    node_name: str = ""
    node_type: str = ""
    os_family: str = ""
    count: int | str | None = None


@dataclass(frozen=True)
class FeatureBinding(ResolvedResource):
    """Feature template bound to a specific node role."""

    node_name: str = ""
    node_address: str = ""
    feature_name: str = ""
    template_address: str = ""
    role_name: str = ""


@dataclass(frozen=True)
class ConditionBinding(ResolvedResource):
    """Condition template bound to a specific node role."""

    node_name: str = ""
    node_address: str = ""
    condition_name: str = ""
    template_address: str = ""
    role_name: str = ""
    result_contract: "EvaluationResultContract" = field(
        default_factory=lambda: EvaluationResultContract(resource_type="condition-binding")
    )
    execution_contract: "EvaluationExecutionContract" = field(
        default_factory=lambda: EvaluationExecutionContract(resource_type="condition-binding")
    )


@dataclass(frozen=True)
class InjectBinding(ResolvedResource):
    """Inject template bound to a specific node role."""

    node_name: str = ""
    node_address: str = ""
    inject_name: str = ""
    template_address: str = ""
    role_name: str = ""


@dataclass(frozen=True)
class InjectRuntime(ResolvedResource):
    """Resolved top-level inject resource."""


@dataclass(frozen=True)
class ContentPlacement(ResolvedResource):
    """Content entry resolved to a concrete target node."""

    content_name: str = ""
    target_node: str = ""
    target_address: str = ""


@dataclass(frozen=True)
class AccountPlacement(ResolvedResource):
    """Account entry resolved to a concrete target node."""

    account_name: str = ""
    node_name: str = ""
    target_address: str = ""


@dataclass(frozen=True)
class EventRuntime(ResolvedResource):
    """Resolved orchestration event."""

    condition_names: tuple[str, ...] = ()
    condition_addresses: tuple[str, ...] = ()
    inject_names: tuple[str, ...] = ()
    inject_addresses: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScriptRuntime(ResolvedResource):
    """Resolved script with event dependencies."""

    event_addresses: tuple[str, ...] = ()


@dataclass(frozen=True)
class StoryRuntime(ResolvedResource):
    """Resolved story with script dependencies."""

    script_addresses: tuple[str, ...] = ()


@dataclass(frozen=True)
class ObjectiveWindowReferenceRuntime:
    """Normalized resolved objective/window reference."""

    raw: str
    canonical_name: str
    reference_kind: str
    dependency_roles: tuple[str, ...] = ()
    workflow_name: str = ""
    step_name: str = ""
    namespace_path: tuple[str, ...] = ()


@dataclass(frozen=True)
class WorkflowStepStatePredicateRuntime:
    """Resolved predicate clause over prior workflow step state."""

    step_name: str
    outcomes: tuple[WorkflowStepOutcome, ...] = ()
    min_attempts: int | str | None = None


@dataclass(frozen=True)
class WorkflowPredicateRuntime:
    """Resolved workflow predicate semantics."""

    condition_addresses: tuple[str, ...] = ()
    metric_addresses: tuple[str, ...] = ()
    evaluation_addresses: tuple[str, ...] = ()
    tlo_addresses: tuple[str, ...] = ()
    goal_addresses: tuple[str, ...] = ()
    objective_addresses: tuple[str, ...] = ()
    step_state_predicates: tuple[WorkflowStepStatePredicateRuntime, ...] = ()

    @property
    def external_addresses(self) -> tuple[str, ...]:
        seen: set[str] = set()
        ordered: list[str] = []
        for address in (
            *self.condition_addresses,
            *self.metric_addresses,
            *self.evaluation_addresses,
            *self.tlo_addresses,
            *self.goal_addresses,
            *self.objective_addresses,
        ):
            if address in seen:
                continue
            seen.add(address)
            ordered.append(address)
        return tuple(ordered)


@dataclass(frozen=True)
class WorkflowStepRuntime:
    """Resolved workflow step semantics."""

    name: str
    step_type: str
    objective_address: str = ""
    predicate: WorkflowPredicateRuntime | None = None
    next_step: str = ""
    on_success: str = ""
    on_failure: str = ""
    on_exhausted: str = ""
    then_step: str = ""
    else_step: str = ""
    branches: tuple[str, ...] = ()
    join_step: str = ""
    owning_parallel_step: str = ""
    max_attempts: int | str | None = None
    state_contract: WorkflowStepSemanticContract = field(
        default_factory=lambda: WorkflowStepSemanticContract(step_type="")
    )


@dataclass(frozen=True)
class WorkflowRuntime(ResolvedResource):
    """Resolved workflow control program."""

    start_step: str = ""
    referenced_objective_addresses: tuple[str, ...] = ()
    control_steps: dict[str, WorkflowStepRuntime] = field(default_factory=dict)
    control_edges: dict[str, tuple[str, ...]] = field(default_factory=dict)
    join_owners: dict[str, str] = field(default_factory=dict)
    step_condition_addresses: dict[str, tuple[str, ...]] = field(default_factory=dict)
    step_predicate_addresses: dict[str, tuple[str, ...]] = field(default_factory=dict)
    required_features: tuple[WorkflowFeature, ...] = ()
    required_state_predicate_features: tuple[
        WorkflowStatePredicateFeature, ...
    ] = ()
    result_contract: "WorkflowResultContract" = field(
        default_factory=lambda: WorkflowResultContract()
    )
    execution_contract: "WorkflowExecutionContract" = field(
        default_factory=lambda: WorkflowExecutionContract()
    )
    state_schema_version: str = WORKFLOW_STATE_SCHEMA_VERSION


@dataclass(frozen=True)
class WorkflowResultContract:
    """Compiled contract for validating portable workflow result envelopes."""

    state_schema_version: str = WORKFLOW_STATE_SCHEMA_VERSION
    observable_steps: dict[str, WorkflowStepSemanticContract] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if not isinstance(self.state_schema_version, str) or not self.state_schema_version:
            raise TypeError(
                "workflow result contract state_schema_version must be a non-empty string"
            )
        if not isinstance(self.observable_steps, dict):
            raise TypeError("workflow result contract observable_steps must be a dict")
        if any(not isinstance(step_name, str) for step_name in self.observable_steps):
            raise TypeError("workflow result contract step names must be strings")
        if any(
            not isinstance(contract, WorkflowStepSemanticContract)
            for contract in self.observable_steps.values()
        ):
            raise TypeError(
                "workflow result contract step contracts must be WorkflowStepSemanticContract values"
            )

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, Any],
    ) -> "WorkflowResultContract":
        if not isinstance(payload, Mapping):
            raise TypeError("workflow result contract must be a mapping")
        observable_steps_payload = payload.get("observable_steps", {})
        if not isinstance(observable_steps_payload, Mapping):
            raise TypeError("workflow result contract observable_steps must be a mapping")
        observable_steps: dict[str, WorkflowStepSemanticContract] = {}
        for step_name, step_payload in observable_steps_payload.items():
            if not isinstance(step_name, str):
                raise TypeError("workflow result contract step names must be strings")
            if not isinstance(step_payload, Mapping):
                raise TypeError(
                    "workflow result contract step payloads must be mappings"
                )
            observable_steps[step_name] = WorkflowStepSemanticContract.from_mapping(
                step_payload
            )
            if not observable_steps[step_name].state_observable:
                raise ValueError(
                    "workflow result contract may only include observable steps"
                )
        return cls(
            state_schema_version=str(
                payload.get("state_schema_version", WORKFLOW_STATE_SCHEMA_VERSION)
            ),
            observable_steps=observable_steps,
        )


@dataclass(frozen=True)
class WorkflowExecutionContract:
    """Compiled contract for validating workflow-level execution state/history."""

    state_schema_version: str = WORKFLOW_STATE_SCHEMA_VERSION
    start_step: str = ""
    steps: dict[str, WorkflowStepSemanticContract] = field(default_factory=dict)
    control_edges: dict[str, tuple[str, ...]] = field(default_factory=dict)
    join_owners: dict[str, str] = field(default_factory=dict)
    observable_steps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.state_schema_version, str) or not self.state_schema_version:
            raise TypeError(
                "workflow execution contract state_schema_version must be a non-empty string"
            )
        if not isinstance(self.start_step, str):
            raise TypeError("workflow execution contract start_step must be a string")
        if not isinstance(self.steps, dict):
            raise TypeError("workflow execution contract steps must be a dict")
        if any(not isinstance(name, str) for name in self.steps):
            raise TypeError("workflow execution contract step names must be strings")
        if any(
            not isinstance(contract, WorkflowStepSemanticContract)
            for contract in self.steps.values()
        ):
            raise TypeError(
                "workflow execution contract step contracts must be WorkflowStepSemanticContract values"
            )
        if not isinstance(self.control_edges, dict):
            raise TypeError("workflow execution contract control_edges must be a dict")
        if not isinstance(self.join_owners, dict):
            raise TypeError("workflow execution contract join_owners must be a dict")
        if any(not isinstance(step_name, str) for step_name in self.observable_steps):
            raise TypeError(
                "workflow execution contract observable_steps must be strings"
            )

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, Any],
    ) -> "WorkflowExecutionContract":
        if not isinstance(payload, Mapping):
            raise TypeError("workflow execution contract must be a mapping")
        steps_payload = payload.get("steps", {})
        if not isinstance(steps_payload, Mapping):
            raise TypeError("workflow execution contract steps must be a mapping")
        steps: dict[str, WorkflowStepSemanticContract] = {}
        for step_name, step_payload in steps_payload.items():
            if not isinstance(step_name, str):
                raise TypeError("workflow execution contract step names must be strings")
            if not isinstance(step_payload, Mapping):
                raise TypeError("workflow execution contract step payloads must be mappings")
            steps[step_name] = WorkflowStepSemanticContract.from_mapping(step_payload)
        control_edges_payload = payload.get("control_edges", {})
        if not isinstance(control_edges_payload, Mapping):
            raise TypeError(
                "workflow execution contract control_edges must be a mapping"
            )
        control_edges = {
            str(step_name): tuple(str(successor) for successor in successors)
            for step_name, successors in control_edges_payload.items()
            if isinstance(successors, Iterable)
        }
        join_owners_payload = payload.get("join_owners", {})
        if not isinstance(join_owners_payload, Mapping):
            raise TypeError("workflow execution contract join_owners must be a mapping")
        return cls(
            state_schema_version=str(
                payload.get("state_schema_version", WORKFLOW_STATE_SCHEMA_VERSION)
            ),
            start_step=str(payload.get("start_step", "")),
            steps=steps,
            control_edges=control_edges,
            join_owners={str(join): str(owner) for join, owner in join_owners_payload.items()},
            observable_steps=tuple(
                str(step_name) for step_name in payload.get("observable_steps", ())
            ),
        )


@dataclass(frozen=True)
class WorkflowHistoryEvent:
    """Internal normalized workflow history event."""

    event_type: WorkflowHistoryEventType
    timestamp: str
    step_name: str | None = None
    branch_name: str | None = None
    join_step: str | None = None
    outcome: WorkflowStepOutcome | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any],
    ) -> "WorkflowHistoryEvent":
        if not isinstance(payload, Mapping):
            raise TypeError("workflow history event must be a mapping")
        event_type_raw = payload.get("event_type")
        timestamp_raw = payload.get("timestamp")
        if event_type_raw is None or timestamp_raw is None:
            raise ValueError(
                "workflow history event is missing required fields: event_type, timestamp"
            )
        outcome_raw = payload.get("outcome")
        return cls(
            event_type=(
                event_type_raw
                if isinstance(event_type_raw, WorkflowHistoryEventType)
                else WorkflowHistoryEventType(str(event_type_raw))
            ),
            timestamp=str(timestamp_raw),
            step_name=(
                str(payload["step_name"]) if payload.get("step_name") is not None else None
            ),
            branch_name=(
                str(payload["branch_name"])
                if payload.get("branch_name") is not None
                else None
            ),
            join_step=(
                str(payload["join_step"]) if payload.get("join_step") is not None else None
            ),
            outcome=(
                outcome_raw
                if isinstance(outcome_raw, WorkflowStepOutcome)
                else (
                    WorkflowStepOutcome(str(outcome_raw))
                    if outcome_raw is not None
                    else None
                )
            ),
            details=dict(payload.get("details", {}))
            if isinstance(payload.get("details", {}), Mapping)
            else {},
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "step_name": self.step_name,
            "branch_name": self.branch_name,
            "join_step": self.join_step,
            "outcome": self.outcome.value if self.outcome is not None else None,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class WorkflowStepExecutionState:
    """Internal normalized execution state for one workflow-visible step."""

    lifecycle: WorkflowStepLifecycle = WorkflowStepLifecycle.PENDING
    outcome: WorkflowStepOutcome | None = None
    attempts: int = 0

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any],
    ) -> "WorkflowStepExecutionState":
        if not isinstance(payload, Mapping):
            raise TypeError("workflow step result must be a mapping")
        missing_keys = [
            key for key in ("lifecycle", "outcome", "attempts") if key not in payload
        ]
        if missing_keys:
            raise ValueError(
                "workflow step result is missing required fields: "
                + ", ".join(missing_keys)
            )
        lifecycle_raw = payload.get("lifecycle")
        outcome_raw = payload.get("outcome")
        attempts_raw = payload.get("attempts")
        lifecycle = (
            lifecycle_raw
            if isinstance(lifecycle_raw, WorkflowStepLifecycle)
            else WorkflowStepLifecycle(str(lifecycle_raw))
        )
        outcome = None
        if outcome_raw is not None:
            outcome = (
                outcome_raw
                if isinstance(outcome_raw, WorkflowStepOutcome)
                else WorkflowStepOutcome(str(outcome_raw))
            )
        if isinstance(attempts_raw, bool) or not isinstance(attempts_raw, int):
            raise TypeError("workflow step attempts must be an int")
        return cls(
            lifecycle=lifecycle,
            outcome=outcome,
            attempts=attempts_raw,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "lifecycle": self.lifecycle.value,
            "outcome": self.outcome.value if self.outcome is not None else None,
            "attempts": self.attempts,
        }

    def __post_init__(self) -> None:
        if not isinstance(self.lifecycle, WorkflowStepLifecycle):
            raise TypeError("lifecycle must be a WorkflowStepLifecycle")
        if self.outcome is not None and not isinstance(self.outcome, WorkflowStepOutcome):
            raise TypeError("outcome must be a WorkflowStepOutcome or None")
        if isinstance(self.attempts, bool) or not isinstance(self.attempts, int):
            raise TypeError("attempts must be an int")
        if self.attempts < 0:
            raise ValueError("attempts must be >= 0")
        if self.lifecycle != WorkflowStepLifecycle.COMPLETED and self.outcome is not None:
            raise ValueError("non-completed workflow steps may not report an outcome")
        if self.lifecycle == WorkflowStepLifecycle.PENDING and self.attempts != 0:
            raise ValueError("pending workflow steps must report 0 attempts")


@dataclass(frozen=True)
class WorkflowExecutionState:
    """Internal normalized workflow result envelope."""

    state_schema_version: str = WORKFLOW_STATE_SCHEMA_VERSION
    workflow_status: WorkflowStatus = WorkflowStatus.PENDING
    run_id: str = ""
    started_at: str = ""
    updated_at: str = ""
    terminal_reason: str | None = None
    steps: dict[str, WorkflowStepExecutionState] = field(default_factory=dict)

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any],
    ) -> "WorkflowExecutionState":
        if not isinstance(payload, Mapping):
            raise TypeError("workflow result payload must be a mapping")
        missing_keys = [
            key
            for key in (
                "state_schema_version",
                "workflow_status",
                "run_id",
                "started_at",
                "updated_at",
                "steps",
            )
            if key not in payload
        ]
        if missing_keys:
            raise ValueError(
                "workflow result payload is missing required fields: "
                + ", ".join(missing_keys)
            )
        state_schema_version = str(payload.get("state_schema_version"))
        workflow_status_raw = payload.get("workflow_status")
        steps_payload = payload.get("steps")
        if not isinstance(steps_payload, Mapping):
            raise TypeError("workflow result steps must be a mapping")
        steps: dict[str, WorkflowStepExecutionState] = {}
        for step_name, step_payload in steps_payload.items():
            if not isinstance(step_name, str):
                raise TypeError("workflow result step names must be strings")
            if not isinstance(step_payload, Mapping):
                raise TypeError("workflow result step payloads must be mappings")
            steps[step_name] = WorkflowStepExecutionState.from_payload(step_payload)
        return cls(
            state_schema_version=state_schema_version,
            workflow_status=(
                workflow_status_raw
                if isinstance(workflow_status_raw, WorkflowStatus)
                else WorkflowStatus(str(workflow_status_raw))
            ),
            run_id=str(payload.get("run_id")),
            started_at=str(payload.get("started_at")),
            updated_at=str(payload.get("updated_at")),
            terminal_reason=(
                str(payload["terminal_reason"])
                if payload.get("terminal_reason") is not None
                else None
            ),
            steps=steps,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "state_schema_version": self.state_schema_version,
            "workflow_status": self.workflow_status.value,
            "run_id": self.run_id,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "terminal_reason": self.terminal_reason,
            "steps": {
                step_name: step_state.to_payload()
                for step_name, step_state in self.steps.items()
            },
        }

    def __post_init__(self) -> None:
        if not isinstance(self.state_schema_version, str) or not self.state_schema_version:
            raise TypeError("workflow result state_schema_version must be a non-empty string")
        if not isinstance(self.workflow_status, WorkflowStatus):
            raise TypeError("workflow_status must be a WorkflowStatus")
        if not isinstance(self.run_id, str) or not self.run_id:
            raise TypeError("run_id must be a non-empty string")
        if not isinstance(self.started_at, str) or not self.started_at:
            raise TypeError("started_at must be a non-empty string")
        if not isinstance(self.updated_at, str) or not self.updated_at:
            raise TypeError("updated_at must be a non-empty string")
        if self.terminal_reason is not None and not isinstance(self.terminal_reason, str):
            raise TypeError("terminal_reason must be a string or None")
        if not isinstance(self.steps, dict):
            raise TypeError("workflow step results must be stored in a dict")
        if any(not isinstance(step_name, str) for step_name in self.steps):
            raise TypeError("workflow step result keys must be strings")
        if any(
            not isinstance(step_state, WorkflowStepExecutionState)
            for step_state in self.steps.values()
        ):
            raise TypeError(
                "workflow step results must be WorkflowStepExecutionState values"
            )
        if self.workflow_status in {
            WorkflowStatus.SUCCEEDED,
            WorkflowStatus.FAILED,
            WorkflowStatus.CANCELLED,
            WorkflowStatus.TIMED_OUT,
        } and self.terminal_reason is None:
            raise ValueError(
                "terminal workflow statuses must include terminal_reason"
            )
        if self.workflow_status in {WorkflowStatus.PENDING, WorkflowStatus.RUNNING} and self.terminal_reason is not None:
            raise ValueError(
                "non-terminal workflow statuses may not include terminal_reason"
            )


@dataclass(frozen=True)
class EvaluationResultContract:
    """Compiled contract for validating evaluator result envelopes."""

    state_schema_version: str = EVALUATION_STATE_SCHEMA_VERSION
    resource_type: str = ""
    supports_passed: bool = False
    supports_score: bool = False
    fixed_max_score: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state_schema_version, str) or not self.state_schema_version:
            raise TypeError(
                "evaluation result contract state_schema_version must be a non-empty string"
            )
        if not isinstance(self.resource_type, str) or not self.resource_type:
            raise TypeError("evaluation result contract resource_type must be a non-empty string")
        if not isinstance(self.supports_passed, bool):
            raise TypeError("evaluation result contract supports_passed must be a bool")
        if not isinstance(self.supports_score, bool):
            raise TypeError("evaluation result contract supports_score must be a bool")
        if self.fixed_max_score is not None:
            if isinstance(self.fixed_max_score, bool) or not isinstance(self.fixed_max_score, int):
                raise TypeError("evaluation result contract fixed_max_score must be an int or None")
            if self.fixed_max_score < 0:
                raise ValueError("evaluation result contract fixed_max_score must be >= 0")
            if not self.supports_score:
                raise ValueError(
                    "evaluation result contract fixed_max_score requires supports_score"
                )

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, Any],
    ) -> "EvaluationResultContract":
        if not isinstance(payload, Mapping):
            raise TypeError("evaluation result contract must be a mapping")
        fixed_max_score_raw = payload.get("fixed_max_score")
        fixed_max_score: int | None
        if fixed_max_score_raw is None:
            fixed_max_score = None
        elif isinstance(fixed_max_score_raw, bool) or not isinstance(fixed_max_score_raw, int):
            raise TypeError("evaluation result contract fixed_max_score must be an int or None")
        else:
            fixed_max_score = fixed_max_score_raw
        return cls(
            state_schema_version=str(
                payload.get("state_schema_version", EVALUATION_STATE_SCHEMA_VERSION)
            ),
            resource_type=str(payload.get("resource_type", "")),
            supports_passed=bool(payload.get("supports_passed", False)),
            supports_score=bool(payload.get("supports_score", False)),
            fixed_max_score=fixed_max_score,
        )


@dataclass(frozen=True)
class EvaluationExecutionContract:
    """Compiled contract for validating evaluator history/state transitions."""

    state_schema_version: str = EVALUATION_STATE_SCHEMA_VERSION
    resource_type: str = ""
    allowed_statuses: tuple[str, ...] = (
        EvaluationResultStatus.PENDING.value,
        EvaluationResultStatus.RUNNING.value,
        EvaluationResultStatus.READY.value,
        EvaluationResultStatus.FAILED.value,
    )
    history_event_types: tuple[str, ...] = (
        EvaluationHistoryEventType.EVALUATION_STARTED.value,
        EvaluationHistoryEventType.EVALUATION_UPDATED.value,
        EvaluationHistoryEventType.EVALUATION_READY.value,
        EvaluationHistoryEventType.EVALUATION_FAILED.value,
    )
    requires_start_event: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.state_schema_version, str) or not self.state_schema_version:
            raise TypeError(
                "evaluation execution contract state_schema_version must be a non-empty string"
            )
        if not isinstance(self.resource_type, str) or not self.resource_type:
            raise TypeError("evaluation execution contract resource_type must be a non-empty string")
        if any(not isinstance(status, str) for status in self.allowed_statuses):
            raise TypeError("evaluation execution contract allowed_statuses must be strings")
        if any(
            not isinstance(event_type, str) for event_type in self.history_event_types
        ):
            raise TypeError("evaluation execution contract history_event_types must be strings")
        if not isinstance(self.requires_start_event, bool):
            raise TypeError("evaluation execution contract requires_start_event must be a bool")

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, Any],
    ) -> "EvaluationExecutionContract":
        if not isinstance(payload, Mapping):
            raise TypeError("evaluation execution contract must be a mapping")
        return cls(
            state_schema_version=str(
                payload.get("state_schema_version", EVALUATION_STATE_SCHEMA_VERSION)
            ),
            resource_type=str(payload.get("resource_type", "")),
            allowed_statuses=tuple(
                str(status)
                for status in payload.get(
                    "allowed_statuses",
                    (
                        EvaluationResultStatus.PENDING.value,
                        EvaluationResultStatus.RUNNING.value,
                        EvaluationResultStatus.READY.value,
                        EvaluationResultStatus.FAILED.value,
                    ),
                )
            ),
            history_event_types=tuple(
                str(event_type)
                for event_type in payload.get(
                    "history_event_types",
                    (
                        EvaluationHistoryEventType.EVALUATION_STARTED.value,
                        EvaluationHistoryEventType.EVALUATION_UPDATED.value,
                        EvaluationHistoryEventType.EVALUATION_READY.value,
                        EvaluationHistoryEventType.EVALUATION_FAILED.value,
                    ),
                )
            ),
            requires_start_event=bool(payload.get("requires_start_event", True)),
        )


@dataclass(frozen=True)
class EvaluationHistoryEvent:
    """Internal normalized evaluator history event."""

    event_type: EvaluationHistoryEventType
    timestamp: str
    status: EvaluationResultStatus
    passed: bool | None = None
    score: float | int | None = None
    max_score: int | None = None
    detail: str | None = None
    evidence_refs: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any],
    ) -> "EvaluationHistoryEvent":
        if not isinstance(payload, Mapping):
            raise TypeError("evaluation history event must be a mapping")
        missing_keys = [
            key for key in ("event_type", "timestamp", "status") if key not in payload
        ]
        if missing_keys:
            raise ValueError(
                "evaluation history event is missing required fields: "
                + ", ".join(missing_keys)
            )
        score_raw = payload.get("score")
        max_score_raw = payload.get("max_score")
        evidence_refs_raw = payload.get("evidence_refs", ())
        if isinstance(evidence_refs_raw, (str, bytes)) or not isinstance(
            evidence_refs_raw, Iterable
        ):
            raise TypeError("evaluation history event evidence_refs must be an iterable of strings")
        evidence_ref_items = list(evidence_refs_raw)
        evidence_refs = tuple(str(ref) for ref in evidence_ref_items if isinstance(ref, str))
        if len(evidence_refs) != len(evidence_ref_items):
            raise TypeError("evaluation history event evidence_refs must contain only strings")
        return cls(
            event_type=(
                payload["event_type"]
                if isinstance(payload["event_type"], EvaluationHistoryEventType)
                else EvaluationHistoryEventType(str(payload["event_type"]))
            ),
            timestamp=str(payload["timestamp"]),
            status=(
                payload["status"]
                if isinstance(payload["status"], EvaluationResultStatus)
                else EvaluationResultStatus(str(payload["status"]))
            ),
            passed=(
                payload.get("passed")
                if isinstance(payload.get("passed"), bool)
                else None
            ),
            score=(
                score_raw
                if isinstance(score_raw, (int, float)) and not isinstance(score_raw, bool)
                else None
            ),
            max_score=(
                max_score_raw
                if isinstance(max_score_raw, int) and not isinstance(max_score_raw, bool)
                else None
            ),
            detail=(
                str(payload["detail"]) if payload.get("detail") is not None else None
            ),
            evidence_refs=evidence_refs,
            details=dict(payload.get("details", {}))
            if isinstance(payload.get("details", {}), Mapping)
            else {},
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "status": self.status.value,
            "passed": self.passed,
            "score": self.score,
            "max_score": self.max_score,
            "detail": self.detail,
            "evidence_refs": list(self.evidence_refs),
            "details": dict(self.details),
        }

    def __post_init__(self) -> None:
        if not isinstance(self.event_type, EvaluationHistoryEventType):
            raise TypeError("event_type must be an EvaluationHistoryEventType")
        if not isinstance(self.timestamp, str) or not self.timestamp:
            raise TypeError("timestamp must be a non-empty string")
        if not isinstance(self.status, EvaluationResultStatus):
            raise TypeError("status must be an EvaluationResultStatus")
        if self.passed is not None and not isinstance(self.passed, bool):
            raise TypeError("passed must be a bool or None")
        if self.score is not None and (
            isinstance(self.score, bool) or not isinstance(self.score, (int, float))
        ):
            raise TypeError("score must be numeric or None")
        if self.max_score is not None and (
            isinstance(self.max_score, bool) or not isinstance(self.max_score, int)
        ):
            raise TypeError("max_score must be an int or None")
        if self.detail is not None and not isinstance(self.detail, str):
            raise TypeError("detail must be a string or None")
        if any(not isinstance(ref, str) for ref in self.evidence_refs):
            raise TypeError("evidence_refs must contain only strings")
        if not isinstance(self.details, dict):
            raise TypeError("details must be a dict")
        if self.status in {
            EvaluationResultStatus.PENDING,
            EvaluationResultStatus.RUNNING,
            EvaluationResultStatus.FAILED,
        }:
            if self.passed is not None or self.score is not None or self.max_score is not None:
                raise ValueError(
                    "pending/running/failed evaluation history events may not report result values"
                )
        if self.status == EvaluationResultStatus.READY:
            if self.passed is None and self.score is None:
                raise ValueError(
                    "ready evaluation history events must report passed or score"
                )
        if self.max_score is not None and self.score is None:
            raise ValueError("evaluation history events may not report max_score without score")


@dataclass(frozen=True)
class EvaluationExecutionState:
    """Internal normalized execution state for one evaluator-observable resource."""

    state_schema_version: str = EVALUATION_STATE_SCHEMA_VERSION
    resource_type: str = ""
    run_id: str = ""
    status: EvaluationResultStatus = EvaluationResultStatus.PENDING
    observed_at: str = ""
    updated_at: str = ""
    passed: bool | None = None
    score: float | int | None = None
    max_score: int | None = None
    detail: str | None = None
    evidence_refs: tuple[str, ...] = ()

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any],
    ) -> "EvaluationExecutionState":
        if not isinstance(payload, Mapping):
            raise TypeError("evaluation result payload must be a mapping")
        missing_keys = [
            key
            for key in (
                "state_schema_version",
                "resource_type",
                "run_id",
                "status",
                "observed_at",
                "updated_at",
            )
            if key not in payload
        ]
        if missing_keys:
            raise ValueError(
                "evaluation result payload is missing required fields: "
                + ", ".join(missing_keys)
            )
        score_raw = payload.get("score")
        max_score_raw = payload.get("max_score")
        evidence_refs_raw = payload.get("evidence_refs", ())
        if isinstance(evidence_refs_raw, (str, bytes)) or not isinstance(
            evidence_refs_raw, Iterable
        ):
            raise TypeError("evaluation result evidence_refs must be an iterable of strings")
        evidence_ref_items = list(evidence_refs_raw)
        evidence_refs = tuple(str(ref) for ref in evidence_ref_items if isinstance(ref, str))
        if len(evidence_refs) != len(evidence_ref_items):
            raise TypeError("evaluation result evidence_refs must contain only strings")
        return cls(
            state_schema_version=str(payload["state_schema_version"]),
            resource_type=str(payload["resource_type"]),
            run_id=str(payload["run_id"]),
            status=(
                payload["status"]
                if isinstance(payload["status"], EvaluationResultStatus)
                else EvaluationResultStatus(str(payload["status"]))
            ),
            observed_at=str(payload["observed_at"]),
            updated_at=str(payload["updated_at"]),
            passed=(
                payload.get("passed")
                if isinstance(payload.get("passed"), bool)
                else None
            ),
            score=(
                score_raw
                if isinstance(score_raw, (int, float)) and not isinstance(score_raw, bool)
                else None
            ),
            max_score=(
                max_score_raw
                if isinstance(max_score_raw, int) and not isinstance(max_score_raw, bool)
                else None
            ),
            detail=(
                str(payload["detail"]) if payload.get("detail") is not None else None
            ),
            evidence_refs=evidence_refs,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "state_schema_version": self.state_schema_version,
            "resource_type": self.resource_type,
            "run_id": self.run_id,
            "status": self.status.value,
            "observed_at": self.observed_at,
            "updated_at": self.updated_at,
            "passed": self.passed,
            "score": self.score,
            "max_score": self.max_score,
            "detail": self.detail,
            "evidence_refs": list(self.evidence_refs),
        }

    def __post_init__(self) -> None:
        if not isinstance(self.state_schema_version, str) or not self.state_schema_version:
            raise TypeError("evaluation result state_schema_version must be a non-empty string")
        if not isinstance(self.resource_type, str) or not self.resource_type:
            raise TypeError("evaluation result resource_type must be a non-empty string")
        if not isinstance(self.run_id, str) or not self.run_id:
            raise TypeError("evaluation result run_id must be a non-empty string")
        if not isinstance(self.status, EvaluationResultStatus):
            raise TypeError("status must be an EvaluationResultStatus")
        if not isinstance(self.observed_at, str) or not self.observed_at:
            raise TypeError("observed_at must be a non-empty string")
        if not isinstance(self.updated_at, str) or not self.updated_at:
            raise TypeError("updated_at must be a non-empty string")
        if self.passed is not None and not isinstance(self.passed, bool):
            raise TypeError("passed must be a bool or None")
        if self.score is not None and (
            isinstance(self.score, bool) or not isinstance(self.score, (int, float))
        ):
            raise TypeError("score must be numeric or None")
        if self.max_score is not None and (
            isinstance(self.max_score, bool) or not isinstance(self.max_score, int)
        ):
            raise TypeError("max_score must be an int or None")
        if self.detail is not None and not isinstance(self.detail, str):
            raise TypeError("detail must be a string or None")
        if any(not isinstance(ref, str) for ref in self.evidence_refs):
            raise TypeError("evidence_refs must contain only strings")
        if self.status in {
            EvaluationResultStatus.PENDING,
            EvaluationResultStatus.RUNNING,
            EvaluationResultStatus.FAILED,
        }:
            if self.passed is not None or self.score is not None or self.max_score is not None:
                raise ValueError(
                    "pending/running/failed evaluation results may not report result values"
                )
        if self.status == EvaluationResultStatus.READY:
            if self.passed is None and self.score is None:
                raise ValueError(
                    "ready evaluation results must report passed or score"
                )
        if self.max_score is not None and self.score is None:
            raise ValueError("evaluation results may not report max_score without score")
        if (
            self.score is not None
            and self.max_score is not None
            and float(self.score) > float(self.max_score)
        ):
            raise ValueError("evaluation result score may not exceed max_score")


def validate_evaluation_result(
    contract: EvaluationResultContract,
    state: EvaluationExecutionState,
) -> list[str]:
    """Return contract violations for one evaluator result envelope."""

    violations: list[str] = []
    if state.resource_type != contract.resource_type:
        violations.append(
            "Result resource_type "
            f"{state.resource_type!r} does not match compiled contract "
            f"{contract.resource_type!r}."
        )
    if state.state_schema_version != contract.state_schema_version:
        violations.append(
            "Result state_schema_version "
            f"{state.state_schema_version!r} does not match compiled contract "
            f"{contract.state_schema_version!r}."
        )
    if not contract.supports_passed and state.passed is not None:
        violations.append("Result may not report 'passed' for this resource type.")
    if contract.supports_passed and state.status == EvaluationResultStatus.READY and state.passed is None:
        violations.append("Ready result must report 'passed' for this resource type.")
    if not contract.supports_score and (state.score is not None or state.max_score is not None):
        violations.append("Result may not report score fields for this resource type.")
    if contract.supports_score and state.status == EvaluationResultStatus.READY and state.score is None:
        violations.append("Ready result must report 'score' for this resource type.")
    if contract.fixed_max_score is not None:
        if state.status == EvaluationResultStatus.READY and state.max_score != contract.fixed_max_score:
            violations.append(
                "Ready result must report max_score "
                f"{contract.fixed_max_score} for this resource type."
            )
    return violations


@dataclass(frozen=True)
class MetricRuntime(ResolvedResource):
    """Resolved metric node."""

    condition_name: str = ""
    condition_addresses: tuple[str, ...] = ()
    result_contract: "EvaluationResultContract" = field(
        default_factory=lambda: EvaluationResultContract(resource_type="metric")
    )
    execution_contract: "EvaluationExecutionContract" = field(
        default_factory=lambda: EvaluationExecutionContract(resource_type="metric")
    )


@dataclass(frozen=True)
class EvaluationRuntime(ResolvedResource):
    """Resolved evaluation node."""

    metric_addresses: tuple[str, ...] = ()
    result_contract: "EvaluationResultContract" = field(
        default_factory=lambda: EvaluationResultContract(resource_type="evaluation")
    )
    execution_contract: "EvaluationExecutionContract" = field(
        default_factory=lambda: EvaluationExecutionContract(resource_type="evaluation")
    )


@dataclass(frozen=True)
class TLORuntime(ResolvedResource):
    """Resolved TLO node."""

    evaluation_address: str = ""
    result_contract: "EvaluationResultContract" = field(
        default_factory=lambda: EvaluationResultContract(resource_type="tlo")
    )
    execution_contract: "EvaluationExecutionContract" = field(
        default_factory=lambda: EvaluationExecutionContract(resource_type="tlo")
    )


@dataclass(frozen=True)
class GoalRuntime(ResolvedResource):
    """Resolved goal node."""

    tlo_addresses: tuple[str, ...] = ()
    result_contract: "EvaluationResultContract" = field(
        default_factory=lambda: EvaluationResultContract(resource_type="goal")
    )
    execution_contract: "EvaluationExecutionContract" = field(
        default_factory=lambda: EvaluationExecutionContract(resource_type="goal")
    )


@dataclass(frozen=True)
class ObjectiveRuntime(ResolvedResource):
    """Resolved objective node."""

    actor_type: str = ""
    actor_name: str = ""
    success_addresses: tuple[str, ...] = ()
    objective_dependencies: tuple[str, ...] = ()
    window_story_addresses: tuple[str, ...] = ()
    window_script_addresses: tuple[str, ...] = ()
    window_event_addresses: tuple[str, ...] = ()
    window_workflow_addresses: tuple[str, ...] = ()
    window_step_refs: tuple[str, ...] = ()
    window_step_workflow_addresses: tuple[str, ...] = ()
    window_references: tuple[ObjectiveWindowReferenceRuntime, ...] = ()
    result_contract: "EvaluationResultContract" = field(
        default_factory=lambda: EvaluationResultContract(resource_type="objective")
    )
    execution_contract: "EvaluationExecutionContract" = field(
        default_factory=lambda: EvaluationExecutionContract(resource_type="objective")
    )


@dataclass(frozen=True)
class RuntimeModel:
    """Compiled SDL runtime model.

    Reusable definitions stay as templates or metadata. Only bound runtime
    instances become planned resources.
    """

    scenario_name: str
    feature_templates: dict[str, RuntimeTemplate] = field(default_factory=dict)
    condition_templates: dict[str, RuntimeTemplate] = field(default_factory=dict)
    inject_templates: dict[str, RuntimeTemplate] = field(default_factory=dict)
    vulnerability_templates: dict[str, RuntimeTemplate] = field(default_factory=dict)
    entity_specs: dict[str, dict[str, Any]] = field(default_factory=dict)
    agent_specs: dict[str, dict[str, Any]] = field(default_factory=dict)
    relationship_specs: dict[str, dict[str, Any]] = field(default_factory=dict)
    variable_specs: dict[str, dict[str, Any]] = field(default_factory=dict)
    networks: dict[str, NetworkRuntime] = field(default_factory=dict)
    node_deployments: dict[str, NodeRuntime] = field(default_factory=dict)
    feature_bindings: dict[str, FeatureBinding] = field(default_factory=dict)
    condition_bindings: dict[str, ConditionBinding] = field(default_factory=dict)
    injects: dict[str, InjectRuntime] = field(default_factory=dict)
    inject_bindings: dict[str, InjectBinding] = field(default_factory=dict)
    content_placements: dict[str, ContentPlacement] = field(default_factory=dict)
    account_placements: dict[str, AccountPlacement] = field(default_factory=dict)
    events: dict[str, EventRuntime] = field(default_factory=dict)
    scripts: dict[str, ScriptRuntime] = field(default_factory=dict)
    stories: dict[str, StoryRuntime] = field(default_factory=dict)
    workflows: dict[str, WorkflowRuntime] = field(default_factory=dict)
    metrics: dict[str, MetricRuntime] = field(default_factory=dict)
    evaluations: dict[str, EvaluationRuntime] = field(default_factory=dict)
    tlos: dict[str, TLORuntime] = field(default_factory=dict)
    goals: dict[str, GoalRuntime] = field(default_factory=dict)
    objectives: dict[str, ObjectiveRuntime] = field(default_factory=dict)
    diagnostics: list[Diagnostic] = field(default_factory=list)


@dataclass(frozen=True)
class PlannedResource:
    """Normalized resource used by the planner and snapshot."""

    address: str
    domain: RuntimeDomain
    resource_type: str
    payload: dict[str, Any]
    ordering_dependencies: tuple[str, ...] = ()
    refresh_dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class PlanOperation:
    """A reconciliation operation for a planned resource."""

    action: ChangeAction
    address: str
    resource_type: str
    payload: dict[str, Any]
    ordering_dependencies: tuple[str, ...] = ()
    refresh_dependencies: tuple[str, ...] = ()


class ProvisionOp(PlanOperation):
    """Provisioning reconciliation operation."""


class OrchestrationOp(PlanOperation):
    """Orchestration reconciliation operation."""


class EvaluationOp(PlanOperation):
    """Evaluation reconciliation operation."""


@dataclass(frozen=True)
class ProvisioningPlan:
    """Provisioning plan over canonical deployment resources."""

    resources: dict[str, PlannedResource] = field(default_factory=dict)
    operations: list[ProvisionOp] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def actionable_operations(self) -> list[ProvisionOp]:
        return [op for op in self.operations if op.action != ChangeAction.UNCHANGED]


@dataclass(frozen=True)
class OrchestrationPlan:
    """Resolved orchestration graph and reconciliation actions."""

    resources: dict[str, PlannedResource] = field(default_factory=dict)
    operations: list[OrchestrationOp] = field(default_factory=list)
    startup_order: list[str] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def actionable_operations(self) -> list[OrchestrationOp]:
        return [op for op in self.operations if op.action != ChangeAction.UNCHANGED]


@dataclass(frozen=True)
class EvaluationPlan:
    """Resolved evaluation graph and reconciliation actions."""

    resources: dict[str, PlannedResource] = field(default_factory=dict)
    operations: list[EvaluationOp] = field(default_factory=list)
    startup_order: list[str] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def actionable_operations(self) -> list[EvaluationOp]:
        return [op for op in self.operations if op.action != ChangeAction.UNCHANGED]


@dataclass(frozen=True)
class ExecutionPlan:
    """Composite runtime execution plan."""

    target_name: str | None
    manifest: BackendManifest
    base_snapshot: "RuntimeSnapshot"
    scenario_name: str
    model: RuntimeModel
    provisioning: ProvisioningPlan
    orchestration: OrchestrationPlan
    evaluation: EvaluationPlan
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not any(diag.is_error for diag in self.diagnostics)


@dataclass(frozen=True)
class SnapshotEntry:
    """Recorded runtime state for a single canonical resource."""

    address: str
    domain: RuntimeDomain
    resource_type: str
    payload: dict[str, Any]
    ordering_dependencies: tuple[str, ...] = ()
    refresh_dependencies: tuple[str, ...] = ()
    status: str = "ready"


@dataclass
class RuntimeSnapshot:
    """Current runtime snapshot."""

    entries: dict[str, SnapshotEntry] = field(default_factory=dict)
    orchestration_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    orchestration_history: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    evaluation_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    evaluation_history: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def get(self, address: str) -> SnapshotEntry | None:
        return self.entries.get(address)

    def for_domain(self, domain: RuntimeDomain) -> dict[str, SnapshotEntry]:
        return {
            address: entry
            for address, entry in self.entries.items()
            if entry.domain == domain
        }

    def with_entries(
        self,
        entries: dict[str, SnapshotEntry],
        *,
        orchestration_results: dict[str, dict[str, Any]] | None = None,
        orchestration_history: dict[str, list[dict[str, Any]]] | None = None,
        evaluation_results: dict[str, dict[str, Any]] | None = None,
        evaluation_history: dict[str, list[dict[str, Any]]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "RuntimeSnapshot":
        return RuntimeSnapshot(
            entries=entries,
            orchestration_results=(
                dict(self.orchestration_results)
                if orchestration_results is None
                else dict(orchestration_results)
            ),
            orchestration_history=(
                {
                    workflow_address: list(events)
                    for workflow_address, events in self.orchestration_history.items()
                }
                if orchestration_history is None
                else {
                    workflow_address: list(events)
                    for workflow_address, events in orchestration_history.items()
                }
            ),
            evaluation_results=(
                dict(self.evaluation_results)
                if evaluation_results is None
                else dict(evaluation_results)
            ),
            evaluation_history=(
                {
                    address: list(events)
                    for address, events in self.evaluation_history.items()
                }
                if evaluation_history is None
                else {
                    address: list(events)
                    for address, events in evaluation_history.items()
                }
            ),
            metadata=dict(self.metadata) if metadata is None else dict(metadata),
        )


@dataclass
class ApplyResult:
    """Result of applying or starting a runtime plan."""

    success: bool
    snapshot: RuntimeSnapshot
    diagnostics: list[Diagnostic] = field(default_factory=list)
    changed_addresses: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OperationReceipt:
    """Portable acknowledgment for an accepted control-plane operation."""

    schema_version: str = OPERATION_SCHEMA_VERSION
    operation_id: str = ""
    domain: RuntimeDomain = RuntimeDomain.PROVISIONING
    submitted_at: str = ""
    accepted: bool = True
    diagnostics: list[Diagnostic] = field(default_factory=list)


@dataclass(frozen=True)
class OperationStatus:
    """Portable status for a submitted control-plane operation."""

    schema_version: str = OPERATION_SCHEMA_VERSION
    operation_id: str = ""
    domain: RuntimeDomain = RuntimeDomain.PROVISIONING
    state: OperationState = OperationState.ACCEPTED
    submitted_at: str = ""
    updated_at: str = ""
    diagnostics: list[Diagnostic] = field(default_factory=list)
    changed_addresses: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RuntimeSnapshotEnvelope:
    """Portable envelope around the current runtime snapshot."""

    schema_version: str = RUNTIME_SNAPSHOT_SCHEMA_VERSION
    snapshot: RuntimeSnapshot = field(default_factory=RuntimeSnapshot)


def resource_payload(resource: ResolvedResource) -> dict[str, Any]:
    """Convert a compiled resource to a stable planner payload."""

    payload = asdict(resource)
    payload.pop("address", None)
    payload.pop("ordering_dependencies", None)
    payload.pop("refresh_dependencies", None)
    return payload
