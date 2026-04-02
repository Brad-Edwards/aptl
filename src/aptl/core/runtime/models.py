"""Runtime data models for the SDL-native execution layer.

The runtime is split into three domains:

- provisioning: desired deployed state
- orchestration: resolved exercise control graph
- evaluation: resolved monitoring/scoring graph

The compiler produces a ``RuntimeModel`` with reusable templates separated
from bound runtime instances. The planner reconciles those instances against
the current ``RuntimeSnapshot`` and emits a composite ``ExecutionPlan``.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

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
    emits_outcome: bool = False


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
    state_schema_version: str = "workflow-step-state/v1"


@dataclass(frozen=True)
class MetricRuntime(ResolvedResource):
    """Resolved metric node."""

    condition_name: str = ""
    condition_addresses: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvaluationRuntime(ResolvedResource):
    """Resolved evaluation node."""

    metric_addresses: tuple[str, ...] = ()


@dataclass(frozen=True)
class TLORuntime(ResolvedResource):
    """Resolved TLO node."""

    evaluation_address: str = ""


@dataclass(frozen=True)
class GoalRuntime(ResolvedResource):
    """Resolved goal node."""

    tlo_addresses: tuple[str, ...] = ()


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
    evaluation_results: dict[str, dict[str, Any]] = field(default_factory=dict)
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
        evaluation_results: dict[str, dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "RuntimeSnapshot":
        return RuntimeSnapshot(
            entries=entries,
            orchestration_results=(
                dict(self.orchestration_results)
                if orchestration_results is None
                else dict(orchestration_results)
            ),
            evaluation_results=(
                dict(self.evaluation_results)
                if evaluation_results is None
                else dict(evaluation_results)
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


def resource_payload(resource: ResolvedResource) -> dict[str, Any]:
    """Convert a compiled resource to a stable planner payload."""

    payload = asdict(resource)
    payload.pop("address", None)
    payload.pop("ordering_dependencies", None)
    payload.pop("refresh_dependencies", None)
    return payload
