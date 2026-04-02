"""Domain-specific runtime capability declarations."""

from dataclasses import dataclass, field
from enum import Enum


class WorkflowFeature(str, Enum):
    """Portable workflow control features that an orchestrator may support."""

    DECISION = "decision"
    RETRY = "retry"
    PARALLEL_BARRIER = "parallel-barrier"
    FAILURE_TRANSITIONS = "failure-transitions"


class WorkflowStatePredicateFeature(str, Enum):
    """Portable workflow state-predicate features that an orchestrator may support."""

    OUTCOME_MATCHING = "outcome-matching"
    ATTEMPT_COUNTS = "attempt-counts"


@dataclass(frozen=True)
class ProvisionerCapabilities:
    """Provisioning support declaration."""

    name: str
    supported_node_types: frozenset[str] = frozenset()
    supported_os_families: frozenset[str] = frozenset()
    supported_content_types: frozenset[str] = frozenset()
    supported_account_features: frozenset[str] = frozenset()
    max_total_nodes: int | None = None
    supports_acls: bool = False
    supports_accounts: bool = False
    constraints: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class OrchestratorCapabilities:
    """Orchestration support declaration."""

    name: str
    supported_sections: frozenset[str] = frozenset()
    supports_workflows: bool = False
    supports_condition_refs: bool = True
    supports_inject_bindings: bool = True
    supported_workflow_features: frozenset[WorkflowFeature] = frozenset()
    supported_workflow_state_predicates: frozenset[
        WorkflowStatePredicateFeature
    ] = frozenset()
    constraints: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class EvaluatorCapabilities:
    """Evaluation support declaration."""

    name: str
    supported_sections: frozenset[str] = frozenset()
    supports_scoring: bool = True
    supports_objectives: bool = True
    constraints: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class BackendManifest:
    """Complete runtime target capability declaration."""

    name: str
    provisioner: ProvisionerCapabilities
    orchestrator: OrchestratorCapabilities | None = None
    evaluator: EvaluatorCapabilities | None = None

    @property
    def has_orchestrator(self) -> bool:
        return self.orchestrator is not None

    @property
    def has_evaluator(self) -> bool:
        return self.evaluator is not None

    @property
    def evaluator_supported_sections(self) -> frozenset[str]:
        if self.evaluator is None:
            return frozenset()
        return self.evaluator.supported_sections

    @property
    def supports_scoring(self) -> bool:
        return self.evaluator.supports_scoring if self.evaluator is not None else False

    @property
    def supports_objectives(self) -> bool:
        return self.evaluator.supports_objectives if self.evaluator is not None else False
