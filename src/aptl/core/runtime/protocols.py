"""Runtime execution protocols."""

from typing import Any, Protocol

from aptl.core.runtime.models import (
    ApplyResult,
    Diagnostic,
    EvaluationPlan,
    OrchestrationPlan,
    ProvisioningPlan,
    RuntimeSnapshot,
)


class Provisioner(Protocol):
    """Applies provisioning plans to the target environment."""

    def validate(self, plan: ProvisioningPlan) -> list[Diagnostic]:
        """Return planner/runtime diagnostics for an apply attempt."""
        ...

    def apply(
        self,
        plan: ProvisioningPlan,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        """Apply provisioning reconciliation operations."""
        ...


class Orchestrator(Protocol):
    """Loads and starts the orchestration graph."""

    def start(
        self,
        plan: OrchestrationPlan,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        """Start or refresh orchestration state."""
        ...

    def status(self) -> dict[str, Any]:
        """Return current orchestration status."""
        ...

    def results(self) -> dict[str, dict[str, Any]]:
        """Return most recent workflow execution state."""
        ...

    def stop(self, snapshot: RuntimeSnapshot) -> ApplyResult:
        """Stop orchestration and clear orchestration state."""
        ...


class Evaluator(Protocol):
    """Loads and starts the evaluation graph."""

    def start(
        self,
        plan: EvaluationPlan,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        """Start or refresh evaluation state."""
        ...

    def status(self) -> dict[str, Any]:
        """Return current evaluator status."""
        ...

    def results(self) -> dict[str, dict[str, Any]]:
        """Return most recent evaluation results."""
        ...

    def stop(self, snapshot: RuntimeSnapshot) -> ApplyResult:
        """Stop evaluation and clear evaluation state."""
        ...
