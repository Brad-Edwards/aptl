"""Reference async-style control plane over runtime targets.

This is a repo-owned, schema-oriented façade that exposes runtime execution as
submitted operations over plain-data-compatible envelopes. The current
implementation completes operations eagerly, but the contract surface matches an
async control plane so non-Python runtimes can evolve behind the same API.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from aptl.core.runtime.manager import _call_backend_apply, _call_backend_diagnostics
from aptl.core.runtime.models import (
    OperationReceipt,
    OperationState,
    OperationStatus,
    OrchestrationPlan,
    ProvisioningPlan,
    EvaluationPlan,
    RuntimeDomain,
    RuntimeSnapshot,
    RuntimeSnapshotEnvelope,
)
from aptl.core.runtime.registry import RuntimeTarget


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class RuntimeControlPlane:
    """Reference control plane for async runtime submission and observation."""

    def __init__(
        self,
        target: RuntimeTarget,
        *,
        initial_snapshot: RuntimeSnapshot | None = None,
    ) -> None:
        self._target = target
        self._snapshot = initial_snapshot if initial_snapshot is not None else RuntimeSnapshot()
        self._operations: dict[str, OperationStatus] = {}

    @property
    def snapshot(self) -> RuntimeSnapshot:
        return self._snapshot

    def submit_provisioning(
        self,
        plan: ProvisioningPlan,
        *,
        base_snapshot: RuntimeSnapshot | None = None,
    ) -> OperationReceipt:
        diagnostics = _call_backend_diagnostics(
            self._target.provisioner.validate,
            plan,
            address="runtime.control-plane.provisioning.validate",
        )
        return self._execute_operation(
            domain=RuntimeDomain.PROVISIONING,
            method=self._target.provisioner.apply,
            plan=plan,
            address="runtime.control-plane.provisioning",
            diagnostics=diagnostics,
            base_snapshot=base_snapshot,
        )

    def submit_orchestration(
        self,
        plan: OrchestrationPlan,
        *,
        base_snapshot: RuntimeSnapshot | None = None,
    ) -> OperationReceipt:
        if self._target.orchestrator is None:
            return self._reject_submission(
                domain=RuntimeDomain.ORCHESTRATION,
                message="Target does not provide an orchestrator.",
            )
        return self._execute_operation(
            domain=RuntimeDomain.ORCHESTRATION,
            method=self._target.orchestrator.start,
            plan=plan,
            address="runtime.control-plane.orchestration",
            diagnostics=[],
            base_snapshot=base_snapshot,
        )

    def submit_evaluation(
        self,
        plan: EvaluationPlan,
        *,
        base_snapshot: RuntimeSnapshot | None = None,
    ) -> OperationReceipt:
        if self._target.evaluator is None:
            return self._reject_submission(
                domain=RuntimeDomain.EVALUATION,
                message="Target does not provide an evaluator.",
            )
        return self._execute_operation(
            domain=RuntimeDomain.EVALUATION,
            method=self._target.evaluator.start,
            plan=plan,
            address="runtime.control-plane.evaluation",
            diagnostics=[],
            base_snapshot=base_snapshot,
        )

    def get_operation(self, operation_id: str) -> OperationStatus | None:
        return self._operations.get(operation_id)

    def get_snapshot(self) -> RuntimeSnapshotEnvelope:
        return RuntimeSnapshotEnvelope(snapshot=self._snapshot)

    def _reject_submission(self, *, domain: RuntimeDomain, message: str) -> OperationReceipt:
        operation_id = str(uuid4())
        submitted_at = _utc_now()
        self._operations[operation_id] = OperationStatus(
            operation_id=operation_id,
            domain=domain,
            state=OperationState.FAILED,
            submitted_at=submitted_at,
            updated_at=submitted_at,
        )
        return OperationReceipt(
            operation_id=operation_id,
            domain=domain,
            submitted_at=submitted_at,
            accepted=False,
        )

    def _execute_operation(
        self,
        *,
        domain: RuntimeDomain,
        method,
        plan,
        address: str,
        diagnostics,
        base_snapshot: RuntimeSnapshot | None,
    ) -> OperationReceipt:
        operation_id = str(uuid4())
        submitted_at = _utc_now()
        snapshot = base_snapshot if base_snapshot is not None else self._snapshot
        status = OperationStatus(
            operation_id=operation_id,
            domain=domain,
            state=OperationState.RUNNING,
            submitted_at=submitted_at,
            updated_at=submitted_at,
            diagnostics=list(diagnostics),
        )
        self._operations[operation_id] = status
        result = _call_backend_apply(
            method,
            plan,
            snapshot,
            address=address,
            snapshot=snapshot,
        )
        self._snapshot = result.snapshot
        final_state = OperationState.SUCCEEDED if result.success else OperationState.FAILED
        self._operations[operation_id] = OperationStatus(
            operation_id=operation_id,
            domain=domain,
            state=final_state,
            submitted_at=submitted_at,
            updated_at=_utc_now(),
            diagnostics=[*status.diagnostics, *result.diagnostics],
            changed_addresses=list(result.changed_addresses),
        )
        return OperationReceipt(
            operation_id=operation_id,
            domain=domain,
            submitted_at=submitted_at,
            accepted=True,
            diagnostics=list(diagnostics),
        )
