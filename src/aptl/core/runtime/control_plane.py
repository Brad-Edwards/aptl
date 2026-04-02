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
    Diagnostic,
    OperationReceipt,
    OperationState,
    OperationStatus,
    OrchestrationPlan,
    ProvisioningPlan,
    EvaluationPlan,
    RuntimeDomain,
    RuntimeSnapshot,
    RuntimeSnapshotEnvelope,
    WorkflowExecutionContract,
    WorkflowExecutionState,
    WorkflowHistoryEvent,
    WorkflowHistoryEventType,
    WorkflowStatus,
)
from aptl.core.runtime.registry import RuntimeTarget
from aptl.core.runtime.control_plane_store import (
    AuditEvent,
    ControlPlaneOperationRecord,
    ControlPlaneStore,
    InMemoryControlPlaneStore,
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class RuntimeControlPlane:
    """Reference control plane for async runtime submission and observation."""

    def __init__(
        self,
        target: RuntimeTarget,
        *,
        initial_snapshot: RuntimeSnapshot | None = None,
        store: ControlPlaneStore | None = None,
    ) -> None:
        self._target = target
        self._store = store or InMemoryControlPlaneStore(initial_snapshot)
        self._snapshot = (
            initial_snapshot
            if initial_snapshot is not None
            else self._store.load_snapshot()
        )
        self._operations: dict[str, ControlPlaneOperationRecord] = self._store.load_records()

    @property
    def snapshot(self) -> RuntimeSnapshot:
        return self._snapshot

    @property
    def target_name(self) -> str:
        return self._target.name

    def audit_log(self) -> list[AuditEvent]:
        return self._store.read_audit()

    def submit_provisioning(
        self,
        plan: ProvisioningPlan,
        *,
        base_snapshot: RuntimeSnapshot | None = None,
        idempotency_key: str = "",
        request_fingerprint: str = "",
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
            idempotency_key=idempotency_key,
            request_fingerprint=request_fingerprint,
        )

    def submit_orchestration(
        self,
        plan: OrchestrationPlan,
        *,
        base_snapshot: RuntimeSnapshot | None = None,
        idempotency_key: str = "",
        request_fingerprint: str = "",
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
            idempotency_key=idempotency_key,
            request_fingerprint=request_fingerprint,
        )

    def submit_evaluation(
        self,
        plan: EvaluationPlan,
        *,
        base_snapshot: RuntimeSnapshot | None = None,
        idempotency_key: str = "",
        request_fingerprint: str = "",
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
            idempotency_key=idempotency_key,
            request_fingerprint=request_fingerprint,
        )

    def get_operation(self, operation_id: str) -> OperationStatus | None:
        record = self._operations.get(operation_id)
        return None if record is None else record.status

    def get_snapshot(self) -> RuntimeSnapshotEnvelope:
        return RuntimeSnapshotEnvelope(snapshot=self._snapshot)

    def cancel_workflow(
        self,
        workflow_address: str,
        *,
        run_id: str | None = None,
        reason: str = "cancelled by operator",
        idempotency_key: str = "",
        request_fingerprint: str = "",
    ) -> OperationReceipt:
        existing = self._idempotent_receipt(
            idempotency_key=idempotency_key,
            request_fingerprint=request_fingerprint,
        )
        if existing is not None:
            return existing
        submitted_at = _utc_now()
        operation_id = str(uuid4())
        result = dict(self._snapshot.orchestration_results.get(workflow_address, {}))
        if not result:
            return self._reject_submission(
                domain=RuntimeDomain.ORCHESTRATION,
                message=f"Unknown workflow run: {workflow_address}",
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
            )
        normalized = WorkflowExecutionState.from_payload(result)
        if run_id and normalized.run_id != run_id:
            return self._reject_submission(
                domain=RuntimeDomain.ORCHESTRATION,
                message=(
                    f"Workflow run_id mismatch for {workflow_address}: "
                    f"{run_id!r} != {normalized.run_id!r}"
                ),
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
            )
        if normalized.workflow_status in {
            WorkflowStatus.SUCCEEDED,
            WorkflowStatus.FAILED,
            WorkflowStatus.CANCELLED,
            WorkflowStatus.TIMED_OUT,
        }:
            receipt = OperationReceipt(
                operation_id=operation_id,
                domain=RuntimeDomain.ORCHESTRATION,
                submitted_at=submitted_at,
                accepted=True,
                diagnostics=[],
            )
            status = OperationStatus(
                operation_id=operation_id,
                domain=RuntimeDomain.ORCHESTRATION,
                state=OperationState.SUCCEEDED,
                submitted_at=submitted_at,
                updated_at=submitted_at,
            )
            self._persist_record(
                ControlPlaneOperationRecord(
                    receipt=receipt,
                    status=status,
                    idempotency_key=idempotency_key,
                    request_fingerprint=request_fingerprint,
                )
            )
            return receipt
        cancelled = WorkflowExecutionState(
            state_schema_version=normalized.state_schema_version,
            workflow_status=WorkflowStatus.CANCELLED,
            run_id=normalized.run_id,
            started_at=normalized.started_at,
            updated_at=submitted_at,
            terminal_reason=reason,
            steps=normalized.steps,
        ).to_payload()
        history = list(self._snapshot.orchestration_history.get(workflow_address, []))
        history.append(
            WorkflowHistoryEvent(
                event_type=WorkflowHistoryEventType.WORKFLOW_CANCELLED,
                timestamp=submitted_at,
                details={"reason": reason},
            ).to_payload()
        )
        self._snapshot = self._snapshot.with_entries(
            dict(self._snapshot.entries),
            orchestration_results={
                **self._snapshot.orchestration_results,
                workflow_address: cancelled,
            },
            orchestration_history={
                **self._snapshot.orchestration_history,
                workflow_address: history,
            },
        )
        self._store.save_snapshot(self._snapshot)
        receipt = OperationReceipt(
            operation_id=operation_id,
            domain=RuntimeDomain.ORCHESTRATION,
            submitted_at=submitted_at,
            accepted=True,
        )
        status = OperationStatus(
            operation_id=operation_id,
            domain=RuntimeDomain.ORCHESTRATION,
            state=OperationState.SUCCEEDED,
            submitted_at=submitted_at,
            updated_at=submitted_at,
            changed_addresses=[workflow_address],
        )
        self._persist_record(
            ControlPlaneOperationRecord(
                receipt=receipt,
                status=status,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
            )
        )
        return receipt

    def reconcile_workflow_timeouts(
        self,
        *,
        now: str | None = None,
        idempotency_key: str = "",
        request_fingerprint: str = "",
    ) -> OperationReceipt:
        existing = self._idempotent_receipt(
            idempotency_key=idempotency_key,
            request_fingerprint=request_fingerprint,
        )
        if existing is not None:
            return existing
        submitted_at = now or _utc_now()
        changed: list[str] = []
        orchestration_results = dict(self._snapshot.orchestration_results)
        orchestration_history = {
            address: list(events)
            for address, events in self._snapshot.orchestration_history.items()
        }
        for workflow_address, entry in self._snapshot.entries.items():
            if entry.domain != RuntimeDomain.ORCHESTRATION or entry.resource_type != "workflow":
                continue
            payload = dict(entry.payload)
            execution_contract_payload = payload.get("execution_contract")
            if not isinstance(execution_contract_payload, dict):
                continue
            timeout_seconds = execution_contract_payload.get("timeout_seconds")
            if timeout_seconds in (None, "", 0):
                continue
            result_payload = orchestration_results.get(workflow_address)
            if not isinstance(result_payload, dict):
                continue
            normalized = WorkflowExecutionState.from_payload(result_payload)
            if normalized.workflow_status != WorkflowStatus.RUNNING:
                continue
            try:
                deadline = _parse_timestamp(normalized.started_at).timestamp() + int(timeout_seconds)
                current = _parse_timestamp(submitted_at).timestamp()
            except Exception:
                continue
            if current < deadline:
                continue
            orchestration_results[workflow_address] = WorkflowExecutionState(
                state_schema_version=normalized.state_schema_version,
                workflow_status=WorkflowStatus.TIMED_OUT,
                run_id=normalized.run_id,
                started_at=normalized.started_at,
                updated_at=submitted_at,
                terminal_reason="workflow timed out",
                steps=normalized.steps,
            ).to_payload()
            orchestration_history.setdefault(workflow_address, []).append(
                WorkflowHistoryEvent(
                    event_type=WorkflowHistoryEventType.WORKFLOW_TIMED_OUT,
                    timestamp=submitted_at,
                    details={"timeout_seconds": int(timeout_seconds)},
                ).to_payload()
            )
            changed.append(workflow_address)
        operation_id = str(uuid4())
        self._snapshot = self._snapshot.with_entries(
            dict(self._snapshot.entries),
            orchestration_results=orchestration_results,
            orchestration_history=orchestration_history,
        )
        self._store.save_snapshot(self._snapshot)
        receipt = OperationReceipt(
            operation_id=operation_id,
            domain=RuntimeDomain.ORCHESTRATION,
            submitted_at=submitted_at,
            accepted=True,
        )
        status = OperationStatus(
            operation_id=operation_id,
            domain=RuntimeDomain.ORCHESTRATION,
            state=OperationState.SUCCEEDED,
            submitted_at=submitted_at,
            updated_at=submitted_at,
            changed_addresses=changed,
        )
        self._persist_record(
            ControlPlaneOperationRecord(
                receipt=receipt,
                status=status,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
            )
        )
        return receipt

    def record_audit(
        self,
        *,
        action: str,
        identity: str,
        allowed: bool,
        target: str,
        reason: str = "",
        operation_id: str = "",
        details: dict[str, object] | None = None,
    ) -> None:
        self._store.append_audit(
            AuditEvent(
                timestamp=_utc_now(),
                action=action,
                identity=identity,
                allowed=allowed,
                target=target,
                operation_id=operation_id,
                reason=reason,
                details=dict(details or {}),
            )
        )

    def _reject_submission(
        self,
        *,
        domain: RuntimeDomain,
        message: str,
        idempotency_key: str = "",
        request_fingerprint: str = "",
    ) -> OperationReceipt:
        operation_id = str(uuid4())
        submitted_at = _utc_now()
        diagnostic = Diagnostic(
            code="runtime.control-plane.rejected",
            domain="runtime",
            address=f"runtime.control-plane.{domain.value}",
            message=message,
        )
        receipt = OperationReceipt(
            operation_id=operation_id,
            domain=domain,
            submitted_at=submitted_at,
            accepted=False,
            diagnostics=[diagnostic],
        )
        status = OperationStatus(
            operation_id=operation_id,
            domain=domain,
            state=OperationState.FAILED,
            submitted_at=submitted_at,
            updated_at=submitted_at,
            diagnostics=[diagnostic],
        )
        self._persist_record(
            ControlPlaneOperationRecord(
                receipt=receipt,
                status=status,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
            )
        )
        return receipt

    def _execute_operation(
        self,
        *,
        domain: RuntimeDomain,
        method,
        plan,
        address: str,
        diagnostics,
        base_snapshot: RuntimeSnapshot | None,
        idempotency_key: str,
        request_fingerprint: str,
    ) -> OperationReceipt:
        existing = self._idempotent_receipt(
            idempotency_key=idempotency_key,
            request_fingerprint=request_fingerprint,
        )
        if existing is not None:
            return existing
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
        receipt = OperationReceipt(
            operation_id=operation_id,
            domain=domain,
            submitted_at=submitted_at,
            accepted=True,
            diagnostics=list(diagnostics),
        )
        self._persist_record(
            ControlPlaneOperationRecord(
                receipt=receipt,
                status=status,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
            )
        )
        result = _call_backend_apply(
            method,
            plan,
            snapshot,
            address=address,
            snapshot=snapshot,
        )
        self._snapshot = result.snapshot
        self._store.save_snapshot(self._snapshot)
        final_state = OperationState.SUCCEEDED if result.success else OperationState.FAILED
        final_status = OperationStatus(
            operation_id=operation_id,
            domain=domain,
            state=final_state,
            submitted_at=submitted_at,
            updated_at=_utc_now(),
            diagnostics=[*status.diagnostics, *result.diagnostics],
            changed_addresses=list(result.changed_addresses),
        )
        self._persist_record(
            ControlPlaneOperationRecord(
                receipt=receipt,
                status=final_status,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
            )
        )
        return receipt

    def _idempotent_receipt(
        self,
        *,
        idempotency_key: str,
        request_fingerprint: str,
    ) -> OperationReceipt | None:
        if not idempotency_key:
            return None
        record = self._store.find_by_idempotency(idempotency_key)
        if record is None:
            return None
        if (
            record.request_fingerprint
            and request_fingerprint
            and record.request_fingerprint != request_fingerprint
        ):
            raise ValueError("Idempotency-Key was reused with a different request body.")
        self._operations[record.receipt.operation_id] = record
        return record.receipt

    def _persist_record(self, record: ControlPlaneOperationRecord) -> None:
        self._operations[record.receipt.operation_id] = record
        self._store.save_record(record)


def _parse_timestamp(raw: str) -> datetime:
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed
