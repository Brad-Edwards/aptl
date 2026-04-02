"""Reference HTTP/JSON adapter for the runtime control plane."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import FastAPI, HTTPException

from aptl.core.runtime.contracts import (
    EvaluationPlanModel,
    OperationReceiptModel,
    OperationStatusModel,
    OrchestrationPlanModel,
    ProvisioningPlanModel,
    RuntimeSnapshotEnvelopeModel,
)
from aptl.core.runtime.control_plane import RuntimeControlPlane
from aptl.core.runtime.models import (
    ChangeAction,
    Diagnostic,
    EvaluationOp,
    EvaluationPlan,
    OperationStatus,
    OrchestrationOp,
    OrchestrationPlan,
    ProvisionOp,
    ProvisioningPlan,
    RuntimeSnapshotEnvelope,
    Severity,
)


def _diagnostic_from_mapping(payload: dict[str, Any]) -> Diagnostic:
    return Diagnostic(
        code=str(payload.get("code", "runtime.control-plane")),
        domain=str(payload.get("domain", "runtime")),
        address=str(payload.get("address", "runtime.control-plane")),
        message=str(payload.get("message", "")),
        severity=Severity(str(payload.get("severity", "error"))),
    )


def _provisioning_plan(model: ProvisioningPlanModel) -> ProvisioningPlan:
    return ProvisioningPlan(
        operations=[
            ProvisionOp(
                action=ChangeAction(str(op.action)),
                address=op.address,
                resource_type=op.resource_type,
                payload=dict(op.payload),
                ordering_dependencies=tuple(op.ordering_dependencies),
                refresh_dependencies=tuple(op.refresh_dependencies),
            )
            for op in model.operations
        ],
        diagnostics=[_diagnostic_from_mapping(payload) for payload in model.diagnostics],
    )


def _orchestration_plan(model: OrchestrationPlanModel) -> OrchestrationPlan:
    return OrchestrationPlan(
        operations=[
            OrchestrationOp(
                action=ChangeAction(str(op.action)),
                address=op.address,
                resource_type=op.resource_type,
                payload=dict(op.payload),
                ordering_dependencies=tuple(op.ordering_dependencies),
                refresh_dependencies=tuple(op.refresh_dependencies),
            )
            for op in model.operations
        ],
        startup_order=list(model.startup_order),
        diagnostics=[_diagnostic_from_mapping(payload) for payload in model.diagnostics],
    )


def _evaluation_plan(model: EvaluationPlanModel) -> EvaluationPlan:
    return EvaluationPlan(
        operations=[
            EvaluationOp(
                action=ChangeAction(str(op.action)),
                address=op.address,
                resource_type=op.resource_type,
                payload=dict(op.payload),
                ordering_dependencies=tuple(op.ordering_dependencies),
                refresh_dependencies=tuple(op.refresh_dependencies),
            )
            for op in model.operations
        ],
        startup_order=list(model.startup_order),
        diagnostics=[_diagnostic_from_mapping(payload) for payload in model.diagnostics],
    )


def _operation_status_model(status: OperationStatus) -> OperationStatusModel:
    return OperationStatusModel.model_validate(
        {
            "schema_version": status.schema_version,
            "operation_id": status.operation_id,
            "domain": status.domain.value,
            "state": status.state.value,
            "submitted_at": status.submitted_at,
            "updated_at": status.updated_at,
            "diagnostics": [asdict(diag) for diag in status.diagnostics],
            "changed_addresses": list(status.changed_addresses),
        }
    )


def _snapshot_model(envelope: RuntimeSnapshotEnvelope) -> RuntimeSnapshotEnvelopeModel:
    snapshot = envelope.snapshot
    return RuntimeSnapshotEnvelopeModel.model_validate(
        {
            "schema_version": envelope.schema_version,
            "entries": {
                address: {
                    "address": entry.address,
                    "domain": entry.domain.value,
                    "resource_type": entry.resource_type,
                    "payload": dict(entry.payload),
                    "ordering_dependencies": list(entry.ordering_dependencies),
                    "refresh_dependencies": list(entry.refresh_dependencies),
                    "status": entry.status,
                }
                for address, entry in snapshot.entries.items()
            },
            "orchestration_results": dict(snapshot.orchestration_results),
            "orchestration_history": dict(snapshot.orchestration_history),
            "evaluation_results": dict(snapshot.evaluation_results),
            "metadata": dict(snapshot.metadata),
        }
    )


def create_control_plane_app(control_plane: RuntimeControlPlane) -> FastAPI:
    """Create a reference HTTP/JSON control-plane app."""

    app = FastAPI(
        title="APTL Runtime Control Plane",
        version="0.1.0",
        description="Reference HTTP/JSON adapter over the repo-owned runtime control plane.",
    )

    @app.post("/operations/provisioning", response_model=OperationReceiptModel)
    async def submit_provisioning(plan: ProvisioningPlanModel) -> OperationReceiptModel:
        receipt = control_plane.submit_provisioning(_provisioning_plan(plan))
        return OperationReceiptModel.model_validate(
            {
                "schema_version": receipt.schema_version,
                "operation_id": receipt.operation_id,
                "domain": receipt.domain.value,
                "submitted_at": receipt.submitted_at,
                "accepted": receipt.accepted,
                "diagnostics": [asdict(diag) for diag in receipt.diagnostics],
            }
        )

    @app.post("/operations/orchestration", response_model=OperationReceiptModel)
    async def submit_orchestration(plan: OrchestrationPlanModel) -> OperationReceiptModel:
        receipt = control_plane.submit_orchestration(_orchestration_plan(plan))
        return OperationReceiptModel.model_validate(
            {
                "schema_version": receipt.schema_version,
                "operation_id": receipt.operation_id,
                "domain": receipt.domain.value,
                "submitted_at": receipt.submitted_at,
                "accepted": receipt.accepted,
                "diagnostics": [asdict(diag) for diag in receipt.diagnostics],
            }
        )

    @app.post("/operations/evaluation", response_model=OperationReceiptModel)
    async def submit_evaluation(plan: EvaluationPlanModel) -> OperationReceiptModel:
        receipt = control_plane.submit_evaluation(_evaluation_plan(plan))
        return OperationReceiptModel.model_validate(
            {
                "schema_version": receipt.schema_version,
                "operation_id": receipt.operation_id,
                "domain": receipt.domain.value,
                "submitted_at": receipt.submitted_at,
                "accepted": receipt.accepted,
                "diagnostics": [asdict(diag) for diag in receipt.diagnostics],
            }
        )

    @app.get("/operations/{operation_id}", response_model=OperationStatusModel)
    async def get_operation(operation_id: str) -> OperationStatusModel:
        status = control_plane.get_operation(operation_id)
        if status is None:
            raise HTTPException(status_code=404, detail=f"Unknown operation: {operation_id}")
        return _operation_status_model(status)

    @app.get("/snapshot", response_model=RuntimeSnapshotEnvelopeModel)
    async def get_snapshot() -> RuntimeSnapshotEnvelopeModel:
        return _snapshot_model(control_plane.get_snapshot())

    return app
