"""Reference HTTP/JSON adapter for the runtime control plane."""

from __future__ import annotations

import hashlib
from dataclasses import asdict
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from aptl.core.runtime.contracts import (
    EvaluationPlanModel,
    OperationReceiptModel,
    OperationStatusModel,
    OrchestrationPlanModel,
    ProvisioningPlanModel,
    RuntimeSnapshotEnvelopeModel,
    WorkflowCancellationRequestModel,
)
from aptl.core.runtime.control_plane import RuntimeControlPlane
from aptl.core.runtime.control_plane_security import (
    ControlPlaneIdentity,
    ControlPlaneRole,
    ControlPlaneSecurityConfig,
)
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
            "evaluation_history": dict(snapshot.evaluation_history),
            "metadata": dict(snapshot.metadata),
        }
    )


def _request_fingerprint(request: Request, body: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(request.url.path.encode("utf-8"))
    digest.update(b"\n")
    digest.update(body)
    return digest.hexdigest()


def create_control_plane_app(
    control_plane: RuntimeControlPlane,
    *,
    security: ControlPlaneSecurityConfig | None = None,
) -> FastAPI:
    """Create a reference HTTP/JSON control-plane app."""

    security = security or ControlPlaneSecurityConfig.strict_defaults(
        target_name=control_plane.target_name
    )
    app = FastAPI(
        title="APTL Runtime Control Plane",
        version="0.1.0",
        description="Reference HTTP/JSON adapter over the repo-owned runtime control plane.",
    )

    @app.middleware("http")
    async def _limit_request_size(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length is not None and int(content_length) > security.max_request_bytes:
            control_plane.record_audit(
                action=request.method,
                identity="anonymous",
                allowed=False,
                target=str(request.url.path),
                reason="request too large",
            )
            return JSONResponse(status_code=413, content={"detail": "request too large"})
        body = await request.body()
        if len(body) > security.max_request_bytes:
            control_plane.record_audit(
                action=request.method,
                identity="anonymous",
                allowed=False,
                target=str(request.url.path),
                reason="request too large",
            )
            return JSONResponse(status_code=413, content={"detail": "request too large"})
        request.state.raw_body = body
        return await call_next(request)

    @app.exception_handler(Exception)
    async def _redacted_errors(request: Request, exc: Exception):
        control_plane.record_audit(
            action=request.method,
            identity="anonymous",
            allowed=False,
            target=str(request.url.path),
            reason=f"internal-error:{type(exc).__name__}",
        )
        return JSONResponse(status_code=500, content={"detail": "internal server error"})

    def _authenticate_request(request: Request) -> ControlPlaneIdentity:
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1].strip()
            identity = security.bearer_tokens.get(token)
            if identity is not None:
                return identity
        identity_name = request.headers.get(security.identity_header, "")
        verified = request.headers.get(security.verified_header, "").lower()
        if security.require_verified_identity and verified != "true":
            raise HTTPException(status_code=401, detail="verified client identity required")
        identity = security.trusted_identities.get(identity_name)
        if identity is None:
            raise HTTPException(status_code=401, detail="unknown client identity")
        if identity.target_name and identity.target_name != control_plane.target_name:
            raise HTTPException(status_code=403, detail="identity is not authorized for this target")
        return identity

    def _authorize(
        identity: ControlPlaneIdentity,
        *,
        roles: set[ControlPlaneRole],
        request: Request,
    ) -> ControlPlaneIdentity:
        if identity.roles.isdisjoint(roles):
            control_plane.record_audit(
                action=request.method,
                identity=identity.identity,
                allowed=False,
                target=str(request.url.path),
                reason="forbidden",
            )
            raise HTTPException(status_code=403, detail="forbidden")
        return identity

    def _mutating_identity(request: Request) -> ControlPlaneIdentity:
        try:
            identity = _authenticate_request(request)
        except HTTPException as exc:
            control_plane.record_audit(
                action=request.method,
                identity="anonymous",
                allowed=False,
                target=str(request.url.path),
                reason=exc.detail,
            )
            raise
        return _authorize(
            identity,
            roles={ControlPlaneRole.BACKEND, ControlPlaneRole.OPERATOR},
            request=request,
        )

    def _read_identity(request: Request) -> ControlPlaneIdentity:
        try:
            identity = _authenticate_request(request)
        except HTTPException as exc:
            control_plane.record_audit(
                action=request.method,
                identity="anonymous",
                allowed=False,
                target=str(request.url.path),
                reason=exc.detail,
            )
            raise
        return _authorize(
            identity,
            roles={
                ControlPlaneRole.BACKEND,
                ControlPlaneRole.OPERATOR,
                ControlPlaneRole.AUDITOR,
            },
            request=request,
        )

    @app.post("/operations/provisioning", response_model=OperationReceiptModel)
    async def submit_provisioning(
        request: Request,
        plan: ProvisioningPlanModel,
        identity: ControlPlaneIdentity = Depends(_mutating_identity),
    ) -> OperationReceiptModel:
        try:
            receipt = control_plane.submit_provisioning(
                _provisioning_plan(plan),
                idempotency_key=request.headers.get("idempotency-key", ""),
                request_fingerprint=_request_fingerprint(
                    request,
                    getattr(request.state, "raw_body", b""),
                ),
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        control_plane.record_audit(
            action="submit_provisioning",
            identity=identity.identity,
            allowed=True,
            target=str(request.url.path),
            operation_id=receipt.operation_id,
        )
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
    async def submit_orchestration(
        request: Request,
        plan: OrchestrationPlanModel,
        identity: ControlPlaneIdentity = Depends(_mutating_identity),
    ) -> OperationReceiptModel:
        try:
            receipt = control_plane.submit_orchestration(
                _orchestration_plan(plan),
                idempotency_key=request.headers.get("idempotency-key", ""),
                request_fingerprint=_request_fingerprint(
                    request,
                    getattr(request.state, "raw_body", b""),
                ),
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        control_plane.record_audit(
            action="submit_orchestration",
            identity=identity.identity,
            allowed=True,
            target=str(request.url.path),
            operation_id=receipt.operation_id,
        )
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
    async def submit_evaluation(
        request: Request,
        plan: EvaluationPlanModel,
        identity: ControlPlaneIdentity = Depends(_mutating_identity),
    ) -> OperationReceiptModel:
        try:
            receipt = control_plane.submit_evaluation(
                _evaluation_plan(plan),
                idempotency_key=request.headers.get("idempotency-key", ""),
                request_fingerprint=_request_fingerprint(
                    request,
                    getattr(request.state, "raw_body", b""),
                ),
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        control_plane.record_audit(
            action="submit_evaluation",
            identity=identity.identity,
            allowed=True,
            target=str(request.url.path),
            operation_id=receipt.operation_id,
        )
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
    async def get_operation(
        operation_id: str,
        request: Request,
        identity: ControlPlaneIdentity = Depends(_read_identity),
    ) -> OperationStatusModel:
        status = control_plane.get_operation(operation_id)
        if status is None:
            raise HTTPException(status_code=404, detail=f"Unknown operation: {operation_id}")
        control_plane.record_audit(
            action="get_operation",
            identity=identity.identity,
            allowed=True,
            target=str(request.url.path),
            operation_id=operation_id,
        )
        return _operation_status_model(status)

    @app.get("/snapshot", response_model=RuntimeSnapshotEnvelopeModel)
    async def get_snapshot(
        request: Request,
        identity: ControlPlaneIdentity = Depends(_read_identity),
    ) -> RuntimeSnapshotEnvelopeModel:
        control_plane.record_audit(
            action="get_snapshot",
            identity=identity.identity,
            allowed=True,
            target=str(request.url.path),
        )
        return _snapshot_model(control_plane.get_snapshot())

    @app.post("/workflows/{workflow_address}/cancel", response_model=OperationReceiptModel)
    async def cancel_workflow(
        workflow_address: str,
        request: Request,
        cancellation: WorkflowCancellationRequestModel | None = None,
        identity: ControlPlaneIdentity = Depends(_mutating_identity),
    ) -> OperationReceiptModel:
        payload = cancellation or WorkflowCancellationRequestModel()
        try:
            receipt = control_plane.cancel_workflow(
                workflow_address,
                run_id=payload.run_id,
                reason=payload.reason,
                idempotency_key=request.headers.get("idempotency-key", ""),
                request_fingerprint=_request_fingerprint(
                    request,
                    getattr(request.state, "raw_body", b""),
                ),
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        control_plane.record_audit(
            action="cancel_workflow",
            identity=identity.identity,
            allowed=True,
            target=str(request.url.path),
            operation_id=receipt.operation_id,
        )
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

    @app.post("/workflows/reconcile-timeouts", response_model=OperationReceiptModel)
    async def reconcile_timeouts(
        request: Request,
        identity: ControlPlaneIdentity = Depends(_mutating_identity),
    ) -> OperationReceiptModel:
        try:
            receipt = control_plane.reconcile_workflow_timeouts(
                idempotency_key=request.headers.get("idempotency-key", ""),
                request_fingerprint=_request_fingerprint(
                    request,
                    getattr(request.state, "raw_body", b""),
                ),
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        control_plane.record_audit(
            action="reconcile_workflow_timeouts",
            identity=identity.identity,
            allowed=True,
            target=str(request.url.path),
            operation_id=receipt.operation_id,
        )
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

    return app
