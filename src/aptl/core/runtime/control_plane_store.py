"""Durable storage for the per-target runtime control plane."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from aptl.core.runtime.models import (
    Diagnostic,
    OperationReceipt,
    OperationState,
    OperationStatus,
    RuntimeDomain,
    RuntimeSnapshot,
    RuntimeSnapshotEnvelope,
    Severity,
    SnapshotEntry,
)


@dataclass(frozen=True)
class AuditEvent:
    """Append-only security and control-plane audit event."""

    timestamp: str
    action: str
    identity: str
    allowed: bool
    target: str
    operation_id: str = ""
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ControlPlaneOperationRecord:
    """Persisted receipt/status pair for one operation."""

    receipt: OperationReceipt
    status: OperationStatus
    request_fingerprint: str = ""
    idempotency_key: str = ""


class ControlPlaneStore(Protocol):
    """Durable persistence for control-plane state."""

    def load_snapshot(self) -> RuntimeSnapshot: ...

    def save_snapshot(self, snapshot: RuntimeSnapshot) -> None: ...

    def load_records(self) -> dict[str, ControlPlaneOperationRecord]: ...

    def save_record(self, record: ControlPlaneOperationRecord) -> None: ...

    def find_by_idempotency(
        self,
        key: str,
    ) -> ControlPlaneOperationRecord | None: ...

    def append_audit(self, event: AuditEvent) -> None: ...

    def read_audit(self) -> list[AuditEvent]: ...


def _snapshot_payload(snapshot: RuntimeSnapshot) -> dict[str, Any]:
    return {
        "schema_version": RuntimeSnapshotEnvelope().schema_version,
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
        "orchestration_history": {
            address: list(events)
            for address, events in snapshot.orchestration_history.items()
        },
        "evaluation_results": dict(snapshot.evaluation_results),
        "evaluation_history": {
            address: list(events)
            for address, events in snapshot.evaluation_history.items()
        },
        "metadata": dict(snapshot.metadata),
    }


def _snapshot_from_payload(payload: dict[str, Any]) -> RuntimeSnapshot:
    entries_payload = payload.get("entries", {})
    entries = {
        address: SnapshotEntry(
            address=str(entry.get("address", address)),
            domain=RuntimeDomain(str(entry.get("domain", "provisioning"))),
            resource_type=str(entry.get("resource_type", "")),
            payload=dict(entry.get("payload", {})),
            ordering_dependencies=tuple(entry.get("ordering_dependencies", ())),
            refresh_dependencies=tuple(entry.get("refresh_dependencies", ())),
            status=str(entry.get("status", "ready")),
        )
        for address, entry in entries_payload.items()
        if isinstance(entry, dict)
    }
    return RuntimeSnapshot(
        entries=entries,
        orchestration_results=dict(payload.get("orchestration_results", {})),
        orchestration_history={
            address: list(events)
            for address, events in payload.get("orchestration_history", {}).items()
        },
        evaluation_results=dict(payload.get("evaluation_results", {})),
        evaluation_history={
            address: list(events)
            for address, events in payload.get("evaluation_history", {}).items()
        },
        metadata=dict(payload.get("metadata", {})),
    )


def _diagnostics_payload(diagnostics: list[Diagnostic]) -> list[dict[str, Any]]:
    return [
        {
            "code": diagnostic.code,
            "domain": diagnostic.domain,
            "address": diagnostic.address,
            "message": diagnostic.message,
            "severity": diagnostic.severity.value,
        }
        for diagnostic in diagnostics
    ]


def _diagnostics_from_payload(payload: list[dict[str, Any]]) -> list[Diagnostic]:
    return [
        Diagnostic(
            code=str(item.get("code", "runtime.control-plane")),
            domain=str(item.get("domain", "runtime")),
            address=str(item.get("address", "runtime.control-plane")),
            message=str(item.get("message", "")),
            severity=Severity(str(item.get("severity", "error"))),
        )
        for item in payload
    ]


def _record_payload(record: ControlPlaneOperationRecord) -> dict[str, Any]:
    return {
        "receipt": {
            "schema_version": record.receipt.schema_version,
            "operation_id": record.receipt.operation_id,
            "domain": record.receipt.domain.value,
            "submitted_at": record.receipt.submitted_at,
            "accepted": record.receipt.accepted,
            "diagnostics": _diagnostics_payload(record.receipt.diagnostics),
        },
        "status": {
            "schema_version": record.status.schema_version,
            "operation_id": record.status.operation_id,
            "domain": record.status.domain.value,
            "state": record.status.state.value,
            "submitted_at": record.status.submitted_at,
            "updated_at": record.status.updated_at,
            "diagnostics": _diagnostics_payload(record.status.diagnostics),
            "changed_addresses": list(record.status.changed_addresses),
        },
        "request_fingerprint": record.request_fingerprint,
        "idempotency_key": record.idempotency_key,
    }


def _record_from_payload(payload: dict[str, Any]) -> ControlPlaneOperationRecord:
    receipt_payload = dict(payload.get("receipt", {}))
    status_payload = dict(payload.get("status", {}))
    receipt = OperationReceipt(
        schema_version=str(receipt_payload.get("schema_version", "runtime-operation/v1")),
        operation_id=str(receipt_payload.get("operation_id", "")),
        domain=RuntimeDomain(str(receipt_payload.get("domain", "provisioning"))),
        submitted_at=str(receipt_payload.get("submitted_at", "")),
        accepted=bool(receipt_payload.get("accepted", False)),
        diagnostics=_diagnostics_from_payload(list(receipt_payload.get("diagnostics", []))),
    )
    status = OperationStatus(
        schema_version=str(status_payload.get("schema_version", "runtime-operation/v1")),
        operation_id=str(status_payload.get("operation_id", "")),
        domain=RuntimeDomain(str(status_payload.get("domain", "provisioning"))),
        state=OperationState(str(status_payload.get("state", "accepted"))),
        submitted_at=str(status_payload.get("submitted_at", "")),
        updated_at=str(status_payload.get("updated_at", "")),
        diagnostics=_diagnostics_from_payload(list(status_payload.get("diagnostics", []))),
        changed_addresses=list(status_payload.get("changed_addresses", [])),
    )
    return ControlPlaneOperationRecord(
        receipt=receipt,
        status=status,
        request_fingerprint=str(payload.get("request_fingerprint", "")),
        idempotency_key=str(payload.get("idempotency_key", "")),
    )


class InMemoryControlPlaneStore:
    """Simple in-memory store."""

    def __init__(self, snapshot: RuntimeSnapshot | None = None) -> None:
        self._snapshot = snapshot if snapshot is not None else RuntimeSnapshot()
        self._records: dict[str, ControlPlaneOperationRecord] = {}
        self._idempotency: dict[str, str] = {}
        self._audit: list[AuditEvent] = []

    def load_snapshot(self) -> RuntimeSnapshot:
        return self._snapshot

    def save_snapshot(self, snapshot: RuntimeSnapshot) -> None:
        self._snapshot = snapshot

    def load_records(self) -> dict[str, ControlPlaneOperationRecord]:
        return dict(self._records)

    def save_record(self, record: ControlPlaneOperationRecord) -> None:
        self._records[record.receipt.operation_id] = record
        if record.idempotency_key:
            self._idempotency[record.idempotency_key] = record.receipt.operation_id

    def find_by_idempotency(
        self,
        key: str,
    ) -> ControlPlaneOperationRecord | None:
        operation_id = self._idempotency.get(key)
        if operation_id is None:
            return None
        return self._records.get(operation_id)

    def append_audit(self, event: AuditEvent) -> None:
        self._audit.append(event)

    def read_audit(self) -> list[AuditEvent]:
        return list(self._audit)


class LocalControlPlaneStore:
    """Filesystem-backed control-plane durability."""

    def __init__(self, base_dir: Path) -> None:
        self._base_dir = base_dir
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._snapshot_path = self._base_dir / "snapshot.json"
        self._operations_path = self._base_dir / "operations.json"
        self._audit_path = self._base_dir / "audit.jsonl"

    def load_snapshot(self) -> RuntimeSnapshot:
        if not self._snapshot_path.exists():
            return RuntimeSnapshot()
        payload = json.loads(self._snapshot_path.read_text(encoding="utf-8"))
        return _snapshot_from_payload(payload)

    def save_snapshot(self, snapshot: RuntimeSnapshot) -> None:
        self._snapshot_path.write_text(
            json.dumps(_snapshot_payload(snapshot), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def load_records(self) -> dict[str, ControlPlaneOperationRecord]:
        if not self._operations_path.exists():
            return {}
        payload = json.loads(self._operations_path.read_text(encoding="utf-8"))
        return {
            operation_id: _record_from_payload(record_payload)
            for operation_id, record_payload in payload.items()
            if isinstance(record_payload, dict)
        }

    def save_record(self, record: ControlPlaneOperationRecord) -> None:
        records = self.load_records()
        records[record.receipt.operation_id] = record
        payload = {
            operation_id: _record_payload(operation_record)
            for operation_id, operation_record in records.items()
        }
        self._operations_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def find_by_idempotency(
        self,
        key: str,
    ) -> ControlPlaneOperationRecord | None:
        for record in self.load_records().values():
            if record.idempotency_key == key:
                return record
        return None

    def append_audit(self, event: AuditEvent) -> None:
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self._audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(event), sort_keys=True) + "\n")

    def read_audit(self) -> list[AuditEvent]:
        if not self._audit_path.exists():
            return []
        events: list[AuditEvent] = []
        for line in self._audit_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            events.append(
                AuditEvent(
                    timestamp=str(payload.get("timestamp", "")),
                    action=str(payload.get("action", "")),
                    identity=str(payload.get("identity", "")),
                    allowed=bool(payload.get("allowed", False)),
                    target=str(payload.get("target", "")),
                    operation_id=str(payload.get("operation_id", "")),
                    reason=str(payload.get("reason", "")),
                    details=dict(payload.get("details", {})),
                )
            )
        return events
