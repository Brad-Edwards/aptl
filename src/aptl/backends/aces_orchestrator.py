"""APTL ACES orchestration adapter.

APTL's full remote-control-plane backend includes this orchestration component
for the workflow surface first introduced by SCN-010 follow-on #311. APTL's
scenario runtime engine (RTE-001) drives scenario steps with state-machine
semantics; this adapter exposes that drive surface through the *portable* ACES
contracts ``workflow-result-envelope-v1`` and
``workflow-history-event-stream-v1`` rather than APTL-native run-archive shapes.

The adapter is the ACES ``Orchestrator`` component published on APTL's
``RuntimeTarget``. ``start()`` loads an ACES ``OrchestrationPlan`` into runtime
state: it registers every orchestration resource as an ACES ``SnapshotEntry``
and, for each workflow, records a truthful ``WorkflowExecutionState`` — the run
is ``PENDING`` (registered and awaiting execution) with every observable step in
the ``pending`` lifecycle and no history events, because no step has executed
yet. ``drive_workflows()`` advances registered runs through RTE-001 using
compiled workflow metadata and portable evaluation outcomes, producing real
``RUNNING`` → terminal transitions and ``WorkflowHistoryEvent`` streams.
``stop()`` clears orchestration state.

The ACES ``WorkflowExecutionState`` / ``WorkflowHistoryEvent`` dataclasses are
the public DTOs — APTL's internal ``aptl.core.runtime`` and run-archive models
are never the published workflow schema. Workflow interpretation is workflow-address
driven; nothing here hardcodes TechVault, a profile, a compose profile, or a
workflow address.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from aces_contracts.diagnostics import Diagnostic, Severity
from aces_contracts.planning import ChangeAction, OrchestrationPlan, RuntimeDomain
from aces_contracts.runtime_state import ApplyResult, RuntimeSnapshot, SnapshotEntry
from aces_contracts.workflow import (
    WorkflowExecutionState,
    WorkflowResultContract,
    WorkflowStatus,
    WorkflowStepOutcome,
)

from aptl.core.runtime.workflow_engine import WorkflowEngine
from aptl.utils.redaction import redact

if TYPE_CHECKING:
    from aptl.core.runstore import RunStorageBackend

ORCHESTRATION_ADDRESS = "runtime.apply.orchestration"
_WORKFLOW_RESOURCE_TYPE = "workflow"


def _orchestration_diagnostic(code: str, address: str, message: str) -> Diagnostic:
    """Build a redacted orchestration-domain ACES error diagnostic."""
    return Diagnostic(
        code=code,
        domain=RuntimeDomain.ORCHESTRATION.value,
        address=address,
        message=redact(message),
        severity=Severity.ERROR,
    )


def _utc_now() -> str:
    """Return the current UTC instant as an ISO-8601 ``...Z`` string."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _register_workflow(
    workflow_address: str,
    payload: dict[str, object],
    registered_at: str,
    engine: WorkflowEngine,
) -> list[Diagnostic]:
    """Record the truthful initial (``PENDING``) portable state for a run."""
    result_contract_payload = payload.get("result_contract")
    if not isinstance(result_contract_payload, dict):
        return [
            _orchestration_diagnostic(
                "aptl.orchestrator.workflow-contract-missing",
                workflow_address,
                "ACES workflow resource is missing its compiled result_contract.",
            )
        ]
    try:
        WorkflowResultContract.from_mapping(result_contract_payload)
    except (TypeError, ValueError) as exc:
        return [
            _orchestration_diagnostic(
                "aptl.orchestrator.workflow-contract-invalid",
                workflow_address,
                f"ACES workflow result_contract is invalid: {exc}",
            )
        ]

    engine.register_pending(workflow_address, payload, registered_at)
    return []


def _objective_outcomes_from_evaluation(
    evaluation_results: dict[str, dict[str, object]],
) -> dict[str, WorkflowStepOutcome]:
    """Map portable evaluation envelopes to workflow objective outcomes when present."""
    outcomes: dict[str, WorkflowStepOutcome] = {}
    for address, payload in evaluation_results.items():
        if not isinstance(payload, dict):
            continue
        raw_outcome = payload.get("outcome")
        if raw_outcome == "succeeded":
            outcomes[address] = WorkflowStepOutcome.SUCCEEDED
        elif raw_outcome == "failed":
            outcomes[address] = WorkflowStepOutcome.FAILED
        elif raw_outcome == "exhausted":
            outcomes[address] = WorkflowStepOutcome.EXHAUSTED
    return outcomes


@dataclass
class AptlOrchestrator(object):
    """Orchestration component of APTL's ``full-remote-control-plane`` target."""

    _engine: WorkflowEngine = field(default_factory=WorkflowEngine, init=False)
    _workflow_payloads: dict[str, dict[str, object]] = field(default_factory=dict, init=False)
    _results: dict[str, dict[str, object]] = field(default_factory=dict, init=False)
    _history: dict[str, list[dict[str, object]]] = field(default_factory=dict, init=False)

    def start(self, plan: object, snapshot: object) -> ApplyResult:
        """Load an ACES orchestration plan and register its workflows."""
        working_snapshot = snapshot if isinstance(snapshot, RuntimeSnapshot) else RuntimeSnapshot()
        if not isinstance(plan, OrchestrationPlan):
            return ApplyResult(
                success=False,
                snapshot=working_snapshot,
                diagnostics=[
                    _orchestration_diagnostic(
                        "aptl.orchestrator.invalid-plan",
                        ORCHESTRATION_ADDRESS,
                        "APTL orchestrator expected an ACES OrchestrationPlan.",
                    )
                ],
            )

        entries = dict(working_snapshot.entries)
        diagnostics: list[Diagnostic] = []
        changed: list[str] = []
        registered_at = _utc_now()
        self._workflow_payloads = {}

        for op in plan.actionable_operations:
            if op.action == ChangeAction.DELETE:
                entries.pop(op.address, None)
                self._workflow_payloads.pop(op.address, None)
                self._engine.discard(op.address)
                changed.append(op.address)
                continue
            entries[op.address] = SnapshotEntry(
                address=op.address,
                domain=RuntimeDomain.ORCHESTRATION,
                resource_type=op.resource_type,
                payload=op.payload,
                ordering_dependencies=op.ordering_dependencies,
                refresh_dependencies=op.refresh_dependencies,
                status="ready",
            )
            changed.append(op.address)
            if op.resource_type == _WORKFLOW_RESOURCE_TYPE:
                if isinstance(op.payload, dict):
                    self._workflow_payloads[op.address] = dict(op.payload)
                workflow_diagnostics = _register_workflow(
                    op.address,
                    op.payload,
                    registered_at,
                    self._engine,
                )
                diagnostics.extend(workflow_diagnostics)

        if diagnostics:
            return ApplyResult(
                success=False,
                snapshot=working_snapshot,
                diagnostics=diagnostics,
            )

        self._sync_from_engine()
        return ApplyResult(
            success=True,
            snapshot=working_snapshot.with_entries(
                entries,
                orchestration_results=self._results,
                orchestration_history=self._history,
            ),
            changed_addresses=changed,
        )

    def drive_workflows(
        self,
        *,
        evaluation_results: dict[str, dict[str, object]] | None = None,
        objective_outcomes: dict[str, WorkflowStepOutcome] | None = None,
        run_store: RunStorageBackend | None = None,
        run_id: str | None = None,
    ) -> list[Diagnostic]:
        """Advance registered workflows through RTE-001 execution."""
        resolved_outcomes = dict(objective_outcomes or {})
        resolved_outcomes.update(
            _objective_outcomes_from_evaluation(evaluation_results or {})
        )
        diagnostics: list[Diagnostic] = []
        for address, payload in self._workflow_payloads.items():
            current = self._engine.get(address)
            if current is None:
                continue
            state = WorkflowExecutionState.from_payload(current.result)
            if state.workflow_status != WorkflowStatus.PENDING:
                continue
            try:
                self._engine.drive(address, payload, objective_outcomes=resolved_outcomes)
            except ValueError as exc:
                diagnostics.append(
                    _orchestration_diagnostic(
                        "aptl.orchestrator.workflow-drive-failed",
                        address,
                        str(exc),
                    )
                )
                continue
            if run_store is not None and run_id is not None:
                record = self._engine.get(address)
                if record is not None:
                    _persist_workflow_run(run_store, run_id, address, record)

        self._sync_from_engine()
        return diagnostics

    def status(self) -> dict[str, object]:
        """Return current orchestration status."""
        return {
            "backend": "aptl",
            "registered_workflows": sorted(self._results),
        }

    def results(self) -> dict[str, dict[str, object]]:
        """Return the most recent workflow execution state envelopes."""
        return {address: dict(result) for address, result in self._results.items()}

    def history(self) -> dict[str, list[dict[str, object]]]:
        """Return the workflow execution history event streams."""
        return {
            address: [dict(event) for event in events]
            for address, events in self._history.items()
        }

    def stop(self, snapshot: object) -> ApplyResult:
        """Stop orchestration and clear orchestration state."""
        working_snapshot = snapshot if isinstance(snapshot, RuntimeSnapshot) else RuntimeSnapshot()
        retained_entries = {
            address: entry
            for address, entry in working_snapshot.entries.items()
            if entry.domain != RuntimeDomain.ORCHESTRATION
        }
        changed = sorted(set(working_snapshot.entries) - set(retained_entries))
        self._results = {}
        self._history = {}
        self._workflow_payloads = {}
        self._engine = WorkflowEngine()
        return ApplyResult(
            success=True,
            snapshot=working_snapshot.with_entries(
                retained_entries,
                orchestration_results={},
                orchestration_history={},
            ),
            changed_addresses=changed,
        )

    def _sync_from_engine(self) -> None:
        results, history = self._engine.export()
        self._results = results
        self._history = history


def _persist_workflow_run(
    run_store: RunStorageBackend,
    run_id: str,
    workflow_address: str,
    record: object,
) -> None:
    """Write workflow result and history artifacts into the run archive."""
    from aptl.core.runtime.workflow_engine import WorkflowRunRecord

    if not isinstance(record, WorkflowRunRecord):
        return
    safe_address = workflow_address.replace("/", "_")
    run_store.write_json(
        run_id,
        f"orchestration/{safe_address}/result.json",
        record.result,
    )
    for event in record.history:
        run_store.append_jsonl(
            run_id,
            f"orchestration/{safe_address}/history.jsonl",
            event,
        )
