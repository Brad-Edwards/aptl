"""APTL ACES orchestration adapter.

Promotes APTL's ACES backend from ``provisioning-only`` to
``orchestration-capable`` (SCN-010 follow-on #311). APTL's scenario runtime
engine (RTE-001) already drives scenario steps with state-machine semantics;
this adapter exposes that drive surface through the *portable* ACES contracts
``workflow-result-envelope-v1`` and ``workflow-history-event-stream-v1`` rather
than APTL-native run-archive shapes.

The adapter is the ACES ``Orchestrator`` component published on APTL's
``RuntimeTarget``. ``start()`` loads an ACES ``OrchestrationPlan`` into runtime
state: it registers every orchestration resource as an ACES ``SnapshotEntry``
and, for each workflow, records a truthful ``WorkflowExecutionState`` — the run
is ``PENDING`` (registered and awaiting execution) with every observable step in
the ``pending`` lifecycle and no history events, because no step has executed
yet. The step lifecycle is *not* fabricated: the adapter never reports a
workflow as ``RUNNING``/``SUCCEEDED`` or invents step outcomes. Step execution
and lifecycle progression are driven out-of-band by RTE-001 and the in-range
agents; when that execution-state integration lands (tracked by #514), the same
``results()`` / ``history()`` surface will report the real ``RUNNING`` →
terminal transitions and ``WorkflowHistoryEvent`` streams. ``stop()`` clears
orchestration state.

This keeps the orchestration-capable claim honest: APTL publishes the workflow
result/history *contract* surface and the loaded/registered run state, not a
synthetic in-memory run that never progresses. The ACES
``WorkflowExecutionState`` / ``WorkflowHistoryEvent`` dataclasses are the public
DTOs — APTL's internal ``aptl.core.runtime`` and run-archive models are never
the published workflow schema. Workflow interpretation is workflow-address
driven; nothing here hardcodes TechVault, a profile, a compose profile, or a
workflow address.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4

from aces_contracts.diagnostics import Diagnostic, Severity
from aces_contracts.planning import ChangeAction, OrchestrationPlan, RuntimeDomain
from aces_contracts.runtime_state import ApplyResult, RuntimeSnapshot, SnapshotEntry
from aces_contracts.workflow import (
    WorkflowExecutionState,
    WorkflowResultContract,
    WorkflowStatus,
    WorkflowStepExecutionState,
    WorkflowStepLifecycle,
)

from aptl.utils.redaction import redact

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
    results: dict[str, dict[str, object]],
) -> list[Diagnostic]:
    """Record the truthful initial (``PENDING``) portable state for a run.

    The workflow is registered with every observable step in the ``pending``
    lifecycle and no history events. Nothing is reported as executing,
    succeeding, or failing — RTE-001 drives those transitions out-of-band and
    reporting them is wired by #514.
    """
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
        result_contract = WorkflowResultContract.from_mapping(result_contract_payload)
    except (TypeError, ValueError) as exc:
        return [
            _orchestration_diagnostic(
                "aptl.orchestrator.workflow-contract-invalid",
                workflow_address,
                f"ACES workflow result_contract is invalid: {exc}",
            )
        ]

    steps = {
        step_name: WorkflowStepExecutionState(lifecycle=WorkflowStepLifecycle.PENDING)
        for step_name in result_contract.observable_steps
    }
    # The ACES contract requires a non-empty started_at; it marks when the run
    # *record* was created. The PENDING status (not RUNNING) is what truthfully
    # says no step has executed yet.
    state = WorkflowExecutionState(
        state_schema_version=result_contract.state_schema_version,
        workflow_status=WorkflowStatus.PENDING,
        run_id=uuid4().hex,
        started_at=registered_at,
        updated_at=registered_at,
        steps=steps,
    )
    results[workflow_address] = state.to_payload()
    return []


@dataclass
class AptlOrchestrator(object):
    """``orchestration-capable`` ACES backend adapter for APTL."""

    # Last observed portable orchestration state, keyed by workflow address.
    # Holds the ACES contract payloads so the no-argument ``results()`` /
    # ``history()`` / ``status()` observation methods report the runtime state
    # produced by the most recent ``start()``.
    _results: dict[str, dict[str, object]] = field(default_factory=dict, init=False)
    _history: dict[str, list[dict[str, object]]] = field(default_factory=dict, init=False)

    def start(self, plan: object, snapshot: object) -> ApplyResult:
        """Load an ACES orchestration plan and register its workflows.

        Each workflow is recorded as a ``PENDING`` run (registered, awaiting
        execution); no step lifecycle or history is fabricated. Returns the
        snapshot extended with the orchestration entries and result payloads.
        """
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
        results = dict(working_snapshot.orchestration_results)
        history = {address: list(events) for address, events in working_snapshot.orchestration_history.items()}
        diagnostics: list[Diagnostic] = []
        changed: list[str] = []
        registered_at = _utc_now()

        for op in plan.actionable_operations:
            if op.action == ChangeAction.DELETE:
                entries.pop(op.address, None)
                results.pop(op.address, None)
                history.pop(op.address, None)
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
                workflow_diagnostics = _register_workflow(op.address, op.payload, registered_at, results)
                diagnostics.extend(workflow_diagnostics)

        if diagnostics:
            return ApplyResult(
                success=False,
                snapshot=working_snapshot,
                diagnostics=diagnostics,
            )

        self._results = {address: dict(result) for address, result in results.items()}
        self._history = {address: [dict(event) for event in events] for address, events in history.items()}
        return ApplyResult(
            success=True,
            snapshot=working_snapshot.with_entries(
                entries,
                orchestration_results=results,
                orchestration_history=history,
            ),
            changed_addresses=changed,
        )

    def status(self) -> dict[str, object]:
        """Return current orchestration status (registered, pending-execution runs)."""
        return {
            "backend": "aptl",
            "registered_workflows": sorted(self._results),
        }

    def results(self) -> dict[str, dict[str, object]]:
        """Return the most recent workflow execution state envelopes."""
        return {address: dict(result) for address, result in self._results.items()}

    def history(self) -> dict[str, list[dict[str, object]]]:
        """Return the workflow execution history event streams."""
        return {address: [dict(event) for event in events] for address, events in self._history.items()}

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
        return ApplyResult(
            success=True,
            snapshot=working_snapshot.with_entries(
                retained_entries,
                orchestration_results={},
                orchestration_history={},
            ),
            changed_addresses=changed,
        )
