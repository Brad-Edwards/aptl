"""APTL ACES evaluation adapter.

APTL's full remote-control-plane backend includes this evaluation component for
the objective/condition surface introduced by SCN-010 follow-on #312. APTL's
scenario runtime engine (RTE-001) already evaluates conditions and objectives;
this adapter exposes that surface through the *portable* ACES contracts
``evaluation-result-envelope-v1`` and ``evaluation-history-event-stream-v1``
rather than APTL-native scoring shapes.

The adapter is the ACES ``Evaluator`` component published on APTL's
``RuntimeTarget``. ``start()`` loads an ACES ``EvaluationPlan`` into runtime
state: it registers every evaluation resource as an ACES ``SnapshotEntry`` and,
for each observable evaluation resource, records a truthful
``EvaluationExecutionState`` — the run is ``PENDING`` (registered and awaiting
execution) with a single ``evaluation_started`` history event, because no
objective or condition outcome has been observed yet. The adapter never reports
``READY``/``FAILED`` outcomes or invents scores. Outcome progression is driven
out-of-band by RTE-001; when that execution-state integration lands (tracked
by #514), the same ``results()`` / ``history()`` surface will report the real
``RUNNING`` → terminal transitions and ``EvaluationHistoryEvent`` streams.
``stop()`` clears evaluation state.

This keeps the full remote-control-plane evaluation claim honest: APTL
publishes the evaluation result/history *contract* surface and the
loaded/registered run state, not a synthetic in-memory result that never
progresses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4

from aces_contracts.diagnostics import Diagnostic, Severity
from aces_contracts.evaluation import (
    EvaluationExecutionState,
    EvaluationHistoryEvent,
    EvaluationHistoryEventType,
    EvaluationResultContract,
    EvaluationResultStatus,
)
from aces_contracts.planning import ChangeAction, EvaluationPlan, RuntimeDomain
from aces_contracts.runtime_state import ApplyResult, RuntimeSnapshot, SnapshotEntry

from aptl.utils.redaction import redact

EVALUATION_ADDRESS = "runtime.apply.evaluation"
_OBSERVABLE_RESOURCE_TYPES = frozenset(
    {"condition-binding", "evaluation", "goal", "metric", "objective", "tlo"}
)


def _evaluation_diagnostic(code: str, address: str, message: str) -> Diagnostic:
    """Build a redacted evaluation-domain ACES error diagnostic."""
    return Diagnostic(
        code=code,
        domain=RuntimeDomain.EVALUATION.value,
        address=address,
        message=redact(message),
        severity=Severity.ERROR,
    )


def _utc_now() -> str:
    """Return the current UTC instant as an ISO-8601 ``...Z`` string."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _register_evaluation(
    evaluation_address: str,
    payload: dict[str, object],
    registered_at: str,
    results: dict[str, dict[str, object]],
    history: dict[str, list[dict[str, object]]],
) -> list[Diagnostic]:
    """Record the truthful initial (``PENDING``) portable state for a run."""
    result_contract_payload = payload.get("result_contract")
    if not isinstance(result_contract_payload, dict):
        return [
            _evaluation_diagnostic(
                "aptl.evaluator.evaluation-contract-missing",
                evaluation_address,
                "ACES evaluation resource is missing its compiled result_contract.",
            )
        ]
    try:
        result_contract = EvaluationResultContract.from_mapping(result_contract_payload)
    except (TypeError, ValueError) as exc:
        return [
            _evaluation_diagnostic(
                "aptl.evaluator.evaluation-contract-invalid",
                evaluation_address,
                f"ACES evaluation result_contract is invalid: {exc}",
            )
        ]

    state = EvaluationExecutionState(
        state_schema_version=result_contract.state_schema_version,
        resource_type=result_contract.resource_type,
        run_id=uuid4().hex,
        status=EvaluationResultStatus.PENDING,
        observed_at=registered_at,
        updated_at=registered_at,
    )
    results[evaluation_address] = state.to_payload()
    history[evaluation_address] = [
        EvaluationHistoryEvent(
            event_type=EvaluationHistoryEventType.EVALUATION_STARTED,
            timestamp=registered_at,
            status=EvaluationResultStatus.PENDING,
        ).to_payload()
    ]
    return []


@dataclass
class AptlEvaluator(object):
    """ACES evaluation adapter for APTL's full remote-control-plane target."""

    _results: dict[str, dict[str, object]] = field(default_factory=dict, init=False)
    _history: dict[str, list[dict[str, object]]] = field(default_factory=dict, init=False)

    def start(self, plan: object, snapshot: object) -> ApplyResult:
        """Load an ACES evaluation plan and register its observable resources."""
        working_snapshot = snapshot if isinstance(snapshot, RuntimeSnapshot) else RuntimeSnapshot()
        if not isinstance(plan, EvaluationPlan):
            return ApplyResult(
                success=False,
                snapshot=working_snapshot,
                diagnostics=[
                    _evaluation_diagnostic(
                        "aptl.evaluator.invalid-plan",
                        EVALUATION_ADDRESS,
                        "APTL evaluator expected an ACES EvaluationPlan.",
                    )
                ],
            )

        entries = dict(working_snapshot.entries)
        results = dict(working_snapshot.evaluation_results)
        history = {
            address: list(events)
            for address, events in working_snapshot.evaluation_history.items()
        }
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
                domain=RuntimeDomain.EVALUATION,
                resource_type=op.resource_type,
                payload=op.payload,
                ordering_dependencies=op.ordering_dependencies,
                refresh_dependencies=op.refresh_dependencies,
                status="ready",
            )
            changed.append(op.address)
            if op.resource_type in _OBSERVABLE_RESOURCE_TYPES:
                evaluation_diagnostics = _register_evaluation(
                    op.address,
                    op.payload,
                    registered_at,
                    results,
                    history,
                )
                diagnostics.extend(evaluation_diagnostics)

        if diagnostics:
            return ApplyResult(
                success=False,
                snapshot=working_snapshot,
                diagnostics=diagnostics,
            )

        self._results = {address: dict(result) for address, result in results.items()}
        self._history = {
            address: [dict(event) for event in events] for address, events in history.items()
        }
        return ApplyResult(
            success=True,
            snapshot=working_snapshot.with_entries(
                entries,
                evaluation_results=results,
                evaluation_history=history,
            ),
            changed_addresses=changed,
        )

    def status(self) -> dict[str, object]:
        """Return current evaluation status (registered, pending-execution runs)."""
        return {
            "backend": "aptl",
            "registered_evaluations": sorted(self._results),
        }

    def results(self) -> dict[str, dict[str, object]]:
        """Return the most recent evaluation result envelopes."""
        return {address: dict(result) for address, result in self._results.items()}

    def history(self) -> dict[str, list[dict[str, object]]]:
        """Return the evaluation history event streams."""
        return {
            address: [dict(event) for event in events]
            for address, events in self._history.items()
        }

    def stop(self, snapshot: object) -> ApplyResult:
        """Stop evaluation and clear evaluation state."""
        working_snapshot = snapshot if isinstance(snapshot, RuntimeSnapshot) else RuntimeSnapshot()
        retained_entries = {
            address: entry
            for address, entry in working_snapshot.entries.items()
            if entry.domain != RuntimeDomain.EVALUATION
        }
        changed = sorted(set(working_snapshot.entries) - set(retained_entries))
        self._results = {}
        self._history = {}
        return ApplyResult(
            success=True,
            snapshot=working_snapshot.with_entries(
                retained_entries,
                evaluation_results={},
                evaluation_history={},
            ),
            changed_addresses=changed,
        )
