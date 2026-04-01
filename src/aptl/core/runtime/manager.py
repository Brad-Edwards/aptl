"""Runtime manager for compiled SDL runtime plans."""

from collections import deque
from collections.abc import Iterable

from aptl.core.runtime.compiler import compile_runtime_model
from aptl.core.runtime.models import (
    ApplyResult,
    ChangeAction,
    Diagnostic,
    ExecutionPlan,
    ProvisionOp,
    ProvisioningPlan,
    RuntimeDomain,
    RuntimeSnapshot,
    SnapshotEntry,
)
from aptl.core.runtime.planner import plan
from aptl.core.runtime.registry import RuntimeTarget, _validate_runtime_target_shape
from aptl.core.sdl.scenario import Scenario


def _delete_order(entries: dict[str, SnapshotEntry]) -> list[str]:
    graph: dict[str, list[str]] = {address: [] for address in entries}
    indegree: dict[str, int] = {address: 0 for address in entries}

    for address, entry in entries.items():
        for dependency in entry.ordering_dependencies:
            if dependency not in entries:
                continue
            graph[dependency].append(address)
            indegree[address] += 1

    queue = deque(sorted(address for address, degree in indegree.items() if degree == 0))
    order: list[str] = []
    while queue:
        current = queue.popleft()
        order.append(current)
        for dependent in sorted(graph[current]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                queue.append(dependent)

    if len(order) != len(entries):
        order.extend(sorted(address for address in entries if address not in order))

    return list(reversed(order))


def _has_error_diagnostic(diagnostics: list[Diagnostic]) -> bool:
    return any(diagnostic.is_error for diagnostic in diagnostics)


def _failure_diagnostic(code: str, address: str, message: str) -> Diagnostic:
    return Diagnostic(
        code=code,
        domain="runtime",
        address=address,
        message=message,
    )


def _call_backend_diagnostics(
    method,
    *args,
    address: str,
) -> list[Diagnostic]:
    try:
        result = method(*args)
    except Exception as exc:
        return [
            _failure_diagnostic(
                "runtime.backend-call-failed",
                address,
                (
                    f"Backend method '{address}' raised "
                    f"{type(exc).__name__}: {exc}."
                ),
            )
        ]

    if not isinstance(result, Iterable) or isinstance(result, (str, bytes)):
        return [
            _failure_diagnostic(
                "runtime.backend-contract-invalid",
                address,
                (
                    f"Backend method '{address}' returned "
                    f"{type(result).__name__}; expected diagnostics iterable."
                ),
            )
        ]

    diagnostics = list(result)
    if any(not isinstance(diagnostic, Diagnostic) for diagnostic in diagnostics):
        return [
            _failure_diagnostic(
                "runtime.backend-contract-invalid",
                address,
                (
                    f"Backend method '{address}' returned a diagnostics iterable "
                    "containing non-Diagnostic values."
                ),
            )
        ]

    return diagnostics


def _call_backend_apply(
    method,
    *args,
    address: str,
    snapshot: RuntimeSnapshot,
) -> ApplyResult:
    try:
        result = method(*args)
    except Exception as exc:
        return ApplyResult(
            success=False,
            snapshot=snapshot,
            diagnostics=[
                _failure_diagnostic(
                    "runtime.backend-call-failed",
                    address,
                    (
                        f"Backend method '{address}' raised "
                        f"{type(exc).__name__}: {exc}."
                    ),
                )
            ],
        )

    if not isinstance(result, ApplyResult):
        return ApplyResult(
            success=False,
            snapshot=snapshot,
            diagnostics=[
                _failure_diagnostic(
                    "runtime.backend-contract-invalid",
                    address,
                    (
                        f"Backend method '{address}' returned "
                        f"{type(result).__name__}; expected ApplyResult."
                    ),
                )
            ],
        )

    return result


def _provenance_diagnostics(
    execution_plan: ExecutionPlan,
    target: RuntimeTarget,
    snapshot: RuntimeSnapshot,
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if execution_plan.target_name is None:
        diagnostics.append(
            _failure_diagnostic(
                "runtime.plan-target-unbound",
                "runtime.apply",
                (
                    "Execution plan is not bound to a runtime target. Use "
                    "RuntimeManager.plan() or pass target_name explicitly."
                ),
            )
        )
    elif execution_plan.target_name != target.name:
        diagnostics.append(
            _failure_diagnostic(
                "runtime.plan-target-mismatch",
                "runtime.apply",
                (
                    f"Execution plan targets '{execution_plan.target_name}', "
                    f"but manager target is '{target.name}'."
                ),
            )
        )
    if execution_plan.manifest != target.manifest:
        diagnostics.append(
            _failure_diagnostic(
                "runtime.plan-manifest-mismatch",
                "runtime.apply",
                "Execution plan manifest does not match the manager target manifest.",
            )
        )
    if execution_plan.base_snapshot != snapshot:
        diagnostics.append(
            _failure_diagnostic(
                "runtime.plan-snapshot-mismatch",
                "runtime.apply",
                "Execution plan base snapshot does not match the manager snapshot.",
            )
        )
    return diagnostics


def _maybe_synthesize_failure(
    diagnostics: list[Diagnostic],
    *,
    result: ApplyResult,
    code: str,
    address: str,
    message: str,
) -> None:
    if not result.success and not _has_error_diagnostic(result.diagnostics):
        diagnostics.append(_failure_diagnostic(code, address, message))


def _rollback_services(
    snapshot: RuntimeSnapshot,
    services: list[tuple[str, object]],
) -> ApplyResult:
    working_snapshot = snapshot
    diagnostics: list[Diagnostic] = []
    changed_addresses: list[str] = []
    success = True

    for address, service in services:
        stop_result = _call_backend_apply(
            service.stop,
            working_snapshot,
            address=address,
            snapshot=working_snapshot,
        )
        diagnostics.extend(stop_result.diagnostics)
        changed_addresses.extend(stop_result.changed_addresses)
        working_snapshot = stop_result.snapshot
        if not stop_result.success:
            success = False
            _maybe_synthesize_failure(
                diagnostics,
                result=stop_result,
                code="runtime.apply-rollback-failed",
                address=address,
                message=f"Rollback failed while stopping '{address}'.",
            )

    return ApplyResult(
        success=success,
        snapshot=working_snapshot,
        diagnostics=diagnostics,
        changed_addresses=changed_addresses,
    )


class RuntimeManager:
    """Plans and executes SDL runtime work against a target."""

    def __init__(
        self,
        target: RuntimeTarget,
        *,
        initial_snapshot: RuntimeSnapshot | None = None,
    ) -> None:
        _validate_runtime_target_shape(
            manifest=target.manifest,
            provisioner=target.provisioner,
            orchestrator=target.orchestrator,
            evaluator=target.evaluator,
        )
        self._target = target
        self._snapshot = initial_snapshot if initial_snapshot is not None else RuntimeSnapshot()

    @property
    def snapshot(self) -> RuntimeSnapshot:
        return self._snapshot

    def plan(
        self,
        scenario: Scenario,
        snapshot: RuntimeSnapshot | None = None,
    ) -> ExecutionPlan:
        model = compile_runtime_model(scenario)
        effective_snapshot = snapshot if snapshot is not None else self._snapshot
        return plan(
            model,
            self._target.manifest,
            effective_snapshot,
            target_name=self._target.name,
        )

    def apply(self, execution_plan: ExecutionPlan) -> ApplyResult:
        diagnostics: list[Diagnostic] = list(execution_plan.diagnostics)
        changed_addresses: list[str] = []

        provenance_diagnostics = _provenance_diagnostics(
            execution_plan,
            self._target,
            self._snapshot,
        )
        diagnostics.extend(provenance_diagnostics)
        if provenance_diagnostics:
            return ApplyResult(
                success=False,
                snapshot=self._snapshot,
                diagnostics=diagnostics,
            )

        if not execution_plan.is_valid:
            return ApplyResult(
                success=False,
                snapshot=self._snapshot,
                diagnostics=diagnostics,
            )

        evaluation_needed = bool(execution_plan.evaluation.actionable_operations)
        if evaluation_needed and self._target.evaluator is None:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.apply-missing-evaluator",
                    "runtime.apply.evaluator",
                    "Execution plan requires an evaluator, but the target does not provide one.",
                )
            )
            return ApplyResult(
                success=False,
                snapshot=self._snapshot,
                diagnostics=diagnostics,
            )

        orchestration_needed = bool(execution_plan.orchestration.actionable_operations)
        if orchestration_needed and self._target.orchestrator is None:
            diagnostics.append(
                _failure_diagnostic(
                    "runtime.apply-missing-orchestrator",
                    "runtime.apply.orchestrator",
                    "Execution plan requires an orchestrator, but the target does not provide one.",
                )
            )
            return ApplyResult(
                success=False,
                snapshot=self._snapshot,
                diagnostics=diagnostics,
            )

        validation = _call_backend_diagnostics(
            self._target.provisioner.validate,
            execution_plan.provisioning,
            address="runtime.apply.provisioning.validate",
        )
        diagnostics.extend(validation)
        if _has_error_diagnostic(validation):
            return ApplyResult(
                success=False,
                snapshot=self._snapshot,
                diagnostics=diagnostics,
            )

        working_snapshot = execution_plan.base_snapshot
        provision_result = _call_backend_apply(
            self._target.provisioner.apply,
            execution_plan.provisioning,
            working_snapshot,
            address="runtime.apply.provisioning",
            snapshot=working_snapshot,
        )
        diagnostics.extend(provision_result.diagnostics)
        changed_addresses.extend(provision_result.changed_addresses)
        working_snapshot = provision_result.snapshot
        if not provision_result.success:
            _maybe_synthesize_failure(
                diagnostics,
                result=provision_result,
                code="runtime.apply-phase-failed",
                address="runtime.apply.provisioning",
                message="Provisioning apply failed.",
            )
            self._snapshot = working_snapshot
            return ApplyResult(
                success=False,
                snapshot=self._snapshot,
                diagnostics=diagnostics,
                changed_addresses=changed_addresses,
            )

        started_evaluator = False
        if evaluation_needed and self._target.evaluator is not None:
            evaluation_result = _call_backend_apply(
                self._target.evaluator.start,
                execution_plan.evaluation,
                working_snapshot,
                address="runtime.apply.evaluator",
                snapshot=working_snapshot,
            )
            diagnostics.extend(evaluation_result.diagnostics)
            changed_addresses.extend(evaluation_result.changed_addresses)
            working_snapshot = evaluation_result.snapshot
            if evaluation_result.success:
                started_evaluator = True
            else:
                _maybe_synthesize_failure(
                    diagnostics,
                    result=evaluation_result,
                    code="runtime.apply-phase-failed",
                    address="runtime.apply.evaluator",
                    message="Evaluator failed to start.",
                )
                rollback_result = _rollback_services(
                    working_snapshot,
                    [("runtime.rollback.evaluator", self._target.evaluator)],
                )
                diagnostics.extend(rollback_result.diagnostics)
                changed_addresses.extend(rollback_result.changed_addresses)
                working_snapshot = rollback_result.snapshot
                self._snapshot = working_snapshot
                return ApplyResult(
                    success=False,
                    snapshot=self._snapshot,
                    diagnostics=diagnostics,
                    changed_addresses=changed_addresses,
                )

        if orchestration_needed and self._target.orchestrator is not None:
            orchestration_result = _call_backend_apply(
                self._target.orchestrator.start,
                execution_plan.orchestration,
                working_snapshot,
                address="runtime.apply.orchestrator",
                snapshot=working_snapshot,
            )
            diagnostics.extend(orchestration_result.diagnostics)
            changed_addresses.extend(orchestration_result.changed_addresses)
            working_snapshot = orchestration_result.snapshot
            if not orchestration_result.success:
                _maybe_synthesize_failure(
                    diagnostics,
                    result=orchestration_result,
                    code="runtime.apply-phase-failed",
                    address="runtime.apply.orchestrator",
                    message="Orchestrator failed to start.",
                )
                rollback_services = [
                    ("runtime.rollback.orchestrator", self._target.orchestrator),
                ]
                if started_evaluator and self._target.evaluator is not None:
                    rollback_services.append(
                        ("runtime.rollback.evaluator", self._target.evaluator)
                    )
                rollback_result = _rollback_services(working_snapshot, rollback_services)
                diagnostics.extend(rollback_result.diagnostics)
                changed_addresses.extend(rollback_result.changed_addresses)
                working_snapshot = rollback_result.snapshot
                self._snapshot = working_snapshot
                return ApplyResult(
                    success=False,
                    snapshot=self._snapshot,
                    diagnostics=diagnostics,
                    changed_addresses=changed_addresses,
                )

        self._snapshot = working_snapshot
        return ApplyResult(
            success=not _has_error_diagnostic(diagnostics),
            snapshot=self._snapshot,
            diagnostics=diagnostics,
            changed_addresses=changed_addresses,
        )

    def status(self) -> dict[str, object]:
        info: dict[str, object] = {
            "backend": self._target.name,
            "resources": len(self._snapshot.entries),
            "domains": {
                RuntimeDomain.PROVISIONING.value: len(
                    self._snapshot.for_domain(RuntimeDomain.PROVISIONING)
                ),
                RuntimeDomain.ORCHESTRATION.value: len(
                    self._snapshot.for_domain(RuntimeDomain.ORCHESTRATION)
                ),
                RuntimeDomain.EVALUATION.value: len(
                    self._snapshot.for_domain(RuntimeDomain.EVALUATION)
                ),
            },
        }
        if self._target.orchestrator is not None:
            info["orchestrator"] = self._target.orchestrator.status()
        if self._target.evaluator is not None:
            info["evaluator"] = self._target.evaluator.status()
            info["evaluation_results"] = self._target.evaluator.results()
        return info

    def destroy(self) -> ApplyResult:
        diagnostics: list[Diagnostic] = []
        changed_addresses: list[str] = []
        working_snapshot = self._snapshot
        phases_succeeded = True

        if self._target.orchestrator is not None:
            stop_result = _call_backend_apply(
                self._target.orchestrator.stop,
                working_snapshot,
                address="runtime.destroy.orchestrator",
                snapshot=working_snapshot,
            )
            diagnostics.extend(stop_result.diagnostics)
            changed_addresses.extend(stop_result.changed_addresses)
            working_snapshot = stop_result.snapshot
            if not stop_result.success:
                phases_succeeded = False
                _maybe_synthesize_failure(
                    diagnostics,
                    result=stop_result,
                    code="runtime.destroy-phase-failed",
                    address="runtime.destroy.orchestrator",
                    message="Orchestrator stop failed.",
                )

        if self._target.evaluator is not None:
            stop_result = _call_backend_apply(
                self._target.evaluator.stop,
                working_snapshot,
                address="runtime.destroy.evaluator",
                snapshot=working_snapshot,
            )
            diagnostics.extend(stop_result.diagnostics)
            changed_addresses.extend(stop_result.changed_addresses)
            working_snapshot = stop_result.snapshot
            if not stop_result.success:
                phases_succeeded = False
                _maybe_synthesize_failure(
                    diagnostics,
                    result=stop_result,
                    code="runtime.destroy-phase-failed",
                    address="runtime.destroy.evaluator",
                    message="Evaluator stop failed.",
                )

        provisioning_entries = working_snapshot.for_domain(RuntimeDomain.PROVISIONING)
        delete_plan = ProvisioningPlan(
            resources={},
            operations=[
                ProvisionOp(
                    action=ChangeAction.DELETE,
                    address=address,
                    resource_type=provisioning_entries[address].resource_type,
                    payload=provisioning_entries[address].payload,
                    ordering_dependencies=(
                        provisioning_entries[address].ordering_dependencies
                    ),
                    refresh_dependencies=(
                        provisioning_entries[address].refresh_dependencies
                    ),
                )
                for address in _delete_order(provisioning_entries)
            ],
        )
        provision_result = _call_backend_apply(
            self._target.provisioner.apply,
            delete_plan,
            working_snapshot,
            address="runtime.destroy.provisioning",
            snapshot=working_snapshot,
        )
        diagnostics.extend(provision_result.diagnostics)
        changed_addresses.extend(provision_result.changed_addresses)
        working_snapshot = provision_result.snapshot
        if not provision_result.success:
            phases_succeeded = False
            _maybe_synthesize_failure(
                diagnostics,
                result=provision_result,
                code="runtime.destroy-phase-failed",
                address="runtime.destroy.provisioning",
                message="Provisioning destroy failed.",
            )

        self._snapshot = working_snapshot
        return ApplyResult(
            success=phases_succeeded and not _has_error_diagnostic(diagnostics),
            snapshot=self._snapshot,
            diagnostics=diagnostics,
            changed_addresses=changed_addresses,
        )
