"""Runtime manager lifecycle tests."""

from __future__ import annotations

import textwrap

import pytest

from aptl.backends.stubs import create_stub_manifest
from aptl.core.runtime.compiler import compile_runtime_model
from aptl.core.runtime.manager import RuntimeManager
from aptl.core.runtime.models import (
    ApplyResult,
    ChangeAction,
    RuntimeDomain,
    RuntimeSnapshot,
    SnapshotEntry,
)
from aptl.core.runtime.planner import plan
from aptl.core.runtime.registry import RuntimeTarget
from aptl.core.sdl import parse_sdl


def _scenario(yaml_str: str):
    return parse_sdl(textwrap.dedent(yaml_str))


def _apply_ops(
    snapshot: RuntimeSnapshot,
    domain: RuntimeDomain,
    operations,
    *,
    status: str,
) -> RuntimeSnapshot:
    entries = dict(snapshot.entries)
    for op in operations:
        if op.action == ChangeAction.DELETE:
            entries.pop(op.address, None)
            continue
        entries[op.address] = SnapshotEntry(
            address=op.address,
            domain=domain,
            resource_type=op.resource_type,
            payload=op.payload,
            ordering_dependencies=op.ordering_dependencies,
            refresh_dependencies=op.refresh_dependencies,
            status=status,
        )
    return snapshot.with_entries(entries)


def _full_scenario():
    return _scenario("""
name: full
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
    conditions: {health: ops}
    roles: {ops: operator}
conditions:
  health: {command: /bin/true, interval: 15}
metrics:
  uptime: {type: conditional, max-score: 100, condition: health}
events:
  kickoff: {conditions: [health]}
scripts:
  timeline: {start-time: 0, end-time: 60, speed: 1, events: {kickoff: 10}}
stories:
  main: {scripts: [timeline]}
""")


def _provisioning_only_scenario():
    return _scenario("""
name: provisioning-only
nodes:
  vm:
    type: vm
    os: linux
    resources: {ram: 1 gib, cpu: 1}
""")


class RecordingProvisioner:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def validate(self, plan) -> list:
        return []

    def apply(self, plan, snapshot: RuntimeSnapshot) -> ApplyResult:
        label = "provision-delete" if plan.operations and all(
            op.action == ChangeAction.DELETE for op in plan.operations
        ) else "provision-apply"
        self.calls.append(label)
        next_snapshot = _apply_ops(
            snapshot,
            RuntimeDomain.PROVISIONING,
            plan.operations,
            status="applied",
        )
        return ApplyResult(
            success=True,
            snapshot=next_snapshot,
            changed_addresses=[
                op.address for op in plan.operations if op.action != ChangeAction.UNCHANGED
            ],
        )


class FailingProvisioner(RecordingProvisioner):
    def apply(self, plan, snapshot: RuntimeSnapshot) -> ApplyResult:
        self.calls.append("provision-apply")
        next_snapshot = _apply_ops(
            snapshot,
            RuntimeDomain.PROVISIONING,
            plan.operations[:1],
            status="partial",
        )
        return ApplyResult(success=False, snapshot=next_snapshot)


class RecordingOrchestrator:
    def __init__(self, calls: list[str], name: str = "orchestrator") -> None:
        self.calls = calls
        self.name = name
        self.running = False
        self._results: dict[str, dict[str, object]] = {}

    def start(self, plan, snapshot: RuntimeSnapshot) -> ApplyResult:
        self.calls.append(f"{self.name}-start")
        self.running = True
        next_snapshot = _apply_ops(
            snapshot,
            RuntimeDomain.ORCHESTRATION,
            plan.operations,
            status="running",
        )
        self._results = {
            op.address: {"steps": {}, "state-schema-version": "workflow-step-state/v1"}
            for op in plan.operations
            if op.action != ChangeAction.DELETE and op.resource_type == "workflow"
        }
        return ApplyResult(
            success=True,
            snapshot=next_snapshot.with_entries(
                next_snapshot.entries,
                orchestration_results=self._results,
            ),
        )

    def status(self) -> dict:
        return {"running": self.running}

    def results(self) -> dict[str, dict[str, object]]:
        return dict(self._results)

    def stop(self, snapshot: RuntimeSnapshot) -> ApplyResult:
        self.calls.append(f"{self.name}-stop")
        self.running = False
        self._results = {}
        entries = {
            address: entry
            for address, entry in snapshot.entries.items()
            if entry.domain != RuntimeDomain.ORCHESTRATION
        }
        return ApplyResult(
            success=True,
            snapshot=snapshot.with_entries(entries, orchestration_results={}),
        )


class FailingStartOrchestrator(RecordingOrchestrator):
    def start(self, plan, snapshot: RuntimeSnapshot) -> ApplyResult:
        self.calls.append(f"{self.name}-start")
        self.running = True
        next_snapshot = _apply_ops(
            snapshot,
            RuntimeDomain.ORCHESTRATION,
            plan.operations,
            status="partial",
        )
        return ApplyResult(success=False, snapshot=next_snapshot)


class FailingStopOrchestrator(RecordingOrchestrator):
    def stop(self, snapshot: RuntimeSnapshot) -> ApplyResult:
        self.calls.append(f"{self.name}-stop")
        self.running = False
        return ApplyResult(success=False, snapshot=snapshot)


class RecordingEvaluator:
    def __init__(self, calls: list[str], name: str) -> None:
        self.calls = calls
        self.name = name
        self.running = False
        self._results: dict[str, dict[str, object]] = {}

    def start(self, plan, snapshot: RuntimeSnapshot) -> ApplyResult:
        self.calls.append(f"{self.name}-start")
        self.running = True
        next_snapshot = _apply_ops(
            snapshot,
            RuntimeDomain.EVALUATION,
            plan.operations,
            status="running",
        )
        self._results = {
            op.address: {"passed": True}
            for op in plan.operations
            if op.action != ChangeAction.DELETE
        }
        return ApplyResult(
            success=True,
            snapshot=next_snapshot.with_entries(
                next_snapshot.entries,
                evaluation_results=self._results,
            ),
        )

    def status(self) -> dict:
        return {"running": self.running}

    def results(self) -> dict[str, dict[str, object]]:
        return dict(self._results)

    def stop(self, snapshot: RuntimeSnapshot) -> ApplyResult:
        self.calls.append(f"{self.name}-stop")
        self.running = False
        self._results = {}
        entries = {
            address: entry
            for address, entry in snapshot.entries.items()
            if entry.domain != RuntimeDomain.EVALUATION
        }
        return ApplyResult(
            success=True,
            snapshot=snapshot.with_entries(entries, evaluation_results={}),
        )


class FailingStartEvaluator(RecordingEvaluator):
    def start(self, plan, snapshot: RuntimeSnapshot) -> ApplyResult:
        self.calls.append(f"{self.name}-start")
        self.running = True
        next_snapshot = _apply_ops(
            snapshot,
            RuntimeDomain.EVALUATION,
            plan.operations,
            status="partial",
        )
        return ApplyResult(
            success=False,
            snapshot=next_snapshot.with_entries(
                next_snapshot.entries,
                evaluation_results={"partial": {"passed": False}},
            ),
        )


class InvalidValidationProvisioner(RecordingProvisioner):
    def validate(self, plan):
        del plan
        return None


class InvalidApplyProvisioner(RecordingProvisioner):
    def apply(self, plan, snapshot: RuntimeSnapshot):
        del plan, snapshot
        self.calls.append("provision-apply")
        return None


class InvalidApplySnapshotProvisioner(RecordingProvisioner):
    def apply(self, plan, snapshot: RuntimeSnapshot) -> ApplyResult:
        del plan
        self.calls.append("provision-apply")
        return ApplyResult(success=True, snapshot=None)  # type: ignore[arg-type]


class InvalidApplyDiagnosticsProvisioner(RecordingProvisioner):
    def apply(self, plan, snapshot: RuntimeSnapshot) -> ApplyResult:
        del plan
        self.calls.append("provision-apply")
        return ApplyResult(
            success=True,
            snapshot=snapshot,
            diagnostics=[object()],  # type: ignore[list-item]
        )


class InvalidApplyChangedAddressesProvisioner(RecordingProvisioner):
    def apply(self, plan, snapshot: RuntimeSnapshot) -> ApplyResult:
        del plan
        self.calls.append("provision-apply")
        return ApplyResult(
            success=True,
            snapshot=snapshot,
            changed_addresses=["provision.node.vm", 7],  # type: ignore[list-item]
        )


class InvalidApplyDetailsProvisioner(RecordingProvisioner):
    def apply(self, plan, snapshot: RuntimeSnapshot) -> ApplyResult:
        del plan
        self.calls.append("provision-apply")
        return ApplyResult(
            success=True,
            snapshot=snapshot,
            details="broken",  # type: ignore[arg-type]
        )


class RaisingStartOrchestrator(RecordingOrchestrator):
    def start(self, plan, snapshot: RuntimeSnapshot) -> ApplyResult:
        del plan, snapshot
        self.calls.append(f"{self.name}-start")
        raise RuntimeError("boom")


class TestRuntimeManager:
    def test_apply_starts_evaluator_before_orchestrator(self):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner(calls),
            orchestrator=RecordingOrchestrator(calls),
            evaluator=RecordingEvaluator(calls, "evaluator"),
        )
        manager = RuntimeManager(target)

        result = manager.apply(manager.plan(_full_scenario()))

        assert result.success
        assert calls[:3] == ["provision-apply", "evaluator-start", "orchestrator-start"]
        assert "orchestrator" in manager.status()
        assert "evaluator" in manager.status()

    def test_apply_rolls_back_started_services_on_orchestrator_failure(self):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner(calls),
            orchestrator=FailingStartOrchestrator(calls),
            evaluator=RecordingEvaluator(calls, "evaluator"),
        )
        manager = RuntimeManager(target)

        result = manager.apply(manager.plan(_full_scenario()))

        assert not result.success
        assert calls == [
            "provision-apply",
            "evaluator-start",
            "orchestrator-start",
            "orchestrator-stop",
            "evaluator-stop",
        ]
        assert manager.snapshot.for_domain(RuntimeDomain.ORCHESTRATION) == {}
        assert manager.snapshot.for_domain(RuntimeDomain.EVALUATION) == {}
        assert manager.snapshot.for_domain(RuntimeDomain.PROVISIONING)

    def test_evaluator_start_failure_rolls_back_evaluation_state(self):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner(calls),
            orchestrator=RecordingOrchestrator(calls),
            evaluator=FailingStartEvaluator(calls, "evaluator"),
        )
        manager = RuntimeManager(target)

        result = manager.apply(manager.plan(_full_scenario()))

        assert not result.success
        assert calls == ["provision-apply", "evaluator-start", "evaluator-stop"]
        assert manager.snapshot.for_domain(RuntimeDomain.EVALUATION) == {}
        assert manager.snapshot.for_domain(RuntimeDomain.PROVISIONING)

    def test_destroy_stops_orchestrator_then_evaluator_then_deletes(self):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner(calls),
            orchestrator=RecordingOrchestrator(calls),
            evaluator=RecordingEvaluator(calls, "evaluator"),
        )
        manager = RuntimeManager(target)

        manager.apply(manager.plan(_full_scenario()))
        calls.clear()

        result = manager.destroy()

        assert result.success
        assert calls == ["orchestrator-stop", "evaluator-stop", "provision-delete"]
        assert manager.snapshot.entries == {}

    def test_destroy_fails_if_stop_phase_fails(self):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner(calls),
            orchestrator=FailingStopOrchestrator(calls),
            evaluator=RecordingEvaluator(calls, "evaluator"),
        )
        manager = RuntimeManager(target)

        manager.apply(manager.plan(_full_scenario()))
        calls.clear()

        result = manager.destroy()

        assert not result.success
        assert "runtime.destroy-phase-failed" in {diag.code for diag in result.diagnostics}
        assert calls == ["orchestrator-stop", "evaluator-stop", "provision-delete"]

    def test_provisioning_failure_preserves_provisioner_snapshot_and_skips_runtime_start(self):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=FailingProvisioner(calls),
            orchestrator=RecordingOrchestrator(calls),
            evaluator=RecordingEvaluator(calls, "evaluator"),
        )
        manager = RuntimeManager(target)

        result = manager.apply(manager.plan(_full_scenario()))

        assert not result.success
        assert calls == ["provision-apply"]
        assert manager.snapshot.for_domain(RuntimeDomain.PROVISIONING)
        assert manager.snapshot.for_domain(RuntimeDomain.ORCHESTRATION) == {}
        assert manager.snapshot.for_domain(RuntimeDomain.EVALUATION) == {}

    def test_apply_fails_gracefully_on_invalid_validation_payload(self):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=InvalidValidationProvisioner(calls),
            orchestrator=RecordingOrchestrator(calls),
            evaluator=RecordingEvaluator(calls, "evaluator"),
        )
        manager = RuntimeManager(target)

        result = manager.apply(manager.plan(_full_scenario()))

        assert not result.success
        assert calls == []
        assert "runtime.backend-contract-invalid" in {
            diag.code for diag in result.diagnostics
        }
        assert manager.snapshot.entries == {}

    def test_apply_fails_gracefully_on_invalid_apply_result(self):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=InvalidApplyProvisioner(calls),
            orchestrator=RecordingOrchestrator(calls),
            evaluator=RecordingEvaluator(calls, "evaluator"),
        )
        manager = RuntimeManager(target)

        result = manager.apply(manager.plan(_provisioning_only_scenario()))

        assert not result.success
        assert calls == ["provision-apply"]
        assert "runtime.backend-contract-invalid" in {
            diag.code for diag in result.diagnostics
        }
        assert manager.snapshot.entries == {}

    @pytest.mark.parametrize(
        "provisioner_cls",
        [
            InvalidApplySnapshotProvisioner,
            InvalidApplyDiagnosticsProvisioner,
            InvalidApplyChangedAddressesProvisioner,
            InvalidApplyDetailsProvisioner,
        ],
    )
    def test_apply_fails_gracefully_on_malformed_apply_result_contents(
        self,
        provisioner_cls,
    ):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=provisioner_cls(calls),
            orchestrator=RecordingOrchestrator(calls),
            evaluator=RecordingEvaluator(calls, "evaluator"),
        )
        manager = RuntimeManager(target)

        result = manager.apply(manager.plan(_provisioning_only_scenario()))

        assert not result.success
        assert calls == ["provision-apply"]
        assert "runtime.backend-contract-invalid" in {
            diag.code for diag in result.diagnostics
        }
        assert manager.snapshot.entries == {}

    def test_apply_fails_gracefully_on_backend_exception(self):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner(calls),
            orchestrator=RaisingStartOrchestrator(calls),
            evaluator=RecordingEvaluator(calls, "evaluator"),
        )
        manager = RuntimeManager(target)

        result = manager.apply(manager.plan(_full_scenario()))

        assert not result.success
        assert calls == [
            "provision-apply",
            "evaluator-start",
            "orchestrator-start",
            "orchestrator-stop",
            "evaluator-stop",
        ]
        assert "runtime.backend-call-failed" in {
            diag.code for diag in result.diagnostics
        }
        assert manager.snapshot.for_domain(RuntimeDomain.ORCHESTRATION) == {}
        assert manager.snapshot.for_domain(RuntimeDomain.EVALUATION) == {}
        assert manager.snapshot.for_domain(RuntimeDomain.PROVISIONING)

    def test_runtime_manager_requires_explicit_manifest(self):
        with pytest.raises(ValueError, match="explicit manifest"):
            RuntimeManager(
                RuntimeTarget(  # type: ignore[arg-type]
                    name="invalid",
                    manifest=None,
                    provisioner=RecordingProvisioner([]),
                )
            )

    def test_apply_fails_closed_before_provisioning_when_required_service_is_missing(self):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner(calls),
            orchestrator=RecordingOrchestrator(calls),
            evaluator=RecordingEvaluator(calls, "evaluator"),
        )
        manager = RuntimeManager(target)
        execution_plan = manager.plan(_full_scenario())

        object.__setattr__(target, "evaluator", None)

        result = manager.apply(execution_plan)

        assert not result.success
        assert calls == []
        assert "runtime.apply-missing-evaluator" in {
            diag.code for diag in result.diagnostics
        }
        assert manager.snapshot.entries == {}

    def test_apply_rejects_unbound_direct_plan(self):
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner([]),
            orchestrator=RecordingOrchestrator([]),
            evaluator=RecordingEvaluator([], "evaluator"),
        )
        execution_plan = plan(
            compile_runtime_model(_provisioning_only_scenario()),
            target.manifest,
        )

        result = RuntimeManager(target).apply(execution_plan)

        assert not result.success
        assert "runtime.plan-target-unbound" in {
            diag.code for diag in result.diagnostics
        }

    def test_manager_plan_binds_target_name(self):
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner([]),
            orchestrator=RecordingOrchestrator([]),
            evaluator=RecordingEvaluator([], "evaluator"),
        )

        execution_plan = RuntimeManager(target).plan(_provisioning_only_scenario())

        assert execution_plan.target_name == "recording"

    def test_apply_accepts_explicitly_bound_direct_plan(self):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner(calls),
            orchestrator=RecordingOrchestrator(calls),
            evaluator=RecordingEvaluator(calls, "evaluator"),
        )
        execution_plan = plan(
            compile_runtime_model(_provisioning_only_scenario()),
            target.manifest,
            target_name=target.name,
        )

        result = RuntimeManager(target).apply(execution_plan)

        assert result.success
        assert calls == ["provision-apply"]

    def test_apply_rejects_target_name_mismatch(self):
        plan_target = RuntimeTarget(
            name="plan-target",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner([]),
            orchestrator=RecordingOrchestrator([]),
            evaluator=RecordingEvaluator([], "evaluator"),
        )
        manager_target = RuntimeTarget(
            name="other-target",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner([]),
            orchestrator=RecordingOrchestrator([]),
            evaluator=RecordingEvaluator([], "evaluator"),
        )

        execution_plan = RuntimeManager(plan_target).plan(_full_scenario())
        result = RuntimeManager(manager_target).apply(execution_plan)

        assert not result.success
        assert "runtime.plan-target-mismatch" in {diag.code for diag in result.diagnostics}

    def test_apply_rejects_manifest_mismatch(self):
        plan_target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner([]),
            orchestrator=RecordingOrchestrator([]),
            evaluator=RecordingEvaluator([], "evaluator"),
        )
        altered_manifest = create_stub_manifest()
        altered_manifest = altered_manifest.__class__(
            name="stub-alt",
            provisioner=altered_manifest.provisioner,
            orchestrator=altered_manifest.orchestrator,
            evaluator=altered_manifest.evaluator,
        )
        manager_target = RuntimeTarget(
            name="recording",
            manifest=altered_manifest,
            provisioner=RecordingProvisioner([]),
            orchestrator=RecordingOrchestrator([]),
            evaluator=RecordingEvaluator([], "evaluator"),
        )

        execution_plan = RuntimeManager(plan_target).plan(_provisioning_only_scenario())
        result = RuntimeManager(manager_target).apply(execution_plan)

        assert not result.success
        assert "runtime.plan-manifest-mismatch" in {diag.code for diag in result.diagnostics}

    def test_apply_rejects_base_snapshot_mismatch(self):
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner([]),
            orchestrator=RecordingOrchestrator([]),
            evaluator=RecordingEvaluator([], "evaluator"),
        )
        execution_plan = RuntimeManager(target).plan(_provisioning_only_scenario())

        manager = RuntimeManager(
            target,
            initial_snapshot=RuntimeSnapshot(metadata={"seed": "different"}),
        )
        result = manager.apply(execution_plan)

        assert not result.success
        assert "runtime.plan-snapshot-mismatch" in {diag.code for diag in result.diagnostics}

    def test_apply_uses_matching_initial_snapshot(self):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner(calls),
            orchestrator=RecordingOrchestrator(calls),
            evaluator=RecordingEvaluator(calls, "evaluator"),
        )
        initial_manager = RuntimeManager(target)
        initial_plan = initial_manager.plan(_provisioning_only_scenario())
        initial_snapshot = _apply_ops(
            RuntimeSnapshot(),
            RuntimeDomain.PROVISIONING,
            initial_plan.provisioning.operations,
            status="existing",
        )

        updated_scenario = _scenario("""
name: provisioning-only
nodes:
  vm:
    type: vm
    os: windows
    resources: {ram: 1 gib, cpu: 1}
""")

        manager = RuntimeManager(target, initial_snapshot=initial_snapshot)
        result = manager.apply(manager.plan(updated_scenario))

        assert result.success
        assert calls == ["provision-apply"]
        assert manager.snapshot.entries["provision.node.vm"].payload["os_family"] == "windows"

    def test_identical_second_apply_skips_runtime_service_restarts(self):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner(calls),
            orchestrator=RecordingOrchestrator(calls),
            evaluator=RecordingEvaluator(calls, "evaluator"),
        )
        manager = RuntimeManager(target)

        first_result = manager.apply(manager.plan(_full_scenario()))
        assert first_result.success

        calls.clear()
        second_result = manager.apply(manager.plan(_full_scenario()))

        assert second_result.success
        assert calls == ["provision-apply"]

    def test_missing_service_checks_use_actionable_runtime_ops(self):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner(calls),
            orchestrator=RecordingOrchestrator(calls),
            evaluator=RecordingEvaluator(calls, "evaluator"),
        )
        manager = RuntimeManager(target)

        first_result = manager.apply(manager.plan(_full_scenario()))
        assert first_result.success

        calls.clear()
        object.__setattr__(target, "evaluator", None)

        second_result = manager.apply(manager.plan(_full_scenario()))

        assert second_result.success
        assert calls == ["provision-apply"]

    def test_apply_skips_empty_runtime_service_starts(self):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner(calls),
            orchestrator=RecordingOrchestrator(calls),
            evaluator=RecordingEvaluator(calls, "evaluator"),
        )
        manager = RuntimeManager(target)

        result = manager.apply(manager.plan(_provisioning_only_scenario()))

        assert result.success
        assert calls == ["provision-apply"]

    def test_apply_runs_delete_only_runtime_reconciliation(self):
        calls: list[str] = []
        target = RuntimeTarget(
            name="recording",
            manifest=create_stub_manifest(),
            provisioner=RecordingProvisioner(calls),
            orchestrator=RecordingOrchestrator(calls),
            evaluator=RecordingEvaluator(calls, "evaluator"),
        )
        manager = RuntimeManager(target)

        manager.apply(manager.plan(_full_scenario()))
        calls.clear()

        result = manager.apply(manager.plan(_provisioning_only_scenario()))

        assert result.success
        assert calls == ["provision-apply", "evaluator-start", "orchestrator-start"]
        assert manager.snapshot.for_domain(RuntimeDomain.ORCHESTRATION) == {}
        assert manager.snapshot.for_domain(RuntimeDomain.EVALUATION) == {}
