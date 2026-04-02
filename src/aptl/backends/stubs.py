"""Stub runtime backends for compiler/planner testing."""

from aptl.core.runtime.capabilities import (
    BackendManifest,
    EvaluatorCapabilities,
    OrchestratorCapabilities,
    ProvisionerCapabilities,
    WorkflowFeature,
    WorkflowStatePredicateFeature,
)
from aptl.core.runtime.models import (
    ApplyResult,
    ChangeAction,
    Diagnostic,
    EvaluationPlan,
    OrchestrationPlan,
    ProvisioningPlan,
    RuntimeDomain,
    RuntimeSnapshot,
    SnapshotEntry,
)
from aptl.core.runtime.registry import RuntimeTarget, RuntimeTargetComponents


def create_stub_manifest(**config) -> BackendManifest:
    """Return the fully capable stub manifest."""

    return BackendManifest(
        name="stub",
        provisioner=ProvisionerCapabilities(
            name="stub-provisioner",
            supported_node_types=frozenset({"vm", "switch"}),
            supported_os_families=frozenset(
                {"linux", "windows", "macos", "freebsd", "other"}
            ),
            supported_content_types=frozenset({"file", "dataset", "directory"}),
            supported_account_features=frozenset(
                {"groups", "mail", "spn", "shell", "home", "disabled", "auth_method"}
            ),
            max_total_nodes=None,
            supports_acls=True,
            supports_accounts=True,
        ),
        orchestrator=OrchestratorCapabilities(
            name="stub-orchestrator",
            supported_sections=frozenset(
                {"injects", "events", "scripts", "stories", "workflows"}
            ),
            supports_workflows=True,
            supports_condition_refs=True,
            supports_inject_bindings=True,
            supported_workflow_features=frozenset(
                {
                    WorkflowFeature.DECISION,
                    WorkflowFeature.PARALLEL_BARRIER,
                    WorkflowFeature.RETRY,
                    WorkflowFeature.FAILURE_TRANSITIONS,
                }
            ),
            supported_workflow_state_predicates=frozenset(
                {
                    WorkflowStatePredicateFeature.OUTCOME_MATCHING,
                    WorkflowStatePredicateFeature.ATTEMPT_COUNTS,
                }
            ),
        ),
        evaluator=EvaluatorCapabilities(
            name="stub-evaluator",
            supported_sections=frozenset(
                {"conditions", "metrics", "evaluations", "tlos", "goals", "objectives"}
            ),
            supports_scoring=True,
            supports_objectives=True,
        ),
    )


class StubProvisioner:
    """In-memory provisioner."""

    def validate(self, plan: ProvisioningPlan) -> list[Diagnostic]:
        return []

    def apply(
        self,
        plan: ProvisioningPlan,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        entries = dict(snapshot.entries)
        changed_addresses: list[str] = []
        for op in plan.operations:
            if op.action == ChangeAction.DELETE:
                entries.pop(op.address, None)
                changed_addresses.append(op.address)
                continue
            status = "unchanged" if op.action == ChangeAction.UNCHANGED else "applied"
            entries[op.address] = SnapshotEntry(
                address=op.address,
                domain=RuntimeDomain.PROVISIONING,
                resource_type=op.resource_type,
                payload=op.payload,
                ordering_dependencies=op.ordering_dependencies,
                refresh_dependencies=op.refresh_dependencies,
                status=status,
            )
            if op.action != ChangeAction.UNCHANGED:
                changed_addresses.append(op.address)

        return ApplyResult(
            success=True,
            snapshot=snapshot.with_entries(entries),
            changed_addresses=changed_addresses,
        )


class StubOrchestrator:
    """In-memory orchestrator."""

    def __init__(self) -> None:
        self._running = False
        self._startup_order: list[str] = []
        self._results: dict[str, dict[str, object]] = {}

    def start(
        self,
        plan: OrchestrationPlan,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        entries = dict(snapshot.entries)
        results = dict(snapshot.orchestration_results)
        changed_addresses: list[str] = []
        for op in plan.operations:
            if op.action == ChangeAction.DELETE:
                entries.pop(op.address, None)
                results.pop(op.address, None)
                changed_addresses.append(op.address)
                continue
            status = "queued" if op.resource_type in {"event", "script", "story", "workflow"} else "bound"
            entries[op.address] = SnapshotEntry(
                address=op.address,
                domain=RuntimeDomain.ORCHESTRATION,
                resource_type=op.resource_type,
                payload=op.payload,
                ordering_dependencies=op.ordering_dependencies,
                refresh_dependencies=op.refresh_dependencies,
                status=status,
            )
            if op.resource_type == "workflow":
                control_steps = op.payload.get("control_steps", {})
                results[op.address] = {
                    "state-schema-version": op.payload.get(
                        "state_schema_version",
                        "workflow-step-state/v1",
                    ),
                    "steps": {
                        step_name: {
                            "lifecycle": "pending",
                            "outcome": None,
                            "attempts": 0,
                        }
                        for step_name in control_steps
                    },
                }
            if op.action != ChangeAction.UNCHANGED:
                changed_addresses.append(op.address)
        self._running = bool(plan.resources)
        self._startup_order = list(plan.startup_order)
        self._results = results
        return ApplyResult(
            success=True,
            snapshot=snapshot.with_entries(entries, orchestration_results=results),
            changed_addresses=changed_addresses,
        )

    def status(self) -> dict[str, object]:
        return {
            "running": self._running,
            "startup_order": list(self._startup_order),
            "results": len(self._results),
        }

    def results(self) -> dict[str, dict[str, object]]:
        return dict(self._results)

    def stop(self, snapshot: RuntimeSnapshot) -> ApplyResult:
        entries = {
            address: entry
            for address, entry in snapshot.entries.items()
            if entry.domain != RuntimeDomain.ORCHESTRATION
        }
        removed = [
            address
            for address, entry in snapshot.entries.items()
            if entry.domain == RuntimeDomain.ORCHESTRATION
        ]
        self._running = False
        self._startup_order = []
        self._results = {}
        return ApplyResult(
            success=True,
            snapshot=snapshot.with_entries(entries, orchestration_results={}),
            changed_addresses=removed,
        )


class StubEvaluator:
    """In-memory evaluator."""

    def __init__(self) -> None:
        self._running = False
        self._startup_order: list[str] = []
        self._results: dict[str, dict[str, object]] = {}

    def start(
        self,
        plan: EvaluationPlan,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        entries = dict(snapshot.entries)
        changed_addresses: list[str] = []
        results = dict(snapshot.evaluation_results)
        for op in plan.operations:
            if op.action == ChangeAction.DELETE:
                entries.pop(op.address, None)
                results.pop(op.address, None)
                changed_addresses.append(op.address)
                continue
            entries[op.address] = SnapshotEntry(
                address=op.address,
                domain=RuntimeDomain.EVALUATION,
                resource_type=op.resource_type,
                payload=op.payload,
                ordering_dependencies=op.ordering_dependencies,
                refresh_dependencies=op.refresh_dependencies,
                status="evaluating",
            )
            results[op.address] = {
                "passed": True,
                "detail": f"stub result for {op.address}",
            }
            if op.action != ChangeAction.UNCHANGED:
                changed_addresses.append(op.address)
        self._running = bool(plan.resources)
        self._startup_order = list(plan.startup_order)
        self._results = results
        return ApplyResult(
            success=True,
            snapshot=snapshot.with_entries(
                entries,
                evaluation_results=results,
            ),
            changed_addresses=changed_addresses,
        )

    def status(self) -> dict[str, object]:
        return {
            "running": self._running,
            "startup_order": list(self._startup_order),
            "results": len(self._results),
        }

    def results(self) -> dict[str, dict[str, object]]:
        return dict(self._results)

    def stop(self, snapshot: RuntimeSnapshot) -> ApplyResult:
        entries = {
            address: entry
            for address, entry in snapshot.entries.items()
            if entry.domain != RuntimeDomain.EVALUATION
        }
        removed = [
            address
            for address, entry in snapshot.entries.items()
            if entry.domain == RuntimeDomain.EVALUATION
        ]
        self._running = False
        self._startup_order = []
        self._results = {}
        return ApplyResult(
            success=True,
            snapshot=snapshot.with_entries(entries, evaluation_results={}),
            changed_addresses=removed,
        )


def create_stub_components(
    *,
    manifest: BackendManifest,
    **config,
) -> RuntimeTargetComponents:
    """Factory for stub runtime components."""

    del manifest, config
    return RuntimeTargetComponents(
        provisioner=StubProvisioner(),
        orchestrator=StubOrchestrator(),
        evaluator=StubEvaluator(),
    )


def create_stub_target(**config) -> RuntimeTarget:
    """Convenience helper returning the fully configured stub target."""

    manifest = create_stub_manifest(**config)
    components = create_stub_components(manifest=manifest, **config)
    return RuntimeTarget(
        name="stub",
        manifest=manifest,
        provisioner=components.provisioner,
        orchestrator=components.orchestrator,
        evaluator=components.evaluator,
    )
