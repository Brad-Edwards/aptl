"""Cross-artifact identity joins, per-condition planning-only feasibility,
and source-set projection for ACES experiment admission (ADR-047
"Experiment-controller boundary", Stage 5 / EXP-002 / issue #438).

Split out of :mod:`aptl.core.experiment.admission` to keep that module
under the 500-line budget (``python:S104``). Everything here is called
exclusively from ``admission._admit_experiment_inner`` — unlike
:mod:`aptl.core.experiment.admission_artifacts`, nothing in this module is
re-exported from ``aptl.core.experiment.admission``; it is an internal
implementation detail of the admission sequence, not a second public entry
point.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from aces_backend_protocols.manifest import BackendManifest
from aces_contracts.contracts import ExperimentCaptureSpecModel, ExperimentReferenceModel, ExperimentTaskModel
from aces_contracts.experiment_spec import ExperimentSpecModel
from aces_sdl import SDLInstantiationError
from aces_sdl.canonical import SDLCanonicalDigest, canonical_instantiated_sdl_digest
from aces_sdl.instantiate import instantiate_scenario
from aces_sdl.scenario import InstantiatedScenario, Scenario

from aptl.core.experiment.admission_artifacts import ResolvedArtifactSource
from aptl.core.experiment.apparatus import plan_condition_feasibility, require_feasible_plan
from aptl.core.experiment.errors import AdmissionRejection, diagnostic, normalize_aces_failure
from aptl.core.experiment.policy import AdmissionPolicy
from aptl.core.experiment.resolver import ResolvedArtifact
from aptl.core.experiment.spec_loading import load_capture_spec

_ADDRESS_TASK_REF = "task_ref"
_ADDRESS_SCENARIO_REF = "intended_scenario_ref"
_ADDRESS_CAPTURE_SPEC_REFS = "capture_spec_refs"

_CODE_REF_IDENTITY_MISMATCH = "aptl.experiment-admission.reference-identity-mismatch"
_CODE_TASK_SCENARIO_MISMATCH = "aptl.experiment-admission.task-scenario-ref-mismatch"
_CODE_SCENARIO_DIGEST_MISMATCH = "aptl.experiment-admission.scenario-ref-digest-mismatch"
_CODE_DUPLICATE_CAPTURE_REF = "aptl.experiment-admission.capture-spec-ref-duplicate"
_CODE_CAPTURE_SCOPE_MISMATCH = "aptl.experiment-admission.capture-scope-mismatch"
_CODE_CONDITION_INSTANTIATION_FAILED = "aptl.experiment-admission.condition-instantiation-failed"


def _reject(code: str, address: str, message: str) -> AdmissionRejection:
    """Build a one-diagnostic AdmissionRejection for a cross-artifact-join or condition-planning failure."""
    return AdmissionRejection((diagnostic(code, address, message),))


# ---------------------------------------------------------------------------
# Cross-artifact identity joins
# ---------------------------------------------------------------------------


def _check_task_identity(spec: ExperimentSpecModel, task: ExperimentTaskModel) -> None:
    """Reject when the resolved task's identity/version does not match spec.task_ref."""
    if task.task_id != spec.task_ref.ref_id:
        raise _reject(
            _CODE_REF_IDENTITY_MISMATCH,
            f"{_ADDRESS_TASK_REF}.ref_id",
            "resolved task identity does not match spec.task_ref",
        )
    if spec.task_ref.ref_version is not None and task.task_version != spec.task_ref.ref_version:
        raise _reject(
            _CODE_REF_IDENTITY_MISMATCH,
            f"{_ADDRESS_TASK_REF}.ref_version",
            "resolved task version does not match spec.task_ref",
        )


def _effective_scenario_ref(spec: ExperimentSpecModel, task: ExperimentTaskModel) -> ExperimentReferenceModel:
    """Return the scenario reference to resolve, cross-checking agreement
    between ``spec.intended_scenario_ref`` and ``task.scenario_ref`` when
    the spec supplies one (ADR-047 "task/scenario agreement")."""
    if spec.intended_scenario_ref is None:
        return task.scenario_ref

    intended = spec.intended_scenario_ref
    from_task = task.scenario_ref
    if intended.ref_id != from_task.ref_id:
        raise _reject(
            _CODE_TASK_SCENARIO_MISMATCH,
            f"{_ADDRESS_SCENARIO_REF}.ref_id",
            "spec.intended_scenario_ref does not agree with task.scenario_ref",
        )
    if (
        intended.ref_version is not None
        and from_task.ref_version is not None
        and intended.ref_version != from_task.ref_version
    ):
        raise _reject(
            _CODE_TASK_SCENARIO_MISMATCH,
            f"{_ADDRESS_SCENARIO_REF}.ref_version",
            "spec.intended_scenario_ref version does not agree with task.scenario_ref",
        )
    if (
        intended.ref_digest is not None
        and from_task.ref_digest is not None
        and intended.ref_digest.casefold() != from_task.ref_digest.casefold()
    ):
        raise _reject(
            _CODE_TASK_SCENARIO_MISMATCH,
            f"{_ADDRESS_SCENARIO_REF}.ref_digest",
            "spec.intended_scenario_ref digest does not agree with task.scenario_ref",
        )
    return intended


def _check_scenario_identity(
    effective_ref: ExperimentReferenceModel, scenario: Scenario, canonical_digest: SDLCanonicalDigest
) -> None:
    """Reject when the resolved scenario's identity/version/canonical digest does not match effective_ref."""
    if scenario.name != effective_ref.ref_id:
        raise _reject(
            _CODE_REF_IDENTITY_MISMATCH,
            f"{_ADDRESS_SCENARIO_REF}.ref_id",
            "resolved scenario identity does not match the scenario reference",
        )
    if effective_ref.ref_version is not None and scenario.version != effective_ref.ref_version:
        raise _reject(
            _CODE_REF_IDENTITY_MISMATCH,
            f"{_ADDRESS_SCENARIO_REF}.ref_version",
            "resolved scenario version does not match the scenario reference",
        )
    if (
        effective_ref.ref_digest is not None
        and canonical_digest.value.casefold() != effective_ref.ref_digest.casefold()
    ):
        raise _reject(
            _CODE_SCENARIO_DIGEST_MISMATCH,
            f"{_ADDRESS_SCENARIO_REF}.ref_digest",
            "resolved scenario canonical digest does not match the pinned scenario reference",
        )


def _reject_duplicate_capture_spec_refs(spec: ExperimentSpecModel) -> None:
    """Raise when spec.capture_spec_refs contains a duplicate reference identity."""
    seen_ids: set[str] = set()
    for ref in spec.capture_spec_refs:
        if ref.ref_id in seen_ids:
            raise _reject(
                _CODE_DUPLICATE_CAPTURE_REF,
                _ADDRESS_CAPTURE_SPEC_REFS,
                "capture_spec_refs contains a duplicate reference identity",
            )
        seen_ids.add(ref.ref_id)


def _capture_spec_task_scope_match(capture_spec: ExperimentCaptureSpecModel, task: ExperimentTaskModel) -> bool:
    """Return whether capture_spec.scope_refs includes the admitted task's identity/version."""
    return any(
        scope.ref_kind == "task"
        and scope.ref_id == task.task_id
        and (scope.ref_version is None or scope.ref_version == task.task_version)
        for scope in capture_spec.scope_refs
    )


def _resolve_one_capture_spec(
    ref: ExperimentReferenceModel,
    task: ExperimentTaskModel,
    artifact_source: ResolvedArtifactSource,
    *,
    policy: AdmissionPolicy,
) -> tuple[ExperimentCaptureSpecModel, ResolvedArtifact]:
    """Resolve, load, and identity/scope-check one capture-spec reference."""
    artifact = artifact_source.artifact_for(ref)
    capture_spec = load_capture_spec(artifact.data, policy=policy)

    if capture_spec.capture_spec_id != ref.ref_id:
        raise _reject(
            _CODE_REF_IDENTITY_MISMATCH,
            f"{_ADDRESS_CAPTURE_SPEC_REFS}.{ref.ref_id}",
            "resolved capture-spec identity does not match its reference",
        )
    if ref.ref_version is not None and capture_spec.spec_version != ref.ref_version:
        raise _reject(
            _CODE_REF_IDENTITY_MISMATCH,
            f"{_ADDRESS_CAPTURE_SPEC_REFS}.{ref.ref_id}.ref_version",
            "resolved capture-spec version does not match its reference",
        )
    if not _capture_spec_task_scope_match(capture_spec, task):
        raise _reject(
            _CODE_CAPTURE_SCOPE_MISMATCH,
            f"capture_spec.{capture_spec.capture_spec_id}.scope_refs",
            "capture spec scope_refs do not include the admitted task",
        )

    return capture_spec, artifact


def _resolve_capture_specs(
    spec: ExperimentSpecModel,
    task: ExperimentTaskModel,
    artifact_source: ResolvedArtifactSource,
    *,
    policy: AdmissionPolicy,
) -> tuple[list[ExperimentCaptureSpecModel], list[ResolvedArtifact]]:
    """Resolve, load, and identity/scope-check every capture-spec reference in spec."""
    _reject_duplicate_capture_spec_refs(spec)

    capture_specs: list[ExperimentCaptureSpecModel] = []
    capture_artifacts: list[ResolvedArtifact] = []
    for ref in spec.capture_spec_refs:
        capture_spec, artifact = _resolve_one_capture_spec(ref, task, artifact_source, policy=policy)
        capture_specs.append(capture_spec)
        capture_artifacts.append(artifact)

    return capture_specs, capture_artifacts


# ---------------------------------------------------------------------------
# Per-condition planning-only feasibility
# ---------------------------------------------------------------------------


def _instantiate_for_digest(
    scenario: Scenario, parameters: Mapping[str, object], *, address: str
) -> InstantiatedScenario:
    """Instantiate scenario under parameters, normalizing a structurally-broken binding into AdmissionRejection."""
    try:
        return instantiate_scenario(scenario, parameters)
    except SDLInstantiationError as exc:
        raise AdmissionRejection(
            normalize_aces_failure(exc, address=address, code=_CODE_CONDITION_INSTANTIATION_FAILED)
        ) from exc


def _plan_conditions(
    spec: ExperimentSpecModel, scenario: Scenario, *, backend_manifest: BackendManifest
) -> tuple[dict[str, str], str | None]:
    """Run the planning-only ACES reference processor over every unique
    condition binding (flat allocation: one empty binding) and derive each
    binding's canonical instantiated-scenario digest.

    Returns ``(condition_snapshot_digests, flat_instantiated_digest)`` — the
    former threaded into :func:`~aptl.core.experiment.trial_plan.
    expand_trial_plan` for a condition allocation, the latter folded into
    the source-set projection for a flat allocation (``trial_plan``'s own
    flat expander never attaches a per-trial snapshot digest, so a flat
    plan's one instantiated identity has nowhere else structural to live).
    """
    condition_snapshot_digests: dict[str, str] = {}
    flat_instantiated_digest: str | None = None

    if spec.run_plan.allocation is not None:
        allocation = spec.run_plan.allocation
        for condition_id in allocation.compared_conditions:
            assignment = allocation.condition_assignments[condition_id]
            parameters = {p.name: p.value for p in assignment.required_parameters}
            address = f"run_plan.allocation.condition_assignments.{condition_id}"

            result = plan_condition_feasibility(scenario, parameters, backend_manifest=backend_manifest)
            require_feasible_plan(result, address=address)

            instantiated = _instantiate_for_digest(scenario, parameters, address=address)
            condition_snapshot_digests[condition_id] = canonical_instantiated_sdl_digest(instantiated).value
    else:
        parameters = {}
        result = plan_condition_feasibility(scenario, parameters, backend_manifest=backend_manifest)
        require_feasible_plan(result, address="run_plan")

        instantiated = _instantiate_for_digest(scenario, parameters, address="run_plan")
        flat_instantiated_digest = canonical_instantiated_sdl_digest(instantiated).value

    return condition_snapshot_digests, flat_instantiated_digest


# ---------------------------------------------------------------------------
# Source-set projection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TaskResolution:
    """The resolved task model plus its source artifact, for source-set projection."""

    task: ExperimentTaskModel
    artifact: ResolvedArtifact


@dataclass(frozen=True)
class ScenarioResolution:
    """The resolved scenario, its effective ref, source artifact, and canonical digest, for source-set projection."""

    effective_ref: ExperimentReferenceModel
    scenario: Scenario
    artifact: ResolvedArtifact
    canonical_digest: SDLCanonicalDigest


@dataclass(frozen=True)
class CaptureResolution:
    """The resolved capture specs paired with their source artifacts, for source-set projection."""

    specs: list[ExperimentCaptureSpecModel]
    artifacts: list[ResolvedArtifact]


def _build_source_set_projection(
    *,
    task: TaskResolution,
    scenario: ScenarioResolution,
    capture: CaptureResolution,
    flat_instantiated_digest: str | None,
) -> dict[str, object]:
    """Build the deterministic source-set projection dict that admission hashes into source_set_digest."""
    projection: dict[str, object] = {
        "schema": "aptl-experiment-source-set/v1",
        "task": {
            "task_id": task.task.task_id,
            "task_version": task.task.task_version,
            "resolved_digest": task.artifact.digest,
        },
        "scenario": {
            "ref_kind": scenario.effective_ref.ref_kind,
            "ref_id": scenario.scenario.name,
            "scenario_version": scenario.scenario.version,
            "resolved_digest": scenario.artifact.digest,
            "canonical_digest": scenario.canonical_digest.value,
        },
        "capture_specs": {
            capture_spec.capture_spec_id: {
                "spec_version": capture_spec.spec_version,
                "resolved_digest": artifact.digest,
            }
            for capture_spec, artifact in zip(capture.specs, capture.artifacts, strict=True)
        },
    }
    if flat_instantiated_digest is not None:
        projection["flat_instantiated_scenario_digest"] = flat_instantiated_digest
    return projection
