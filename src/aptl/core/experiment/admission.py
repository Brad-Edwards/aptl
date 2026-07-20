"""The ACES experiment admission coordinator (ADR-047 "Experiment-controller
boundary", Stage 5 / EXP-002 / issue #438).

This module wires the previously-landed Stage 1-4 modules
(``errors``, ``policy``, ``resolver``, ``spec_loading``, ``apparatus``,
``capture_mapping``, ``trial_plan``) into one all-or-nothing admission
sequence: :func:`admit_experiment`. It performs ONLY:

* bounded, hardened loading of the ACES experiment graph (root, task,
  scenario, capture specs) from resolver-owned bytes;
* cross-artifact identity/version joins between those already-validated
  ACES objects;
* apparatus and capture capability admission;
* planning-only per-condition feasibility plus the canonical
  instantiated-scenario digest ACES itself derives;
* pure, deterministic trial-plan expansion; and
* create-once, digest-reverified persistence of the resulting plan via the
  injected ``RunStorageBackend``.

ADR-047 "Range-mutation gate": nothing here calls ``.env`` hydration,
``EnvVars``, key/cert generation, rendered service config, volume seeding,
image pulls, a collector, a session, or any ``DeploymentBackend`` method.
Admission is read-only and offline except for its own final, narrow,
create-once write of the admitted plan.

``admit_experiment`` never raises :class:`~aptl.core.experiment.errors.
AdmissionRejection` to its own caller — every rejection anywhere in the
sequence is caught internally and converted into
``AdmissionResult.rejected(diagnostics)``, matching the ADR's "one-shot
result, not a parallel workflow engine" rule (rejected: diagnostics and no
plan; admitted: immutable plan bytes, identity, and trial tuple — nothing
in between).

Naming note: the driving spec for this stage asked for a classmethod named
``AdmissionResult.admitted(...)`` alongside an ``.admitted: bool`` instance
field with the SAME name. That is not expressible on one Python class (a
``@dataclass`` field named ``admitted`` and a class-body ``def admitted``
in the same class body collide — the method definition becomes what
dataclass reads back as the field's default, not a separate name). The
``.admitted: bool`` shape discriminator is the more heavily used contract
(every caller branches on it), so it wins; the ADMITTED-side constructor is
named :meth:`AdmissionResult.admit` instead.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from aces_backend_protocols.manifest import BackendManifest
from aces_contracts.associated_artifacts import (
    AssociatedArtifactManifestModel,
    AssociatedArtifactValidationLimits,
    load_associated_artifact_manifest_json,
    validate_associated_artifact_manifest,
)
from aces_contracts.contracts import ExperimentCaptureSpecModel, ExperimentReferenceModel
from aces_contracts.diagnostics import Diagnostic
from aces_contracts.experiment_spec import ExperimentSpecModel
from aces_processor.capabilities import ProcessorManifest
from aces_processor.manifest import create_reference_processor_manifest
from aces_sdl import SDLInstantiationError
from aces_sdl.canonical import canonical_instantiated_sdl_digest
from aces_sdl.instantiate import instantiate_scenario

from aptl.backends.aces_manifest import create_aptl_manifest
from aptl.core.experiment.apparatus import check_apparatus_admission, plan_condition_feasibility, require_feasible_plan
from aptl.core.experiment.capture_mapping import map_capture_requirements
from aptl.core.experiment.errors import AdmissionRejection, diagnostic, normalize_aces_failure
from aptl.core.experiment.policy import AdmissionPolicy
from aptl.core.experiment.resolver import (
    ProjectContainedResolver,
    ProjectFileLocator,
    ResolvedArtifact,
    parse_locator,
)
from aptl.core.experiment.spec_loading import (
    load_capture_spec,
    load_experiment_root,
    load_task,
    parse_scenario_bytes,
)
from aptl.core.experiment.trial_plan import TrialPlan, compute_source_set_digest, expand_trial_plan
from aptl.core.runstore import RunStorageBackend
from aptl.utils.pathsafe import PathContainmentError

_ADDRESS_TASK_REF = "task_ref"
_ADDRESS_SCENARIO_REF = "intended_scenario_ref"
_ADDRESS_CAPTURE_SPEC_REFS = "capture_spec_refs"
_ADDRESS_PLAN_PERSISTENCE = "trial_plan.persistence"

_CODE_ARTIFACT_SOURCE_UNRESOLVED = "aptl.experiment-admission.artifact-source-unresolved"
_CODE_REF_IDENTITY_MISMATCH = "aptl.experiment-admission.reference-identity-mismatch"
_CODE_TASK_SCENARIO_MISMATCH = "aptl.experiment-admission.task-scenario-ref-mismatch"
_CODE_SCENARIO_DIGEST_MISMATCH = "aptl.experiment-admission.scenario-ref-digest-mismatch"
_CODE_DUPLICATE_CAPTURE_REF = "aptl.experiment-admission.capture-spec-ref-duplicate"
_CODE_CAPTURE_SCOPE_MISMATCH = "aptl.experiment-admission.capture-scope-mismatch"
_CODE_CONDITION_INSTANTIATION_FAILED = "aptl.experiment-admission.condition-instantiation-failed"
_CODE_ASSOCIATED_ARTIFACT_MANIFEST_INVALID = "aptl.experiment-admission.associated-artifact-manifest-invalid"
_CODE_PERSISTENCE_FAILED = "aptl.experiment-admission.plan-persistence-failed"
_CODE_PERSISTED_PLAN_MISMATCH = "aptl.experiment-admission.persisted-plan-digest-mismatch"


# ---------------------------------------------------------------------------
# AdmissionResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdmissionResult:
    """The one-shot outcome of :func:`admit_experiment`.

    Two disjoint shapes (ADR-047 "Persistence and state model": "a one-shot
    result, not a parallel workflow engine"):

    * REJECTED — ``admitted is False``, ``diagnostics`` non-empty, every
      plan-related field ``None``.
    * ADMITTED — ``admitted is True``, ``plan``/``plan_digest``/
      ``persisted_path`` all set, ``diagnostics`` empty (``warnings`` may be
      non-empty — e.g. the ``allow_uncertified_apparatus`` debug override).

    ``__post_init__`` enforces this split structurally so a rejected result
    can NEVER carry a plan, even if a future caller misuses the plain
    constructor instead of :meth:`rejected`/:meth:`admit`.
    """

    admitted: bool
    diagnostics: tuple[Diagnostic, ...] = ()
    plan: TrialPlan | None = None
    plan_digest: str | None = None
    persisted_path: Path | None = None
    warnings: tuple[Diagnostic, ...] = ()
    trial_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.admitted:
            if self.plan is None or self.plan_digest is None or self.persisted_path is None:
                raise ValueError(
                    "an admitted AdmissionResult must carry plan, plan_digest, and persisted_path"
                )
        else:
            if self.plan is not None or self.plan_digest is not None or self.persisted_path is not None:
                raise ValueError("a rejected AdmissionResult must never carry a plan")
            if not self.diagnostics:
                raise ValueError("a rejected AdmissionResult must carry at least one diagnostic")

    @classmethod
    def rejected(cls, diagnostics: Iterable[Diagnostic]) -> AdmissionResult:
        return cls(admitted=False, diagnostics=tuple(diagnostics))

    @classmethod
    def admit(
        cls,
        *,
        plan: TrialPlan,
        plan_digest: str,
        persisted_path: Path,
        trial_ids: Iterable[str],
        warnings: Iterable[Diagnostic] = (),
    ) -> AdmissionResult:
        return cls(
            admitted=True,
            plan=plan,
            plan_digest=plan_digest,
            persisted_path=persisted_path,
            warnings=tuple(warnings),
            trial_ids=tuple(trial_ids),
        )


# ---------------------------------------------------------------------------
# ResolvedArtifactSource
# ---------------------------------------------------------------------------


class ResolvedArtifactSource(Protocol):
    """The injectable seam admission resolves ``task_ref``/
    ``intended_scenario_ref`` (or ``task.scenario_ref``)/``capture_spec_refs``
    through — never a raw path admission could reopen.
    """

    def artifact_for(self, ref: ExperimentReferenceModel) -> ResolvedArtifact: ...


def _unresolved(ref: ExperimentReferenceModel) -> AdmissionRejection:
    return AdmissionRejection(
        (
            diagnostic(
                _CODE_ARTIFACT_SOURCE_UNRESOLVED,
                f"artifact_source.{ref.ref_kind}",
                "no artifact is bound for this reference identity",
            ),
        )
    )


@dataclass(frozen=True)
class MappingArtifactSource:
    """A simple in-memory :class:`ResolvedArtifactSource` (``ref_id ->
    ResolvedArtifact``) for tests — no filesystem, no ACES associated-
    artifact manifest. Production admission uses
    :func:`build_associated_artifact_source` instead.
    """

    artifacts: Mapping[str, ResolvedArtifact]

    def artifact_for(self, ref: ExperimentReferenceModel) -> ResolvedArtifact:
        try:
            return self.artifacts[ref.ref_id]
        except KeyError:
            raise _unresolved(ref) from None


def build_associated_artifact_source(
    base_dir: Path,
    manifest_relative_path: str,
    spec: ExperimentSpecModel,
    policy: AdmissionPolicy,
) -> ResolvedArtifactSource:
    """Build the production :class:`ResolvedArtifactSource`.

    The ADR-blessed binding: an ACES associated-artifact manifest anchored
    to the authoring-input ``spec`` (``parent_ref.ref_kind ==
    "authoring-input"``) binds each artifact's ``artifact_id`` -> a
    project-relative ``uri`` plus declared ``size_bytes``/``checksum`` — by
    APTL convention, ``artifact_id`` IS the ACES reference's ``ref_id`` it
    binds (``spec.task_ref.ref_id``, ``spec.intended_scenario_ref.ref_id``
    or ``task.scenario_ref.ref_id``, each ``capture_spec_refs[].ref_id``).
    Every declared artifact is resolved via :class:`ProjectContainedResolver`
    (offline, no-follow, bounded, digest-verified), then the WHOLE manifest
    is validated in one shot through ``validate_associated_artifact_manifest``
    (identity, set-digest, per-artifact size/checksum) before anything is
    handed back — a validation failure anywhere rejects the whole source,
    never a partial binding.

    ``spec`` must already be the ACES-validated authoring-input model (the
    controller parses ``experiment_root.data`` once to build this source,
    before ``admit_experiment`` parses the same bytes again as its own step
    1 — a harmless repeat of one pure, deterministic public loader call,
    not a second trust boundary: :func:`admit_experiment`'s contracted
    signature takes an already-built :class:`ResolvedArtifactSource`, so
    there is no way to thread ``spec`` through to here except by resolving
    it once for this purpose).
    """
    resolver = ProjectContainedResolver(base_dir=base_dir)

    manifest_locator = parse_locator(manifest_relative_path, address="associated_artifact_manifest")
    manifest_artifact = resolver.resolve(manifest_locator, policy=policy)

    try:
        manifest: AssociatedArtifactManifestModel = load_associated_artifact_manifest_json(
            manifest_artifact.data
        )
    except (ValueError, TypeError) as exc:
        raise AdmissionRejection(
            normalize_aces_failure(
                exc,
                address="associated_artifact_manifest",
                code=_CODE_ASSOCIATED_ARTIFACT_MANIFEST_INVALID,
            )
        ) from exc

    resolved_by_artifact_id: dict[str, ResolvedArtifact] = {}
    readers: dict[str, io.BytesIO] = {}
    for artifact_id, artifact_ref in manifest.artifacts.items():
        # ACES requires `uri` to be an absolute URI (a scheme is mandatory —
        # see `aces_contracts.contracts._validate_associated_artifact_uri`),
        # so a project-relative binding is authored as `file:<relative
        # path>`. `parse_locator` extracts and re-validates the relative
        # path (scheme/traversal/NUL-byte checks); the declared
        # size/digest come from the associated-artifact model's own
        # structured `size_bytes`/`checksum` fields, not from a query
        # string (the URI carries none).
        address = f"associated_artifact_manifest.artifacts.{artifact_id}"
        parsed_locator = parse_locator(artifact_ref.uri, address=address)
        locator = ProjectFileLocator(
            relative_path=parsed_locator.relative_path,
            declared_size=artifact_ref.size_bytes,
            declared_digest=f"{artifact_ref.checksum.algorithm}:{artifact_ref.checksum.value}",
            media_type=artifact_ref.media_type,
        )
        resolved = resolver.resolve(locator, policy=policy)
        resolved_by_artifact_id[artifact_id] = resolved
        readers[artifact_id] = io.BytesIO(resolved.data)

    validation_diagnostics = validate_associated_artifact_manifest(
        manifest,
        parent=spec,
        artifact_readers=readers,
        limits=AssociatedArtifactValidationLimits(
            max_artifacts=policy.max_reference_count,
            max_artifact_bytes=policy.max_artifact_bytes,
            max_total_bytes=policy.max_aggregate_bytes,
        ),
    )
    errors = tuple(item for item in validation_diagnostics if item.is_error)
    if errors:
        raise AdmissionRejection(errors)

    return MappingArtifactSource(artifacts=resolved_by_artifact_id)


# ---------------------------------------------------------------------------
# admit_experiment
# ---------------------------------------------------------------------------


def _reject(code: str, address: str, message: str) -> AdmissionRejection:
    return AdmissionRejection((diagnostic(code, address, message),))


def _check_task_identity(spec: ExperimentSpecModel, task) -> None:
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


def _effective_scenario_ref(spec: ExperimentSpecModel, task) -> ExperimentReferenceModel:
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


def _check_scenario_identity(effective_ref: ExperimentReferenceModel, scenario, canonical_digest) -> None:
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
    if effective_ref.ref_digest is not None and canonical_digest.value.casefold() != effective_ref.ref_digest.casefold():
        raise _reject(
            _CODE_SCENARIO_DIGEST_MISMATCH,
            f"{_ADDRESS_SCENARIO_REF}.ref_digest",
            "resolved scenario canonical digest does not match the pinned scenario reference",
        )


def _resolve_capture_specs(
    spec: ExperimentSpecModel, task, artifact_source: ResolvedArtifactSource, *, policy: AdmissionPolicy
) -> tuple[list[ExperimentCaptureSpecModel], list[ResolvedArtifact]]:
    seen_ids: set[str] = set()
    for ref in spec.capture_spec_refs:
        if ref.ref_id in seen_ids:
            raise _reject(
                _CODE_DUPLICATE_CAPTURE_REF,
                _ADDRESS_CAPTURE_SPEC_REFS,
                "capture_spec_refs contains a duplicate reference identity",
            )
        seen_ids.add(ref.ref_id)

    capture_specs = []
    capture_artifacts: list[ResolvedArtifact] = []
    for ref in spec.capture_spec_refs:
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

        task_scope_match = any(
            scope.ref_kind == "task"
            and scope.ref_id == task.task_id
            and (scope.ref_version is None or scope.ref_version == task.task_version)
            for scope in capture_spec.scope_refs
        )
        if not task_scope_match:
            raise _reject(
                _CODE_CAPTURE_SCOPE_MISMATCH,
                f"capture_spec.{capture_spec.capture_spec_id}.scope_refs",
                "capture spec scope_refs do not include the admitted task",
            )

        capture_specs.append(capture_spec)
        capture_artifacts.append(artifact)

    return capture_specs, capture_artifacts


def _instantiate_for_digest(scenario, parameters: Mapping[str, object], *, address: str):
    try:
        return instantiate_scenario(scenario, parameters)
    except SDLInstantiationError as exc:
        raise AdmissionRejection(
            normalize_aces_failure(exc, address=address, code=_CODE_CONDITION_INSTANTIATION_FAILED)
        ) from exc


def _plan_conditions(
    spec: ExperimentSpecModel, scenario, *, backend_manifest: BackendManifest
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


def _build_source_set_projection(
    *,
    spec: ExperimentSpecModel,
    task,
    task_artifact: ResolvedArtifact,
    effective_scenario_ref: ExperimentReferenceModel,
    scenario,
    scenario_artifact: ResolvedArtifact,
    scenario_canonical_digest,
    capture_specs,
    capture_artifacts: list[ResolvedArtifact],
    flat_instantiated_digest: str | None,
) -> dict[str, object]:
    projection: dict[str, object] = {
        "schema": "aptl-experiment-source-set/v1",
        "task": {
            "task_id": task.task_id,
            "task_version": task.task_version,
            "resolved_digest": task_artifact.digest,
        },
        "scenario": {
            "ref_kind": effective_scenario_ref.ref_kind,
            "ref_id": scenario.name,
            "scenario_version": scenario.version,
            "resolved_digest": scenario_artifact.digest,
            "canonical_digest": scenario_canonical_digest.value,
        },
        "capture_specs": {
            capture_spec.capture_spec_id: {
                "spec_version": capture_spec.spec_version,
                "resolved_digest": artifact.digest,
            }
            for capture_spec, artifact in zip(capture_specs, capture_artifacts, strict=True)
        },
    }
    if flat_instantiated_digest is not None:
        projection["flat_instantiated_scenario_digest"] = flat_instantiated_digest
    return projection


def _persist_plan(plan: TrialPlan, *, run_store: RunStorageBackend) -> Path:
    payload = json.loads(plan.canonical_bytes)
    try:
        persisted_path = run_store.create_json_once("experiment-plans", plan.plan_id, payload)
    except (PathContainmentError, ValueError) as exc:
        # SecretInvariantError / RunStoreConflictError are ValueError
        # subclasses; caught here without restating them.
        raise _reject(
            _CODE_PERSISTENCE_FAILED,
            _ADDRESS_PLAN_PERSISTENCE,
            "trial plan could not be persisted",
        ) from exc

    persisted_bytes = persisted_path.read_bytes()
    if persisted_bytes != plan.canonical_bytes:
        raise _reject(
            _CODE_PERSISTED_PLAN_MISMATCH,
            _ADDRESS_PLAN_PERSISTENCE,
            "persisted plan bytes do not match the computed plan digest",
        )
    return persisted_path


def _admit_experiment_inner(
    *,
    experiment_root: ResolvedArtifact,
    artifact_source: ResolvedArtifactSource,
    run_store: RunStorageBackend,
    policy: AdmissionPolicy,
    backend_manifest: BackendManifest,
    processor_manifest: ProcessorManifest,
) -> AdmissionResult:
    # Step 1: root.
    spec = load_experiment_root(experiment_root.data, policy=policy)

    # Step 2: resolve + load task, scenario, capture specs. Pin digests.
    task_artifact = artifact_source.artifact_for(spec.task_ref)
    task = load_task(task_artifact.data, policy=policy)

    effective_scenario_ref = _effective_scenario_ref(spec, task)
    scenario_artifact = artifact_source.artifact_for(effective_scenario_ref)
    scenario, scenario_canonical_digest = parse_scenario_bytes(scenario_artifact.data, policy=policy)

    capture_specs, capture_artifacts = _resolve_capture_specs(spec, task, artifact_source, policy=policy)

    # Step 3: cross-artifact joins.
    _check_task_identity(spec, task)
    _check_scenario_identity(effective_scenario_ref, scenario, scenario_canonical_digest)

    # Step 4: apparatus admission.
    warnings = check_apparatus_admission(
        task,
        spec.apparatus_intent,
        backend_manifest=backend_manifest,
        processor_manifest=processor_manifest,
        policy=policy,
    )

    # Step 5: capture-requirement mapping (fail-closed; empty w/o refs).
    map_capture_requirements(capture_specs, backend_manifest=backend_manifest, policy=policy)

    # Step 6: per-condition planning-only feasibility + snapshot digests.
    condition_snapshot_digests, flat_instantiated_digest = _plan_conditions(
        spec, scenario, backend_manifest=backend_manifest
    )

    # Step 7: source-set projection + digest.
    source_set_projection = _build_source_set_projection(
        spec=spec,
        task=task,
        task_artifact=task_artifact,
        effective_scenario_ref=effective_scenario_ref,
        scenario=scenario,
        scenario_artifact=scenario_artifact,
        scenario_canonical_digest=scenario_canonical_digest,
        capture_specs=capture_specs,
        capture_artifacts=capture_artifacts,
        flat_instantiated_digest=flat_instantiated_digest,
    )
    source_set_digest = compute_source_set_digest(source_set_projection)

    # Step 8: pure trial-plan expansion.
    plan = expand_trial_plan(
        spec,
        source_set_digest=source_set_digest,
        condition_snapshot_digests=condition_snapshot_digests or None,
        policy=policy,
    )

    # Step 9: create-once persistence + digest re-verification.
    persisted_path = _persist_plan(plan, run_store=run_store)

    # Step 10.
    return AdmissionResult.admit(
        plan=plan,
        plan_digest=plan.plan_digest,
        persisted_path=persisted_path,
        warnings=warnings,
        trial_ids=tuple(trial.planned_trial_id for trial in plan.trials),
    )


def admit_experiment(
    *,
    experiment_root: ResolvedArtifact,
    artifact_source: ResolvedArtifactSource,
    run_store: RunStorageBackend,
    policy: AdmissionPolicy,
    backend_manifest: BackendManifest | None = None,
    processor_manifest: ProcessorManifest | None = None,
) -> AdmissionResult:
    """Run ADR-047 admission for one experiment-authoring-input document.

    ALL-OR-NOTHING: any :class:`~aptl.core.experiment.errors.
    AdmissionRejection` raised anywhere in the sequence — by this function's
    own cross-artifact joins or by any Stage 1-4 module it calls — is
    caught here and converted to ``AdmissionResult.rejected(diagnostics)``.
    Nothing is persisted and no range mutation occurs on a rejected path;
    this function never calls ``.env`` hydration, ``EnvVars``, key/cert
    generation, a collector, a session, or any ``DeploymentBackend`` method
    at all, admitted or rejected (that is downstream EXECUTION work — see
    :class:`aptl.core.experiment.controller.ExperimentController`).

    A retry with the SAME admitted inputs recomputes the same deterministic
    plan (same ``plan_id``/``plan_digest``/``canonical_bytes``) and
    ``run_store.create_json_once`` treats the byte-identical existing
    target as idempotent success — this function does not special-case
    retries itself.
    """
    resolved_backend = backend_manifest if backend_manifest is not None else create_aptl_manifest()
    resolved_processor = (
        processor_manifest if processor_manifest is not None else create_reference_processor_manifest()
    )
    try:
        return _admit_experiment_inner(
            experiment_root=experiment_root,
            artifact_source=artifact_source,
            run_store=run_store,
            policy=policy,
            backend_manifest=resolved_backend,
            processor_manifest=resolved_processor,
        )
    except AdmissionRejection as exc:
        return AdmissionResult.rejected(exc.diagnostics)
