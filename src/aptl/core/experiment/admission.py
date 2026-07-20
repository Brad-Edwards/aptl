"""The ACES experiment admission coordinator (ADR-047 "Experiment-controller
boundary", Stage 5 / EXP-002 / issue #438).

This module wires the previously-landed Stage 1-4 modules
(``errors``, ``policy``, ``resolver``, ``spec_loading``, ``apparatus``,
``capture_mapping``, ``trial_plan``) — plus this stage's own
:mod:`aptl.core.experiment.admission_artifacts` (artifact-source
implementations) and :mod:`aptl.core.experiment.admission_steps`
(cross-artifact joins, per-condition planning, source-set projection),
split out to keep this module under the 500-line budget — into one
all-or-nothing admission sequence: :func:`admit_experiment`. It performs
ONLY:

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

Public import surface (also relied on by ``controller.py`` and tests):
``admit_experiment``, ``AdmissionResult``, ``ResolvedArtifact``,
``ResolvedArtifactSource``, ``MappingArtifactSource``,
``build_associated_artifact_source`` — ``ResolvedArtifact`` is defined in
:mod:`aptl.core.experiment.resolver`, the other three re-exported names are
defined in :mod:`aptl.core.experiment.admission_artifacts`; all are
re-exported here.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from aces_backend_protocols.manifest import BackendManifest
from aces_contracts.diagnostics import Diagnostic
from aces_processor.capabilities import ProcessorManifest
from aces_processor.manifest import create_reference_processor_manifest

from aptl.backends.aces_manifest import create_aptl_manifest
from aptl.core.experiment.admission_artifacts import (
    MappingArtifactSource,
    ResolvedArtifactSource,
    build_associated_artifact_source,
)
from aptl.core.experiment.admission_steps import (
    CaptureResolution,
    ScenarioResolution,
    TaskResolution,
    _build_source_set_projection,
    _check_scenario_identity,
    _check_task_identity,
    _effective_scenario_ref,
    _plan_conditions,
    _resolve_capture_specs,
)
from aptl.core.experiment.apparatus import check_apparatus_admission
from aptl.core.experiment.capture_mapping import map_capture_requirements
from aptl.core.experiment.errors import AdmissionRejection, diagnostic
from aptl.core.experiment.policy import AdmissionPolicy
from aptl.core.experiment.resolver import ResolvedArtifact
from aptl.core.experiment.spec_loading import load_experiment_root, load_task, parse_scenario_bytes
from aptl.core.experiment.trial_plan import TrialPlan, compute_source_set_digest, expand_trial_plan
from aptl.core.runstore import RunStorageBackend
from aptl.utils.pathsafe import PathContainmentError

__all__ = [
    "AdmissionResult",
    "MappingArtifactSource",
    "ResolvedArtifact",
    "ResolvedArtifactSource",
    "admit_experiment",
    "build_associated_artifact_source",
]

_ADDRESS_PLAN_PERSISTENCE = "trial_plan.persistence"

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
        """Build a REJECTED result carrying diagnostics and no plan."""
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
        """Build an ADMITTED result carrying the persisted plan, its digest/path, and any warnings."""
        return cls(
            admitted=True,
            plan=plan,
            plan_digest=plan_digest,
            persisted_path=persisted_path,
            warnings=tuple(warnings),
            trial_ids=tuple(trial_ids),
        )


# ---------------------------------------------------------------------------
# admit_experiment
# ---------------------------------------------------------------------------


def _reject(code: str, address: str, message: str) -> AdmissionRejection:
    """Build a one-diagnostic AdmissionRejection for a plan-persistence failure."""
    return AdmissionRejection((diagnostic(code, address, message),))


def _persist_plan(plan: TrialPlan, *, run_store: RunStorageBackend) -> Path:
    """Create-once persist plan's canonical bytes and re-verify the written bytes match exactly."""
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
    """Run the full admission sequence once; raises AdmissionRejection on any fail-closed gap."""
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
        task=TaskResolution(task=task, artifact=task_artifact),
        scenario=ScenarioResolution(
            effective_ref=effective_scenario_ref,
            scenario=scenario,
            artifact=scenario_artifact,
            canonical_digest=scenario_canonical_digest,
        ),
        capture=CaptureResolution(specs=capture_specs, artifacts=capture_artifacts),
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
