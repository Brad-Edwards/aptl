"""The experiment-controller composition boundary (ADR-047
"Experiment-controller boundary", Stage 5 / EXP-002 / issue #438).

:class:`ExperimentController` is a coordinator, not a runtime manager
(ADR-047: "Do not split it into speculative repository, service, provider,
DTO, and policy hierarchies"). Its dependencies are explicit constructor
inputs — the configured :class:`~aptl.core.runstore.RunStorageBackend`, an
:class:`~aptl.core.experiment.policy.AdmissionPolicy`, and the canonical
processor/backend manifests — never a deployment backend. ``Deployment is
not an admission dependency`` (ADR-047): this module does not import
``DeploymentBackend``, ``EnvVars``, ``.env`` hydration, key/cert
generation, a collector, or a session at all.

``.admit()`` is the ONLY public operation and it delegates to
:func:`aptl.core.experiment.admission.admit_experiment`. EXECUTION —
actually running the admitted plan's trials — is downstream work
(issues #437/#459) that consumes an :class:`~aptl.core.experiment.
admission.AdmissionResult`'s ``plan``; it is intentionally NOT implemented
here, and this class holds no ``PENDING``/``RUNNING``/``FAILED`` execution
state (ADR-047 "Persistence and state model": "Do not create
PENDING/RUNNING/FAILED experiment-controller states that duplicate those
incumbents").
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from aces_backend_protocols.manifest import BackendManifest
from aces_contracts.experiment_spec import ExperimentSpecModel
from aces_processor.capabilities import ProcessorManifest
from aces_processor.manifest import create_reference_processor_manifest

from aptl.backends.aces_manifest import create_aptl_manifest
from aptl.core.experiment.admission import (
    AdmissionResult,
    ResolvedArtifact,
    ResolvedArtifactSource,
    admit_experiment,
    build_associated_artifact_source,
)
from aptl.core.experiment.errors import AdmissionRejection
from aptl.core.experiment.policy import AdmissionPolicy, default_admission_policy
from aptl.core.experiment.spec_loading import load_experiment_root
from aptl.core.runstore import RunStorageBackend

#: Factory signature for the production `ResolvedArtifactSource`: given the
#: project root, a manifest locator, the already-parsed authoring-input
#: spec, and the active policy, return a ready artifact source. Matches
#: :func:`aptl.core.experiment.admission.build_associated_artifact_source`.
ArtifactSourceFactory = Callable[[Path, str, ExperimentSpecModel, AdmissionPolicy], ResolvedArtifactSource]


@dataclass
class ExperimentController:
    """The single composition boundary above lab lifecycle for ADR-047
    experiment admission.

    All dependencies are explicit and injected — none are constructed
    ambiently. ``artifact_source_factory`` defaults to the production
    associated-artifact-manifest-backed resolver
    (:func:`build_associated_artifact_source`); tests can inject a factory
    that returns a :class:`~aptl.core.experiment.admission.
    MappingArtifactSource` instead.
    """

    run_store: RunStorageBackend
    policy: AdmissionPolicy | None = None
    backend_manifest: BackendManifest | None = None
    processor_manifest: ProcessorManifest | None = None
    artifact_source_factory: ArtifactSourceFactory = build_associated_artifact_source

    def __post_init__(self) -> None:
        # Resolved to concrete defaults here (rather than in the field
        # declarations) so every instance genuinely owns its own policy/
        # manifest objects and a caller inspecting `.policy` after
        # construction never sees `None`.
        if self.policy is None:
            self.policy = default_admission_policy()
        if self.backend_manifest is None:
            self.backend_manifest = create_aptl_manifest()
        if self.processor_manifest is None:
            self.processor_manifest = create_reference_processor_manifest()

    def admit(
        self,
        *,
        experiment_root: ResolvedArtifact,
        base_dir: Path,
        manifest_locator: str,
    ) -> AdmissionResult:
        """Run ADR-047 admission for one experiment-authoring-input document.

        This is the ADMISSION phase only (bounded loading, cross-artifact
        joins, apparatus/capture capability checks, planning-only
        feasibility, deterministic plan expansion, create-once persistence
        with digest re-verification). It never raises
        :class:`~aptl.core.experiment.errors.AdmissionRejection` — every
        rejection anywhere in the sequence, including while building the
        artifact source below, is returned as
        ``AdmissionResult.rejected(diagnostics)``.

        EXECUTION (actually running the admitted plan's trials against
        ``RuntimeManager``/lab lifecycle) is downstream work in #437/#459
        that consumes the returned ``AdmissionResult.plan``; it is not
        implemented by this method.

        ``base_dir``/``manifest_locator`` describe where the production
        associated-artifact manifest binding the experiment's task/scenario/
        capture-spec references to project files lives — see
        :func:`aptl.core.experiment.admission.build_associated_artifact_source`.
        A test-injected ``artifact_source_factory`` may ignore them.
        """
        try:
            spec = load_experiment_root(experiment_root.data, policy=self.policy)
            artifact_source = self.artifact_source_factory(base_dir, manifest_locator, spec, self.policy)
        except AdmissionRejection as exc:
            return AdmissionResult.rejected(exc.diagnostics)

        return admit_experiment(
            experiment_root=experiment_root,
            artifact_source=artifact_source,
            run_store=self.run_store,
            policy=self.policy,
            backend_manifest=self.backend_manifest,
            processor_manifest=self.processor_manifest,
        )
