"""Artifact-source implementations for ACES experiment admission (ADR-047
"Experiment-controller boundary", Stage 5 / EXP-002 / issue #438).

Split out of :mod:`aptl.core.experiment.admission` to keep that module
under the 500-line budget (``python:S104``). ``ResolvedArtifactSource``,
``MappingArtifactSource``, and ``build_associated_artifact_source`` are
re-exported from ``admission`` for the public import surface (tests and
``controller.py`` import them from ``aptl.core.experiment.admission``);
this module is the implementation home, not a second public entry point.

Two implementations of the ``ResolvedArtifactSource`` seam admission
resolves ``task_ref``/``intended_scenario_ref``/``capture_spec_refs``
through:

* :class:`MappingArtifactSource` — a simple in-memory mapping, for tests.
* :func:`build_associated_artifact_source` — the production binding, via an
  ACES associated-artifact manifest anchored to the authoring-input spec.
"""

from __future__ import annotations

import io
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from aces_contracts.associated_artifacts import (
    AssociatedArtifactManifestModel,
    AssociatedArtifactValidationLimits,
    load_associated_artifact_manifest_json,
    validate_associated_artifact_manifest,
)
from aces_contracts.contracts import ExperimentReferenceModel
from aces_contracts.experiment_spec import ExperimentSpecModel

from aptl.core.experiment.errors import AdmissionRejection, diagnostic, normalize_aces_failure
from aptl.core.experiment.policy import AdmissionPolicy
from aptl.core.experiment.resolver import (
    ProjectContainedResolver,
    ProjectFileLocator,
    ResolvedArtifact,
    parse_locator,
)

_CODE_ARTIFACT_SOURCE_UNRESOLVED = "aptl.experiment-admission.artifact-source-unresolved"
_CODE_ASSOCIATED_ARTIFACT_MANIFEST_INVALID = "aptl.experiment-admission.associated-artifact-manifest-invalid"


class ResolvedArtifactSource(Protocol):
    """The injectable seam admission resolves ``task_ref``/
    ``intended_scenario_ref`` (or ``task.scenario_ref``)/``capture_spec_refs``
    through — never a raw path admission could reopen.
    """

    def artifact_for(self, ref: ExperimentReferenceModel) -> ResolvedArtifact:
        """Return the bound artifact for ref's reference identity, or raise AdmissionRejection."""
        ...


def _unresolved(ref: ExperimentReferenceModel) -> AdmissionRejection:
    """Build the fail-closed rejection for a reference with no bound artifact."""
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
        """Return the mapped artifact for ref.ref_id, or raise the unresolved rejection."""
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
