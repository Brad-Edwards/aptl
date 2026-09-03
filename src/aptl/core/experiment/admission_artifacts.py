"""Artifact-source implementations for RAES experiment admission (ADR-047
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
  RAES associated-artifact manifest anchored to the authoring-input spec.
"""

from __future__ import annotations

import io
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from raes_contracts.associated_artifacts import (
    AssociatedArtifactManifestModel,
    AssociatedArtifactValidationLimits,
    load_associated_artifact_manifest_json,
    validate_associated_artifact_manifest,
)
from raes_contracts.contracts import (
    ExperimentReferenceModel,
    ParticipantImplementationBindingTargetModel,
)
from raes_contracts.experiment_spec import ExperimentSpecModel

from aptl.core.experiment.errors import AdmissionRejection, diagnostic, normalize_raes_failure
from aptl.core.experiment.bindings import (
    ParticipantManifestBinding,
    ParticipantManifestMap,
)
from aptl.core.experiment.policy import AdmissionPolicy
from aptl.core.experiment.resolver import (
    ProjectContainedResolver,
    ProjectFileLocator,
    ResolvedArtifact,
    parse_locator,
)
from aptl.core.experiment.spec_loading import load_participant_manifest

_CODE_ARTIFACT_SOURCE_UNRESOLVED = "aptl.experiment-admission.artifact-source-unresolved"
_CODE_ASSOCIATED_ARTIFACT_MANIFEST_INVALID = "aptl.experiment-admission.associated-artifact-manifest-invalid"


class ResolvedArtifactSource(Protocol):
    """The injectable seam admission resolves ``task_ref``/
    ``intended_scenario_ref`` (or ``task.scenario_ref``)/``capture_spec_refs``
    through — never a raw path admission could reopen.
    """

    participant_manifests: ParticipantManifestMap

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
    ResolvedArtifact``) for tests — no filesystem, no RAES associated-
    artifact manifest. Production admission uses
    :func:`build_associated_artifact_source` instead.
    """

    artifacts: Mapping[str, ResolvedArtifact]
    participant_manifests: ParticipantManifestMap = field(default_factory=dict)

    def artifact_for(self, ref: ExperimentReferenceModel) -> ResolvedArtifact:
        """Return the mapped artifact for ref.ref_id, or raise the unresolved rejection."""
        try:
            return self.artifacts[ref.ref_id]
        except KeyError:
            raise _unresolved(ref) from None


def _expected_participant_manifest_keys(
    spec: ExperimentSpecModel,
) -> set[tuple[str, str, str, str]]:
    """Return participant manifest identities explicitly required by bindings."""

    descriptors = spec.binding_descriptors
    if descriptors is None:
        return set()
    return {
        (
            target.participant_address,
            target.implementation_name,
            target.implementation_version,
            target.manifest_version,
        )
        for descriptor in descriptors.descriptors
        if isinstance(
            (target := descriptor.target),
            ParticipantImplementationBindingTargetModel,
        )
    }


def _resolved_participant_manifests(
    *,
    spec: ExperimentSpecModel,
    manifest: AssociatedArtifactManifestModel,
    artifacts: Mapping[str, ResolvedArtifact],
    policy: AdmissionPolicy,
) -> dict[tuple[str, str, str, str], ParticipantManifestBinding]:
    """Resolve unique expected participant manifests from validated artifacts."""

    expected = _expected_participant_manifest_keys(spec)
    expected_identities = {(name, version, schema) for _, name, version, schema in expected}
    candidates: dict[
        tuple[str, str, str],
        ParticipantManifestBinding,
    ] = {}
    for artifact_id, artifact_ref in manifest.artifacts.items():
        if artifact_ref.role != "manifest":
            continue
        resolved = artifacts[artifact_id]
        model = load_participant_manifest(resolved.data, policy=policy)
        if model is None:
            continue
        identity = (
            model.identity.name,
            model.identity.version,
            model.schema_version,
        )
        if identity not in expected_identities:
            continue
        if identity in candidates:
            raise AdmissionRejection(
                (
                    diagnostic(
                        _CODE_ASSOCIATED_ARTIFACT_MANIFEST_INVALID,
                        "associated_artifact_manifest.artifacts",
                        "multiple participant manifests resolve the same implementation identity",
                    ),
                )
            )
        candidates[identity] = ParticipantManifestBinding(
            manifest=model,
            manifest_ref=artifact_id,
            manifest_digest=resolved.digest,
        )

    return {
        key: candidates[(key[1], key[2], key[3])]
        for key in expected
        if (key[1], key[2], key[3]) in candidates
    }


def build_associated_artifact_source(
    base_dir: Path,
    manifest_relative_path: str,
    spec: ExperimentSpecModel,
    policy: AdmissionPolicy,
) -> ResolvedArtifactSource:
    """Build the production :class:`ResolvedArtifactSource`.

    The ADR-blessed binding: a RAES associated-artifact manifest anchored
    to the authoring-input ``spec`` (``parent_ref.ref_kind ==
    "authoring-input"``) binds each artifact's ``artifact_id`` -> a
    project-relative ``uri`` plus declared ``size_bytes``/``checksum`` — by
    APTL convention, ``artifact_id`` IS the RAES reference's ``ref_id`` it
    binds (``spec.task_ref.ref_id``, ``spec.intended_scenario_ref.ref_id``
    or ``task.scenario_ref.ref_id``, each ``capture_spec_refs[].ref_id``).
    Every declared artifact is resolved via :class:`ProjectContainedResolver`
    (offline, no-follow, bounded, digest-verified), then the WHOLE manifest
    is validated in one shot through ``validate_associated_artifact_manifest``
    (identity, set-digest, per-artifact size/checksum) before anything is
    handed back — a validation failure anywhere rejects the whole source,
    never a partial binding.

    ``spec`` must already be the RAES-validated authoring-input model (the
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
            normalize_raes_failure(
                exc,
                address="associated_artifact_manifest",
                code=_CODE_ASSOCIATED_ARTIFACT_MANIFEST_INVALID,
            )
        ) from exc

    resolved_by_artifact_id: dict[str, ResolvedArtifact] = {}
    readers: dict[str, io.BytesIO] = {}
    for artifact_id, artifact_ref in manifest.artifacts.items():
        # RAES requires `uri` to be an absolute URI (a scheme is mandatory —
        # see `raes_contracts.contracts._validate_associated_artifact_uri`),
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

    participant_manifests = _resolved_participant_manifests(
        spec=spec,
        manifest=manifest,
        artifacts=resolved_by_artifact_id,
        policy=policy,
    )
    return MappingArtifactSource(
        artifacts=resolved_by_artifact_id,
        participant_manifests=participant_manifests,
    )
