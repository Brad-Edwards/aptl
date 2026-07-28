"""Assemble the RAES ``ExperimentApparatusContextModel`` from owner-native
manifests (#437/#459 → EXP-009 / ADR-044).

The run record's apparatus context is a portable RAES projection of the realized
instrument. This builder composes it from the code-owned backend and processor
manifests (``create_aptl_manifest`` / ``create_reference_processor_manifest``)
plus the observing clock — it mirrors no RAES fields it does not own and adds no
second apparatus schema. A participant-implementation component is included when
participant provenance is supplied, so the run's participant provenance
requirement is satisfied consistently.
"""

from __future__ import annotations

from raes_contracts.contracts import (
    ExperimentApparatusComponentModel,
    ExperimentApparatusContextModel,
    ExperimentApparatusCompatibilityReferenceModel,
    ExperimentArtifactRefModel,
    ExperimentChecksumModel,
    ExperimentClockContextModel,
    ExperimentMeasurementChannelReferenceModel,
    ExperimentParameterModel,
    ExperimentReferenceModel,
    ExperimentStochasticControlModel,
    ExperimentValidityNoteModel,
)
from raes_contracts.contracts.capabilities import ApparatusIdentityModel
from raes_contracts.contracts.experiment_manifest_references import (
    ExperimentManifestReferenceModel,
)

_BACKEND_MANIFEST_VERSION = "backend-manifest/v2"
_PROCESSOR_MANIFEST_VERSION = "processor-manifest/v2"
_PARTICIPANT_MANIFEST_VERSION = "participant-implementation-manifest/v1"

#: A zero-length setup-attestation digest is honest: the apparatus context
#: references the setup evidence by role/identity, and the actual bytes are
#: sealed as run evidence, not embedded here.
_EMPTY_SHA256 = "0" * 64


def _component(
    *, component_kind: str, name: str, version: str, manifest_version: str
) -> ExperimentApparatusComponentModel:
    return ExperimentApparatusComponentModel(
        component_kind=component_kind,
        identity=ApparatusIdentityModel(name=name, version=version),
        manifest_ref=ExperimentManifestReferenceModel(
            ref_kind="manifest",
            ref_id=name,
            ref_version=manifest_version,
            subject_ref=ExperimentReferenceModel(
                ref_kind=component_kind, ref_id=name, ref_version=version
            ),
        ),
        observed=True,
    )


def build_apparatus_context(
    *,
    apparatus_context_id: str,
    declared_at: str,
    clock: ExperimentClockContextModel,
    backend_name: str = "aptl",
    backend_version: str = "0.1.0",
    processor_name: str = "raes-reference-processor",
    processor_version: str = "2.0.0",
    participant: tuple[str, str] | None = None,
    context_version: str = "1.0.0",
) -> ExperimentApparatusContextModel:
    """Return the portable apparatus context for a realized APTL run.

    ``participant`` is an optional ``(name, version)`` for the realized
    participant-implementation component; supply it whenever participant
    provenance is recorded so the RAES run model's participant requirement holds.
    """
    processor = _component(
        component_kind="processor",
        name=processor_name,
        version=processor_version,
        manifest_version=_PROCESSOR_MANIFEST_VERSION,
    )
    backend = _component(
        component_kind="backend",
        name=backend_name,
        version=backend_version,
        manifest_version=_BACKEND_MANIFEST_VERSION,
    )
    components = {"processor": processor, "backend": backend}
    selected_manifests = [processor.manifest_ref, backend.manifest_ref]
    if participant is not None:
        name, version = participant
        participant_component = _component(
            component_kind="participant-implementation",
            name=name,
            version=version,
            manifest_version=_PARTICIPANT_MANIFEST_VERSION,
        )
        components["participant"] = participant_component
        selected_manifests.append(participant_component.manifest_ref)

    setup_evidence = ExperimentArtifactRefModel(
        artifact_id="apparatus-setup-attestation",
        role="apparatus-evidence",
        media_type="application/json",
        uri=f"apparatus/{apparatus_context_id}.json",
        checksum=ExperimentChecksumModel(algorithm="sha256", value=_EMPTY_SHA256),
        size_bytes=0,
        created_at=declared_at,
        source="aptl backend apparatus projection",
        sensitivity="internal",
    )

    return ExperimentApparatusContextModel(
        schema_version="experiment-apparatus-context/v1",
        apparatus_context_id=apparatus_context_id,
        context_version=context_version,
        declared_at=declared_at,
        components=components,
        selected_manifests=selected_manifests,
        compatibility_declarations=[
            ExperimentApparatusCompatibilityReferenceModel(
                ref_kind="capability", ref_id="workflow-results"
            ),
            ExperimentApparatusCompatibilityReferenceModel(
                ref_kind="capability", ref_id="evaluation-results"
            ),
        ],
        configuration_parameters=[
            ExperimentParameterModel(name="backend", value=backend_name, value_kind="apparatus")
        ],
        stochastic_controls=[
            ExperimentStochasticControlModel(
                control_id="apparatus-baseline",
                role="other",
                description="Apparatus-level determinism baseline.",
            )
        ],
        clocks=[clock],
        measurement_channels=[
            ExperimentMeasurementChannelReferenceModel(
                ref_kind="measurement-channel",
                ref_id="evaluation-history-channel",
                ref_version="1.0.0",
            )
        ],
        observed_setup_evidence=[setup_evidence],
        known_limitations=[
            ExperimentValidityNoteModel(
                category="apparatus",
                note="APTL backend apparatus projection; fidelity is scenario-dependent.",
            )
        ],
    )
