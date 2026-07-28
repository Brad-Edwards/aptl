"""Artifact route selection and satisfaction disclosure (ADR-050).

The disclosure exists so RAES's runtime non-approximation gate can prove APTL
realized what the author declared. These tests run that real gate
(``evaluate_artifact_realization``) rather than asserting on the payload shape,
because a payload that merely looks right but the gate rejects is worthless.

The decisive case is the substituted digest: a backend that realized a
*different* artifact must be caught, not disclosed as if it complied.
"""

from __future__ import annotations

from raes.artifact_requirements import (
    ArtifactIdentity,
    ArtifactRequirement,
    ArtifactSatisfactionRoute,
)
from raes.explicitness import ExplicitnessClass, ExplicitnessProvenance
from raes_contracts.contracts import (
    ArtifactAvailabilityContext,
    ArtifactRequirementAvailability,
)
from raes_contracts.planning import ChangeAction, ProvisionOp
from raes_contracts.runtime_state import RuntimeSnapshot, SnapshotEntry
from raes_processor.semantics.artifact_realization import evaluate_artifact_realization
from raes_processor.semantics.realization import CompiledRealizationRequirement

from aptl.backends.raes_artifact_mechanisms import (
    SOURCE_ARTIFACT_REQUIREMENT_KIND,
    exact_artifact_profile,
    exact_artifact_provenance_ref,
)
from aptl.backends.raes_artifact_satisfaction import satisfaction_payload, select_route
from aptl.backends.raes_manifest import create_aptl_manifest

_ADDRESS = "provision.node.target"
_DIGEST = "sha256:" + "3" * 64
_OTHER_DIGEST = "sha256:" + "4" * 64


def _identity(digest: str = _DIGEST) -> ArtifactIdentity:
    return ArtifactIdentity(
        artifact_id="example/app",
        version="1.0",
        digest=digest,
        media_type="application/vnd.oci.image.manifest.v1+json",
    )


def _contract() -> ArtifactRequirement:
    profile = exact_artifact_profile()
    return ArtifactRequirement(
        requirement_id="target-image",
        explicitness=ExplicitnessClass.EXACT,
        exact_artifact=_identity(),
        permitted_routes=[
            ArtifactSatisfactionRoute(
                mechanism=profile, acquisition="pull", timing="backend-preparation"
            )
        ],
    )


def _compiled(contract: ArtifactRequirement) -> CompiledRealizationRequirement:
    return CompiledRealizationRequirement(
        field_path="nodes.target.source.artifact_requirement",
        address=_ADDRESS,
        domain="runtime-realization",
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
        explicitness=ExplicitnessClass.EXACT,
        provenance=ExplicitnessProvenance.AUTHOR_DECLARED,
        governing_scope="#/nodes/target",
        artifact_requirement=contract,
    )


def _availability() -> ArtifactAvailabilityContext:
    return ArtifactAvailabilityContext(
        requirements=[
            ArtifactRequirementAvailability(
                address=_ADDRESS,
                available_artifact_digests=[_DIGEST],
                verified_integrity_refs=[_DIGEST],
                verified_provenance_refs=[exact_artifact_provenance_ref()],
            )
        ]
    )


def _evaluate(payload: dict[str, object] | None):
    """Run RAES's runtime gate over a disclosure attached to the snapshot."""

    contract = _contract()
    compiled = _compiled(contract)
    snapshot = RuntimeSnapshot(
        entries={
            _ADDRESS: SnapshotEntry(
                address=_ADDRESS,
                domain="runtime-realization",
                resource_type="node",
                payload={} if payload is None else {"artifact_satisfaction": payload},
            )
        }
    )
    return evaluate_artifact_realization(
        compiled,
        {
            _ADDRESS: ProvisionOp(
                address=_ADDRESS,
                action=ChangeAction.CREATE,
                resource_type="node",
                payload={},
            )
        },
        snapshot,
        manifest=create_aptl_manifest(),
        availability=_availability(),
    )


def test_route_selection_picks_an_advertised_route():
    """Selection intersects authored permission with manifest capability."""

    route = select_route(
        _contract(),
        create_aptl_manifest(),
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
    )

    assert route is not None
    assert route.mechanism.mechanism == "exact-artifact"
    assert (route.acquisition, route.timing) == ("pull", "backend-preparation")


def test_route_selection_refuses_an_unadvertised_route():
    """A route outside the manifest is refused, never silently swapped."""

    profile = exact_artifact_profile()
    contract = ArtifactRequirement(
        requirement_id="target-image",
        explicitness=ExplicitnessClass.EXACT,
        exact_artifact=_identity(),
        permitted_routes=[
            # Acquisition/timing pair APTL does not advertise.
            ArtifactSatisfactionRoute(
                mechanism=profile, acquisition="pull", timing="realization"
            )
        ],
    )

    assert (
        select_route(
            contract,
            create_aptl_manifest(),
            requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
        )
        is None
    )


def test_disclosure_of_the_realized_digest_passes_the_runtime_gate():
    """The happy path: what was realized matches what was authored."""

    payload = satisfaction_payload(
        _contract(),
        create_aptl_manifest(),
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
        realized_digest=_DIGEST,
    )
    diagnostic, provenance = _evaluate(payload)

    assert diagnostic is None, getattr(diagnostic, "message", "")
    assert provenance is not None


def test_a_substituted_digest_is_refused_rather_than_disclosed():
    """SEM-218 I2: realizing a different artifact must not be papered over."""

    payload = satisfaction_payload(
        _contract(),
        create_aptl_manifest(),
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
        realized_digest=_OTHER_DIGEST,
    )

    assert payload is None
    # And with no disclosure attached, the runtime gate rejects the apply.
    diagnostic, provenance = _evaluate(payload)
    assert diagnostic is not None
    assert diagnostic.code == "runtime.backend-contract-invalid"
    assert provenance is None


def test_missing_disclosure_is_rejected():
    """Omitting the disclosure entirely is also a contract violation."""

    diagnostic, _ = _evaluate(None)

    assert diagnostic is not None
    assert diagnostic.code == "runtime.backend-contract-invalid"
