"""APTL's declared RAES artifact-satisfaction mechanisms (ADR-050, RAES ADR-098).

Two things matter here and they pull in opposite directions:

* CAPABILITY IS REAL — an authored ``exact`` artifact requirement whose digest is
  available must be admitted by RAES's own planner gate against APTL's real
  manifest, otherwise declaring the mechanism bought nothing.
* CAPABILITY IS NOT OVERCLAIMED — SEM-218 I4 permits declaring a mechanism only
  once APTL can materialize *and* independently read it back. Mechanisms whose
  implementation does not exist yet must be refused loudly rather than quietly
  accepted, and an ``open`` posture must be refused because APTL declares
  CONSTRAINED support.

The gate under test is RAES's ``artifact_requirement_diagnostics``, not an
APTL reimplementation of it.
"""

from __future__ import annotations

import json

from raes.artifact_requirements import (
    ArtifactIdentity,
    ArtifactLockedInput,
    ArtifactMaterializationSpecification,
    ArtifactMechanismProfile,
    ArtifactRequirement,
    ArtifactSatisfactionRoute,
)
from raes.explicitness import ExplicitnessClass, ExplicitnessProvenance
from raes_contracts.contracts import (
    ArtifactAvailabilityContext,
    ArtifactRequirementAvailability,
)
from raes_processor.semantics.artifact_realization import artifact_requirement_diagnostics
from raes_processor.semantics.realization import CompiledRealizationRequirement

from aptl.backends.raes_artifact_mechanisms import (
    SOURCE_ARTIFACT_REQUIREMENT_KIND,
    aptl_artifact_mechanisms,
    dynamic_composition_profile,
    exact_artifact_profile,
)
from aptl.backends.raes_manifest import create_aptl_manifest

_ADDRESS = "nodes.wazuh-manager"
_DIGEST = "sha256:" + "a" * 64


def _requirement(
    *,
    explicitness: ExplicitnessClass,
    route: ArtifactSatisfactionRoute,
    exact: ArtifactIdentity | None = None,
) -> CompiledRealizationRequirement:
    """Return one compiled source-artifact requirement at ``_ADDRESS``."""

    return CompiledRealizationRequirement(
        field_path=f"{_ADDRESS}.source.artifact_requirement",
        address=_ADDRESS,
        domain="runtime-realization",
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
        explicitness=explicitness,
        provenance=ExplicitnessProvenance.AUTHOR_DECLARED,
        governing_scope="#/nodes/wazuh-manager",
        artifact_requirement=ArtifactRequirement(
            requirement_id="wazuh-manager-image",
            explicitness=explicitness,
            exact_artifact=exact,
            permitted_routes=[route],
        ),
    )


def _exact_route() -> ArtifactSatisfactionRoute:
    """Return a route matching APTL's declared exact-artifact capability."""

    return ArtifactSatisfactionRoute(
        mechanism=exact_artifact_profile(),
        acquisition="pull",
        timing="backend-preparation",
    )


def _dynamic_composition_route() -> ArtifactSatisfactionRoute:
    """Return a route matching APTL's declared dynamic-composition capability."""

    return ArtifactSatisfactionRoute(
        mechanism=dynamic_composition_profile(),
        acquisition="local-lookup",
        timing="realization",
    )


def _availability(digests: list[str]) -> ArtifactAvailabilityContext:
    """Return address-scoped availability facts carrying ``digests``."""

    return ArtifactAvailabilityContext(
        requirements=[
            ArtifactRequirementAvailability(
                address=_ADDRESS, available_artifact_digests=digests
            )
        ]
    )


def _codes(requirement: CompiledRealizationRequirement, availability) -> list[str]:
    """Return diagnostic codes RAES raises for one requirement against APTL."""

    return [
        d.code
        for d in artifact_requirement_diagnostics(
            (requirement,), create_aptl_manifest(), availability=availability
        )
    ]


def test_profile_digest_is_the_canonical_body_hash():
    """The advertised digest is reproducible from the profile body, not invented."""

    profile = exact_artifact_profile()
    assert profile.digest.startswith("sha256:")
    assert len(profile.digest) == len("sha256:") + 64
    # Stable across calls: capability identity must not drift per-process.
    assert profile.digest == exact_artifact_profile().digest


def test_manifest_declares_only_mechanisms_backed_by_readback():
    """SEM-218 I4: no mechanism is advertised before its readback exists."""

    declared = {c.mechanism.mechanism for c in aptl_artifact_mechanisms()}
    assert declared == {
        "exact-artifact",
        "materialization-specification",
        "dynamic-composition",
    }
    # dynamic-composition is backed now: raes 3.1.0 lowers the runtime concerns
    # (OpenRAE/rae#985) and APTL reads each declared dimension back off the
    # realized container (issue #876), satisfying the I4 precondition.
    assert "dynamic-composition" in declared


def test_declared_routes_are_explicit_pairs_not_a_cartesian_product():
    """ADR-098 §3 forbids unjoined mechanism/acquisition/timing lists."""

    capability = aptl_artifact_mechanisms()[0]
    pairs = {(r.acquisition, r.timing) for r in capability.supported_routes}
    assert pairs == {
        ("pull", "backend-preparation"),
        ("local-lookup", "backend-preparation"),
    }
    # Nothing claims realization-time acquisition, which APTL does not do.
    assert all(r.timing != "realization" for r in capability.supported_routes)


def test_dynamic_composition_declares_one_honest_local_lookup_realization_route():
    """Generic composition is resolved locally and applied at realization time,
    and claims no other acquisition/timing combination (issue #876)."""

    capability = next(
        c
        for c in aptl_artifact_mechanisms()
        if c.mechanism.mechanism == "dynamic-composition"
    )
    assert capability.mechanism.digest.startswith("sha256:")
    pairs = {(r.acquisition, r.timing) for r in capability.supported_routes}
    assert pairs == {("local-lookup", "realization")}


def test_available_exact_artifact_is_admitted():
    """An authored exact pin whose digest is available passes RAES admission."""

    requirement = _requirement(
        explicitness=ExplicitnessClass.EXACT,
        route=_exact_route(),
        exact=ArtifactIdentity(
            artifact_id="wazuh/wazuh-manager",
            version="4.12.0",
            digest=_DIGEST,
            media_type="application/vnd.docker.distribution.manifest.v2+json",
        ),
    )

    assert _codes(requirement, _availability([_DIGEST])) == []


def test_unavailable_exact_artifact_is_rejected_not_substituted():
    """ADR-098 §2.1: missing exact bytes are rejection, never fallback."""

    requirement = _requirement(
        explicitness=ExplicitnessClass.EXACT,
        route=_exact_route(),
        exact=ArtifactIdentity(
            artifact_id="wazuh/wazuh-manager",
            version="4.12.0",
            digest=_DIGEST,
            media_type="application/vnd.docker.distribution.manifest.v2+json",
        ),
    )

    assert "artifact.unavailable-exact-artifact" in _codes(requirement, _availability([]))


def test_open_posture_is_admitted_now_that_dynamic_composition_is_supported():
    """APTL declares open-realization support, so a dynamic-composition open
    requirement is admitted rather than refused (issue #876)."""

    requirement = _requirement(
        explicitness=ExplicitnessClass.OPEN, route=_dynamic_composition_route()
    )

    codes = _codes(requirement, _availability([]))
    assert "artifact.unsupported-open-realization" not in codes
    assert "artifact.unsupported-backend-mechanism" not in codes


def test_undeclared_mechanism_route_is_refused():
    """A per-component build route APTL never advertised must not be admitted.

    This is the honesty guard for the purpose-built component image: until
    APTL implements and reads back ``materialization-specification``, authoring
    one must fail admission rather than fall through to some other route.
    """

    build_profile = ArtifactMechanismProfile(
        mechanism="materialization-specification",
        profile="aptl-component-build",
        version="1",
        digest="sha256:" + "b" * 64,
    )
    requirement = CompiledRealizationRequirement(
        field_path=f"{_ADDRESS}.source.artifact_requirement",
        address=_ADDRESS,
        domain="runtime-realization",
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
        explicitness=ExplicitnessClass.CONSTRAINED,
        provenance=ExplicitnessProvenance.AUTHOR_DECLARED,
        governing_scope="#/nodes/ad",
        artifact_requirement=ArtifactRequirement(
            requirement_id="ad-component-image",
            explicitness=ExplicitnessClass.CONSTRAINED,
            locked_inputs=[
                ArtifactLockedInput(
                    input_id="rootfs",
                    artifact=ArtifactIdentity(
                        artifact_id="ubuntu",
                        version="22.04",
                        digest="sha256:" + "c" * 64,
                        media_type="application/vnd.oci.image.layer.v1.tar+gzip",
                    ),
                    associated_artifact_manifest_ref="associated-artifact-manifest-v1:rootfs",
                    trust_policy_ref="reusable-asset-trust-policy-v1#associated_artifact_set",
                )
            ],
            materialization_specifications=[
                ArtifactMaterializationSpecification(
                    specification_id="ad-samba-dc",
                    profile=build_profile,
                    digest="sha256:" + "d" * 64,
                    locked_input_ids=["rootfs"],
                )
            ],
            permitted_routes=[
                ArtifactSatisfactionRoute(
                    mechanism=build_profile,
                    acquisition="none",
                    timing="backend-preparation",
                )
            ],
        ),
    )

    availability = ArtifactAvailabilityContext(
        requirements=[
            ArtifactRequirementAvailability(
                address=_ADDRESS,
                verified_locked_input_ids=["rootfs"],
                available_materialization_specification_digests=["sha256:" + "d" * 64],
            )
        ]
    )

    assert "artifact.unsupported-backend-mechanism" in _codes(requirement, availability)


def test_manifest_still_serializes_under_the_published_v2_contract():
    """Adding artifact mechanisms must not break backend-manifest-v2 shape gates."""

    from raes_backend_protocols.manifest import backend_manifest_v2_model

    model = backend_manifest_v2_model(create_aptl_manifest())
    payload = json.loads(model.model_dump_json())
    declarations = payload["realization_support"]
    mechanisms = [m for d in declarations for m in d.get("artifact_mechanisms", [])]
    # Two exact-artifact profiles: OCI pull (images) and env-pack copy (content).
    assert sorted(m["mechanism"]["mechanism"] for m in mechanisms) == [
        "dynamic-composition",
        "exact-artifact",
        "exact-artifact",
        "materialization-specification",
    ]
    assert sorted(m["mechanism"]["profile"] for m in mechanisms) == [
        "aptl-contained-component-build",
        "aptl-generic-substrate-composition",
        "aptl-oci-exact-pull",
        "raes-env-pack-exact-copy",
    ]
