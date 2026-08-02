"""Route-3 dynamic-composition artifact satisfaction (issue #876, ADR-051 route 3).

A node whose ``source.artifact_requirement`` is ``open`` with a
``dynamic-composition`` route composes onto the generic substrate rather than
selecting a container image. These tests run the REAL RAES admission
(``artifact_requirement_diagnostics``) and runtime
(``evaluate_artifact_realization``) gates, not payload-shape assertions: the
disclosure represents the daemon-verified substrate, and a node whose container
is not running that exact substrate -- or whose substrate cannot be resolved --
must fail closed rather than be papered over.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from raes.artifact_requirements import ArtifactRequirement, ArtifactSatisfactionRoute
from raes.explicitness import ExplicitnessClass, ExplicitnessProvenance
from raes.runtime_configuration import RuntimeConfiguration
from raes_contracts.contracts import (
    ArtifactAvailabilityContext,
    ArtifactRequirementAvailability,
)
from raes_contracts.planning import (
    ChangeAction,
    PlannedResource,
    ProvisionOp,
    RuntimeDomain,
)
from raes_contracts.runtime_state import RuntimeSnapshot, SnapshotEntry
from raes_processor.semantics.artifact_realization import (
    artifact_requirement_diagnostics,
    evaluate_artifact_realization,
)
from raes_processor.semantics.realization import CompiledRealizationRequirement

from aptl.backends.raes_artifact_mechanisms import (
    SOURCE_ARTIFACT_REQUIREMENT_KIND,
    dynamic_composition_profile,
    dynamic_composition_provenance_ref,
    exact_artifact_profile,
    is_dynamic_composition_requirement,
    route_is_dynamic_composition,
)
from aptl.backends.raes_artifact_satisfaction import (
    satisfaction_payload,
    satisfactions_for_plan,
    select_route,
)
from aptl.backends.raes_image_realization import resolve_node_image
from aptl.backends.raes_manifest import create_aptl_manifest
from aptl.backends.raes_substrate import SubstrateIdentity, resolve_substrate

_ADDRESS = "provision.node.web"
_SUBSTRATE_DIGEST = "sha256:" + "5" * 64
_OTHER_DIGEST = "sha256:" + "6" * 64
_MANIFEST_MEDIA = "application/vnd.oci.image.manifest.v1+json"
_CONFIG_MEDIA = "application/vnd.oci.image.config.v1+json"


def _dc_route() -> ArtifactSatisfactionRoute:
    return ArtifactSatisfactionRoute(
        mechanism=dynamic_composition_profile(),
        acquisition="local-lookup",
        timing="realization",
    )


def _dc_contract() -> ArtifactRequirement:
    return ArtifactRequirement(
        requirement_id="web-node",
        explicitness=ExplicitnessClass.OPEN,
        permitted_routes=[_dc_route()],
    )


def _exact_route() -> ArtifactSatisfactionRoute:
    # An APTL-supported exact-artifact route (see exact_artifact_capability).
    return ArtifactSatisfactionRoute(
        mechanism=exact_artifact_profile(),
        acquisition="pull",
        timing="backend-preparation",
    )


def _dc_compiled(contract: ArtifactRequirement) -> CompiledRealizationRequirement:
    return CompiledRealizationRequirement(
        field_path="nodes.web.source.artifact_requirement",
        address=_ADDRESS,
        domain="runtime-realization",
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
        explicitness=ExplicitnessClass.OPEN,
        provenance=ExplicitnessProvenance.AUTHOR_DECLARED,
        governing_scope="#/nodes/web/source/artifact_requirement",
        artifact_requirement=contract,
    )


def _substrate(digest: str = _SUBSTRATE_DIGEST) -> SubstrateIdentity:
    return SubstrateIdentity(
        artifact_id="aptl-generic-substrate",
        version="linux.debian.base",
        digest=digest,
        media_type=_CONFIG_MEDIA,
    )


def _dc_availability(
    *, digest: str = _SUBSTRATE_DIGEST, provenance: list[str] | None = None
) -> ArtifactAvailabilityContext:
    return ArtifactAvailabilityContext(
        requirements=[
            ArtifactRequirementAvailability(
                address=_ADDRESS,
                available_artifact_digests=[digest],
                verified_integrity_refs=[digest],
                verified_provenance_refs=(
                    [dynamic_composition_provenance_ref()]
                    if provenance is None
                    else provenance
                ),
            )
        ]
    )


def _evaluate(payload, *, availability: ArtifactAvailabilityContext):
    """Run RAES's runtime gate over a disclosure attached to the snapshot."""

    compiled = _dc_compiled(_dc_contract())
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
        availability=availability,
    )


def _dc_payload(*, substrate, realized_digest):
    return satisfaction_payload(
        _dc_contract(),
        create_aptl_manifest(),
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
        realized_digest=realized_digest,
        resolve_substrate=lambda: substrate,
    )


# --------------------------------------------------------------------------- #
# route selection + admission
# --------------------------------------------------------------------------- #


def test_select_route_picks_the_dynamic_composition_route():
    route = select_route(
        _dc_contract(),
        create_aptl_manifest(),
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
    )
    assert route is not None
    assert route.mechanism.mechanism == "dynamic-composition"
    assert (route.acquisition, route.timing) == ("local-lookup", "realization")


def test_availability_and_satisfaction_agree_on_route_3_for_multi_route_requirements():
    """The seams key on the SELECTED route, never on mere permission (#876 review).

    A requirement is route 3 iff the route APTL *selects* (an intersection over
    the full profile/acquisition/timing tuple) is dynamic-composition — not iff it
    merely lists one among its permitted routes. Availability's
    ``is_dynamic_composition_requirement`` must return exactly what satisfaction's
    ``select_route`` would drive, so a multi-route requirement can never resolve a
    substrate on one path while the other follows a non-dynamic route.
    """

    manifest = create_aptl_manifest()
    # Permits BOTH APTL's dynamic-composition route and its exact-artifact route.
    multi = ArtifactRequirement(
        requirement_id="multi-route",
        explicitness=ExplicitnessClass.OPEN,
        permitted_routes=[_dc_route(), _exact_route()],
    )
    # OPEN, but permits only the exact-artifact route: not route 3.
    exact_only = ArtifactRequirement(
        requirement_id="exact-only",
        explicitness=ExplicitnessClass.OPEN,
        permitted_routes=[_exact_route()],
    )

    for requirement in (multi, exact_only):
        selected = select_route(
            requirement, manifest, requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND
        )
        # Availability's predicate equals satisfaction's selected-route verdict:
        # the two seams cannot disagree for any requirement.
        assert is_dynamic_composition_requirement(requirement) == (
            selected is not None and route_is_dynamic_composition(selected)
        )

    # Concretely: dynamic-composition sorts first, so the multi-route requirement
    # selects it; the exact-only requirement never does.
    assert is_dynamic_composition_requirement(multi) is True
    assert is_dynamic_composition_requirement(exact_only) is False


def test_permitting_an_unsupported_dynamic_shaped_route_is_not_route_3():
    """Permission is not selection: a dynamic-composition-mechanism route whose
    acquisition/timing APTL never advertised is not eligible, so a requirement
    that also permits a supported exact route selects exact and is not route 3
    (#876 review). Availability must not resolve a substrate for it.
    """

    unsupported_dc = ArtifactSatisfactionRoute(
        mechanism=dynamic_composition_profile(),
        acquisition="pull",  # APTL advertises only local-lookup / realization
        timing="backend-preparation",
    )
    requirement = ArtifactRequirement(
        requirement_id="mixed",
        explicitness=ExplicitnessClass.OPEN,
        permitted_routes=[unsupported_dc, _exact_route()],
    )
    selected = select_route(
        requirement,
        create_aptl_manifest(),
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
    )
    assert selected is not None
    assert selected.mechanism.mechanism == "exact-artifact"
    assert is_dynamic_composition_requirement(requirement) is False


def test_open_dynamic_composition_source_is_admitted():
    codes = [
        d.code
        for d in artifact_requirement_diagnostics(
            (_dc_compiled(_dc_contract()),),
            create_aptl_manifest(),
            availability=_dc_availability(),
        )
    ]
    assert codes == []


# --------------------------------------------------------------------------- #
# runtime disclosure through the real gate
# --------------------------------------------------------------------------- #


def test_disclosure_of_the_verified_substrate_passes_the_runtime_gate():
    payload = _dc_payload(substrate=_substrate(), realized_digest=_SUBSTRATE_DIGEST)
    assert payload is not None
    assert payload["integrity_refs"] == [_SUBSTRATE_DIGEST]
    assert payload["provenance_refs"] == [dynamic_composition_provenance_ref()]

    diagnostic, provenance = _evaluate(payload, availability=_dc_availability())
    assert diagnostic is None, getattr(diagnostic, "message", "")
    assert provenance is not None


def test_unresolvable_substrate_is_refused_not_disclosed():
    payload = _dc_payload(substrate=None, realized_digest=_SUBSTRATE_DIGEST)
    assert payload is None
    diagnostic, provenance = _evaluate(payload, availability=_dc_availability())
    assert diagnostic is not None
    assert diagnostic.code == "runtime.backend-contract-invalid"
    assert provenance is None


def test_container_running_a_different_substrate_is_refused():
    # A tag or cache change between planning and apply: the resolved substrate is
    # not the one the container is actually running. No disclosure -> fail closed.
    payload = _dc_payload(substrate=_substrate(), realized_digest=_OTHER_DIGEST)
    assert payload is None
    diagnostic, _ = _evaluate(payload, availability=_dc_availability())
    assert diagnostic is not None
    assert diagnostic.code == "runtime.backend-contract-invalid"


class _Plan:
    """Minimal stand-in exposing the ``resources`` mapping the disclosure reads."""

    def __init__(self, resources: dict):
        self.resources = resources


class _RealizedOnlyBackend:
    """A backend whose container runs a known config id but whose tag is GONE.

    ``substrate_image_identity`` returns None (the mutable tag was removed after a
    correct start); the container itself still reports its immutable image id.
    """

    def __init__(self, config_id: str):
        self._config_id = config_id

    def container_image_config_id(self, container: str) -> str:
        return self._config_id

    def container_image_digest(self, container: str) -> str | None:
        return None

    def substrate_image_identity(self, image_ref: str):
        return None


def test_satisfaction_reuses_the_realized_config_id_when_the_tag_is_gone():
    # Cycle-5 review: satisfaction must name the substrate from the digest the
    # container is ACTUALLY running, not by re-resolving the tag -- otherwise a
    # tag removed after a correct start discloses nothing and the gate falsely
    # rejects a good node. The backend's tag lookup returns None here, yet the
    # disclosure still succeeds off the container's own image id.
    resource = _node_resource(
        {"name": "web", "artifact_requirement": _dc_contract().model_dump(mode="json")}
    )
    plan = _Plan({_ADDRESS: resource})
    disclosures = satisfactions_for_plan(
        plan,
        {_ADDRESS: "aptl-web"},
        _RealizedOnlyBackend(_SUBSTRATE_DIGEST),
        create_aptl_manifest(),
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
    )
    assert _ADDRESS in disclosures
    assert disclosures[_ADDRESS]["integrity_refs"] == [_SUBSTRATE_DIGEST]
    assert disclosures[_ADDRESS]["artifact"]["digest"] == _SUBSTRATE_DIGEST


def test_unverified_provenance_is_refused_by_the_trust_check():
    # The disclosure is well-formed, but availability never verified the
    # dynamic-composition provenance reference, so the gate rejects it: disclosed
    # provenance must be a subset of the verified set (ADR-098).
    payload = _dc_payload(substrate=_substrate(), realized_digest=_SUBSTRATE_DIGEST)
    diagnostic, _ = _evaluate(payload, availability=_dc_availability(provenance=[]))
    assert diagnostic is not None
    assert diagnostic.code == "runtime.backend-contract-invalid"


# --------------------------------------------------------------------------- #
# substrate resolution
# --------------------------------------------------------------------------- #


class _FakeProbe:
    def __init__(self, identity):
        self._identity = identity

    def substrate_image_identity(self, image_ref):
        return self._identity


def test_resolve_substrate_records_the_daemon_verified_identity():
    probe = _FakeProbe((_SUBSTRATE_DIGEST, _MANIFEST_MEDIA))
    substrate = resolve_substrate(
        _ADDRESS,
        os="linux",
        os_version="12",
        runtime=RuntimeConfiguration.model_validate({}),
        probe=probe,
    )
    assert substrate is not None
    assert substrate.digest == _SUBSTRATE_DIGEST
    assert substrate.media_type == _MANIFEST_MEDIA
    assert substrate.artifact_id == "aptl-generic-substrate"


def test_absent_substrate_yields_no_verified_identity():
    assert (
        resolve_substrate(
            _ADDRESS,
            os="linux",
            os_version="12",
            runtime=RuntimeConfiguration.model_validate({}),
            probe=_FakeProbe(None),
        )
        is None
    )


def test_unsupported_os_family_yields_no_substrate():
    assert (
        resolve_substrate(
            _ADDRESS,
            os="windows",
            os_version="",
            runtime=None,
            probe=_FakeProbe((_SUBSTRATE_DIGEST, _MANIFEST_MEDIA)),
        )
        is None
    )


# --------------------------------------------------------------------------- #
# resolve_node_image treats a dynamic-composition source as image-free
# --------------------------------------------------------------------------- #


def _node_resource(source: dict) -> PlannedResource:
    return PlannedResource(
        address=_ADDRESS,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="node",
        payload={"spec": {"node": {"os": "linux", "source": source}}},
    )


def test_dynamic_composition_source_is_image_free():
    resource = _node_resource(
        {"name": "web", "artifact_requirement": _dc_contract().model_dump(mode="json")}
    )
    diagnostics: list = []
    image = resolve_node_image(
        resource=resource,
        payload=resource.payload,
        project_dir=Path("."),
        service_name=None,
        diagnostics=diagnostics,
    )
    assert image is None
    assert diagnostics == []


def test_non_dynamic_source_keeps_its_failures():
    resource = _node_resource({"name": "wazuh-manager", "version": "4.x"})
    diagnostics: list = []
    resolve_node_image(
        resource=resource,
        payload=resource.payload,
        project_dir=Path("."),
        service_name=None,
        diagnostics=diagnostics,
    )
    assert any(d.code == "aptl.provisioner.image-policy-rejected" for d in diagnostics)


# --------------------------------------------------------------------------- #
# substrate_image_identity backend method (digest domain + truthful media type)
# --------------------------------------------------------------------------- #


class _SubstrateRun:
    def __init__(self, image_id):
        self.image_id = image_id

    def __call__(self, argv, timeout=None):
        # Both the image-ref config id ({{.Id}}) and the container's backing image
        # ({{.Image}}) are read in the one config-id domain; no RepoDigest lookup.
        if ("{{.Id}}" in argv or "{{.Image}}" in argv) and self.image_id:
            return subprocess.CompletedProcess(
                argv, 0, stdout=f"{self.image_id}\n", stderr=""
            )
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="")


def _substrate_backend(image_id):
    from aptl.core.deployment._compose_image_realization import (
        ComposeRealizationImageMixin,
    )

    backend = ComposeRealizationImageMixin()
    backend._run = _SubstrateRun(image_id)  # type: ignore[attr-defined]
    return backend


def test_substrate_identity_is_the_image_config_id():
    # The one digest domain whose media type is locally knowable and that matches
    # the container readback; a registry RepoDigest (ambiguous, possibly a Docker
    # rather than OCI manifest) is deliberately not used.
    backend = _substrate_backend("sha256:configid")
    assert backend.substrate_image_identity("debian:12-slim") == (
        "sha256:configid",
        _CONFIG_MEDIA,
    )


def test_container_config_id_reads_the_backing_image_in_the_same_domain():
    backend = _substrate_backend("sha256:configid")
    assert backend.container_image_config_id("aptl-web") == "sha256:configid"


def test_absent_substrate_image_has_no_identity():
    assert _substrate_backend(None).substrate_image_identity("missing:tag") is None
    assert _substrate_backend(None).container_image_config_id("missing") is None
