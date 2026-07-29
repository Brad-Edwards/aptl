"""Artifact route selection and satisfaction disclosure (ADR-050, RAES ADR-098).

Two responsibilities, both narrow:

* **Route selection.** Intersect the routes the author permitted with the routes
  APTL's manifest advertises, then pick one deterministically. The preference is
  keyed by mechanism and profile only — never by scenario name, node name,
  Compose service, or what happens to be in the local image cache. Selection
  never overrides authored intent: it only breaks ties inside the set the author
  already permitted, which is what SEM-218 I1/I2 require.

* **Satisfaction disclosure.** Report what was actually realized so RAES's
  runtime non-approximation gate can compare it against the author's
  declaration. The disclosure is built from the *observed* digest, not the
  planned one. Echoing the plan back would make the gate compare the plan
  against itself and pass unconditionally — the same trap issue #578 documents
  for SEM-218 realized values.

The disclosure claims only what APTL verified. The realized digest is the one
integrity fact it can vouch for, and the provenance it discloses is its own
digest-bound mechanism profile — how the artifact was obtained, never a registry
location. Authenticity, admission, and evidence references stay empty unless a
trust policy genuinely established them, because the runtime gate requires every
disclosed reference to be a subset of the processor-owned verified sets.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from pydantic import ValidationError
from raes.artifact_requirements import ArtifactSatisfactionRoute

from aptl.backends.raes_artifact_mechanisms import (
    exact_artifact_provenance_ref,
    materialization_provenance_ref,
)

if TYPE_CHECKING:
    from raes.artifact_requirements import ArtifactRequirement
    from raes_backend_protocols.capabilities import BackendManifest

_REALIZATION_DOMAIN = "runtime-realization"


def _mechanism_key(mechanism: object) -> tuple[str, str, str, str]:
    """Return the comparable identity of one mechanism profile."""

    return (
        getattr(mechanism, "mechanism", ""),
        getattr(mechanism, "profile", ""),
        getattr(mechanism, "version", ""),
        getattr(mechanism, "digest", ""),
    )


def _supported_routes(
    manifest: BackendManifest, requirement_kind: str
) -> set[tuple[tuple[str, str, str, str], str, str]]:
    """Return every (mechanism, acquisition, timing) the manifest advertises."""

    return {
        (_mechanism_key(capability.mechanism), route.acquisition, route.timing)
        for declaration in manifest.realization_support
        if declaration.domain == _REALIZATION_DOMAIN
        for capability in declaration.artifact_mechanisms
        if requirement_kind in capability.supported_requirement_kinds
        for route in capability.supported_routes
    }


def select_route(
    contract: ArtifactRequirement,
    manifest: BackendManifest,
    *,
    requirement_kind: str,
) -> ArtifactSatisfactionRoute | None:
    """Return the one route APTL will use, or None when none is admissible.

    Returning None is not a fallback: the caller surfaces it as a refusal, and
    RAES's planner gate independently rejects the same requirement with
    ``artifact.unsupported-backend-mechanism``.
    """

    supported = _supported_routes(manifest, requirement_kind)
    eligible = [
        route
        for route in contract.permitted_routes
        if (_mechanism_key(route.mechanism), route.acquisition, route.timing)
        in supported
    ]
    if not eligible:
        return None
    # Deterministic and content-keyed, so the same authored contract and the
    # same manifest always select the same route on any machine.
    return min(
        eligible,
        key=lambda route: (
            *_mechanism_key(route.mechanism),
            route.acquisition,
            route.timing,
        ),
    )


def satisfaction_payload(
    contract: ArtifactRequirement,
    manifest: BackendManifest,
    *,
    requirement_kind: str,
    realized_digest: str,
) -> dict[str, object] | None:
    """Return the ``artifact_satisfaction`` payload for one realized resource.

    Args:
        contract: The authored artifact requirement being satisfied.
        manifest: APTL's backend manifest, whose identity the gate binds to.
        requirement_kind: Compiled requirement kind, e.g. ``source-artifact``.
        realized_digest: The digest observed on the realized resource.

    Returns:
        A disclosure mapping, or None when no route is admissible or the
        observed digest does not match the authored exact identity. Returning
        None makes the runtime gate reject with ``runtime.backend-contract-invalid``
        rather than let a mismatch pass.
    """

    route = select_route(contract, manifest, requirement_kind=requirement_kind)
    if route is None:
        return None
    if contract.exact_artifact is None:
        return _materialized_payload(
            contract, manifest, route=route, realized_digest=realized_digest
        )
    return _exact_payload(
        contract, manifest, route=route, realized_digest=realized_digest
    )


def _exact_payload(
    contract: ArtifactRequirement,
    manifest: BackendManifest,
    *,
    route: ArtifactSatisfactionRoute,
    realized_digest: str,
) -> dict[str, object] | None:
    """Return the disclosure for an exactly-pinned artifact, if the digest matches.

    Returns None when the observed digest is not the one the author pinned:
    disclosing it anyway would be the silent approximation I2 forbids.
    """

    exact = contract.exact_artifact
    if exact is None or realized_digest != exact.digest:
        return None
    return {
        "requirement_id": contract.requirement_id,
        "artifact": exact.model_dump(mode="json"),
        "mechanism": route.mechanism.model_dump(mode="json"),
        "acquisition": route.acquisition,
        "timing": route.timing,
        "backend": {
            "name": manifest.identity.name,
            "version": manifest.identity.version,
        },
        "integrity_refs": [realized_digest],
        "provenance_refs": [exact_artifact_provenance_ref()],
    }


def _authored_requirement(payload: object) -> ArtifactRequirement | None:
    """Return the artifact requirement authored on one planned node resource."""

    from raes.artifact_requirements import ArtifactRequirement as _Requirement

    spec = payload.get("spec") if isinstance(payload, Mapping) else None
    node = spec.get("node") if isinstance(spec, Mapping) else None
    source = node.get("source") if isinstance(node, Mapping) else None
    authored = source.get("artifact_requirement") if isinstance(source, Mapping) else None
    if authored is None:
        return None
    try:
        return _Requirement.model_validate(authored)
    except ValidationError:
        # A malformed requirement is a parse/compile concern, already reported
        # upstream. Producing no disclosure here makes the runtime gate reject
        # rather than letting a half-understood contract look satisfied.
        return None


def satisfactions_for_plan(
    plan: object,
    container_names: Mapping[str, str],
    backend: object,
    manifest: BackendManifest,
    *,
    requirement_kind: str,
) -> dict[str, dict[str, object]]:
    """Return the ``artifact_satisfaction`` payload for each realized address.

    An address is omitted when it authors no artifact requirement, when no
    container backs it, when its realized digest cannot be read, or when that
    digest differs from the authored pin. Every one of those omissions makes
    RAES's runtime gate reject the apply, which is the intended behaviour: a
    missing disclosure is a refusal, never an implicit pass.
    """

    disclosures: dict[str, dict[str, object]] = {}
    for address, resource in getattr(plan, "resources", {}).items():
        if getattr(resource, "resource_type", None) != "node":
            continue
        contract = _authored_requirement(getattr(resource, "payload", None))
        container = container_names.get(address)
        if contract is None or not container:
            continue
        realized = backend.container_image_digest(container)
        if not realized:
            continue
        payload = satisfaction_payload(
            contract,
            manifest,
            requirement_kind=requirement_kind,
            realized_digest=realized,
        )
        if payload is not None:
            disclosures[address] = payload
    return disclosures


def _materialized_payload(
    contract: ArtifactRequirement,
    manifest: BackendManifest,
    *,
    route: ArtifactSatisfactionRoute,
    realized_digest: str,
) -> dict[str, object] | None:
    """Return the disclosure for a locally materialized component artifact.

    A built image has no authored digest to compare against, because a build is
    not bit-reproducible. Its identity is therefore the digest it actually
    materialized to, which entered the verified integrity set when backend
    preparation built it. The authored specification is disclosed alongside, so
    the gate can confirm the backend built the specification the author declared
    rather than something else.

    The specification digest is deliberately not reused as the artifact digest:
    that would claim the build specification is the built image.
    """

    selected = next(
        (
            specification
            for specification in sorted(
                contract.materialization_specifications,
                key=lambda item: item.specification_id,
            )
            if _mechanism_key(specification.profile) == _mechanism_key(route.mechanism)
        ),
        None,
    )
    if selected is None or not realized_digest:
        return None
    return {
        "requirement_id": contract.requirement_id,
        "artifact": {
            "artifact_id": selected.specification_id,
            "version": "local",
            "digest": realized_digest,
            "media_type": "application/vnd.oci.image.manifest.v1+json",
        },
        "mechanism": route.mechanism.model_dump(mode="json"),
        "acquisition": route.acquisition,
        "timing": route.timing,
        "backend": {
            "name": manifest.identity.name,
            "version": manifest.identity.version,
        },
        "materialization_specification_id": selected.specification_id,
        "materialization_specification_digest": selected.digest,
        "locked_input_ids": list(selected.locked_input_ids),
        "integrity_refs": [realized_digest],
        "provenance_refs": [materialization_provenance_ref()],
    }
