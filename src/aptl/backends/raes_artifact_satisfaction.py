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

from typing import TYPE_CHECKING

from raes.artifact_requirements import ArtifactSatisfactionRoute

from aptl.backends.raes_artifact_mechanisms import exact_artifact_provenance_ref

if TYPE_CHECKING:  # pragma: no cover - typing only
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
    exact = contract.exact_artifact
    if route is None or exact is None:
        return None
    if realized_digest != exact.digest:
        # The backend realized something other than what the author pinned.
        # Disclosing it anyway would be the silent approximation I2 forbids.
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
