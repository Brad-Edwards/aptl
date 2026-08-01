"""APTL's declared RAES artifact-satisfaction mechanisms (ADR-050, RAES ADR-098).

A backend may advertise an artifact mechanism only once it can both materialize
that mechanism's effect and independently read the result back (SEM-218 I4).
Capability disclosure follows implementation; it never anticipates it. Every
mechanism declared here therefore has a corresponding realization path in
``aptl.core.deployment`` and a corresponding readback in
``aptl.backends.raes_artifact_availability``.

A mechanism profile is digest-bound: the profile's canonical JSON body is
hashed, and that digest is what planner admission matches against the authored
``permitted_routes``. The body is declared here rather than loaded from a data
file so the digest is reproducible from source with no packaging dependency.

Acquisition/timing pairs are enumerated explicitly per mechanism. RAES ADR-098
§3 forbids publishing unjoined mechanism/acquisition/timing lists, because their
Cartesian product would overclaim support.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

from raes.artifact_requirements import ArtifactMechanismProfile

# Import from the ``raes_contracts.contracts`` package surface, not from the
# ``raes_contracts.artifact_requirements`` leaf module. In raes 2.0.0 the leaf
# module cannot be imported first: it imports ``.contracts.base`` while
# ``contracts/__init__.py`` imports back from ``..artifact_requirements``, so a
# direct leaf import always raises ImportError on the partially initialized
# module. The package surface re-exports the same models and resolves cleanly.
from raes_contracts.contracts import (
    ArtifactAcquisitionTimingModel,
    ArtifactMechanismCapability,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from raes.artifact_requirements import (
        ArtifactRequirement,
        ArtifactSatisfactionRoute,
    )

# The compiled requirement kind that ``Source.artifact_requirement`` lowers to.
# See ``raes_processor.compiler.realization_requirements``.
SOURCE_ARTIFACT_REQUIREMENT_KIND = "source-artifact"

_PROFILE_VERSION = "1"

# Canonical profile bodies. The body states what APTL actually does for the
# mechanism, so a change in behaviour changes the digest and therefore the
# advertised capability identity.
_EXACT_ARTIFACT_PROFILE_BODY: dict[str, Any] = {
    "mechanism": "exact-artifact",
    "profile": "aptl-oci-exact-pull",
    "version": _PROFILE_VERSION,
    "description": (
        "Resolve one immutable OCI artifact by digest through the APTL "
        "deployment backend, then verify the realized container's image "
        "digest by read-after-write."
    ),
    "artifact_kind": "oci-image",
    "identity": "sha256 manifest digest",
    "verification": "docker image inspect of the realized digest",
    "substitution": "forbidden",
}


# Per-component build. The profile body states the containment rule so the
# mapping from an authored specification to a build context is a uniform,
# scenario-agnostic convention rather than a per-product lookup table: the
# specification id names a directory under ``containers/`` and nothing else.
_MATERIALIZATION_PROFILE_BODY: dict[str, Any] = {
    "mechanism": "materialization-specification",
    "profile": "aptl-contained-component-build",
    "version": _PROFILE_VERSION,
    "description": (
        "Build one component image from a project-contained build context "
        "named by the authored specification id, verify the context's "
        "Dockerfile hashes to the authored specification digest, then verify "
        "the built image by read-after-write."
    ),
    "context_root": "containers",
    "context_selector": "specification_id",
    "integrity": "sha256 of the context Dockerfile equals the specification digest",
    "inputs": "every declared locked input must be an immutable pinned base",
    "substitution": "forbidden",
}


# Generic runtime composition (ADR-051 route 3, RAESystem/rae#985). APTL composes
# a node's declared runtime shape onto a pinned generic OS substrate and proves
# the composition by independently reading every declared runtime realization
# concern back off the realized container. raes 3.1.0 lowers runtime-environment,
# runtime-mounts, linux-capabilities, published-ports, forwarding-agents, and
# service-listeners as realization concerns; RAES's non-approximation gate then
# compares each observed value against the author's declaration. The substrate is
# obtained locally during backend preparation; the composition is applied and
# read back at realization, so no artifact is fetched at composition time.
_DYNAMIC_COMPOSITION_PROFILE_BODY: dict[str, Any] = {
    "mechanism": "dynamic-composition",
    "profile": "aptl-generic-substrate-composition",
    "version": _PROFILE_VERSION,
    "description": (
        "Compose an authored node's complete runtime contract onto a pinned "
        "generic OS substrate through the APTL deployment backend, then verify "
        "every declared runtime realization concern by independent "
        "read-after-write against the realized container."
    ),
    "substrate": "pinned generic OS image",
    "composition": "authored RuntimeConfiguration concerns lowered by RAES",
    "verification": "per-concern read-after-write via typed DeploymentBackend inspection",
    "substitution": "forbidden",
}


def _profile_digest(body: dict[str, Any]) -> str:
    """Return the SHA-256 digest of a profile body's canonical JSON encoding."""

    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def exact_artifact_profile() -> ArtifactMechanismProfile:
    """Return APTL's digest-bound ``exact-artifact`` mechanism profile."""

    body = _EXACT_ARTIFACT_PROFILE_BODY
    return ArtifactMechanismProfile(
        mechanism=body["mechanism"],
        profile=body["profile"],
        version=body["version"],
        digest=_profile_digest(body),
    )


def materialization_profile() -> ArtifactMechanismProfile:
    """Return APTL's digest-bound per-component build profile."""

    body = _MATERIALIZATION_PROFILE_BODY
    return ArtifactMechanismProfile(
        mechanism=body["mechanism"],
        profile=body["profile"],
        version=body["version"],
        digest=_profile_digest(body),
    )


def materialization_capability() -> ArtifactMechanismCapability:
    """Return the backend capability entry for per-component builds.

    Acquisition is ``none``: nothing is fetched, the artifact is produced
    locally during backend preparation from inputs the author pinned.
    """

    return ArtifactMechanismCapability(
        mechanism=materialization_profile(),
        supported_requirement_kinds=[SOURCE_ARTIFACT_REQUIREMENT_KIND],
        supported_routes=[
            ArtifactAcquisitionTimingModel(
                acquisition="none", timing="backend-preparation"
            )
        ],
    )


def materialization_provenance_ref() -> str:
    """Return the provenance reference for a locally materialized component."""

    profile = materialization_profile()
    return f"{profile.mechanism}:{profile.profile}@{profile.digest}"


def exact_artifact_provenance_ref() -> str:
    """Return the provenance reference APTL can honestly vouch for.

    The provenance of an exactly-pinned artifact is *how it was obtained*: through
    this backend's declared, digest-bound mechanism profile. That is a non-secret
    capability identity, and it changes whenever the profile body changes.

    It deliberately is not a registry URL, region, account, or repository path.
    ADR-098 §5 forbids location and channel fields in a satisfaction disclosure,
    because they are mutable operational facts that do not identify artifact
    bytes and can leak host or account information.
    """

    profile = exact_artifact_profile()
    return f"{profile.mechanism}:{profile.profile}@{profile.digest}"


def exact_artifact_capability() -> ArtifactMechanismCapability:
    """Return the backend capability entry for immutable artifact pulls.

    APTL obtains an exact artifact during backend preparation, before the
    Compose model starts, either by pulling it or by finding it already present
    (the offline/appliance staging path). Both are enumerated; no other
    acquisition or timing combination is claimed.
    """

    return ArtifactMechanismCapability(
        mechanism=exact_artifact_profile(),
        supported_requirement_kinds=[SOURCE_ARTIFACT_REQUIREMENT_KIND],
        supported_routes=[
            ArtifactAcquisitionTimingModel(
                acquisition="pull", timing="backend-preparation"
            ),
            ArtifactAcquisitionTimingModel(
                acquisition="local-lookup", timing="backend-preparation"
            ),
        ],
    )


def dynamic_composition_profile() -> ArtifactMechanismProfile:
    """Return APTL's digest-bound generic runtime-composition profile."""

    body = _DYNAMIC_COMPOSITION_PROFILE_BODY
    return ArtifactMechanismProfile(
        mechanism=body["mechanism"],
        profile=body["profile"],
        version=body["version"],
        digest=_profile_digest(body),
    )


def dynamic_composition_provenance_ref() -> str:
    """Return the provenance reference for a generically composed node.

    Like the other mechanisms, the provenance APTL vouches for is *how* the node
    was obtained — its digest-bound composition profile — never a registry
    location (ADR-098 §5).
    """

    profile = dynamic_composition_profile()
    return f"{profile.mechanism}:{profile.profile}@{profile.digest}"


def dynamic_composition_capability() -> ArtifactMechanismCapability:
    """Return the backend capability entry for generic runtime composition.

    Acquisition is ``local-lookup``: the generic substrate is resolved from what
    backend preparation already staged, nothing is fetched for the composition
    itself. Timing is ``realization``: the runtime shape is composed and read
    back when the node is realized. No other acquisition or timing combination is
    claimed.
    """

    return ArtifactMechanismCapability(
        mechanism=dynamic_composition_profile(),
        supported_requirement_kinds=[SOURCE_ARTIFACT_REQUIREMENT_KIND],
        supported_routes=[
            ArtifactAcquisitionTimingModel(
                acquisition="local-lookup", timing="realization"
            )
        ],
    )


def route_is_dynamic_composition(route: "ArtifactSatisfactionRoute") -> bool:
    """Whether a satisfaction route IS APTL's declared dynamic-composition route.

    Matches the complete mechanism/profile/version/digest + acquisition + timing
    tuple, never the mechanism name alone: the name could appear with a different
    profile or an acquisition/timing APTL never advertised. This is the route
    ``select_route`` selects, so availability, image realization, and satisfaction
    all agree on which nodes are route 3.
    """

    capability = dynamic_composition_capability()
    supported = capability.supported_routes[0]
    mechanism = capability.mechanism
    return (
        route.mechanism.mechanism == mechanism.mechanism
        and route.mechanism.profile == mechanism.profile
        and route.mechanism.version == mechanism.version
        and route.mechanism.digest == mechanism.digest
        and route.acquisition == supported.acquisition
        and route.timing == supported.timing
    )


def _mechanism_key(mechanism: object) -> tuple[str, str, str, str]:
    """Return the comparable identity of one mechanism profile."""

    return (
        getattr(mechanism, "mechanism", ""),
        getattr(mechanism, "profile", ""),
        getattr(mechanism, "version", ""),
        getattr(mechanism, "digest", ""),
    )


def select_route_over_mechanisms(
    requirement: "ArtifactRequirement",
    mechanisms: "Iterable[ArtifactMechanismCapability]",
    *,
    requirement_kind: str,
) -> "ArtifactSatisfactionRoute | None":
    """Return the single route the permitted-vs-supported intersection selects.

    The one deterministic selection algorithm every seam shares: satisfaction
    runs it over the manifest's advertised mechanisms (via ``select_route``),
    availability and image realization run it over APTL's own
    ``aptl_artifact_mechanisms()`` (via :func:`is_dynamic_composition_requirement`).
    Because both select from the same intersection with the same content-keyed
    ``min``, they cannot disagree about which route -- and therefore whether route
    3 -- a multi-route requirement resolves to (issue #876 core review).
    """

    supported = {
        (_mechanism_key(capability.mechanism), route.acquisition, route.timing)
        for capability in mechanisms
        if requirement_kind in capability.supported_requirement_kinds
        for route in capability.supported_routes
    }
    eligible = [
        route
        for route in requirement.permitted_routes
        if (_mechanism_key(route.mechanism), route.acquisition, route.timing)
        in supported
    ]
    if not eligible:
        return None
    return min(
        eligible,
        key=lambda route: (
            *_mechanism_key(route.mechanism),
            route.acquisition,
            route.timing,
        ),
    )


def is_dynamic_composition_requirement(requirement: "ArtifactRequirement") -> bool:
    """Whether the route APTL SELECTS for this requirement is its route 3.

    Not "permits" but "selects": RAES route selection intersects the full
    profile/acquisition/timing tuple and can pick a different permitted route, so
    a requirement that merely lists dynamic-composition among its permitted routes
    -- while its selected route is exact or materialized -- is NOT route 3.
    Availability, image realization, and satisfaction all key on this selected
    route (satisfaction through ``select_route``, which shares
    ``select_route_over_mechanisms``), so they cannot diverge for a multi-route
    requirement (issue #876 core review). Because APTL's manifest advertises
    exactly ``aptl_artifact_mechanisms()`` for the runtime-realization domain, the
    set selected over here is identical to the one satisfaction selects over.
    """

    route = select_route_over_mechanisms(
        requirement,
        aptl_artifact_mechanisms(),
        requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
    )
    return route is not None and route_is_dynamic_composition(route)


def aptl_artifact_mechanisms() -> tuple[ArtifactMechanismCapability, ...]:
    """Return every artifact mechanism APTL can materialize and verify.

    ``dynamic-composition`` is advertised now that raes 3.1.0 lowers the runtime
    realization concerns (RAESystem/rae#985) and APTL composes a node onto a
    generic substrate and reads every declared runtime concern back by
    read-after-write (issue #876) — so the SEM-218 I4 precondition
    "materialize *and* independently read back" holds for it.
    """

    return (
        exact_artifact_capability(),
        materialization_capability(),
        dynamic_composition_capability(),
    )
