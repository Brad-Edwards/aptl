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
from typing import Any

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


def aptl_artifact_mechanisms() -> tuple[ArtifactMechanismCapability, ...]:
    """Return every artifact mechanism APTL can materialize and verify.

    ``materialization-specification`` (digest-bound per-component builds) and
    ``dynamic-composition`` (generic runtime composition) are deliberately absent
    until their selection, materialization, and readback exist end to end. Adding
    them here before that would be exactly the optimistic capability declaration
    SEM-218 I4 forbids.
    """

    return (exact_artifact_capability(),)
