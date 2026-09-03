"""Generic-substrate policy resolution for dynamic-composition route 3 (#876).

A dynamic-composition node is realized onto the same pinned generic base
substrate ``base_container_spec()`` selects for realization (ADR-051 route 3).
Its portable artifact identity is a stable *policy* identity -- never the mutable
registry ref used to locate the image, a Compose service, a node address, or a
bundle path. The immutable digest and truthful media type are read from the
target daemon by strict local-lookup, in the same digest domain the
post-realization readback (``container_image_digest``) uses, so availability and
satisfaction compare like with like.

This module is the single extensibility seam the preflight fixes:
``(OS, OS version, package family, service-manager need) -> substrate policy
variant -> immutable target-daemon image identity``. Both the plan-time
availability facts and the realization-time satisfaction disclosure resolve the
substrate through here, so they cannot drift.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from raes.runtime_configuration import RuntimeConfiguration

from aptl.backends.raes_base_substrate import base_container_spec
from aptl.backends.raes_materializer import UnsupportedOsFamilyError, package_family

# A stable, provider-neutral policy identity for the generic substrate. It is
# deliberately not a registry reference: the digest carries the bytes, this
# carries the capability identity, and the variant distinguishes the base the
# typed substrate decision selects.
_SUBSTRATE_ARTIFACT_ID = "aptl-generic-substrate"

# The one digest domain APTL discloses for a dynamically composed substrate: the
# image config id, whose media type is locally knowable and equals the config id
# read back off the realized container (issue #876).
_SUBSTRATE_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"


class SubstrateProbe(Protocol):
    """The single backend capability substrate resolution needs."""

    def substrate_image_identity(self, image_ref: str) -> tuple[str, str] | None:
        """Return the ``(digest, media_type)`` of a locally present image ref."""
        ...


@dataclass(frozen=True)
class SubstrateIdentity:
    """The immutable identity of the generic substrate a node composes onto."""

    artifact_id: str
    version: str
    digest: str
    media_type: str

    def artifact_identity(self) -> dict[str, object]:
        """Return the RAES ``ArtifactIdentity`` payload for this substrate."""

        return {
            "artifact_id": self.artifact_id,
            "version": self.version,
            "digest": self.digest,
            "media_type": self.media_type,
        }


def substrate_image_ref(
    node_address: str,
    *,
    os: str,
    os_version: str,
    runtime: RuntimeConfiguration | None,
) -> str | None:
    """Return the generic base image ref realization selects for this node.

    None when the OS family has no generic base, so the caller fails closed
    rather than guessing an image.
    """

    if not os:
        return None
    try:
        spec = base_container_spec(
            node_address, os=os, os_version=os_version, runtime=runtime
        )
    except UnsupportedOsFamilyError:
        return None
    return spec.image_ref


def substrate_policy_variant(*, os: str, runtime: RuntimeConfiguration | None) -> str:
    """Return a stable policy-variant string for the selected substrate.

    Keyed only by the typed inputs the substrate decision uses (OS family,
    package family, service-manager need) -- never a registry ref, tag, or
    cache contents.
    """

    runs_services = bool(runtime is not None and runtime.service_manager_units)
    return f"{os or 'unknown'}.{package_family(runtime)}.{'systemd' if runs_services else 'base'}"


def resolve_substrate(
    node_address: str,
    *,
    os: str,
    os_version: str,
    runtime: RuntimeConfiguration | None,
    probe: SubstrateProbe,
) -> SubstrateIdentity | None:
    """Resolve the substrate's immutable local identity for a node, or None.

    Fails closed when the OS family has no generic base, or when the substrate is
    not present on the target daemon (a strict local-lookup, no registry pull).
    """

    image_ref = substrate_image_ref(
        node_address, os=os, os_version=os_version, runtime=runtime
    )
    if image_ref is None:
        return None
    identity = probe.substrate_image_identity(image_ref)
    if identity is None:
        return None
    digest, media_type = identity
    return SubstrateIdentity(
        artifact_id=_SUBSTRATE_ARTIFACT_ID,
        version=substrate_policy_variant(os=os, runtime=runtime),
        digest=digest,
        media_type=media_type,
    )


def realized_substrate_identity(
    *,
    os: str,
    runtime: RuntimeConfiguration | None,
    digest: str,
) -> SubstrateIdentity | None:
    """Return the substrate identity for a digest read back off the container.

    Unlike :func:`resolve_substrate`, this takes the digest the container is
    ACTUALLY running -- its own immutable image config id -- rather than
    re-resolving the mutable registry ref. The realized container *is* the
    substrate it composed onto, so satisfaction reuses that id instead of a second
    lookup that a moved or removed tag would break, which was a real false-negative
    (a correctly realized node disclosed as a mismatch, issue #876 cycle-5 review).
    Fails closed when the OS family has no generic base or the digest is empty. The
    RAES gate still checks this digest against the availability-verified set, so an
    unverified substrate cannot pass.
    """

    if not os or not digest:
        return None
    return SubstrateIdentity(
        artifact_id=_SUBSTRATE_ARTIFACT_ID,
        version=substrate_policy_variant(os=os, runtime=runtime),
        digest=digest,
        media_type=_SUBSTRATE_CONFIG_MEDIA_TYPE,
    )


__all__ = [
    "SubstrateIdentity",
    "SubstrateProbe",
    "realized_substrate_identity",
    "resolve_substrate",
    "substrate_image_ref",
    "substrate_policy_variant",
]
