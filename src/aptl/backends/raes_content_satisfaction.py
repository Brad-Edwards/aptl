"""Satisfaction disclosure for env-pack-resolved content (ADR-051, issue #875).

A ``content-placement`` resource can author an EXACT ``source.artifact_requirement``
whose permitted route is APTL's env-pack content-copy mechanism: the bytes are
resolved from the staged, validated pack by opaque id + ``sha256`` and copied
into the range. SEM-218 I2 requires the backend to disclose what it realized for
that requirement exactly as it does for a node's image, so this module is the
content-shaped sibling of the node path in
:mod:`aptl.backends.raes_artifact_satisfaction` and reuses its route selection
and payload construction unchanged.

Two things differ from a node, and both are about what "realized" means here:

* The realized artifact is **content bytes**, not an OCI image, so there is no
  container image digest to read back. The digest disclosed here is computed in
  this module over the bytes ``resolve_pack_artifact`` returns from the same pack
  the placement resolved its bytes from — never copied out of the author's
  declaration, and never taken from the resolver's own reported identity. Both
  of those would make the gate compare a declaration against itself, which is
  the trap issue #578 documents. A pack whose bytes hash to anything other than
  the pin therefore produces no disclosure and the gate rejects the address.
* The "it landed" half of the claim is carried by observation, not by this
  module. A placement the backend was not observed to have realized gets no
  snapshot entry at all (``snapshot_after_apply``), so the caller has nothing to
  attach a disclosure to and the gate rejects. Disclosure and realization cannot
  come apart even though the digest is established at the resolution boundary.

Everything else fails closed: content that carries no pack-resolved bytes, a
selected route that is not the advertised copy route, or an unresolvable
artifact id all yield no disclosure, which the runtime gate reports as an
unrealized exact requirement rather than an implicit pass.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import TYPE_CHECKING

from aptl.backends.raes_artifact_mechanisms import route_is_env_pack_copy
from aptl.backends.raes_artifact_satisfaction import (
    authored_source_requirement,
    satisfaction_payload,
    select_route,
)

if TYPE_CHECKING:
    from pathlib import Path

    from raes.artifact_requirements import ArtifactRequirement
    from raes_backend_protocols.capabilities import BackendManifest

    from aptl.core.deployment.realization import DeploymentContentRealization

# The two realization kinds whose bytes come from the pack. Every other content
# kind (inline text, a checked-in project path, an empty directory) declares no
# artifact requirement, so it has nothing to disclose.
_PACK_SOURCE_KINDS = ("pack-file", "pack-directory")


def content_satisfactions_for_plan(
    plan: object,
    content_by_address: Mapping[str, "DeploymentContentRealization"],
    scenario_root: "Path",
    manifest: "BackendManifest",
    *,
    requirement_kind: str,
) -> dict[str, dict[str, object]]:
    """Return the ``artifact_satisfaction`` payload for each pack-content address.

    ``content_by_address`` is the typed content the realization actually lowered
    for each placement, so an address the interpreter refused never reaches the
    resolver here. The pack is opened at most once per artifact id: several
    placements can share one artifact (four nodes plant the same flag generator),
    and re-validating the pack per placement would buy nothing.
    """

    resolved_digests: dict[str, str | None] = {}
    disclosures: dict[str, dict[str, object]] = {}
    for address, resource in getattr(plan, "resources", {}).items():
        if getattr(resource, "resource_type", None) != "content-placement":
            continue
        payload = _content_satisfaction(
            getattr(resource, "payload", None),
            content_by_address.get(address),
            scenario_root,
            manifest,
            requirement_kind=requirement_kind,
            resolved_digests=resolved_digests,
        )
        if payload is not None:
            disclosures[address] = payload
    return disclosures


def _content_satisfaction(
    resource_payload: object,
    content: "DeploymentContentRealization | None",
    scenario_root: "Path",
    manifest: "BackendManifest",
    *,
    requirement_kind: str,
    resolved_digests: dict[str, str | None],
) -> dict[str, object] | None:
    """Return one content placement's disclosure, or None to refuse."""

    contract = _authored_content_requirement(resource_payload)
    if contract is None or content is None:
        return None
    if content.source_kind not in _PACK_SOURCE_KINDS or not content.artifact_id:
        return None
    route = select_route(contract, manifest, requirement_kind=requirement_kind)
    # Only the advertised copy route resolves its bytes from the pack, so only
    # that route's realized digest is the one derived below. A requirement whose
    # selected route is some other mechanism discloses nothing rather than a
    # digest established in the wrong domain.
    if route is None or not route_is_env_pack_copy(route):
        return None
    if content.artifact_id not in resolved_digests:
        resolved_digests[content.artifact_id] = _resolved_content_digest(
            scenario_root, content.artifact_id
        )
    realized = resolved_digests[content.artifact_id]
    if realized is None:
        return None
    return satisfaction_payload(
        contract,
        manifest,
        requirement_kind=requirement_kind,
        realized_digest=realized,
    )


def _authored_content_requirement(payload: object) -> "ArtifactRequirement | None":
    """Return the artifact requirement authored on one planned content resource.

    Content authors its source directly at ``spec.source``; a node authors it one
    level deeper at ``spec.node.source``. The two readers share the parsing and
    differ only in the path.
    """

    spec = payload.get("spec") if isinstance(payload, Mapping) else None
    return authored_source_requirement(
        spec.get("source") if isinstance(spec, Mapping) else None
    )


def _resolved_content_digest(scenario_root: "Path", artifact_id: str) -> str | None:
    """Return the sha256 of the bytes the pack actually resolves for an artifact.

    Hashed here rather than read off ``resolved.identity``: the resolver's own
    claim is a declaration too, and a disclosure built from it would let the gate
    compare a declaration against itself. Hashing the returned bytes makes the
    disclosed digest an independent observation of the content that was placed,
    so a pack resolving anything other than what the author pinned is caught by
    the exact-payload digest check instead of being disclosed as compliant.

    Fail-closed: an unresolvable id, a digest-bound resolution failure, or an
    unreadable pack yields nothing and the runtime gate rejects the address.
    """

    from raes_env_packs import PackDigestError, resolve_pack_artifact

    try:
        resolved = resolve_pack_artifact(str(scenario_root), artifact_id)
    except (PackDigestError, OSError, ValueError):
        return None
    data = getattr(resolved, "data", None)
    if not isinstance(data, bytes):
        return None
    return "sha256:" + hashlib.sha256(data).hexdigest()
