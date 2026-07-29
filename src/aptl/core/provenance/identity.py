"""Canonical identity primitives for run-scoped provenance (REP-003 / #452).

Every derived structured identity in this package is an RFC 8785 canonical
JSON digest under an explicit version/domain separator, and every SHA-256
value is normalized to one representation (``sha256:<lowercase-hex>``) at the
provenance boundary.

The central rule is that content identity is **framed by logical role**.
Provenance records a leaf per stable logical id, then folds a family identity
over the SORTED canonical sequence of ``{logical_id, digest}`` entries. The
incumbent :func:`aptl.core.experiment.trial_plan.compute_source_set_digest`
establishes the canonical-JSON-plus-SHA-256 pattern; this module applies it to
provenance and adds the framing.

Framing is not decoration. The behavior it replaces
(``snapshot.detection_content_digest``) hashed an unframed concatenation of
file bytes, so ``"ab" + "c"`` and ``"a" + "bc"`` produced the same digest and a
targeted difference could not be explained. Folding ``{logical_id, digest}``
pairs makes each file's boundary part of the identity.

Volatile observation data — timestamps, container IDs, health state, durations
— never enters an identity computed here. Those are observations recorded
beside identity, so unchanged apparatus content cannot drift.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

import rfc8785

#: The single normalized digest representation used across provenance.
DIGEST_PREFIX = "sha256:"

#: Versioned domain-separator template. A future revision of the identity
#: algorithm bumps the version so an archived record's identities can never be
#: silently reinterpreted under new rules.
_DOMAIN_TEMPLATE = "aptl.provenance.{domain}/v1"

#: A bare lowercase SHA-256 hex digest.
_HEX_RE = re.compile(r"[0-9a-f]{64}")

#: A domain label: a short, non-executable slug. Deliberately strict — the
#: domain is a code-owned constant, never caller metadata.
_DOMAIN_RE = re.compile(r"[a-z][a-z0-9-]{0,63}")

#: A logical id names a stable role (for example ``suricata/rules/custom.rules``).
#: It is a record key, so control characters, whitespace, and unbounded length
#: are rejected before it can reach a key, path, or log template.
_LOGICAL_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}")


class ProvenanceIdentityError(ValueError):
    """Raised when an identity input is malformed, hostile, or unserializable.

    Identity fails closed: a rejected input never degrades to a fabricated
    digest, an empty string, or an omitted key.
    """


@dataclass(frozen=True, order=True)
class ProvenanceLeaf:
    """One content leaf: a stable logical role bound to the digest of its bytes.

    Ordering is ``(logical_id, digest)`` so a sequence of leaves sorts
    deterministically without the caller choosing a key function.
    """

    logical_id: str
    digest: str


def normalize_digest(value: str) -> str:
    """Return ``value`` as ``sha256:<lowercase-hex>``.

    Accepts a bare or already-prefixed hex digest in any case. Anything else —
    a wrong algorithm, a wrong length, a doubled prefix, a non-string — raises
    :class:`ProvenanceIdentityError` rather than becoming a fabricated identity.
    """
    if not isinstance(value, str):
        raise ProvenanceIdentityError("digest must be a string")
    candidate = value[len(DIGEST_PREFIX) :] if value.startswith(DIGEST_PREFIX) else value
    candidate = candidate.lower()
    if _HEX_RE.fullmatch(candidate) is None:
        raise ProvenanceIdentityError("digest is not a SHA-256 hex value")
    return f"{DIGEST_PREFIX}{candidate}"


def validate_logical_id(logical_id: str) -> str:
    """Return ``logical_id`` when it is a safe record key, else raise."""
    if not isinstance(logical_id, str) or _LOGICAL_ID_RE.fullmatch(logical_id) is None:
        raise ProvenanceIdentityError("logical_id is not a safe provenance role")
    return logical_id


def _domain_separator(domain: str) -> str:
    """Return the versioned domain separator for ``domain``, else raise."""
    if not isinstance(domain, str) or _DOMAIN_RE.fullmatch(domain) is None:
        raise ProvenanceIdentityError("identity domain is not a safe code-owned label")
    return _DOMAIN_TEMPLATE.format(domain=domain)


def digest_bytes(data: bytes) -> str:
    """Return the normalized digest of ``data``."""
    return f"{DIGEST_PREFIX}{hashlib.sha256(data).hexdigest()}"


def leaf_identity(logical_id: str, data: bytes) -> ProvenanceLeaf:
    """Return the :class:`ProvenanceLeaf` binding ``logical_id`` to ``data``.

    An empty payload still yields an explicit digest: an empty rule file is a
    real observation about the apparatus, distinct from an absent source.
    """
    return ProvenanceLeaf(logical_id=validate_logical_id(logical_id), digest=digest_bytes(data))


def derive_identity(domain: str, payload: Mapping[str, object]) -> str:
    """Return the domain-separated canonical identity of ``payload``.

    The separator is folded into the hashed document, so two structurally
    identical payloads in different domains cannot collide.
    """
    separator = _domain_separator(domain)
    try:
        canonical = rfc8785.dumps({"domain": separator, "payload": dict(payload)})
    except (TypeError, ValueError) as exc:
        raise ProvenanceIdentityError("payload is not canonical-JSON serializable") from exc
    return digest_bytes(canonical)


def family_identity(domain: str, leaves: Iterable[ProvenanceLeaf]) -> str:
    """Return the aggregate identity of ``leaves`` under ``domain``.

    Folds the SORTED sequence of ``{logical_id, digest}`` entries, so provider
    iteration order and filesystem order are never significant, while each
    file's role boundary stays part of the identity. Duplicate logical ids are
    rejected — two leaves claiming one role would make the family ambiguous.
    """
    ordered: Sequence[ProvenanceLeaf] = sorted(leaves)
    seen: set[str] = set()
    entries: list[dict[str, str]] = []
    for leaf in ordered:
        if leaf.logical_id in seen:
            raise ProvenanceIdentityError("duplicate logical_id in provenance family")
        seen.add(leaf.logical_id)
        entries.append({"logical_id": leaf.logical_id, "digest": normalize_digest(leaf.digest)})
    return derive_identity(domain, {"entries": entries})
