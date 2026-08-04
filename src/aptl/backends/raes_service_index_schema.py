"""ADR-088 ``service-search-index-schema`` materialization: portable field-schema
projection, canonical digest, ownership marker, and native-readback proof.

RAES ADR-088 / OpenRAE/rae#1011 add a second closed service-materialization
profile (``service-search-index-schema`` v1) whose desired state is a portable
map from top-level field name to a closed portable semantic
(``exact-token`` / ``full-text`` / ``integer`` / ``temporal`` / ``boolean``).
The SDL carries no vendor type literal, endpoint, query, or native index name;
the backend owns the projection from portable semantic to a native field type
and its inverse on readback (issue #889).

This module is the pure, IO-free core shared by:

- the content-placement lowering (:mod:`aptl.backends.raes_content_realization`),
- the Elasticsearch provider that materializes and reads the index back
  (the deployment backend), and
- realization observation.

Success is proven only by a fresh native readback projected back to the same
portable field map: the observed projection's canonical digest must reproduce
the declared ``canonical_field_schema_digest`` compiled by RAES. A mutation
response, a stored marker echo, or container health is never proof.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from raes_contracts.canonical import canonical_json_digest

INTERFACE_PROFILE = "service-search-index-schema"
PROFILE_VERSION = "1"
PROJECTION_SCOPE = "declared-fields"

# Portable top-level field semantic -> Elasticsearch/OpenSearch native field
# type. ADR-088 keeps vendor type literals out of the SDL; the provider owns
# this projection (portable semantic in, native type out) and its inverse on
# readback. A native type with no portable inverse is not projectable and fails
# closed rather than being silently approximated.
_PORTABLE_TO_NATIVE_TYPE: dict[str, str] = {
    "exact-token": "keyword",
    "full-text": "text",
    "integer": "long",
    "temporal": "date",
    "boolean": "boolean",
}
_NATIVE_TYPE_TO_PORTABLE: dict[str, str] = {
    native: portable for portable, native in _PORTABLE_TO_NATIVE_TYPE.items()
}

# Custom index metadata keys (Elasticsearch ``mappings._meta``) that bind the
# native index to the exact portable content address and declared field-schema
# digest. ``reject-unowned-collision`` (ADR-088): an existing same-name index
# without this owner marker is an unowned collision even when empty; it is never
# adopted, deleted, or recreated.
OWNER_META_KEY = "aptl_service_content_owner"
DIGEST_META_KEY = "aptl_field_schema_digest"


def native_field_type(semantic: str) -> str | None:
    """Return the native field type for a portable semantic, or ``None``."""

    return _PORTABLE_TO_NATIVE_TYPE.get(semantic)


def canonical_field_schema_digest(field_semantics: Mapping[str, str]) -> str:
    """Return the canonical portable field-schema digest (RFC 8785 / JCS SHA-256).

    Reproduces the RAES compiler's ``canonical_field_schema_digest`` exactly so a
    fresh native readback projected back to portable semantics can be compared to
    the declared digest. ``canonical_json_digest`` canonicalizes (sorted keys),
    so callers need not order ``field_semantics``.
    """

    return canonical_json_digest(
        {
            "interface_profile": INTERFACE_PROFILE,
            "profile_version": PROFILE_VERSION,
            "projection_scope": PROJECTION_SCOPE,
            "field_semantics": {name: field_semantics[name] for name in field_semantics},
        }
    )


def desired_native_mapping(
    field_semantics: Mapping[str, str],
    *,
    owner_address: str,
    field_schema_digest: str,
) -> dict[str, object]:
    """Return the native index mapping body for the declared portable schema.

    Carries a provider-owned ``_meta`` marker binding the index to the exact
    portable content address and declared digest so re-entry can distinguish an
    owned index from an unowned same-name collision.
    """

    return {
        "mappings": {
            "_meta": {
                OWNER_META_KEY: owner_address,
                DIGEST_META_KEY: field_schema_digest,
            },
            "properties": {
                name: {"type": _PORTABLE_TO_NATIVE_TYPE[semantic]}
                for name, semantic in field_semantics.items()
            },
        }
    }


def project_observed_properties(
    properties: Mapping[str, object],
    declared_fields: Iterable[str],
) -> tuple[dict[str, str] | None, str | None]:
    """Project observed native index ``properties`` to portable semantics.

    Projects exactly the declared field names. Returns ``(projection, None)`` on
    success or ``(None, reason)`` fail-closed. A declared field that is absent,
    carries no native type, or whose native type has no portable inverse fails —
    no multi-field or analyzer fallback satisfies an exactly named field.
    """

    projection: dict[str, str] = {}
    for field in declared_fields:
        entry = properties.get(field)
        if not isinstance(entry, Mapping):
            return None, f"declared field '{field}' is absent from the native index mapping"
        native_type = entry.get("type")
        if not isinstance(native_type, str) or not native_type:
            return None, f"declared field '{field}' has no concrete native type"
        portable = _NATIVE_TYPE_TO_PORTABLE.get(native_type)
        if portable is None:
            return (
                None,
                f"declared field '{field}' native type '{native_type}' is not projectable to a portable semantic",
            )
        projection[field] = portable
    return projection, None


def verify_readback(
    properties: Mapping[str, object],
    field_semantics: Mapping[str, str],
    *,
    declared_digest: str,
) -> tuple[bool, dict[str, str] | None, str | None]:
    """Prove a fresh native readback matches the declared portable field schema.

    Returns ``(True, projection, None)`` when the observed projection's canonical
    digest reproduces ``declared_digest``; otherwise ``(False, projection, reason)``.
    """

    projection, reason = project_observed_properties(properties, field_semantics.keys())
    if projection is None:
        return False, None, reason
    observed_digest = canonical_field_schema_digest(projection)
    if observed_digest != declared_digest:
        return (
            False,
            projection,
            "fresh native readback does not reproduce the declared portable field-schema digest",
        )
    return True, projection, None


def owner_marker(mapping_meta: Mapping[str, object]) -> tuple[str, str]:
    """Return the ``(owner_address, digest)`` marker from an index's ``_meta``.

    Missing keys yield empty strings so an unmarked (unowned) index is not
    mistaken for an owned one.
    """

    owner = mapping_meta.get(OWNER_META_KEY)
    digest = mapping_meta.get(DIGEST_META_KEY)
    return (
        owner if isinstance(owner, str) else "",
        digest if isinstance(digest, str) else "",
    )
