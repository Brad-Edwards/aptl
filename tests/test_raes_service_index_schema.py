"""Unit tests for the ADR-088 service-search-index-schema materialization core.

Proves the portable field-schema digest reproduces the RAES compiler's binding
digest exactly, the native projection is fail-closed and exact, and the readback
proof accepts only an observed schema whose portable projection matches the
declared digest.
"""

from __future__ import annotations

import pytest
from raes_contracts.canonical import canonical_json_digest

from aptl.backends import raes_service_index_schema as sis

_CORTEX_FIELDS = {"key": "exact-token", "status": "exact-token", "relations": "exact-token"}


def test_digest_matches_raes_compiler_binding_exactly() -> None:
    """The APTL digest must equal what RAES compiles into the plan binding.

    RAES computes canonical_json_digest over profile id, version, the fixed
    projection scope, and the field map. If APTL's readback digest ever diverges,
    a truthful native readback would be rejected as a mismatch.
    """

    expected = canonical_json_digest(
        {
            "interface_profile": "service-search-index-schema",
            "profile_version": "1",
            "projection_scope": "declared-fields",
            "field_semantics": _CORTEX_FIELDS,
        }
    )
    assert sis.canonical_field_schema_digest(_CORTEX_FIELDS) == expected


def test_digest_is_order_independent_and_semantic_sensitive() -> None:
    reordered = {"relations": "exact-token", "key": "exact-token", "status": "exact-token"}
    changed = {"key": "exact-token", "status": "full-text", "relations": "exact-token"}
    assert sis.canonical_field_schema_digest(_CORTEX_FIELDS) == sis.canonical_field_schema_digest(reordered)
    assert sis.canonical_field_schema_digest(_CORTEX_FIELDS) != sis.canonical_field_schema_digest(changed)


def test_native_field_type_projection_is_closed() -> None:
    assert sis.native_field_type("exact-token") == "keyword"
    assert sis.native_field_type("full-text") == "text"
    assert sis.native_field_type("integer") == "long"
    assert sis.native_field_type("temporal") == "date"
    assert sis.native_field_type("boolean") == "boolean"
    assert sis.native_field_type("not-a-semantic") is None


def test_desired_native_mapping_carries_owner_marker_and_types() -> None:
    digest = sis.canonical_field_schema_digest(_CORTEX_FIELDS)
    body = sis.desired_native_mapping(
        _CORTEX_FIELDS, owner_address="provision.content.cortex-job-index-schema", field_schema_digest=digest
    )
    mappings = body["mappings"]
    assert mappings["properties"] == {
        "key": {"type": "keyword"},
        "status": {"type": "keyword"},
        "relations": {"type": "keyword"},
    }
    assert mappings["_meta"][sis.OWNER_META_KEY] == "provision.content.cortex-job-index-schema"
    assert mappings["_meta"][sis.DIGEST_META_KEY] == digest


def test_project_observed_properties_maps_declared_fields_only() -> None:
    observed = {
        "key": {"type": "keyword"},
        "status": {"type": "keyword"},
        "relations": {"type": "keyword"},
        "extra": {"type": "text"},  # undeclared native field is outside the claim
    }
    projection, reason = sis.project_observed_properties(observed, _CORTEX_FIELDS.keys())
    assert reason is None
    assert projection == _CORTEX_FIELDS


@pytest.mark.parametrize(
    ("observed", "needle"),
    [
        ({"key": {"type": "keyword"}, "status": {"type": "keyword"}}, "relations"),  # absent field
        (
            {"key": {"type": "keyword"}, "status": {"type": "keyword"}, "relations": {}},
            "no concrete native type",
        ),
        (
            {
                "key": {"type": "keyword"},
                "status": {"type": "keyword"},
                "relations": {"type": "text"},  # analyzed fallback does not satisfy exact-token
            },
            "does not reproduce",
        ),
    ],
)
def test_readback_fails_closed_on_absent_typeless_or_weakened_field(observed: dict, needle: str) -> None:
    declared = sis.canonical_field_schema_digest(_CORTEX_FIELDS)
    ok, _projection, reason = sis.verify_readback(observed, _CORTEX_FIELDS, declared_digest=declared)
    assert ok is False
    assert reason is not None
    assert needle in reason


def test_readback_proves_matching_native_schema() -> None:
    observed = {
        "key": {"type": "keyword"},
        "status": {"type": "keyword"},
        "relations": {"type": "keyword"},
    }
    declared = sis.canonical_field_schema_digest(_CORTEX_FIELDS)
    ok, projection, reason = sis.verify_readback(observed, _CORTEX_FIELDS, declared_digest=declared)
    assert ok is True
    assert reason is None
    assert projection == _CORTEX_FIELDS


def test_owner_marker_defaults_to_empty_for_unmarked_index() -> None:
    assert sis.owner_marker({}) == ("", "")
    assert sis.owner_marker({sis.OWNER_META_KEY: "addr", sis.DIGEST_META_KEY: "sha256:x"}) == ("addr", "sha256:x")
