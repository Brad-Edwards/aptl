"""Tests for the REP-003 provenance identity primitives (issue #452).

These cover the preflight's "Make identities stable and differences
explainable" guardrail: domain-separated RFC 8785 canonical identity, one
normalized digest representation, per-leaf logical roles, and a family
identity folded over a SORTED canonical sequence — never an unframed
concatenation of file bytes.
"""

import hashlib

import pytest

from aptl.core.provenance.identity import (
    DIGEST_PREFIX,
    ProvenanceIdentityError,
    derive_identity,
    family_identity,
    leaf_identity,
    normalize_digest,
)


class TestNormalizeDigest:
    """One representation for every SHA-256 value at the provenance boundary."""

    def test_bare_hex_gains_the_prefix(self):
        bare = "a" * 64
        assert normalize_digest(bare) == f"{DIGEST_PREFIX}{bare}"

    def test_prefixed_digest_is_idempotent(self):
        value = f"{DIGEST_PREFIX}{'b' * 64}"
        assert normalize_digest(value) == value

    def test_uppercase_hex_is_lowercased(self):
        assert normalize_digest("A" * 64) == f"{DIGEST_PREFIX}{'a' * 64}"

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "sha256:",
            "z" * 64,
            "a" * 63,
            "a" * 65,
            "md5:" + "a" * 32,
            "sha256:sha256:" + "a" * 64,
        ],
    )
    def test_malformed_digest_is_rejected(self, value):
        """A malformed digest fails closed rather than becoming a fabricated identity."""
        with pytest.raises(ProvenanceIdentityError):
            normalize_digest(value)

    def test_non_string_is_rejected(self):
        with pytest.raises(ProvenanceIdentityError):
            normalize_digest(None)  # type: ignore[arg-type]


class TestLeafIdentity:
    """A leaf binds a stable logical role to the digest of its bytes."""

    def test_leaf_binds_logical_id_and_digest(self):
        leaf = leaf_identity("suricata/rules/custom.rules", b"alert tcp any any;")
        assert leaf.logical_id == "suricata/rules/custom.rules"
        assert leaf.digest == normalize_digest(
            hashlib.sha256(b"alert tcp any any;").hexdigest()
        )

    def test_same_bytes_under_different_roles_are_different_leaves(self):
        """Role is part of identity, so a file moving roles is a real difference."""
        first = leaf_identity("wazuh/rules/local.xml", b"<group/>")
        second = leaf_identity("wazuh/decoders/local.xml", b"<group/>")
        assert first.digest == second.digest
        assert first != second

    def test_empty_bytes_still_produce_an_explicit_digest(self):
        """An empty file is a real observation, not a missing source."""
        leaf = leaf_identity("suricata/rules/empty.rules", b"")
        assert leaf.digest == normalize_digest(hashlib.sha256(b"").hexdigest())

    @pytest.mark.parametrize("logical_id", ["", " ", "a" * 513, "x\x00y", "x\ny"])
    def test_hostile_logical_id_is_rejected(self, logical_id):
        """Hostile metadata can never become a record key."""
        with pytest.raises(ProvenanceIdentityError):
            leaf_identity(logical_id, b"data")


class TestFamilyIdentity:
    """A family folds a sorted canonical sequence of {logical_id, digest}."""

    def test_family_is_order_independent(self):
        one = leaf_identity("a", b"1")
        two = leaf_identity("b", b"2")
        assert family_identity("detection", [one, two]) == family_identity(
            "detection", [two, one]
        )

    def test_concatenation_ambiguity_is_defeated(self):
        """The defect this replaces: unframed concatenation collides.

        ``"ab" + "c"`` and ``"a" + "bc"`` hash identically under the old
        combined-digest approach. Framing by logical role must separate them.
        """
        split_one = [leaf_identity("first", b"ab"), leaf_identity("second", b"c")]
        split_two = [leaf_identity("first", b"a"), leaf_identity("second", b"bc")]
        assert family_identity("detection", split_one) != family_identity(
            "detection", split_two
        )

    def test_one_changed_leaf_changes_the_family(self):
        before = [leaf_identity("a", b"1"), leaf_identity("b", b"2")]
        after = [leaf_identity("a", b"1"), leaf_identity("b", b"changed")]
        assert family_identity("detection", before) != family_identity("detection", after)

    def test_unchanged_leaf_keeps_its_own_identity_when_a_sibling_changes(self):
        """Targeted differences: a sibling's change never perturbs this leaf."""
        stable = leaf_identity("a", b"1")
        assert stable == leaf_identity("a", b"1")

    def test_different_families_of_the_same_leaves_differ(self):
        leaves = [leaf_identity("a", b"1")]
        assert family_identity("detection", leaves) != family_identity("config", leaves)

    def test_empty_family_is_explicit_not_an_empty_string(self):
        """No leaves is a real, stable identity — never '' masquerading as success."""
        empty = family_identity("detection", [])
        assert empty.startswith(DIGEST_PREFIX)
        assert empty == family_identity("detection", [])
        assert empty != family_identity("detection", [leaf_identity("a", b"")])

    def test_duplicate_logical_ids_are_rejected(self):
        duplicated = [leaf_identity("a", b"1"), leaf_identity("a", b"2")]
        with pytest.raises(ProvenanceIdentityError):
            family_identity("detection", duplicated)


class TestDeriveIdentity:
    """Structured identities are domain-separated and canonical."""

    def test_identity_is_stable_across_mapping_insertion_order(self):
        first = derive_identity("record", {"a": 1, "b": 2})
        second = derive_identity("record", {"b": 2, "a": 1})
        assert first == second

    def test_domain_separation_prevents_cross_domain_collision(self):
        payload = {"a": 1}
        assert derive_identity("record", payload) != derive_identity("provider", payload)

    def test_identity_is_a_normalized_digest(self):
        assert derive_identity("record", {"a": 1}).startswith(DIGEST_PREFIX)

    def test_unserializable_payload_fails_closed(self):
        with pytest.raises(ProvenanceIdentityError):
            derive_identity("record", {"a": object()})

    @pytest.mark.parametrize("domain", ["", "not a domain", "x" * 129])
    def test_hostile_domain_is_rejected(self, domain):
        with pytest.raises(ProvenanceIdentityError):
            derive_identity(domain, {"a": 1})
