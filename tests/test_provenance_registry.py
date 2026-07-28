"""Tests for the REP-003 provenance provider registry (issue #452).

Covers the preflight's "narrow, trusted, capability-declared provenance-provider
seam": a registration pins a stable non-executable id, implementation version,
the capability it supplies, its owner adapter, applicable seal point,
requiredness policy key, and hard count/byte/time limits.
"""

import pytest

from aptl.core.provenance.registry import (
    REGISTRY_SCHEMA_VERSION,
    ProvenanceLimits,
    ProvenanceProviderRegistration,
    ProvenanceProviderRegistry,
    ProvenanceRegistrationError,
    SealPoint,
    SealProfile,
)

_LIMITS = ProvenanceLimits(max_bytes=1024, max_entries=8, timeout_s=5)


def _registration(provider_id: str = "detection-content", **overrides):
    fields = dict(
        provider_id=provider_id,
        implementation_version="1.0.0",
        provenance_kind="detection-content",
        owner_adapter="aptl.core.snapshot",
        seal_point=SealPoint.RUN_READY_TO_SEAL,
        requiredness_policy_key="detection-content-required",
        limits=_LIMITS,
    )
    fields.update(overrides)
    return ProvenanceProviderRegistration(**fields)


class TestRegistration:
    """A registration is a bounded, code-owned capability declaration."""

    def test_declaration_projection_is_canonical_ready(self):
        projection = _registration().declaration_projection()
        assert projection["registry_schema"] == REGISTRY_SCHEMA_VERSION
        assert projection["provider_id"] == "detection-content"
        assert projection["max_bytes"] == 1024
        assert projection["max_entries"] == 8
        assert projection["timeout_s"] == 5

    def test_effective_config_digest_pins_the_declaration(self):
        assert _registration().effective_config_digest().startswith("sha256:")

    def test_digest_changes_when_a_declared_limit_changes(self):
        tighter = ProvenanceLimits(max_bytes=512, max_entries=8, timeout_s=5)
        assert (
            _registration().effective_config_digest()
            != _registration(limits=tighter).effective_config_digest()
        )

    def test_digest_changes_when_the_implementation_version_changes(self):
        assert (
            _registration().effective_config_digest()
            != _registration(implementation_version="1.0.1").effective_config_digest()
        )

    def test_digest_is_stable_for_an_identical_declaration(self):
        assert _registration().effective_config_digest() == _registration().effective_config_digest()

    @pytest.mark.parametrize(
        "provider_id",
        [
            "",
            "Detection",
            "detection content",
            "aptl.core.snapshot:collect",
            "../../etc/passwd",
            "https://example.test/provider",
            "x" * 65,
        ],
    )
    def test_provider_id_must_not_be_resolvable_to_code_or_a_location(self, provider_id):
        """The id can never be an import path, command, URL, or host path."""
        with pytest.raises(ProvenanceRegistrationError):
            _registration(provider_id=provider_id)

    @pytest.mark.parametrize(
        "limits",
        [
            ProvenanceLimits(max_bytes=0, max_entries=8, timeout_s=5),
            ProvenanceLimits(max_bytes=1024, max_entries=0, timeout_s=5),
            ProvenanceLimits(max_bytes=1024, max_entries=8, timeout_s=0),
            ProvenanceLimits(max_bytes=-1, max_entries=8, timeout_s=5),
        ],
    )
    def test_limits_must_be_positive(self, limits):
        """An unbounded provider is not admissible."""
        with pytest.raises(ProvenanceRegistrationError):
            _registration(limits=limits)

    def test_registration_is_immutable(self):
        with pytest.raises(AttributeError):
            _registration().provider_id = "other"  # type: ignore[misc]


class TestRegistry:
    """The registry is the sole source of truth and iterates deterministically."""

    def test_duplicate_provider_ids_are_rejected(self):
        with pytest.raises(ProvenanceRegistrationError):
            ProvenanceProviderRegistry((_registration(), _registration()))

    def test_iteration_is_id_sorted_regardless_of_construction_order(self):
        first = _registration("apparatus")
        second = _registration("detection-content")
        forward = ProvenanceProviderRegistry((first, second))
        backward = ProvenanceProviderRegistry((second, first))
        assert [r.provider_id for r in forward.ordered()] == ["apparatus", "detection-content"]
        assert [r.provider_id for r in forward.ordered()] == [
            r.provider_id for r in backward.ordered()
        ]

    def test_declaration_projection_is_order_independent(self):
        first = _registration("apparatus")
        second = _registration("detection-content")
        assert (
            ProvenanceProviderRegistry((first, second)).declaration_digest()
            == ProvenanceProviderRegistry((second, first)).declaration_digest()
        )

    def test_lookup_returns_the_registration(self):
        registry = ProvenanceProviderRegistry((_registration("apparatus"),))
        assert registry.get("apparatus") is not None
        assert registry.get("absent") is None

    def test_empty_registry_has_a_stable_declaration_digest(self):
        assert (
            ProvenanceProviderRegistry(()).declaration_digest()
            == ProvenanceProviderRegistry(()).declaration_digest()
        )

    def test_for_seal_point_selects_only_matching_registrations(self):
        run_scoped = _registration("apparatus", seal_point=SealPoint.RUN_READY_TO_SEAL)
        trial_scoped = _registration("experiment", seal_point=SealPoint.TRIAL_READY_TO_SEAL)
        registry = ProvenanceProviderRegistry((run_scoped, trial_scoped))
        selected = registry.for_seal_point(SealPoint.RUN_READY_TO_SEAL)
        assert [r.provider_id for r in selected] == ["apparatus"]


class TestSealProfile:
    """The seal profile is the extension parameter: seal point + required ids."""

    def test_profile_reports_required_providers(self):
        profile = SealProfile(
            seal_point=SealPoint.RUN_READY_TO_SEAL,
            required_provider_ids=frozenset({"apparatus"}),
        )
        assert profile.requires("apparatus")
        assert not profile.requires("detection-content")

    def test_profile_rejects_a_required_id_absent_from_the_registry(self):
        """A policy naming a provider nobody implements must fail closed."""
        registry = ProvenanceProviderRegistry((_registration("apparatus"),))
        profile = SealProfile(
            seal_point=SealPoint.RUN_READY_TO_SEAL,
            required_provider_ids=frozenset({"nonexistent"}),
        )
        with pytest.raises(ProvenanceRegistrationError):
            profile.validate_against(registry)

    def test_profile_validates_when_every_required_id_is_registered(self):
        registry = ProvenanceProviderRegistry((_registration("apparatus"),))
        profile = SealProfile(
            seal_point=SealPoint.RUN_READY_TO_SEAL,
            required_provider_ids=frozenset({"apparatus"}),
        )
        profile.validate_against(registry)

    @pytest.mark.parametrize("provider_id", ["", "Apparatus", "a b"])
    def test_profile_rejects_a_hostile_required_id(self, provider_id):
        with pytest.raises(ProvenanceRegistrationError):
            SealProfile(
                seal_point=SealPoint.RUN_READY_TO_SEAL,
                required_provider_ids=frozenset({provider_id}),
            )
