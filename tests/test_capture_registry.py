"""Tests for the code-owned collector registry (ADR-047 "Apparatus and
capture capability admission"; EXP-010 / issue #752).

The registry is the single source of truth for capture support: admission
matches an authored ``ExperimentCaptureRequirementModel`` against it and
returns an immutable :class:`CaptureBinding`, and the backend
``ObservationCapabilities`` manifest is an aggregate projection of the same
declarations. These tests prove the matching is deterministic across every
requirement axis, fails closed on any unknown, keeps ``registration_id``
non-executable, and that the observation projection is honest (``None`` while
the registry is empty).

Uses the installed ACES fixture corpus as the contract test source (ADR-047
testing contract), never a copied-in schema.
"""

from __future__ import annotations

import dataclasses
import json

import pytest
from aces_backend_protocols.capabilities import observation_capability_contract_gaps
from aces_contracts.contracts import ExperimentCaptureSpecModel
from aces_contracts.corpus import FIXTURES, corpus_family_root

from aptl.core.experiment.capture_registry import (
    DEFAULT_COLLECTOR_REGISTRY,
    OBSERVATION_EVIDENCE_CONTRACTS,
    CaptureBinding,
    CaptureLimits,
    CaptureVisibility,
    CollectorRegistration,
    CollectorRegistry,
    RegistrationIdError,
    validate_registration_id,
)

CORPUS_ROOT = corpus_family_root(FIXTURES)

_LIMITS = CaptureLimits(max_bytes=1_048_576, max_artifact_count=100, max_duration_s=300)


def _read(*parts: str) -> bytes:
    """Read a byte payload from the installed ACES fixture corpus."""
    path = CORPUS_ROOT
    for part in parts:
        path = path / part
    return path.read_bytes()


def _reference_spec_payload() -> dict:
    """Return the parsed reference capture-spec fixture payload (single requirement)."""
    return json.loads(_read("experiment-core", "experiment-capture-spec-v1", "valid", "reference.json"))


def _spec_with(**requirement_overrides: object) -> ExperimentCaptureSpecModel:
    """Build a one-requirement capture spec from the corpus reference, overriding fields.

    The reference ``network-trace`` requirement is the fully-covered baseline
    every miss test deviates from by exactly one field.
    """
    payload = _reference_spec_payload()
    requirement = next(iter(payload["capture_requirements"].values()))
    requirement.update(requirement_overrides)
    payload["capture_requirements"] = {requirement["requirement_id"]: requirement}
    return ExperimentCaptureSpecModel.model_validate(payload)


def _covering_registration(**overrides: object) -> CollectorRegistration:
    """Return a registration that covers the reference ``network-trace`` requirement.

    Every miss test overrides exactly one field so that, if the corresponding
    match guard were deleted, the requirement would wrongly bind.
    """
    fields: dict[str, object] = {
        "registration_id": "aptl.collector.network-trace",
        "implementation_version": "1.0.0",
        "contract_version": "experiment-capture-spec/v1",
        "channel_kind": "evaluation-history",
        "capture_kind": "trace",
        "capture_scope": "network",
        "window_kinds": frozenset({"run"}),
        "media_types": frozenset({"application/json"}),
        "required_artifact_roles": frozenset({"observation"}),
        "supported_sensitivities": frozenset({"internal", "public"}),
        "supports_redaction": True,
        "integrity_modes": frozenset({"sha256-digest"}),
        "sealing_modes": frozenset({"digest"}),
        "supports_chain_of_custody": False,
        "supports_retention": True,
        "supports_loss_disclosure": True,
        "visibility_class": CaptureVisibility.EVALUATOR_ONLY,
        "limits": _LIMITS,
    }
    fields.update(overrides)
    return CollectorRegistration(**fields)


def _bind_reference(registration: CollectorRegistration, **requirement_overrides: object) -> CaptureBinding | None:
    """Match the reference requirement (with overrides) against a single-registration registry."""
    spec = _spec_with(**requirement_overrides)
    requirement = next(iter(spec.capture_requirements.values()))
    return CollectorRegistry((registration,)).match(spec, requirement)


# ---------------------------------------------------------------------------
# registration_id — non-executable slug
# ---------------------------------------------------------------------------


class TestRegistrationIdValidation:
    @pytest.mark.parametrize(
        "value",
        ["aptl.collector.wazuh-alerts", "x", "a-b.c-d", "trace1", "a1-b2.c3"],
    )
    def test_safe_slugs_are_accepted(self, value):
        assert validate_registration_id(value) == value

    @pytest.mark.parametrize(
        "value",
        [
            "Foo.Bar",  # class name (uppercase)
            "aptl/collector",  # path separator
            "a\\b",  # windows path separator
            "http://example",  # URL scheme
            "a..b",  # traversal
            "../escape",  # traversal
            "a b",  # whitespace
            "a;rm -rf",  # shell metachar
            "a:b",  # scheme / host:port
            "a__b",  # underscore not in the slug alphabet
            "a.",  # trailing separator
            ".a",  # leading separator
            "",  # empty
            "aptl.collector.$evil",  # shell expansion char
        ],
    )
    def test_executable_or_unsafe_ids_are_rejected(self, value):
        with pytest.raises(RegistrationIdError):
            validate_registration_id(value)

    def test_a_registration_validates_its_id_at_construction(self):
        with pytest.raises(RegistrationIdError):
            _covering_registration(registration_id="Not/A/Slug")

    def test_an_over_long_id_is_rejected(self):
        with pytest.raises(RegistrationIdError):
            validate_registration_id("a" + "-b" * 200)


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_registration_is_frozen(self):
        registration = _covering_registration()
        with pytest.raises(dataclasses.FrozenInstanceError):
            registration.capture_kind = "log"

    def test_binding_is_frozen(self):
        binding = _bind_reference(_covering_registration())
        assert binding is not None
        with pytest.raises(dataclasses.FrozenInstanceError):
            binding.registration_id = "other"

    def test_registry_rejects_duplicate_registration_ids(self):
        registration = _covering_registration()
        with pytest.raises(ValueError, match="duplicate registration IDs"):
            CollectorRegistry((registration, _covering_registration()))


# ---------------------------------------------------------------------------
# Deterministic match — the covered baseline binds, one miss per axis does not
# ---------------------------------------------------------------------------


class TestMatchSuccessBaseline:
    def test_the_covered_reference_requirement_binds(self):
        binding = _bind_reference(_covering_registration())

        assert binding is not None
        assert binding.registration_id == "aptl.collector.network-trace"
        assert binding.requirement_id == "network-trace"
        assert binding.capture_kind == "trace"
        assert binding.capture_scope == "network"

    def test_the_binding_records_the_author_channel_ref_and_provider_channel_kind(self):
        binding = _bind_reference(_covering_registration())

        assert binding is not None
        # The AUTHOR's measurement channel the evidence satisfies...
        assert binding.channel_ref_id == "evaluation-history-channel"
        assert binding.channel_ref_version == "1.0.0"
        # ...and the provider (registration) channel kind.
        assert binding.channel_kind == "evaluation-history"

    def test_the_binding_pins_the_registration_config_digest(self):
        registration = _covering_registration()
        binding = _bind_reference(registration)

        assert binding is not None
        assert binding.effective_config_digest == registration.effective_config_digest()
        assert binding.effective_config_digest.startswith("sha256:")

    def test_the_binding_carries_free_text_retention_verbatim(self):
        binding = _bind_reference(_covering_registration())

        assert binding is not None
        assert binding.retention_policy is not None
        assert "Retain raw evidence" in binding.retention_policy


class TestMatchOneMissPerAxisFailsClosed:
    """Each test deviates from the covered baseline on exactly one axis; the
    guard for that axis must make the match return ``None``."""

    def test_contract_version_mismatch(self):
        assert _bind_reference(_covering_registration(contract_version="experiment-capture-spec/v2")) is None

    def test_capture_kind_mismatch(self):
        assert _bind_reference(_covering_registration(capture_kind="log")) is None

    def test_capture_scope_mismatch(self):
        assert _bind_reference(_covering_registration(capture_scope="service")) is None

    def test_window_kind_not_supported(self):
        assert _bind_reference(_covering_registration(window_kinds=frozenset({"task"}))) is None

    def test_media_type_not_a_subset(self):
        assert _bind_reference(_covering_registration(media_types=frozenset({"text/plain"}))) is None

    def test_required_artifact_role_not_a_subset(self):
        assert _bind_reference(_covering_registration(required_artifact_roles=frozenset({"report"}))) is None

    def test_sensitivity_not_supported(self):
        assert _bind_reference(_covering_registration(supported_sensitivities=frozenset({"public"}))) is None

    def test_integrity_mode_not_a_subset(self):
        assert _bind_reference(_covering_registration(integrity_modes=frozenset({"sha512-digest"}))) is None

    def test_redaction_required_but_unsupported(self):
        registration = _covering_registration(supports_redaction=False)
        assert _bind_reference(registration, redaction_policy="redact-secrets") is None

    def test_retention_required_but_unsupported(self):
        registration = _covering_registration(supports_retention=False)
        assert _bind_reference(registration, retention_policy="retain-30d") is None

    def test_loss_disclosure_required_but_unsupported(self):
        registration = _covering_registration(supports_loss_disclosure=False)
        assert _bind_reference(registration, loss_disclosure_required=True) is None

    def test_an_unmatched_optional_axis_still_binds(self):
        # A requirement that does NOT require redaction/retention/loss binds
        # against a registration that also does not support them — the guards
        # are "required implies supported", not "supported implies required".
        registration = _covering_registration(
            supports_redaction=False, supports_retention=False, supports_loss_disclosure=False
        )
        binding = _bind_reference(
            registration, redaction_policy=None, retention_policy=None, loss_disclosure_required=False
        )
        assert binding is not None


class TestMatchIsDeterministic:
    def test_selection_is_id_sorted_not_insertion_ordered(self):
        first = _covering_registration(registration_id="aptl.collector.aaa")
        second = _covering_registration(registration_id="aptl.collector.bbb")
        spec = _spec_with()
        requirement = next(iter(spec.capture_requirements.values()))

        forward = CollectorRegistry((first, second)).match(spec, requirement)
        reverse = CollectorRegistry((second, first)).match(spec, requirement)

        assert forward is not None and reverse is not None
        # Both cover; ID-sorted selection picks "aaa" regardless of insertion order.
        assert forward.registration_id == reverse.registration_id == "aptl.collector.aaa"


# ---------------------------------------------------------------------------
# effective_config_digest — stable and sensitive
# ---------------------------------------------------------------------------


class TestConfigDigest:
    def test_two_identical_registrations_share_a_digest(self):
        assert _covering_registration().effective_config_digest() == _covering_registration().effective_config_digest()

    def test_changing_any_declared_field_changes_the_digest(self):
        base = _covering_registration().effective_config_digest()
        changed = _covering_registration(implementation_version="2.0.0").effective_config_digest()
        assert base != changed


# ---------------------------------------------------------------------------
# observation projection — honest and vocabulary-valid
# ---------------------------------------------------------------------------


class TestObservationProjection:
    def test_empty_registry_projects_no_observation(self):
        assert DEFAULT_COLLECTOR_REGISTRY.observation_projection() is None
        assert CollectorRegistry().observation_projection() is None

    def test_populated_registry_aggregates_declarations(self):
        registry = CollectorRegistry(
            (
                _covering_registration(registration_id="aptl.collector.a", capture_kind="trace"),
                _covering_registration(
                    registration_id="aptl.collector.b",
                    capture_kind="log",
                    channel_kind="backend-log",
                    media_types=frozenset({"text/plain"}),
                ),
            )
        )
        observation = registry.observation_projection()

        assert observation is not None
        assert observation.supported_capture_kinds == frozenset({"trace", "log"})
        assert observation.supported_channel_kinds == frozenset({"evaluation-history", "backend-log"})
        assert observation.supported_media_types == frozenset({"application/json", "text/plain"})
        assert observation.supported_evidence_contracts == OBSERVATION_EVIDENCE_CONTRACTS

    def test_projection_uses_governed_vocabulary_terms(self):
        # ObservationCapabilities validates channel/capture/sealing terms
        # against the ACES controlled-vocabulary catalog at construction, so a
        # successful projection proves the declared terms are governed.
        registry = CollectorRegistry((_covering_registration(),))
        observation = registry.observation_projection()
        assert observation is not None
        assert observation.supports_loss_disclosure is True


# ---------------------------------------------------------------------------
# Fuzz — determinism and order-independence
# ---------------------------------------------------------------------------

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402


@pytest.mark.fuzz
class TestFuzzRegistry:
    @given(version=st.text(alphabet="0123456789.", min_size=1, max_size=8))
    @settings(max_examples=40, deadline=2000)
    def test_config_digest_is_stable_across_reconstruction(self, version):
        left = _covering_registration(implementation_version=version).effective_config_digest()
        right = _covering_registration(implementation_version=version).effective_config_digest()
        assert left == right

    @given(shuffle=st.permutations([f"aptl.collector.c{i}" for i in range(4)]))
    @settings(max_examples=40, deadline=2000)
    def test_match_selection_is_insertion_order_independent(self, shuffle):
        registrations = tuple(_covering_registration(registration_id=rid) for rid in shuffle)
        spec = _spec_with()
        requirement = next(iter(spec.capture_requirements.values()))
        binding = CollectorRegistry(registrations).match(spec, requirement)
        assert binding is not None
        assert binding.registration_id == "aptl.collector.c0"


# ---------------------------------------------------------------------------
# Canonical identity — insertion order never leaks into the projection
# ---------------------------------------------------------------------------


class TestProjectionIsOrderCanonical:
    """ADR-047: semantically unordered requirement axes must be sorted in the
    identity-bearing binding projection so authored list order never changes
    the plan digest."""

    def test_set_valued_axes_are_sorted_in_the_projection(self):
        registration = _covering_registration(
            media_types=frozenset({"application/json", "text/plain"}),
            integrity_modes=frozenset({"sha256-digest", "blake3-digest"}),
            required_artifact_roles=frozenset({"observation", "report"}),
        )
        binding = _bind_reference(
            registration,
            expected_media_types=["text/plain", "application/json"],
            integrity_requirements=["sha256-digest", "blake3-digest"],
            required_artifact_roles=["report", "observation"],
        )
        assert binding is not None
        projection = binding.binding_projection()
        assert projection["expected_media_types"] == ["application/json", "text/plain"]
        assert projection["integrity_requirements"] == ["blake3-digest", "sha256-digest"]
        assert projection["required_artifact_roles"] == ["observation", "report"]

    def test_authored_axis_order_does_not_change_the_projection(self):
        registration = _covering_registration(media_types=frozenset({"application/json", "text/plain"}))
        forward = _bind_reference(registration, expected_media_types=["application/json", "text/plain"])
        reverse = _bind_reference(registration, expected_media_types=["text/plain", "application/json"])
        assert forward is not None and reverse is not None
        assert forward.binding_projection() == reverse.binding_projection()
