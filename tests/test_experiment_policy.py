"""Tests for ``aptl.core.experiment.policy`` (ADR-047 admission policy and
allocation-ordering resolution).

``allocation_method`` is FREE TEXT in the ACES contract
(``ExperimentRunAllocationPlanModel.allocation_method: NonEmptyString``) —
never evaluated, only mapped through a small controller-owned, versioned
table to a supported :class:`OrderingKind`. An unmapped value fails closed.
"""

from __future__ import annotations

import pytest

from aptl.core.experiment.errors import EXPERIMENT_ADMISSION_DOMAIN, AdmissionRejection
from aptl.core.experiment.policy import (
    AdmissionPolicy,
    OrderingKind,
    default_admission_policy,
    resolve_allocation_ordering,
)


class TestDefaultAdmissionPolicy:
    def test_returns_an_admission_policy(self):
        policy = default_admission_policy()
        assert isinstance(policy, AdmissionPolicy)

    def test_is_frozen(self):
        policy = default_admission_policy()
        with pytest.raises(Exception):  # noqa: B017 - dataclass frozen raises FrozenInstanceError
            policy.max_root_bytes = 1  # type: ignore[misc]

    @pytest.mark.parametrize(
        "field_name",
        [
            "max_root_bytes",
            "max_artifact_bytes",
            "max_aggregate_bytes",
            "max_reference_count",
            "max_allocation_size",
            "max_nesting_depth",
        ],
    )
    def test_limits_are_positive_integers(self, field_name):
        policy = default_admission_policy()
        value = getattr(policy, field_name)
        assert isinstance(value, int)
        assert value > 0

    def test_aggregate_bytes_is_at_least_the_per_artifact_limit(self):
        policy = default_admission_policy()
        assert policy.max_aggregate_bytes >= policy.max_artifact_bytes

    def test_has_a_stable_policy_version_string(self):
        policy = default_admission_policy()
        assert isinstance(policy.policy_version, str)
        assert policy.policy_version

    def test_supported_allocation_methods_is_a_non_empty_mapping(self):
        policy = default_admission_policy()
        assert len(policy.supported_allocation_methods) > 0
        for method, kind in policy.supported_allocation_methods.items():
            assert isinstance(method, str)
            assert isinstance(kind, OrderingKind)

    def test_supported_stochastic_control_roles_is_a_non_empty_set(self):
        policy = default_admission_policy()
        assert len(policy.supported_stochastic_control_roles) > 0
        assert all(isinstance(role, str) for role in policy.supported_stochastic_control_roles)

    def test_supported_orderings_is_a_non_empty_set_of_ordering_kind(self):
        policy = default_admission_policy()
        assert len(policy.supported_orderings) > 0
        assert all(isinstance(kind, OrderingKind) for kind in policy.supported_orderings)

    def test_allow_uncertified_apparatus_defaults_to_false(self):
        policy = default_admission_policy()
        assert policy.allow_uncertified_apparatus is False

    def test_allow_uncertified_apparatus_is_overridable_via_replace(self):
        import dataclasses

        policy = dataclasses.replace(default_admission_policy(), allow_uncertified_apparatus=True)
        assert policy.allow_uncertified_apparatus is True


class TestResolveAllocationOrdering:
    def test_resolves_a_supported_allocation_method(self):
        policy = default_admission_policy()
        method, expected_kind = next(iter(policy.supported_allocation_methods.items()))

        kind = resolve_allocation_ordering(policy, method)

        assert kind == expected_kind
        assert kind in policy.supported_orderings

    def test_rejects_an_unsupported_free_text_allocation_method(self):
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection) as excinfo:
            resolve_allocation_ordering(policy, "definitely-not-a-real-method")

        assert excinfo.value.diagnostics
        assert all(d.domain == EXPERIMENT_ADMISSION_DOMAIN for d in excinfo.value.diagnostics)
        assert all(d.is_error for d in excinfo.value.diagnostics)

    def test_never_evaluates_the_free_text_value(self):
        """`allocation_method` is data, not code — a value shaped like an
        expression/import must be rejected exactly like any other unknown
        method, never executed or imported."""
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            resolve_allocation_ordering(policy, "__import__('os').system('echo pwned')")

    def test_rejection_message_does_not_echo_the_raw_free_text_value(self):
        policy = default_admission_policy()
        injected = "sk-should-never-appear-in-a-diagnostic"

        with pytest.raises(AdmissionRejection) as excinfo:
            resolve_allocation_ordering(policy, injected)

        for d in excinfo.value.diagnostics:
            assert injected not in d.message
            assert injected not in d.code
            assert injected not in d.address

    def test_is_case_sensitive_not_fuzzy_matched(self):
        policy = default_admission_policy()
        method, _ = next(iter(policy.supported_allocation_methods.items()))

        with pytest.raises(AdmissionRejection):
            resolve_allocation_ordering(policy, method.upper() + "-not-quite")


class TestOrderingKind:
    def test_has_a_flat_and_condition_major_replication_member(self):
        assert OrderingKind.FLAT is not OrderingKind.CONDITION_MAJOR_REPLICATION
