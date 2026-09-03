"""Tests for the REP-003 apparatus/experiment/participant providers (issue #452).

These providers compose OWNER-NATIVE payloads: RAES manifest serializers and
the admitted trial plan. They never restate a RAES DTO, reparse an authored
artifact at seal time, or reconstruct an accepted selection from current
configuration.
"""

import pytest

from aptl.core.provenance.outcomes import ProvenanceStatus
from aptl.core.provenance.protocol import ProvenanceContext, ProvenanceResult
from aptl.core.provenance.providers.apparatus import (
    APPARATUS_PROVIDER_ID,
    ApparatusManifestProvider,
)
from aptl.core.provenance.providers.experiment import (
    EXPERIMENT_PROVIDER_ID,
    AdmittedExperimentProvider,
)
from aptl.core.provenance.providers.participant import (
    PARTICIPANT_PROVIDER_ID,
    ParticipantApparatusProvider,
)
from aptl.core.provenance.registry import (
    ProvenanceLimits,
    ProvenanceProviderRegistration,
    SealPoint,
)


def _context(provider_id, *, max_entries=64, timeout_s=30, clock=None):
    registration = ProvenanceProviderRegistration(
        provider_id=provider_id,
        implementation_version="1.0.0",
        provenance_kind=provider_id,
        owner_adapter="tests",
        seal_point=SealPoint.RUN_READY_TO_SEAL,
        requiredness_policy_key=f"{provider_id}-required",
        limits=ProvenanceLimits(
            max_bytes=1_000_000, max_entries=max_entries, timeout_s=timeout_s
        ),
    )
    return ProvenanceContext(
        registration=registration, clock=clock or (lambda: 0.0), started_at=0.0
    )


class TestApparatusProvider:
    """Backend + processor manifest identity comes from the owner serializers."""

    def test_collects_backend_and_processor_identity(self):
        result = ApparatusManifestProvider().collect(_context(APPARATUS_PROVIDER_ID))
        assert result.status is ProvenanceStatus.COLLECTED
        names = {leaf.logical_id for leaf in result.leaves}
        assert "backend-manifest" in names
        assert "processor-manifest" in names

    def test_payload_records_owner_declared_identity(self):
        result = ApparatusManifestProvider().collect(_context(APPARATUS_PROVIDER_ID))
        assert result.payload["backend"]["name"] == "aptl"
        assert result.payload["processor"]["name"] == "raes-reference-processor"
        assert result.payload["backend"]["schema_version"] == "backend-manifest/v2"
        assert result.payload["processor"]["schema_version"] == "processor-manifest/v2"

    def test_identity_is_stable_across_collections(self):
        first = ApparatusManifestProvider().collect(_context(APPARATUS_PROVIDER_ID))
        second = ApparatusManifestProvider().collect(_context(APPARATUS_PROVIDER_ID))
        assert first.leaves == second.leaves

    def test_declared_capability_contracts_are_recorded(self):
        """Capability claims come from the registries that implement them."""
        result = ApparatusManifestProvider().collect(_context(APPARATUS_PROVIDER_ID))
        assert isinstance(result.payload["backend"]["supported_contract_versions"], list)

    def test_a_failing_owner_serializer_is_reported_not_raised(self):
        def broken():
            raise RuntimeError("manifest unavailable")

        provider = ApparatusManifestProvider(backend_manifest_factory=broken)
        result = provider.collect(_context(APPARATUS_PROVIDER_ID))
        assert result.status is ProvenanceStatus.FAILED
        assert result.leaves == ()


class _StubTrial:
    def __init__(self, trial_id, snapshot_digest="sha256:" + "a" * 64):
        self.planned_trial_id = trial_id
        self.scenario_snapshot_digest = snapshot_digest
        self.condition_id = "baseline"
        self.replication_ordinal = 0
        self.capture_spec_refs = ("capture-1",)
        self.stochastic_seeds = (("seed-a", "b" * 64),)


class _StubPlan:
    def __init__(self, trials=None, plan_id="plan-1"):
        self.plan_id = plan_id
        self.policy_version = "aptl-admission/v1"
        self.source_set_digest = "sha256:" + "c" * 64
        self.plan_digest = "sha256:" + "d" * 64
        self.trials = tuple(trials or [_StubTrial("trial-1")])
        self.capture_bindings = ()


class TestExperimentProvider:
    """Admitted identities are preserved, never recomputed from current files."""

    def test_collects_plan_and_trial_identities(self):
        result = AdmittedExperimentProvider(_StubPlan()).collect(
            _context(EXPERIMENT_PROVIDER_ID)
        )
        assert result.status is ProvenanceStatus.COLLECTED
        names = {leaf.logical_id for leaf in result.leaves}
        assert "plan" in names
        assert any(name.startswith("trial/") for name in names)

    def test_payload_records_the_admitted_plan_identity(self):
        plan = _StubPlan()
        result = AdmittedExperimentProvider(plan).collect(_context(EXPERIMENT_PROVIDER_ID))
        assert result.payload["plan_id"] == plan.plan_id
        assert result.payload["plan_digest"] == plan.plan_digest
        assert result.payload["source_set_digest"] == plan.source_set_digest
        assert result.payload["trial_count"] == 1

    def test_a_changed_scenario_snapshot_changes_only_that_trial_leaf(self):
        before = AdmittedExperimentProvider(_StubPlan()).collect(
            _context(EXPERIMENT_PROVIDER_ID)
        )
        changed = _StubPlan(trials=[_StubTrial("trial-1", "sha256:" + "e" * 64)])
        after = AdmittedExperimentProvider(changed).collect(_context(EXPERIMENT_PROVIDER_ID))
        before_ids = {leaf.logical_id: leaf.digest for leaf in before.leaves}
        after_ids = {leaf.logical_id: leaf.digest for leaf in after.leaves}
        assert before_ids["plan"] == after_ids["plan"]
        assert before_ids["trial/trial-1"] != after_ids["trial/trial-1"]

    def test_no_admitted_plan_is_unavailable_not_a_fabricated_identity(self):
        result = AdmittedExperimentProvider(None).collect(_context(EXPERIMENT_PROVIDER_ID))
        assert result.status is ProvenanceStatus.UNAVAILABLE
        assert result.leaves == ()

    def test_more_trials_than_the_entry_budget_is_truncated(self):
        plan = _StubPlan(trials=[_StubTrial(f"trial-{index}") for index in range(10)])
        result = AdmittedExperimentProvider(plan).collect(
            _context(EXPERIMENT_PROVIDER_ID, max_entries=4)
        )
        assert result.status is ProvenanceStatus.TRUNCATED

    def test_parameter_bindings_are_not_recorded(self):
        """Scenario parameter VALUES are not persisted (ADR-044 / REP-001)."""
        result = AdmittedExperimentProvider(_StubPlan()).collect(
            _context(EXPERIMENT_PROVIDER_ID)
        )
        assert "parameter_bindings" not in result.payload
        assert "parameters" not in result.payload


class _StubApparatus:
    def __init__(self, model="claude-x", provider="claude"):
        self.implementation_selection_ref = "selection-1"
        self.manifest_ref = "manifest-1"
        self.provider = provider
        self.model = model


class TestParticipantProvider:
    """The accepted selection is recorded, not a reconstruction."""

    def test_collects_participant_selection_identity(self):
        result = ParticipantApparatusProvider({"red": _StubApparatus()}).collect(
            _context(PARTICIPANT_PROVIDER_ID)
        )
        assert result.status is ProvenanceStatus.COLLECTED
        assert {leaf.logical_id for leaf in result.leaves} == {"red"}

    def test_payload_records_provider_and_model_identity(self):
        """Model identity must be reconstructable from the record."""
        result = ParticipantApparatusProvider({"red": _StubApparatus()}).collect(
            _context(PARTICIPANT_PROVIDER_ID)
        )
        assert result.payload["participants"]["red"]["provider"] == "claude"
        assert result.payload["participants"]["red"]["model"] == "claude-x"

    def test_a_changed_model_changes_that_participants_leaf(self):
        before = ParticipantApparatusProvider({"red": _StubApparatus()}).collect(
            _context(PARTICIPANT_PROVIDER_ID)
        )
        after = ParticipantApparatusProvider({"red": _StubApparatus(model="other")}).collect(
            _context(PARTICIPANT_PROVIDER_ID)
        )
        assert before.leaves != after.leaves

    def test_no_participants_is_unavailable(self):
        result = ParticipantApparatusProvider({}).collect(_context(PARTICIPANT_PROVIDER_ID))
        assert result.status is ProvenanceStatus.UNAVAILABLE

    def test_a_participant_without_a_model_is_explicit_not_guessed(self):
        """An absent model is null, never a fabricated default."""
        result = ParticipantApparatusProvider({"red": _StubApparatus(model=None)}).collect(
            _context(PARTICIPANT_PROVIDER_ID)
        )
        assert result.payload["participants"]["red"]["model"] is None

    @pytest.mark.parametrize("address", ["", "bad address", "x" * 300])
    def test_a_hostile_participant_address_is_rejected(self, address):
        result = ParticipantApparatusProvider({address: _StubApparatus()}).collect(
            _context(PARTICIPANT_PROVIDER_ID)
        )
        assert result.status is ProvenanceStatus.FAILED

    def test_results_carry_the_declared_provider_id(self):
        for provider, expected in (
            (ApparatusManifestProvider(), APPARATUS_PROVIDER_ID),
            (AdmittedExperimentProvider(_StubPlan()), EXPERIMENT_PROVIDER_ID),
            (ParticipantApparatusProvider({"red": _StubApparatus()}), PARTICIPANT_PROVIDER_ID),
        ):
            result = provider.collect(_context(expected))
            assert isinstance(result, ProvenanceResult)
            assert result.provider_id == expected
