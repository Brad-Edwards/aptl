"""Tests for REP-003 dependency/asset and host-fact provenance (issue #452).

Closes the requirement's "image and dependency digests", "collector and tool
versions ... measurement channels", and "relevant host/runtime inventory"
clauses.
"""

import pytest

from aptl.core.provenance.outcomes import ProvenanceStatus
from aptl.core.provenance.protocol import ProvenanceContext
from aptl.core.provenance.providers.artifacts import (
    ARTIFACTS_PROVIDER_ID,
    DEPENDENCY_ARTIFACTS,
    DependencyArtifactProvider,
)
from aptl.core.provenance.providers.experiment import AdmittedExperimentProvider
from aptl.core.provenance.providers.runtime_facts import RuntimeFactsProvider
from aptl.core.provenance.registry import (
    ProvenanceLimits,
    ProvenanceProviderRegistration,
    SealPoint,
)


def _context(provider_id, *, max_bytes=10_000_000, max_entries=64, timeout_s=30, clock=None):
    registration = ProvenanceProviderRegistration(
        provider_id=provider_id,
        implementation_version="1.0.0",
        provenance_kind=provider_id,
        owner_adapter="tests",
        seal_point=SealPoint.RUN_READY_TO_SEAL,
        requiredness_policy_key=f"{provider_id}-required",
        limits=ProvenanceLimits(
            max_bytes=max_bytes, max_entries=max_entries, timeout_s=timeout_s
        ),
    )
    return ProvenanceContext(
        registration=registration, clock=clock or (lambda: 0.0), started_at=0.0
    )


class TestDependencyArtifacts:
    """Dependency and asset locks are recorded from the lock actually present."""

    def test_declared_artifacts_are_project_relative_locks(self):
        for artifact in DEPENDENCY_ARTIFACTS:
            assert not artifact.relative_path.startswith("/")
            assert ".." not in artifact.relative_path

    def test_uv_lock_is_recorded(self, tmp_path):
        (tmp_path / "uv.lock").write_text("version = 1\n")
        result = DependencyArtifactProvider(tmp_path).collect(_context(ARTIFACTS_PROVIDER_ID))
        assert result.status is ProvenanceStatus.COLLECTED
        assert any("uv.lock" in leaf.logical_id for leaf in result.leaves)

    def test_participant_asset_locks_are_recorded(self, tmp_path):
        profile = tmp_path / "participant-profiles" / "guided-purple-v1"
        profile.mkdir(parents=True)
        (profile / "asset-lock.json").write_text("{}")
        result = DependencyArtifactProvider(tmp_path).collect(_context(ARTIFACTS_PROVIDER_ID))
        assert any("asset-lock" in leaf.logical_id for leaf in result.leaves)

    def test_a_changed_lock_changes_its_leaf(self, tmp_path):
        (tmp_path / "uv.lock").write_text("version = 1\n")
        before = DependencyArtifactProvider(tmp_path).collect(
            _context(ARTIFACTS_PROVIDER_ID)
        )
        (tmp_path / "uv.lock").write_text("version = 2\n")
        after = DependencyArtifactProvider(tmp_path).collect(_context(ARTIFACTS_PROVIDER_ID))
        assert before.leaves != after.leaves

    def test_absent_locks_are_unavailable_not_empty_success(self, tmp_path):
        result = DependencyArtifactProvider(tmp_path).collect(_context(ARTIFACTS_PROVIDER_ID))
        assert result.status is ProvenanceStatus.UNAVAILABLE

    def test_a_symlinked_lock_is_not_followed(self, tmp_path):
        import os

        secret = tmp_path / "outside.lock"
        secret.write_text("SECRET")
        os.symlink(secret, tmp_path / "uv.lock")
        result = DependencyArtifactProvider(tmp_path).collect(_context(ARTIFACTS_PROVIDER_ID))
        assert result.status is ProvenanceStatus.UNAVAILABLE
        assert "SECRET" not in repr(result)

    def test_an_oversized_lock_is_truncated_not_partially_hashed(self, tmp_path):
        (tmp_path / "uv.lock").write_text("x" * 5000)
        result = DependencyArtifactProvider(tmp_path).collect(
            _context(ARTIFACTS_PROVIDER_ID, max_bytes=1024)
        )
        assert result.status is ProvenanceStatus.TRUNCATED


class _StubBinding:
    def __init__(self, registration_id="pcap-collector", version="1.2.0"):
        self.registration_id = registration_id
        self.implementation_version = version
        self.contract_version = "experiment-capture-spec-v1"
        self.channel_ref_id = "channel-1"
        self.channel_ref_version = "1"
        self.channel_kind = "network-packet"
        self.capture_spec_id = "capture-1"
        self.requirement_id = "req-1"
        self.effective_config_digest = "sha256:" + "7" * 64


class _StubTrial:
    planned_trial_id = "trial-1"
    scenario_snapshot_digest = "sha256:" + "a" * 64
    condition_id = "baseline"
    replication_ordinal = 0
    capture_spec_refs = ("capture-1",)
    stochastic_seeds = ()


class _StubPlan:
    plan_id = "plan-1"
    policy_version = "aptl-admission/v1"
    source_set_digest = "sha256:" + "c" * 64
    plan_digest = "sha256:" + "d" * 64

    def __init__(self, bindings=()):
        self.trials = (_StubTrial(),)
        self.capture_bindings = tuple(bindings)


class TestCollectorAndChannelProvenance:
    """Collector selection and measurement channels come from admitted bindings."""

    def test_capture_bindings_become_collector_leaves(self):
        plan = _StubPlan(bindings=[_StubBinding()])
        result = AdmittedExperimentProvider(plan).collect(_context("experiment"))
        assert any(leaf.logical_id.startswith("capture/") for leaf in result.leaves)

    def test_payload_records_collector_version_and_channel(self):
        plan = _StubPlan(bindings=[_StubBinding()])
        result = AdmittedExperimentProvider(plan).collect(_context("experiment"))
        collectors = result.payload["collectors"]
        assert collectors[0]["registration_id"] == "pcap-collector"
        assert collectors[0]["implementation_version"] == "1.2.0"
        assert collectors[0]["channel_kind"] == "network-packet"

    def test_a_changed_collector_version_changes_only_its_leaf(self):
        before = AdmittedExperimentProvider(_StubPlan([_StubBinding()])).collect(
            _context("experiment")
        )
        after = AdmittedExperimentProvider(
            _StubPlan([_StubBinding(version="1.3.0")])
        ).collect(_context("experiment"))
        before_ids = {leaf.logical_id: leaf.digest for leaf in before.leaves}
        after_ids = {leaf.logical_id: leaf.digest for leaf in after.leaves}
        assert before_ids["plan"] == after_ids["plan"]
        changed = [k for k in before_ids if before_ids[k] != after_ids.get(k)]
        assert all(name.startswith("capture/") for name in changed)

    def test_no_bindings_records_no_collectors(self):
        result = AdmittedExperimentProvider(_StubPlan()).collect(_context("experiment"))
        assert result.payload["collectors"] == []


class _StubSoftware:
    python_version = "3.12.1"
    docker_version = "27.0"
    compose_version = "2.29"
    wazuh_manager_version = ""
    wazuh_indexer_version = ""
    aptl_version = "0.2.0"
    raes_version = "2.0.0"


class _StubSnapshot:
    timestamp = "2026-01-01T00:00:00Z"
    containers: list = []
    software = _StubSoftware()

    def to_dict(self):
        return {"timestamp": self.timestamp}


class TestHostFacts:
    """Host inventory is a closed allowlist of validity-relevant facts."""

    def test_host_facts_leaf_is_recorded(self):
        result = RuntimeFactsProvider(
            _StubSnapshot(), host_facts=lambda: {"os": "linux", "arch": "x86_64"}
        ).collect(_context("runtime-facts"))
        assert any(leaf.logical_id == "host-facts" for leaf in result.leaves)

    def test_host_facts_are_recorded_in_the_payload(self):
        result = RuntimeFactsProvider(
            _StubSnapshot(), host_facts=lambda: {"os": "linux", "arch": "x86_64"}
        ).collect(_context("runtime-facts"))
        assert result.payload["host_facts"]["os"] == "linux"

    def test_host_facts_are_restricted_to_the_allowlist(self):
        """A rogue owner cannot widen the record into a host inventory dump."""
        result = RuntimeFactsProvider(
            _StubSnapshot(),
            host_facts=lambda: {"os": "linux", "hostname": "secret-box", "user": "root"},
        ).collect(_context("runtime-facts"))
        rendered = repr(result.payload)
        assert "secret-box" not in rendered
        assert "root" not in rendered

    def test_default_host_facts_are_bounded_and_safe(self):
        result = RuntimeFactsProvider(_StubSnapshot()).collect(_context("runtime-facts"))
        assert set(result.payload["host_facts"]) <= {
            "os",
            "arch",
            "kernel",
            "python",
            "docker_mode",
        }

    def test_a_failing_host_probe_does_not_fail_the_provider(self):
        def broken():
            raise RuntimeError("probe failed")

        result = RuntimeFactsProvider(_StubSnapshot(), host_facts=broken).collect(
            _context("runtime-facts")
        )
        assert result.status is ProvenanceStatus.COLLECTED
        assert result.payload["host_facts"] == {}

    @pytest.mark.parametrize("value", [{"os": "x" * 5000}, {"os": object()}])
    def test_hostile_host_fact_values_are_rejected(self, value):
        result = RuntimeFactsProvider(_StubSnapshot(), host_facts=lambda: value).collect(
            _context("runtime-facts")
        )
        assert result.payload["host_facts"] == {}
