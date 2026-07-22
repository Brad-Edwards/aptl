"""Tests for the backend manifest's observation capability (EXP-010 / #752).

``create_aptl_manifest().observation`` is an aggregate projection of the
code-owned collector registry, not a hand-maintained matrix. Two invariants
matter:

* HONEST DEFAULT — while the production registry is empty, the manifest must
  declare no observation capability and must NOT carry the observation-only
  evidence contracts (turning them on without a backed capability is the exact
  dishonesty the registry prevents).
* CONTRACT-COMPLETE WHEN ON — when a real registration turns the projection on,
  ACES's ``observation_capability_contract_gaps`` invariant must be clean,
  which requires the capture-spec/evidence-record/derived-measure/experiment-run
  contracts in the manifest's ``supported_contract_versions``.
"""

from __future__ import annotations

from aces_backend_protocols.capabilities import observation_capability_contract_gaps

import aptl.backends.aces_manifest as aces_manifest
from aptl.backends.aces_manifest import create_aptl_manifest
from aptl.core.experiment.capture_registry import (
    OBSERVATION_EVIDENCE_CONTRACTS,
    CaptureLimits,
    CaptureVisibility,
    CollectorRegistration,
    CollectorRegistry,
)

_LIMITS = CaptureLimits(max_bytes=1_048_576, max_artifact_count=100, max_duration_s=300)


def _registration() -> CollectorRegistration:
    """Return one governed-vocabulary registration for the populated-projection tests."""
    return CollectorRegistration(
        registration_id="aptl.collector.network-trace",
        implementation_version="1.0.0",
        contract_version="experiment-capture-spec/v1",
        channel_kind="evaluation-history",
        capture_kind="trace",
        capture_scope="network",
        window_kinds=frozenset({"run"}),
        media_types=frozenset({"application/json"}),
        required_artifact_roles=frozenset({"observation"}),
        supported_sensitivities=frozenset({"internal", "public"}),
        supports_redaction=True,
        integrity_modes=frozenset({"sha256-digest"}),
        sealing_modes=frozenset({"digest"}),
        supports_chain_of_custody=False,
        supports_retention=True,
        supports_loss_disclosure=True,
        visibility_class=CaptureVisibility.EVALUATOR_ONLY,
        limits=_LIMITS,
    )


class TestBackedDefault:
    """EXP-010 PR 2 turned the production registry on together with the
    acquisition machinery + adapters + conformance fixtures (the honesty
    rule), so the default manifest now declares a real observation capability
    and carries the required evidence contracts."""

    def test_default_manifest_declares_observation(self):
        assert create_aptl_manifest().observation is not None

    def test_default_manifest_includes_the_observation_contracts(self):
        supported = create_aptl_manifest().supported_contract_versions
        assert OBSERVATION_EVIDENCE_CONTRACTS <= supported

    def test_default_manifest_has_no_observation_contract_gaps(self):
        from aces_backend_protocols.capabilities import observation_capability_contract_gaps

        assert observation_capability_contract_gaps(create_aptl_manifest()) == ()


class TestPopulatedProjection:
    def test_a_populated_registry_turns_observation_on(self, monkeypatch):
        monkeypatch.setattr(
            aces_manifest, "DEFAULT_COLLECTOR_REGISTRY", CollectorRegistry((_registration(),))
        )
        manifest = create_aptl_manifest()

        assert manifest.observation is not None
        assert manifest.observation.supported_capture_kinds == frozenset({"trace"})

    def test_turning_observation_on_adds_the_required_contracts(self, monkeypatch):
        monkeypatch.setattr(
            aces_manifest, "DEFAULT_COLLECTOR_REGISTRY", CollectorRegistry((_registration(),))
        )
        manifest = create_aptl_manifest()

        assert OBSERVATION_EVIDENCE_CONTRACTS <= manifest.supported_contract_versions

    def test_the_populated_manifest_has_no_observation_contract_gaps(self, monkeypatch):
        # The ACES invariant: a declared observation's required contracts must
        # all be present in supported_contract_versions.
        monkeypatch.setattr(
            aces_manifest, "DEFAULT_COLLECTOR_REGISTRY", CollectorRegistry((_registration(),))
        )
        manifest = create_aptl_manifest()

        assert observation_capability_contract_gaps(manifest) == ()

    def test_the_default_manifest_also_has_no_observation_contract_gaps(self):
        # With observation None the gap check is vacuously clean — the honest
        # default must never trip the invariant either.
        assert observation_capability_contract_gaps(create_aptl_manifest()) == ()
