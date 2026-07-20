"""Tests for ``aptl.core.experiment.capture_mapping`` (ADR-047 "Apparatus and
capture capability admission"; EXP-010 / issue #752).

EXP-002 shipped an empty ``SUPPORTED_CAPTURE_CAPABILITIES`` table here; EXP-010
evolves capture support into the code-owned
:mod:`aptl.core.experiment.capture_registry` and turns this module into the
thin admission entry point :func:`bind_capture_requirements`. The production
:data:`~aptl.core.experiment.capture_registry.DEFAULT_COLLECTOR_REGISTRY` is
EMPTY, so the honest fail-closed baseline is preserved: a capture requirement
is admitted only when a trusted registration covers it, never because a
collector function exists.

Uses the installed ACES fixture corpus as the contract test source (ADR-047).
"""

from __future__ import annotations

import json

import pytest
from aces_contracts.contracts import ExperimentCaptureSpecModel
from aces_contracts.corpus import FIXTURES, corpus_family_root

from aptl.core.collectors import collect_traces
from aptl.core.experiment.capture_mapping import bind_capture_requirements
from aptl.core.experiment.capture_registry import (
    CaptureLimits,
    CaptureVisibility,
    CollectorRegistration,
    CollectorRegistry,
)
from aptl.core.experiment.errors import EXPERIMENT_ADMISSION_DOMAIN, AdmissionRejection
from aptl.core.experiment.policy import (
    AdmissionPolicy,
    CaptureLimitationAcceptance,
    default_admission_policy,
)

CORPUS_ROOT = corpus_family_root(FIXTURES)

_LIMITS = CaptureLimits(max_bytes=1_048_576, max_artifact_count=100, max_duration_s=300)


def _read(*parts: str) -> bytes:
    """Read a byte payload from the installed ACES fixture corpus."""
    path = CORPUS_ROOT
    for part in parts:
        path = path / part
    return path.read_bytes()


def _load_reference_capture_spec() -> ExperimentCaptureSpecModel:
    """Load the realistic reference capture spec from the corpus."""
    payload = json.loads(_read("experiment-core", "experiment-capture-spec-v1", "valid", "reference.json"))
    return ExperimentCaptureSpecModel.model_validate(payload)


def _covering_registration(**overrides: object) -> CollectorRegistration:
    """Return a registration that covers the reference ``network-trace`` requirement."""
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


# ---------------------------------------------------------------------------
# Fail-closed baseline (empty production registry)
# ---------------------------------------------------------------------------


class TestBindCaptureRequirementsFailsClosed:
    def test_the_realistic_corpus_capture_spec_is_rejected_by_default(self):
        spec = _load_reference_capture_spec()
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection) as excinfo:
            bind_capture_requirements([spec], policy=policy)

        assert excinfo.value.diagnostics
        assert all(d.domain == EXPERIMENT_ADMISSION_DOMAIN for d in excinfo.value.diagnostics)

    def test_the_rejection_names_the_unsupported_capture_kind_and_scope(self):
        spec = _load_reference_capture_spec()
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection) as excinfo:
            bind_capture_requirements([spec], policy=policy)

        messages = " ".join(d.message + " " + d.address for d in excinfo.value.diagnostics)
        assert "trace" in messages
        assert "network" in messages

    def test_a_collector_function_existing_does_not_cause_admission(self):
        # collect_traces is a real, importable collector for exactly the
        # "trace" capture_kind the corpus spec requires. Its mere existence
        # must never be what admission consults.
        assert callable(collect_traces)
        spec = _load_reference_capture_spec()
        assert spec.capture_requirements["network-trace"].capture_kind == "trace"
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            bind_capture_requirements([spec], policy=policy)


# ---------------------------------------------------------------------------
# Empty input
# ---------------------------------------------------------------------------


class TestBindCaptureRequirementsEmptyInput:
    def test_no_capture_specs_yields_an_empty_tuple_and_does_not_reject(self):
        result = bind_capture_requirements([], policy=default_admission_policy())
        assert result == ()


# ---------------------------------------------------------------------------
# Success path (injected covering registry)
# ---------------------------------------------------------------------------


class TestBindCaptureRequirementsSuccess:
    def test_a_covered_requirement_binds_to_an_immutable_binding(self):
        registry = CollectorRegistry((_covering_registration(),))
        spec = _load_reference_capture_spec()

        bindings = bind_capture_requirements([spec], registry=registry, policy=default_admission_policy())

        assert len(bindings) == 1
        assert bindings[0].registration_id == "aptl.collector.network-trace"
        assert bindings[0].requirement_id == "network-trace"

    def test_binding_is_all_or_nothing_across_specs(self):
        # A registry that covers "trace" but not a second "log" requirement:
        # ANY unbound requirement rejects the whole admission.
        registry = CollectorRegistry((_covering_registration(),))
        covered = _load_reference_capture_spec()
        payload = json.loads(_read("experiment-core", "experiment-capture-spec-v1", "valid", "reference.json"))
        requirement = next(iter(payload["capture_requirements"].values()))
        requirement["capture_kind"] = "log"
        payload["capture_requirements"] = {requirement["requirement_id"]: requirement}
        uncovered = ExperimentCaptureSpecModel.model_validate(payload)
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            bind_capture_requirements([covered, uncovered], registry=registry, policy=policy)


# ---------------------------------------------------------------------------
# Degradation — accepted only via explicit policy, never inferred
# ---------------------------------------------------------------------------


class TestCaptureDegradationAcceptance:
    def test_a_bound_requirement_carries_no_limitation_by_default(self):
        registry = CollectorRegistry((_covering_registration(),))
        spec = _load_reference_capture_spec()

        binding = bind_capture_requirements([spec], registry=registry, policy=default_admission_policy())[0]

        assert binding.accepted_limitation is None
        assert binding.comparability_disclosure_ref is None

    def test_an_explicit_policy_acceptance_annotates_the_binding(self):
        registry = CollectorRegistry((_covering_registration(),))
        spec = _load_reference_capture_spec()
        key = f"{spec.capture_spec_id}.network-trace"
        policy = AdmissionPolicy(
            accepted_capture_limitations={
                key: CaptureLimitationAcceptance(
                    limitation_code="partial-window",
                    comparability_disclosure_ref="disclosure:partial-window/v1",
                )
            }
        )

        binding = bind_capture_requirements([spec], registry=registry, policy=policy)[0]

        assert binding.accepted_limitation == "partial-window"
        assert binding.comparability_disclosure_ref == "disclosure:partial-window/v1"

    def test_an_acceptance_for_a_different_requirement_does_not_leak(self):
        registry = CollectorRegistry((_covering_registration(),))
        spec = _load_reference_capture_spec()
        policy = AdmissionPolicy(
            accepted_capture_limitations={
                "some-other-spec.some-other-requirement": CaptureLimitationAcceptance(
                    limitation_code="irrelevant",
                    comparability_disclosure_ref="disclosure:irrelevant/v1",
                )
            }
        )

        binding = bind_capture_requirements([spec], registry=registry, policy=policy)[0]

        assert binding.accepted_limitation is None


# ---------------------------------------------------------------------------
# Fuzz — every ACES-legal kind/scope still fails closed against the empty default
# ---------------------------------------------------------------------------

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

_CAPTURE_KINDS = ("artifact", "observation", "trace", "telemetry", "log", "packet-capture", "other")
_CAPTURE_SCOPES = ("task", "run", "apparatus", "participant", "backend", "processor", "network", "service")


@pytest.mark.fuzz
class TestFuzzCaptureRequirementsFailClosed:
    @given(
        capture_kind=st.sampled_from(_CAPTURE_KINDS),
        capture_scope=st.sampled_from(_CAPTURE_SCOPES),
    )
    @settings(max_examples=56, deadline=2000)
    def test_every_legal_kind_scope_combination_fails_closed_by_default(self, capture_kind, capture_scope):
        payload = json.loads(_read("experiment-core", "experiment-capture-spec-v1", "valid", "reference.json"))
        requirement = next(iter(payload["capture_requirements"].values()))
        requirement["capture_kind"] = capture_kind
        requirement["capture_scope"] = capture_scope
        payload["capture_requirements"] = {requirement["requirement_id"]: requirement}
        spec = ExperimentCaptureSpecModel.model_validate(payload)
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            bind_capture_requirements([spec], policy=policy)
