"""Tests for ``aptl.core.experiment.capture_mapping`` (ADR-047 "Apparatus and
capture capability admission" + the ``observation=None`` gotcha).

``create_aptl_manifest().observation`` is currently ``None`` (Stage 3 /
EXP-002), and the existing capture collectors (``aptl.core.collectors``) are
best-effort primitives that often collapse failure into an empty result.
Per ADR-047's Gotchas: "Do not admit a capture requirement merely because a
collector function exists." This module's ``SUPPORTED_CAPTURE_CAPABILITIES``
table is the ONLY thing that can admit a capture requirement, and it is
empty/minimal for #438 — an honest fail-closed baseline. EXP-010 (#752) is
the seam that extends the table alongside an honest
``create_aptl_manifest().observation`` declaration.

Uses the installed ACES fixture corpus
(``aces_contracts.corpus.corpus_family_root(FIXTURES)``) as the contract
test source rather than a copied-in schema, per ADR-047's testing contract.
"""

from __future__ import annotations

import dataclasses
import json

import pytest
from aces_backend_protocols.capabilities import BackendManifest, ObservationCapabilities
from aces_contracts.contracts import ExperimentCaptureSpecModel
from aces_contracts.corpus import FIXTURES, corpus_family_root

from aptl.backends.aces_manifest import create_aptl_manifest
from aptl.core.collectors import collect_traces
from aptl.core.experiment import capture_mapping
from aptl.core.experiment.capture_mapping import (
    SUPPORTED_CAPTURE_CAPABILITIES,
    CaptureCapability,
    map_capture_requirements,
)
from aptl.core.experiment.errors import EXPERIMENT_ADMISSION_DOMAIN, AdmissionRejection
from aptl.core.experiment.policy import default_admission_policy

CORPUS_ROOT = corpus_family_root(FIXTURES)


def _read(*parts: str) -> bytes:
    path = CORPUS_ROOT
    for part in parts:
        path = path / part
    return path.read_bytes()


def _load_reference_capture_spec() -> ExperimentCaptureSpecModel:
    payload = json.loads(
        _read("experiment-core", "experiment-capture-spec-v1", "valid", "reference.json")
    )
    return ExperimentCaptureSpecModel.model_validate(payload)


def _capture_spec_with_requirement(*, capture_kind: str, capture_scope: str) -> ExperimentCaptureSpecModel:
    payload = json.loads(
        _read("experiment-core", "experiment-capture-spec-v1", "valid", "reference.json")
    )
    requirement = next(iter(payload["capture_requirements"].values()))
    requirement["capture_kind"] = capture_kind
    requirement["capture_scope"] = capture_scope
    payload["capture_requirements"] = {requirement["requirement_id"]: requirement}
    return ExperimentCaptureSpecModel.model_validate(payload)


def _capture_spec_with_requirement_fields(
    *,
    capture_kind: str = "trace",
    capture_scope: str = "network",
    expected_media_types: list[str] | None = None,
    integrity_requirements: list[str] | None = None,
) -> ExperimentCaptureSpecModel:
    """Like :func:`_capture_spec_with_requirement` but also lets a test
    independently override ``expected_media_types``/``integrity_requirements``
    -- needed to isolate the media-type-subset and integrity-subset
    continue-conditions in ``_resolve_capture_owner`` from the
    capture_kind/capture_scope ones.
    """
    payload = json.loads(
        _read("experiment-core", "experiment-capture-spec-v1", "valid", "reference.json")
    )
    requirement = next(iter(payload["capture_requirements"].values()))
    requirement["capture_kind"] = capture_kind
    requirement["capture_scope"] = capture_scope
    if expected_media_types is not None:
        requirement["expected_media_types"] = expected_media_types
    if integrity_requirements is not None:
        requirement["integrity_requirements"] = integrity_requirements
    payload["capture_requirements"] = {requirement["requirement_id"]: requirement}
    return ExperimentCaptureSpecModel.model_validate(payload)


def _matching_capability(*, capture_owner: str = "aptl.core.collectors.collect_traces") -> CaptureCapability:
    """The one ``CaptureCapability`` that exactly matches
    ``_capture_spec_with_requirement_fields()``'s default requirement
    (capture_kind="trace", capture_scope="network",
    expected_media_types=["application/json"],
    integrity_requirements=["sha256-digest"]) on every predicate --
    the SUCCESS baseline every miss-test below deviates from by exactly
    one field.
    """
    return CaptureCapability(
        capture_kind="trace",
        capture_scope="network",
        media_types=frozenset({"application/json"}),
        integrity_requirements=frozenset({"sha256-digest"}),
        capture_owner=capture_owner,
    )


def _matching_observation(
    *,
    supported_capture_kinds: frozenset[str] = frozenset({"trace"}),
    supported_media_types: frozenset[str] = frozenset({"application/json"}),
) -> ObservationCapabilities:
    return ObservationCapabilities(
        name="test-observation",
        supported_capture_kinds=supported_capture_kinds,
        supported_channel_kinds=frozenset({"file-artifact"}),
        supported_evidence_contracts=frozenset({"experiment-capture-spec-v1"}),
        supported_media_types=supported_media_types,
        supported_sealing_modes=frozenset({"digest"}),
    )


def _backend_manifest_with_observation(observation: ObservationCapabilities) -> BackendManifest:
    # NOTE: dataclasses.replace(create_aptl_manifest(), observation=...)
    # does NOT work here -- BackendManifest has a custom __init__ that
    # resolves a pre-built `capabilities` object from its own `capabilities`
    # kwarg when present (which dataclasses.replace always supplies, since
    # it is itself a real dataclass field), silently discarding a sibling
    # `observation=` kwarg. Explicit reconstruction (the pattern the
    # existing "never fabricates support" test below already uses) is the
    # only way to actually set `observation`.
    manifest = create_aptl_manifest()
    return BackendManifest(
        name=manifest.name,
        version=manifest.version,
        supported_contract_versions=manifest.supported_contract_versions,
        compatible_processors=manifest.compatible_processors,
        realization_support=manifest.realization_support,
        concept_bindings=manifest.concept_bindings,
        provisioner=manifest.provisioner,
        orchestrator=manifest.orchestrator,
        evaluator=manifest.evaluator,
        participant_runtime=manifest.participant_runtime,
        observation=observation,
    )


# ---------------------------------------------------------------------------
# SUPPORTED_CAPTURE_CAPABILITIES — honest fail-closed baseline
# ---------------------------------------------------------------------------


class TestSupportedCaptureCapabilitiesBaseline:
    def test_the_table_is_empty_for_438(self):
        assert tuple(SUPPORTED_CAPTURE_CAPABILITIES) == ()

    def test_create_aptl_manifest_observation_is_still_none(self):
        # If this ever flips true, SUPPORTED_CAPTURE_CAPABILITIES may gain
        # entries (EXP-010) — until then the fail-closed baseline below is
        # load-bearing and this sanity check documents the precondition.
        assert create_aptl_manifest().observation is None

    def test_capture_capability_is_a_frozen_dataclass_shape(self):
        capability = CaptureCapability(
            capture_kind="trace",
            capture_scope="network",
            media_types=frozenset({"application/json"}),
            integrity_requirements=frozenset({"sha256-digest"}),
            capture_owner="aptl.core.collectors.collect_traces",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            capability.capture_kind = "log"


# ---------------------------------------------------------------------------
# map_capture_requirements — fail-closed on the realistic corpus spec
# ---------------------------------------------------------------------------


class TestMapCaptureRequirementsFailsClosed:
    def test_the_realistic_corpus_capture_spec_is_rejected(self):
        spec = _load_reference_capture_spec()
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection) as excinfo:
            map_capture_requirements([spec], policy=policy)

        assert excinfo.value.diagnostics
        assert all(d.domain == EXPERIMENT_ADMISSION_DOMAIN for d in excinfo.value.diagnostics)

    def test_the_rejection_names_the_unsupported_capture_kind_and_scope(self):
        spec = _load_reference_capture_spec()
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection) as excinfo:
            map_capture_requirements([spec], policy=policy)

        messages = " ".join(d.message + " " + d.address for d in excinfo.value.diagnostics)
        assert "trace" in messages
        assert "network" in messages

    def test_an_unknown_capture_kind_also_fails_closed(self):
        spec = _capture_spec_with_requirement(capture_kind="other", capture_scope="service")
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            map_capture_requirements([spec], policy=policy)

    def test_a_collector_function_existing_does_not_cause_admission(self):
        # collect_traces is a real, importable, callable collector for
        # exactly the "trace" capture_kind the corpus spec requires. Its
        # mere existence must never be what admission consults.
        assert callable(collect_traces)
        spec = _load_reference_capture_spec()
        assert spec.capture_requirements["network-trace"].capture_kind == "trace"
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            map_capture_requirements([spec], policy=policy)

    def test_never_fabricates_support_by_injecting_a_backend_manifest_with_non_none_observation_but_wrong_terms(self):
        # Even if a caller injects a backend manifest whose observation IS
        # populated, an empty SUPPORTED_CAPTURE_CAPABILITIES table still
        # fails closed -- the table gates admission, not observation
        # presence alone.
        from aces_backend_protocols.capabilities import BackendManifest, ObservationCapabilities

        manifest = create_aptl_manifest()
        with_observation = BackendManifest(
            name=manifest.name,
            version=manifest.version,
            supported_contract_versions=manifest.supported_contract_versions,
            compatible_processors=manifest.compatible_processors,
            realization_support=manifest.realization_support,
            concept_bindings=manifest.concept_bindings,
            provisioner=manifest.provisioner,
            orchestrator=manifest.orchestrator,
            evaluator=manifest.evaluator,
            participant_runtime=manifest.participant_runtime,
            observation=ObservationCapabilities(
                name="test-observation",
                supported_capture_kinds=frozenset({"trace"}),
                supported_channel_kinds=frozenset({"file-artifact"}),
                supported_evidence_contracts=frozenset({"experiment-capture-spec-v1"}),
                supported_media_types=frozenset({"application/json"}),
                supported_sealing_modes=frozenset({"digest"}),
            ),
        )
        spec = _load_reference_capture_spec()
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            map_capture_requirements([spec], backend_manifest=with_observation, policy=policy)


# ---------------------------------------------------------------------------
# map_capture_requirements — no capture specs at all
# ---------------------------------------------------------------------------


class TestMapCaptureRequirementsEmptyInput:
    def test_no_capture_specs_yields_an_empty_mapping_and_does_not_reject(self):
        result = map_capture_requirements([], policy=default_admission_policy())

        assert result == {}


# ---------------------------------------------------------------------------
# _resolve_capture_owner — the matching loop's own predicates (Finding 1)
#
# SUPPORTED_CAPTURE_CAPABILITIES is empty in production (see the module
# docstring), so this loop body -- every `continue` and the eventual
# `return capability.capture_owner` -- never runs against the real table.
# Each test below monkeypatches in exactly ONE synthetic capability so the
# loop body genuinely executes, and isolates exactly one predicate at a
# time: the requirement deviates from a capability/observation pair that
# would otherwise fully match on every other axis, so if that one guard
# were ever deleted the requirement WOULD wrongly match and the test would
# fail (no AdmissionRejection raised).
# ---------------------------------------------------------------------------


class TestResolveCaptureOwnerSuccessPath:
    def test_a_requirement_matching_a_supported_capability_and_observation_is_admitted(self, monkeypatch):
        capability = _matching_capability()
        monkeypatch.setattr(capture_mapping, "SUPPORTED_CAPTURE_CAPABILITIES", (capability,))
        manifest = _backend_manifest_with_observation(_matching_observation())
        spec = _capture_spec_with_requirement_fields()

        result = map_capture_requirements([spec], backend_manifest=manifest, policy=default_admission_policy())

        assert result == {f"{spec.capture_spec_id}.network-trace": "aptl.core.collectors.collect_traces"}


class TestResolveCaptureOwnerEachContinueConditionFailsClosed:
    """One requirement per miss -- every test below deviates from the
    matching baseline (``_matching_capability()``/``_matching_observation()``
    exactly matching ``_capture_spec_with_requirement_fields()``'s default
    requirement) on exactly one predicate.
    """

    def test_capture_kind_mismatch(self, monkeypatch):
        capability = _matching_capability()  # capture_kind="trace"
        monkeypatch.setattr(capture_mapping, "SUPPORTED_CAPTURE_CAPABILITIES", (capability,))
        manifest = _backend_manifest_with_observation(_matching_observation())
        spec = _capture_spec_with_requirement_fields(capture_kind="observation", capture_scope="network")
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            map_capture_requirements([spec], backend_manifest=manifest, policy=policy)

    def test_capture_scope_mismatch(self, monkeypatch):
        capability = _matching_capability()  # capture_scope="network"
        monkeypatch.setattr(capture_mapping, "SUPPORTED_CAPTURE_CAPABILITIES", (capability,))
        manifest = _backend_manifest_with_observation(_matching_observation())
        spec = _capture_spec_with_requirement_fields(capture_kind="trace", capture_scope="service")
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            map_capture_requirements([spec], backend_manifest=manifest, policy=policy)

    def test_expected_media_types_not_a_subset_of_the_capability(self, monkeypatch):
        capability = _matching_capability()  # media_types={"application/json"}
        monkeypatch.setattr(capture_mapping, "SUPPORTED_CAPTURE_CAPABILITIES", (capability,))
        # The observation's own supported_media_types is deliberately made
        # WIDER than the capability's (includes "application/xml" too) so
        # this test isolates the capability-side subset guard specifically
        # from the later, separate observation-side subset guard (which
        # would otherwise also reject "application/xml" and mask a removal
        # of the earlier check).
        manifest = _backend_manifest_with_observation(
            _matching_observation(supported_media_types=frozenset({"application/json", "application/xml"}))
        )
        spec = _capture_spec_with_requirement_fields(expected_media_types=["application/xml"])
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            map_capture_requirements([spec], backend_manifest=manifest, policy=policy)

    def test_integrity_requirements_not_a_subset_of_the_capability(self, monkeypatch):
        capability = _matching_capability()  # integrity_requirements={"sha256-digest"}
        monkeypatch.setattr(capture_mapping, "SUPPORTED_CAPTURE_CAPABILITIES", (capability,))
        manifest = _backend_manifest_with_observation(_matching_observation())
        spec = _capture_spec_with_requirement_fields(integrity_requirements=["sha512-digest"])
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            map_capture_requirements([spec], backend_manifest=manifest, policy=policy)

    def test_capability_capture_kind_not_declared_by_the_observation(self, monkeypatch):
        # Requirement fully matches the capability on every one of its own
        # fields; the capability's declared capture_kind ("trace") is
        # simply never named in the observation's own declaration.
        capability = _matching_capability()
        monkeypatch.setattr(capture_mapping, "SUPPORTED_CAPTURE_CAPABILITIES", (capability,))
        manifest = _backend_manifest_with_observation(
            _matching_observation(supported_capture_kinds=frozenset({"log"}))
        )
        spec = _capture_spec_with_requirement_fields()
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            map_capture_requirements([spec], backend_manifest=manifest, policy=policy)

    def test_expected_media_types_not_a_subset_of_the_observation(self, monkeypatch):
        # Requirement/capability fully match each other (and the
        # capability's capture_kind IS declared by the observation); only
        # the observation's own supported_media_types excludes what the
        # requirement asks for.
        capability = _matching_capability()
        monkeypatch.setattr(capture_mapping, "SUPPORTED_CAPTURE_CAPABILITIES", (capability,))
        manifest = _backend_manifest_with_observation(
            _matching_observation(supported_media_types=frozenset({"text/plain"}))
        )
        spec = _capture_spec_with_requirement_fields()
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            map_capture_requirements([spec], backend_manifest=manifest, policy=policy)


# ---------------------------------------------------------------------------
# Fuzz
# ---------------------------------------------------------------------------

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

_CAPTURE_KINDS = ("artifact", "observation", "trace", "telemetry", "log", "packet-capture", "other")
_CAPTURE_SCOPES = ("task", "run", "apparatus", "participant", "backend", "processor", "network", "service")


@pytest.mark.fuzz
class TestFuzzCaptureRequirementsAlwaysFailClosed:
    @given(
        capture_kind=st.sampled_from(_CAPTURE_KINDS),
        capture_scope=st.sampled_from(_CAPTURE_SCOPES),
    )
    @settings(max_examples=56, deadline=2000)
    def test_every_aces_legal_capture_kind_and_scope_combination_fails_closed(
        self, capture_kind, capture_scope
    ):
        spec = _capture_spec_with_requirement(capture_kind=capture_kind, capture_scope=capture_scope)
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            map_capture_requirements([spec], policy=policy)
