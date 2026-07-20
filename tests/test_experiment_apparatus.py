"""Tests for ``aptl.core.experiment.apparatus`` (ADR-047 "Apparatus and
capture capability admission").

Two things are exercised here:

* ``check_apparatus_admission`` — conjunctive identity/manifest-ref/
  capability/mutual-compat admission over ``ExperimentTaskModel.
  apparatus_constraints`` and the authoring input's optional
  ``apparatus_intent``. At the locked ACES 0.23.1 surface the published
  reference-processor manifest names only ``stub`` as a compatible backend
  while APTL names ``aces-reference-processor`` as compatible — a
  one-directional mismatch — so ANY admission using the real default
  manifests is expected to fail closed at the mutual-compatibility gate.
  This is documented, ADR-mandated behavior, not a bug.
* ``plan_condition_feasibility``/``require_feasible_plan`` — planning-only
  feasibility over a real parsed SDL ``Scenario``, using ACES's reference
  processor directly (no ``AptlConfig``/``DeploymentBackend``/Docker).

Uses the installed ACES fixture corpus
(``aces_contracts.corpus.corpus_family_root(FIXTURES)``) as the contract
test source rather than a copied-in schema, per ADR-047's testing contract.
"""

from __future__ import annotations

import dataclasses
import json
import sys

import pytest
from aces_contracts.contracts import ExperimentApparatusConstraintModel, ExperimentTaskModel
from aces_contracts.corpus import FIXTURES, corpus_family_root
from aces_contracts.diagnostics import Severity
from aces_processor.manifest import create_reference_processor_manifest
from aces_processor.reference import ReferenceProcessorResult, run_reference_processor
from aces_sdl import parse_sdl

from aptl.backends.aces_manifest import create_aptl_manifest
from aptl.core.experiment.apparatus import (
    check_apparatus_admission,
    plan_condition_feasibility,
    require_feasible_plan,
)
from aptl.core.experiment.errors import EXPERIMENT_ADMISSION_DOMAIN, AdmissionRejection
from aptl.core.experiment.policy import default_admission_policy

CORPUS_ROOT = corpus_family_root(FIXTURES)
SECRET = "sk-super-secret-injected-token-98765"


def _read(*parts: str) -> bytes:
    path = CORPUS_ROOT
    for part in parts:
        path = path / part
    return path.read_bytes()


def _load_reference_task() -> ExperimentTaskModel:
    payload = json.loads(
        _read("experiment-core", "experiment-task-v1", "valid", "reference.json")
    )
    return ExperimentTaskModel.model_validate(payload)


def _load_reference_task_payload() -> dict:
    return json.loads(
        _read("experiment-core", "experiment-task-v1", "valid", "reference.json")
    )


def _task_with_apparatus_constraints(apparatus_constraints: dict) -> ExperimentTaskModel:
    payload = _load_reference_task_payload()
    payload["apparatus_constraints"] = apparatus_constraints
    return ExperimentTaskModel.model_validate(payload)


def _minimal_scenario_bytes() -> bytes:
    return _read("sdl", "sdl-yaml-v1", "valid", "minimal.yaml")


# ---------------------------------------------------------------------------
# check_apparatus_admission — mutual-compat fail-closed gotcha
# ---------------------------------------------------------------------------


class TestCheckApparatusAdmissionMutualCompatGotcha:
    def test_the_realistic_corpus_task_requiring_aces_reference_processor_is_rejected(self):
        task = _load_reference_task()

        with pytest.raises(AdmissionRejection) as excinfo:
            check_apparatus_admission(
                task,
                None,
                policy=default_admission_policy(),
            )

        assert excinfo.value.diagnostics
        assert all(d.domain == EXPERIMENT_ADMISSION_DOMAIN for d in excinfo.value.diagnostics)

    def test_default_aptl_and_reference_processor_manifests_are_not_mutually_declared_compatible(self):
        # Structural fact about the two *canonical* manifests, independent
        # of any task: aptl.compatible_processors names
        # "aces-reference-processor", but the reference-processor manifest's
        # compatible_backends names only "stub" (never "aptl"). Isolated
        # here with a task that explicitly allows both identities (and
        # pins them correctly via required_manifest_refs) so the
        # rejection can only be coming from the mutual-compat rule, not a
        # simpler identity mismatch.
        task = _task_with_apparatus_constraints(
            {
                "allowed_processor_refs": [
                    {"ref_kind": "processor", "ref_id": "aces-reference-processor", "ref_version": "0.1.0"}
                ],
                "allowed_backend_refs": [
                    {"ref_kind": "backend", "ref_id": "aptl", "ref_version": "0.1.0"}
                ],
                "required_manifest_refs": [
                    {
                        "ref_kind": "manifest",
                        "ref_id": "aces-reference-processor",
                        "ref_version": "processor-manifest/v2",
                        "subject_ref": {
                            "ref_kind": "processor",
                            "ref_id": "aces-reference-processor",
                            "ref_version": "0.1.0",
                        },
                    },
                    {
                        "ref_kind": "manifest",
                        "ref_id": "aptl",
                        "ref_version": "backend-manifest/v2",
                        "subject_ref": {
                            "ref_kind": "backend",
                            "ref_id": "aptl",
                            "ref_version": "0.1.0",
                        },
                    },
                ],
                "required_capabilities": [],
                "notes": [],
            }
        )

        with pytest.raises(AdmissionRejection) as excinfo:
            check_apparatus_admission(task, None, policy=default_admission_policy())

        messages = " ".join(d.message for d in excinfo.value.diagnostics)
        assert "compat" in messages.lower()

    def test_never_fabricates_compatibility_by_patching_the_processor_payload(self):
        # Injecting a *real* (unpatched) reference processor manifest whose
        # compatible_backends genuinely includes "aptl" would pass; the
        # locked surface's actual manifest does not, and admission must
        # never treat a superficially-similar payload as proof.
        real_processor_manifest = create_reference_processor_manifest()
        assert "aptl" not in real_processor_manifest.compatible_backends

        task = _task_with_apparatus_constraints(
            {
                "allowed_processor_refs": [
                    {"ref_kind": "processor", "ref_id": "aces-reference-processor", "ref_version": "0.1.0"}
                ],
                "allowed_backend_refs": [
                    {"ref_kind": "backend", "ref_id": "aptl", "ref_version": "0.1.0"}
                ],
                "required_manifest_refs": [
                    {
                        "ref_kind": "manifest",
                        "ref_id": "aces-reference-processor",
                        "ref_version": "processor-manifest/v2",
                        "subject_ref": {
                            "ref_kind": "processor",
                            "ref_id": "aces-reference-processor",
                            "ref_version": "0.1.0",
                        },
                    },
                    {
                        "ref_kind": "manifest",
                        "ref_id": "aptl",
                        "ref_version": "backend-manifest/v2",
                        "subject_ref": {
                            "ref_kind": "backend",
                            "ref_id": "aptl",
                            "ref_version": "0.1.0",
                        },
                    },
                ],
                "required_capabilities": [],
                "notes": [],
            }
        )

        with pytest.raises(AdmissionRejection):
            check_apparatus_admission(
                task,
                None,
                backend_manifest=create_aptl_manifest(),
                processor_manifest=real_processor_manifest,
                policy=default_admission_policy(),
            )


    def _pinned_task(self) -> ExperimentTaskModel:
        return _task_with_apparatus_constraints(
            {
                "allowed_processor_refs": [
                    {"ref_kind": "processor", "ref_id": "aces-reference-processor", "ref_version": "0.1.0"}
                ],
                "allowed_backend_refs": [
                    {"ref_kind": "backend", "ref_id": "aptl", "ref_version": "0.1.0"}
                ],
                "required_manifest_refs": [
                    {
                        "ref_kind": "manifest",
                        "ref_id": "aces-reference-processor",
                        "ref_version": "processor-manifest/v2",
                        "subject_ref": {
                            "ref_kind": "processor",
                            "ref_id": "aces-reference-processor",
                            "ref_version": "0.1.0",
                        },
                    },
                    {
                        "ref_kind": "manifest",
                        "ref_id": "aptl",
                        "ref_version": "backend-manifest/v2",
                        "subject_ref": {
                            "ref_kind": "backend",
                            "ref_id": "aptl",
                            "ref_version": "0.1.0",
                        },
                    },
                ],
                "required_capabilities": [],
                "notes": [],
            }
        )


def _synthetic_mutually_compatible_manifests():
    """A genuinely mutually-compatible test backend/processor pair (mirrors
    ``test_experiment_admission.py``'s ``_synthetic_manifests()``) so a test
    can isolate ONE apparatus gate at a time without the unconditional
    mutual-compatibility gate also firing alongside it.
    """
    from aces_backend_protocols.backend_manifest import BackendManifest
    from aces_processor.capabilities import ProcessorManifest

    real_backend = create_aptl_manifest()
    real_processor = create_reference_processor_manifest()
    test_backend = BackendManifest(
        name="test-backend",
        version=real_backend.version,
        supported_contract_versions=real_backend.supported_contract_versions,
        compatible_processors=frozenset({"test-processor"}),
        realization_support=real_backend.realization_support,
        concept_bindings=real_backend.concept_bindings,
        provisioner=real_backend.provisioner,
        orchestrator=real_backend.orchestrator,
        evaluator=real_backend.evaluator,
        participant_runtime=real_backend.participant_runtime,
    )
    test_processor = ProcessorManifest(
        name="test-processor",
        version=real_processor.version,
        supported_contract_versions=real_processor.supported_contract_versions,
        capabilities=real_processor.capabilities,
        compatible_backends=frozenset({"test-backend"}),
        concept_bindings=real_processor.concept_bindings,
        constraints=real_processor.constraints,
    )
    return test_backend, test_processor


# ---------------------------------------------------------------------------
# check_apparatus_admission — _identity_violations / _manifest_ref_violations
# distinct from the unconditional mutual-compat gate
# ---------------------------------------------------------------------------


class TestCheckApparatusAdmissionIdentityAndManifestRefViolations:
    """Both gates isolated with a synthetic, genuinely mutually-compatible
    backend/processor pair, so the unconditional mutual-compat gate cannot
    be what raises -- only the gate under test.
    """

    def test_identity_violation_when_the_resolved_processor_is_outside_the_allow_list(self):
        backend, processor = _synthetic_mutually_compatible_manifests()
        # ExperimentApparatusConstraintModel's own pydantic validator
        # requires any allowed_processor_refs entry to have a PAIRED
        # required_manifest_refs entry (same ref_id, canonical schema-
        # version literal) -- so that paired manifest ref necessarily also
        # names the same "wrong" identity, which independently also trips
        # _manifest_ref_violations' subject-identity check below (both are
        # real, structurally-coupled diagnostics for this input shape, not
        # a test artifact). The assertion below checks the
        # identity-unresolved code is genuinely PRESENT rather than
        # requiring total exclusivity.
        task = _task_with_apparatus_constraints(
            {
                "allowed_processor_refs": [
                    {"ref_kind": "processor", "ref_id": "some-other-processor", "ref_version": "9.9.9"}
                ],
                "required_manifest_refs": [
                    {
                        "ref_kind": "manifest",
                        "ref_id": "some-other-processor",
                        "ref_version": "processor-manifest/v2",
                        "subject_ref": {
                            "ref_kind": "processor",
                            "ref_id": "some-other-processor",
                            "ref_version": "9.9.9",
                        },
                    }
                ],
                "notes": [],
            }
        )

        with pytest.raises(AdmissionRejection) as excinfo:
            check_apparatus_admission(
                task, None, backend_manifest=backend, processor_manifest=processor, policy=default_admission_policy()
            )

        codes = {d.code for d in excinfo.value.diagnostics}
        assert "aptl.experiment-admission.apparatus-identity-unresolved" in codes
        identity_diagnostics = [
            d for d in excinfo.value.diagnostics if d.code == "aptl.experiment-admission.apparatus-identity-unresolved"
        ]
        assert identity_diagnostics
        assert all("allowed_processor_refs" in d.address for d in identity_diagnostics)

    def test_identity_violation_when_the_resolved_backend_is_outside_the_allow_list(self):
        backend, processor = _synthetic_mutually_compatible_manifests()
        # Same pydantic pairing requirement as the processor case above,
        # mirrored for allowed_backend_refs/required_manifest_refs.
        task = _task_with_apparatus_constraints(
            {
                "allowed_backend_refs": [
                    {"ref_kind": "backend", "ref_id": "some-other-backend", "ref_version": "9.9.9"}
                ],
                "required_manifest_refs": [
                    {
                        "ref_kind": "manifest",
                        "ref_id": "some-other-backend",
                        "ref_version": "backend-manifest/v2",
                        "subject_ref": {
                            "ref_kind": "backend",
                            "ref_id": "some-other-backend",
                            "ref_version": "9.9.9",
                        },
                    }
                ],
                "notes": [],
            }
        )

        with pytest.raises(AdmissionRejection) as excinfo:
            check_apparatus_admission(
                task, None, backend_manifest=backend, processor_manifest=processor, policy=default_admission_policy()
            )

        codes = {d.code for d in excinfo.value.diagnostics}
        assert "aptl.experiment-admission.apparatus-identity-unresolved" in codes
        identity_diagnostics = [
            d for d in excinfo.value.diagnostics if d.code == "aptl.experiment-admission.apparatus-identity-unresolved"
        ]
        assert identity_diagnostics
        assert all("allowed_backend_refs" in d.address for d in identity_diagnostics)

    def test_manifest_ref_mismatch_when_the_schema_version_literal_is_wrong(self):
        backend, processor = _synthetic_mutually_compatible_manifests()
        task = _task_with_apparatus_constraints(
            {
                "required_manifest_refs": [
                    {
                        "ref_kind": "manifest",
                        "ref_id": "test-processor",
                        # Wrong literal: must be the slash form
                        # "processor-manifest/v2", never a
                        # supported_contract_versions-shaped hyphen entry.
                        "ref_version": "processor-manifest/v1",
                        "subject_ref": {
                            "ref_kind": "processor",
                            "ref_id": "test-processor",
                            "ref_version": "0.1.0",
                        },
                    }
                ],
                "notes": [],
            }
        )

        with pytest.raises(AdmissionRejection) as excinfo:
            check_apparatus_admission(
                task, None, backend_manifest=backend, processor_manifest=processor, policy=default_admission_policy()
            )

        codes = {d.code for d in excinfo.value.diagnostics}
        assert codes == {"aptl.experiment-admission.apparatus-manifest-ref-mismatch"}
        assert all("required_manifest_refs" in d.address for d in excinfo.value.diagnostics)

    def test_manifest_ref_mismatch_when_the_subject_identity_is_wrong(self):
        backend, processor = _synthetic_mutually_compatible_manifests()
        task = _task_with_apparatus_constraints(
            {
                "required_manifest_refs": [
                    {
                        "ref_kind": "manifest",
                        "ref_id": "wrong-processor-name",
                        "ref_version": "processor-manifest/v2",
                        "subject_ref": {
                            # Correct schema-version literal, but the
                            # subject identity does not match the resolved
                            # processor manifest's own name.
                            "ref_kind": "processor",
                            "ref_id": "wrong-processor-name",
                            "ref_version": "0.1.0",
                        },
                    }
                ],
                "notes": [],
            }
        )

        with pytest.raises(AdmissionRejection) as excinfo:
            check_apparatus_admission(
                task, None, backend_manifest=backend, processor_manifest=processor, policy=default_admission_policy()
            )

        codes = {d.code for d in excinfo.value.diagnostics}
        assert codes == {"aptl.experiment-admission.apparatus-manifest-ref-mismatch"}
        assert all("required_manifest_refs" in d.address for d in excinfo.value.diagnostics)


# ---------------------------------------------------------------------------
# check_apparatus_admission — allow_uncertified_apparatus debug override
# ---------------------------------------------------------------------------


class TestCheckApparatusAdmissionUncertifiedApparatusOverride:
    """ADR-047: production stays strict/fail-closed, but a clearly-named
    DEBUG override (``AdmissionPolicy.allow_uncertified_apparatus``) lets
    dev/test admit against the REAL ``aptl`` manifest despite the
    reference-processor manifest naming only ``stub``.
    """

    def _pinned_task(self) -> ExperimentTaskModel:
        return TestCheckApparatusAdmissionMutualCompatGotcha()._pinned_task()

    def test_default_return_value_on_a_clean_admission_is_an_empty_tuple(self):
        # A synthetic (test-only, but honest) manifest pair that genuinely
        # DOES mutually declare compatibility, cloned from the real aptl /
        # reference-processor manifests' capability fields so only `name`
        # and the compatibility declarations differ. This is dependency
        # injection through the function's own documented override params,
        # never patching the real manifest objects (which the sibling
        # "never fabricates compatibility" test above forbids).
        real_backend = create_aptl_manifest()
        real_processor = create_reference_processor_manifest()
        from aces_backend_protocols.backend_manifest import BackendManifest
        from aces_processor.capabilities import ProcessorManifest

        test_backend = BackendManifest(
            name="test-backend",
            version=real_backend.version,
            supported_contract_versions=real_backend.supported_contract_versions,
            compatible_processors=frozenset({"test-processor"}),
            realization_support=real_backend.realization_support,
            concept_bindings=real_backend.concept_bindings,
            provisioner=real_backend.provisioner,
            orchestrator=real_backend.orchestrator,
            evaluator=real_backend.evaluator,
            participant_runtime=real_backend.participant_runtime,
        )
        test_processor = ProcessorManifest(
            name="test-processor",
            version=real_processor.version,
            supported_contract_versions=real_processor.supported_contract_versions,
            capabilities=real_processor.capabilities,
            compatible_backends=frozenset({"test-backend"}),
            concept_bindings=real_processor.concept_bindings,
            constraints=real_processor.constraints,
        )
        declared_capability = sorted(test_backend.supported_contract_versions)[0]
        task = _task_with_apparatus_constraints(
            {"required_capabilities": [declared_capability], "notes": []}
        )

        warnings = check_apparatus_admission(
            task,
            None,
            backend_manifest=test_backend,
            processor_manifest=test_processor,
            policy=default_admission_policy(),
        )

        assert warnings == ()

    def test_flag_off_the_mutual_compat_mismatch_still_raises(self):
        task = self._pinned_task()

        with pytest.raises(AdmissionRejection) as excinfo:
            check_apparatus_admission(task, None, policy=default_admission_policy())

        assert excinfo.value.diagnostics

    def test_flag_on_it_returns_exactly_one_warning_and_does_not_raise(self):
        task = self._pinned_task()
        policy = dataclasses.replace(default_admission_policy(), allow_uncertified_apparatus=True)

        warnings = check_apparatus_admission(task, None, policy=policy)

        assert len(warnings) == 1
        assert warnings[0].severity == Severity.WARNING
        assert warnings[0].code == "aptl.experiment-admission.apparatus-uncertified-compatibility"
        assert warnings[0].domain == EXPERIMENT_ADMISSION_DOMAIN

    def test_flag_on_a_non_mutual_compat_failure_still_raises(self):
        # required_capabilities names something neither manifest declares:
        # a real fatal gate independent of mutual-compat. The flag must not
        # blanket-suppress it.
        task = _task_with_apparatus_constraints(
            {"required_capabilities": ["totally-made-up-capability"], "notes": []}
        )
        policy = dataclasses.replace(default_admission_policy(), allow_uncertified_apparatus=True)

        with pytest.raises(AdmissionRejection) as excinfo:
            check_apparatus_admission(task, None, policy=policy)

        codes = {d.code for d in excinfo.value.diagnostics}
        assert any("capability" in code for code in codes)

    def test_flag_on_with_both_a_fatal_gate_and_mutual_compat_failing_raises_both(self):
        # Pinned identity (mutual-compat WILL fail with real manifests) plus
        # an unrelated bogus capability requirement (a second, independent
        # fatal gate). The flag must not make the overall call succeed.
        task = _task_with_apparatus_constraints(
            {
                "allowed_processor_refs": [
                    {"ref_kind": "processor", "ref_id": "aces-reference-processor", "ref_version": "0.1.0"}
                ],
                "allowed_backend_refs": [
                    {"ref_kind": "backend", "ref_id": "aptl", "ref_version": "0.1.0"}
                ],
                "required_manifest_refs": [
                    {
                        "ref_kind": "manifest",
                        "ref_id": "aces-reference-processor",
                        "ref_version": "processor-manifest/v2",
                        "subject_ref": {
                            "ref_kind": "processor",
                            "ref_id": "aces-reference-processor",
                            "ref_version": "0.1.0",
                        },
                    },
                    {
                        "ref_kind": "manifest",
                        "ref_id": "aptl",
                        "ref_version": "backend-manifest/v2",
                        "subject_ref": {
                            "ref_kind": "backend",
                            "ref_id": "aptl",
                            "ref_version": "0.1.0",
                        },
                    },
                ],
                "required_capabilities": ["totally-made-up-capability"],
                "notes": [],
            }
        )
        policy = dataclasses.replace(default_admission_policy(), allow_uncertified_apparatus=True)

        with pytest.raises(AdmissionRejection) as excinfo:
            check_apparatus_admission(task, None, policy=policy)

        codes = {d.code for d in excinfo.value.diagnostics}
        assert any("capability" in code for code in codes)
        assert any("compat" in code for code in codes)


# ---------------------------------------------------------------------------
# check_apparatus_admission — conjunctive narrowing of apparatus_intent
# ---------------------------------------------------------------------------


class TestCheckApparatusAdmissionIntentNarrowing:
    @staticmethod
    def _processor_intent(ref_id: str, ref_version: str) -> ExperimentApparatusConstraintModel:
        return ExperimentApparatusConstraintModel.model_validate(
            {
                "allowed_processor_refs": [
                    {"ref_kind": "processor", "ref_id": ref_id, "ref_version": ref_version}
                ],
                "required_manifest_refs": [
                    {
                        "ref_kind": "manifest",
                        "ref_id": ref_id,
                        "ref_version": "processor-manifest/v2",
                        "subject_ref": {
                            "ref_kind": "processor",
                            "ref_id": ref_id,
                            "ref_version": ref_version,
                        },
                    }
                ],
            }
        )

    @staticmethod
    def _backend_intent(ref_id: str, ref_version: str) -> ExperimentApparatusConstraintModel:
        return ExperimentApparatusConstraintModel.model_validate(
            {
                "allowed_backend_refs": [
                    {"ref_kind": "backend", "ref_id": ref_id, "ref_version": ref_version}
                ],
                "required_manifest_refs": [
                    {
                        "ref_kind": "manifest",
                        "ref_id": ref_id,
                        "ref_version": "backend-manifest/v2",
                        "subject_ref": {
                            "ref_kind": "backend",
                            "ref_id": ref_id,
                            "ref_version": ref_version,
                        },
                    }
                ],
            }
        )

    def test_intent_naming_a_processor_the_task_does_not_allow_is_rejected(self):
        task = _load_reference_task()
        intent = self._processor_intent("some-other-processor", "9.9.9")

        with pytest.raises(AdmissionRejection) as excinfo:
            check_apparatus_admission(task, intent, policy=default_admission_policy())

        assert excinfo.value.diagnostics

    def test_intent_naming_a_backend_the_task_does_not_allow_is_rejected(self):
        task = _load_reference_task()
        intent = self._backend_intent("some-other-backend", "9.9.9")

        with pytest.raises(AdmissionRejection):
            check_apparatus_admission(task, intent, policy=default_admission_policy())

    def test_intent_that_only_narrows_to_an_already_allowed_processor_does_not_add_a_narrowing_violation(self):
        # The task's own allow-list still fails admission (mutual compat /
        # capability gates), but the *narrowing* check itself must not be
        # what rejects a same-or-subset intent.
        task = _load_reference_task()
        intent = self._processor_intent("aces-reference-processor", "0.1.0")

        with pytest.raises(AdmissionRejection) as excinfo:
            check_apparatus_admission(task, intent, policy=default_admission_policy())

        codes = {d.code for d in excinfo.value.diagnostics}
        assert not any("intent-expands" in code for code in codes)


# ---------------------------------------------------------------------------
# check_apparatus_admission — required_capabilities
# ---------------------------------------------------------------------------


class TestCheckApparatusAdmissionRequiredCapabilities:
    def test_a_capability_not_declared_by_either_manifest_is_rejected(self):
        task = _task_with_apparatus_constraints(
            {"required_capabilities": ["totally-made-up-capability"], "notes": []}
        )

        with pytest.raises(AdmissionRejection) as excinfo:
            check_apparatus_admission(task, None, policy=default_admission_policy())

        assert excinfo.value.diagnostics

    def test_a_capability_declared_in_backend_supported_contract_versions_passes_that_gate(self):
        backend_manifest = create_aptl_manifest()
        declared = sorted(backend_manifest.supported_contract_versions)[0]
        task = _task_with_apparatus_constraints(
            {"required_capabilities": [declared], "notes": []}
        )

        # Overall admission still fails (mutual compat is unconditional at
        # the locked surface), but the diagnostics must not include a
        # capability-unsupported complaint about this specific capability.
        with pytest.raises(AdmissionRejection) as excinfo:
            check_apparatus_admission(task, None, policy=default_admission_policy())

        for d in excinfo.value.diagnostics:
            assert declared not in d.address or "capability" not in d.code


# ---------------------------------------------------------------------------
# check_apparatus_admission — does not leak values
# ---------------------------------------------------------------------------


class TestCheckApparatusAdmissionDoesNotLeak:
    def test_an_unsupported_capability_name_is_safe_to_echo_but_a_secret_note_never_is(self):
        task = _task_with_apparatus_constraints(
            {"required_capabilities": ["made-up"], "notes": [f"secret={SECRET}"]}
        )

        with pytest.raises(AdmissionRejection) as excinfo:
            check_apparatus_admission(task, None, policy=default_admission_policy())

        for d in excinfo.value.diagnostics:
            assert SECRET not in d.message
            assert SECRET not in d.code
            assert SECRET not in d.address


# ---------------------------------------------------------------------------
# plan_condition_feasibility / require_feasible_plan — happy path
# ---------------------------------------------------------------------------


class TestPlanConditionFeasibilityHappyPath:
    def test_a_valid_corpus_scenario_with_empty_parameters_is_feasible(self):
        scenario = parse_sdl(_minimal_scenario_bytes().decode("utf-8"))

        result = plan_condition_feasibility(scenario, {})

        assert isinstance(result, ReferenceProcessorResult)
        assert result.is_valid is True
        require_feasible_plan(result, address="condition")  # must not raise

    def test_uses_the_aptl_manifest_by_default(self):
        scenario = parse_sdl(_minimal_scenario_bytes().decode("utf-8"))

        result = plan_condition_feasibility(scenario, {})
        direct = run_reference_processor(scenario, create_aptl_manifest(), parameters={})

        assert result.scenario_name == direct.scenario_name
        assert result.is_valid == direct.is_valid


class TestPlanConditionFeasibilityBrokenParameterBinding:
    """At the locked ACES 0.23.1 surface, ``run_reference_processor`` itself
    *raises* ``SDLInstantiationError`` for a structurally broken parameter
    binding (verified live) rather than returning an invalid
    ``ReferenceProcessorResult`` — a delta from what a naive reading of the
    planning API might suggest. ``plan_condition_feasibility`` normalizes
    that raise into the same fail-closed ``AdmissionRejection`` surface as
    every other admission rejection, rather than letting a raw ACES
    exception escape or fabricating a fake successful plan.
    """

    def test_an_undeclared_parameter_target_is_rejected(self):
        scenario = parse_sdl(_minimal_scenario_bytes().decode("utf-8"))

        with pytest.raises(AdmissionRejection) as excinfo:
            plan_condition_feasibility(scenario, {"undeclared_target": SECRET})

        assert excinfo.value.diagnostics

    def test_the_bound_secret_value_is_never_leaked_in_the_rejection(self):
        scenario = parse_sdl(_minimal_scenario_bytes().decode("utf-8"))

        with pytest.raises(AdmissionRejection) as excinfo:
            plan_condition_feasibility(scenario, {"undeclared_target": SECRET})

        for d in excinfo.value.diagnostics:
            assert SECRET not in d.message
            assert SECRET not in d.code
            assert SECRET not in d.address


class TestRequireFeasiblePlanRejectsAnInvalidResult:
    def test_raises_when_the_result_carries_an_error_diagnostic(self):
        from aces_contracts.diagnostics import Diagnostic, Severity

        bad_diagnostic = Diagnostic(
            code="aces.some-planning-error",
            domain="aces-processor",
            address="scenario.nodes",
            message=f"unresolvable reference; rejected value was {SECRET}",
            severity=Severity.ERROR,
        )
        fake_result = ReferenceProcessorResult(
            scenario_name="fake",
            runtime_model=None,
            execution_plan=None,
            diagnostics=(bad_diagnostic,),
        )
        assert fake_result.is_valid is False

        with pytest.raises(AdmissionRejection) as excinfo:
            require_feasible_plan(fake_result, address="condition")

        assert excinfo.value.diagnostics == (bad_diagnostic,)

    def test_does_not_raise_for_a_valid_result(self):
        fake_result = ReferenceProcessorResult(
            scenario_name="fake",
            runtime_model=None,
            execution_plan=None,
            diagnostics=(),
        )

        require_feasible_plan(fake_result, address="condition")  # must not raise


# ---------------------------------------------------------------------------
# plan_condition_feasibility — no Docker / DeploymentBackend construction
# ---------------------------------------------------------------------------


class TestPlanConditionFeasibilityNeverTouchesDocker:
    def test_no_deployment_backend_or_docker_module_is_imported_or_invoked(self, monkeypatch):
        # `monkeypatch.delitem` (not a raw `sys.modules.pop`) so the ENTIRE
        # sys.modules mutation — including the fresh re-import performed
        # below to install the spy — is unconditionally reverted at test
        # teardown. A bare pop/reimport would leak a *different* module
        # object into sys.modules for the rest of this worker process,
        # which can break identity/patch-target assumptions in unrelated
        # tests sharing the same pytest-xdist worker.
        for leftover in (
            "aptl.core.deployment.docker_compose",
            "aptl.core.deployment.ssh_compose",
            "aces_runtime.manager",
        ):
            monkeypatch.delitem(sys.modules, leftover, raising=False)

        def _boom(*args, **kwargs):
            raise AssertionError("subprocess.run must never be called by planning-only admission")

        # Belt-and-suspenders spy: if docker_compose ever gets imported and
        # exercised, its one real chokepoint (subprocess.run) must not fire.
        import aptl.core.deployment.docker_compose as docker_compose_module

        monkeypatch.setattr(docker_compose_module.subprocess, "run", _boom)

        scenario = parse_sdl(_minimal_scenario_bytes().decode("utf-8"))
        result = plan_condition_feasibility(scenario, {})

        assert result.is_valid is True
        assert "aptl.core.deployment.ssh_compose" not in sys.modules
        # aces_runtime.manager (RuntimeManager, the execution-side
        # incumbent) must never be pulled in by planning-only admission.
        assert "aces_runtime.manager" not in sys.modules


# ---------------------------------------------------------------------------
# Fuzz
# ---------------------------------------------------------------------------

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402


@pytest.mark.fuzz
class TestFuzzApparatusIntentSupersetsAlwaysReject:
    @given(
        extra_ref_id=st.text(alphabet="abcdefghijklmnopqrstuvwxyz-", min_size=1, max_size=24),
        extra_ref_version=st.text(alphabet="0123456789.", min_size=1, max_size=8),
    )
    @settings(max_examples=50, deadline=2000)
    def test_an_intent_processor_ref_outside_the_tasks_allow_list_always_rejects(
        self, extra_ref_id, extra_ref_version
    ):
        task = _load_reference_task()
        allowed_ids = {ref.ref_id for ref in task.apparatus_constraints.allowed_processor_refs}
        if extra_ref_id in allowed_ids:
            extra_ref_id += "-not-allowed"

        intent = ExperimentApparatusConstraintModel.model_validate(
            {
                "allowed_processor_refs": [
                    {"ref_kind": "processor", "ref_id": extra_ref_id, "ref_version": extra_ref_version}
                ],
                "required_manifest_refs": [
                    {
                        "ref_kind": "manifest",
                        "ref_id": extra_ref_id,
                        "ref_version": "processor-manifest/v2",
                        "subject_ref": {
                            "ref_kind": "processor",
                            "ref_id": extra_ref_id,
                            "ref_version": extra_ref_version,
                        },
                    }
                ],
            }
        )

        with pytest.raises(AdmissionRejection):
            check_apparatus_admission(task, intent, policy=default_admission_policy())

    @given(
        capture_kind=st.text(alphabet="abcdefghijklmnopqrstuvwxyz-", min_size=1, max_size=24),
    )
    @settings(max_examples=50, deadline=2000)
    def test_an_arbitrary_unknown_required_capability_always_rejects(self, capture_kind):
        task = _task_with_apparatus_constraints(
            {"required_capabilities": [capture_kind], "notes": []}
        )

        with pytest.raises(AdmissionRejection):
            check_apparatus_admission(task, None, policy=default_admission_policy())
