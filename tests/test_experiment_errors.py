"""Tests for ``aptl.core.experiment.errors`` (ADR-047 "Error envelope").

``normalize_aces_failure`` is the one place admission is allowed to turn an
ACES/pydantic exception into a :class:`Diagnostic`. It must handle exactly
the three documented failure shapes and must never let a raw
``str(exc))`` — which for pydantic ``ValidationError`` embeds the rejected
``input_value`` — leak into the produced diagnostics.
"""

from __future__ import annotations

import pydantic
import pytest
from aces_contracts.diagnostics import Diagnostic, Severity
from aces_contracts.experiment_spec import (
    ExperimentSpecValidationError,
    parse_experiment_spec,
)
from aces_sdl import SDLInstantiationError, SDLParseError, SDLValidationError, parse_sdl

from aptl.core.experiment.errors import (
    EXPERIMENT_ADMISSION_DOMAIN,
    EXPERIMENT_ADMISSION_STAGE_LABEL,
    AdmissionRejection,
    diagnostic,
    normalize_aces_failure,
)

SECRET = "sk-super-secret-injected-token-12345"


class TestAdmissionRejection:
    def test_stores_diagnostics_tuple(self):
        d = diagnostic("aptl.experiment-admission.x", "root", "bad thing")

        rejection = AdmissionRejection((d,))

        assert rejection.diagnostics == (d,)
        assert isinstance(rejection.diagnostics, tuple)

    def test_is_an_exception(self):
        d = diagnostic("aptl.experiment-admission.x", "root", "bad thing")
        with pytest.raises(AdmissionRejection):
            raise AdmissionRejection((d,))

    def test_accepts_any_iterable_and_normalizes_to_a_tuple(self):
        d = diagnostic("aptl.experiment-admission.x", "root", "bad thing")

        rejection = AdmissionRejection(iter([d, d]))

        assert rejection.diagnostics == (d, d)


class TestDiagnosticHelper:
    def test_builds_a_redacted_error_diagnostic(self):
        d = diagnostic("aptl.experiment-admission.x", "root.field", "message text")

        assert d.code == "aptl.experiment-admission.x"
        assert d.domain == EXPERIMENT_ADMISSION_DOMAIN
        assert d.address == "root.field"
        assert d.message == "message text"
        assert d.severity == Severity.ERROR
        assert d.is_error

    def test_redacts_secret_shaped_message_content(self):
        d = diagnostic("aptl.experiment-admission.x", "root", "password=hunter2hunter2")

        assert "hunter2hunter2" not in d.message


class TestNormalizeAcesFailurePassthrough:
    def test_passes_a_single_diagnostic_through_unchanged(self):
        original = Diagnostic(
            code="c", domain="d", address="a", message="m", severity=Severity.ERROR
        )

        result = normalize_aces_failure(
            original, address="root", code="aptl.experiment-admission.x"
        )

        assert result == (original,)

    def test_passes_a_tuple_of_diagnostics_through_unchanged(self):
        d1 = Diagnostic(code="c1", domain="d", address="a1", message="m1")
        d2 = Diagnostic(code="c2", domain="d", address="a2", message="m2")

        result = normalize_aces_failure(
            (d1, d2), address="root", code="aptl.experiment-admission.x"
        )

        assert result == (d1, d2)

    def test_passes_an_empty_diagnostic_tuple_through_unchanged(self):
        result = normalize_aces_failure(
            (), address="root", code="aptl.experiment-admission.x"
        )

        assert result == ()


class TestNormalizeAcesFailurePydanticValidationError:
    def _validation_error(self) -> pydantic.ValidationError:
        class Model(pydantic.BaseModel):
            x: int

        try:
            Model(x=SECRET)
        except pydantic.ValidationError as exc:
            return exc
        raise AssertionError("expected a ValidationError")

    def test_extracts_one_diagnostic_per_pydantic_error(self):
        exc = self._validation_error()

        result = normalize_aces_failure(
            exc, address="root", code="aptl.experiment-admission.root-invalid"
        )

        assert len(result) == 1
        assert all(isinstance(item, Diagnostic) for item in result)

    def test_never_leaks_the_rejected_input_value(self):
        exc = self._validation_error()
        assert SECRET in str(exc)  # sanity: pydantic's own str() DOES leak it

        result = normalize_aces_failure(
            exc, address="root", code="aptl.experiment-admission.root-invalid"
        )

        for item in result:
            assert SECRET not in item.message
            assert SECRET not in item.code
            assert SECRET not in item.address

    def test_diagnostic_carries_loc_derived_address_and_safe_code(self):
        exc = self._validation_error()

        result = normalize_aces_failure(
            exc, address="root", code="aptl.experiment-admission.root-invalid"
        )

        item = result[0]
        assert item.code == "aptl.experiment-admission.root-invalid"
        assert "root" in item.address
        assert "x" in item.address
        assert item.domain == EXPERIMENT_ADMISSION_DOMAIN


class TestNormalizeAcesFailureExperimentSpecValidationError:
    """``ExperimentSpecValidationError`` wraps a pydantic ``ValidationError``
    via ``str()`` (ADR-047 gotcha) — the normalizer must reach through
    ``__cause__`` rather than ever calling ``str(exc)`` on it.
    """

    def _leaking_yaml(self) -> str:
        return f"""
schema_version: experiment-authoring-input/v1
spec_id: s1
spec_version: v1
title: t
description: d
task_ref: {{ref_kind: {SECRET}, ref_id: t1}}
run_plan: {{}}
"""

    def test_never_leaks_a_secret_embedded_in_the_rejected_field(self):
        try:
            parse_experiment_spec(self._leaking_yaml())
        except ExperimentSpecValidationError as exc:
            assert SECRET in str(exc)  # sanity: the wrapped str() DOES leak it

            result = normalize_aces_failure(
                exc, address="root", code="aptl.experiment-admission.root-invalid"
            )
        else:
            raise AssertionError("expected ExperimentSpecValidationError")

        assert result
        for item in result:
            assert SECRET not in item.message
            assert SECRET not in item.code
            assert SECRET not in item.address

    def test_falls_back_to_a_safe_generic_diagnostic_without_a_pydantic_cause(self):
        # "Experiment spec must be a YAML mapping" — no `__cause__` at all;
        # the normalizer must not try to inspect a non-existent cause and
        # must not surface the (safe, but still untrusted) raw message.
        try:
            parse_experiment_spec("- a\n- b\n")
        except ExperimentSpecValidationError as exc:
            assert exc.__cause__ is None

            result = normalize_aces_failure(
                exc, address="root", code="aptl.experiment-admission.root-invalid"
            )
        else:
            raise AssertionError("expected ExperimentSpecValidationError")

        assert len(result) == 1
        assert result[0].code == "aptl.experiment-admission.root-invalid"
        assert result[0].domain == EXPERIMENT_ADMISSION_DOMAIN


class TestNormalizeAcesFailureSdlParseError:
    def test_uses_structured_parse_diagnostics_when_present(self):
        try:
            parse_sdl(f"name: x\nimports:\n  - path: {SECRET}.yaml\n")
        except SDLParseError as exc:
            result = normalize_aces_failure(
                exc, address="scenario", code="aptl.experiment-admission.scenario-invalid"
            )
        else:
            raise AssertionError("expected SDLParseError")

        assert result
        assert all(isinstance(item, Diagnostic) for item in result)
        # The SECRET was embedded in the SDL import path this exception was
        # raised for; matching the adjacent secret-absence pattern
        # (TestNormalizeAcesFailureExperimentSpecValidationError above), the
        # secret must never surface in any produced diagnostic field.
        for item in result:
            assert SECRET not in item.message
            assert SECRET not in item.code
            assert SECRET not in item.address

    def test_scrubs_an_absolute_path_embedded_in_the_message(self):
        # Constructed directly: exercise the scrub without depending on a
        # real ACES code path happening to embed a path today.
        exc = SDLParseError("failed near /home/attacker/secret-project/scenario.yaml")

        result = normalize_aces_failure(
            exc, address="scenario", code="aptl.experiment-admission.scenario-invalid"
        )

        assert len(result) == 1
        assert "/home/attacker/secret-project/scenario.yaml" not in result[0].message


class TestNormalizeAcesFailureSdlValidationError:
    def test_one_diagnostic_per_error_string(self):
        exc = SDLValidationError(["first problem", "second problem"])

        result = normalize_aces_failure(
            exc, address="scenario", code="aptl.experiment-admission.scenario-invalid"
        )

        assert len(result) == 2
        messages = {item.message for item in result}
        assert messages == {"first problem", "second problem"}

    def test_scrubs_an_absolute_path_embedded_in_an_error_string(self):
        exc = SDLValidationError(["bad reference at /etc/aptl/secret-config.yaml"])

        result = normalize_aces_failure(
            exc, address="scenario", code="aptl.experiment-admission.scenario-invalid"
        )

        assert "/etc/aptl/secret-config.yaml" not in result[0].message


class TestNormalizeAcesFailureSdlInstantiationError:
    """``run_reference_processor`` raises this (not documented in the ACES
    API reference consulted for Stage 1) when a condition's parameter
    binding is structurally broken — verified live in Stage 3. It shares
    ``SDLValidationError``'s safe ``errors: list[str]`` shape.
    """

    def test_one_diagnostic_per_error_string(self):
        exc = SDLInstantiationError(["first problem", "second problem"])

        result = normalize_aces_failure(
            exc, address="condition.parameters", code="aptl.experiment-admission.condition-parameters-invalid"
        )

        assert len(result) == 2
        messages = {item.message for item in result}
        assert messages == {"first problem", "second problem"}

    def test_scrubs_an_absolute_path_embedded_in_an_error_string(self):
        exc = SDLInstantiationError(["bad target at /etc/aptl/secret-config.yaml"])

        result = normalize_aces_failure(
            exc, address="condition.parameters", code="aptl.experiment-admission.condition-parameters-invalid"
        )

        assert "/etc/aptl/secret-config.yaml" not in result[0].message

    def test_a_real_undeclared_parameter_binding_never_leaks_the_bound_value(self):
        # Mirrors the real Stage 3 call shape: run_reference_processor
        # raises SDLInstantiationError naming the undeclared parameter
        # *name*; the *value* bound to it must never appear anywhere.
        from aces_processor.reference import run_reference_processor
        from aces_sdl import parse_sdl

        from aptl.backends.aces_manifest import create_aptl_manifest

        scenario = parse_sdl("name: canonical-minimal\n")
        try:
            run_reference_processor(
                scenario,
                create_aptl_manifest(),
                parameters={"undeclared_target": SECRET},
            )
        except SDLInstantiationError as exc:
            result = normalize_aces_failure(
                exc,
                address="condition.parameters",
                code="aptl.experiment-admission.condition-parameters-invalid",
            )
        else:
            raise AssertionError("expected SDLInstantiationError")

        assert result
        for item in result:
            assert SECRET not in item.message


def test_stage_label_is_not_the_misleading_default():
    assert EXPERIMENT_ADMISSION_STAGE_LABEL != "ACES runtime handoff failed"
    assert "admission" in EXPERIMENT_ADMISSION_STAGE_LABEL.lower()
