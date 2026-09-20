"""Redacted, unretryable outcome translation for RAES scenario start."""

from __future__ import annotations

from pathlib import Path

from raes import SDLInstantiationError
from raes_contracts.runtime_state import RuntimeSnapshot

from aptl.backends.raes_diagnostics import render_raes_diagnostics
from aptl.backends.raes_start_model import AcesStartOutcome
from aptl.core.experiment.errors import AdmissionRejection
from aptl.core.lab_types import LabResult
from aptl.core.scenario_bundle import EnvPackError
from aptl.utils.redaction import redact

# A rejected variable can be an operator secret, so no admission failure may
# echo the value back (issue #951 moved the second call site into lab start).
INSTANTIATION_FAILURE_MESSAGE = (
    "RAES runtime variable binding failed before deployment. Provide every "
    "required variable using its declared type and allowed values."
)


def start_failure_outcome(exc: Exception, resolved_scenario: Path) -> AcesStartOutcome:
    """Map scenario-start failures to redacted, unretryable outcomes.

    Pack acquisition and runtime handoff report redacted exceptions. Variable
    binding uses a fixed message, never the rejected operator value.
    """

    if isinstance(exc, AdmissionRejection):
        error = render_raes_diagnostics(
            list(exc.diagnostics), stage_label="Scenario evidence admission failed"
        )
    elif isinstance(exc, EnvPackError):
        error = redact(f"RAES scenario pack acquisition failed: {exc}")
    elif isinstance(exc, SDLInstantiationError):
        error = INSTANTIATION_FAILURE_MESSAGE
    else:
        error = redact(f"RAES runtime handoff failed: {exc}")
    return AcesStartOutcome(
        lab_result=LabResult(success=False, error=error),
        final_snapshot=RuntimeSnapshot(),
        realization_details={},
        selected_profiles=[],
        scenario_path=resolved_scenario,
        retryable=False,
    )
