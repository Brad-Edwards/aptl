"""Owner-native → RAES sub-model bridges for the execution controller
(#437/#459 → EXP-009).

The archival coordinator consumes owner-native RAES sub-models on a
:class:`~aptl.core.archival.context.TerminalAttemptContext` (ADR-050). These
pure functions convert the runtime facts an executed trial produces — the clock
reading, the planned-trial parameters and stochastic seeds, the evidence
coordinator's acquisition result, and the evaluator's supplied summaries — into
those RAES sub-models. They define no metrics and derive no results; they record
what the owners supplied (ADR boundary: "APTL records results supplied by the
ACES evaluator ... It does not define metrics").
"""

from __future__ import annotations

from collections.abc import Mapping

from raes_contracts.contracts import (
    ExperimentArtifactRefModel,
    ExperimentClockContextModel,
    ExperimentParameterModel,
    ExperimentResultSummaryModel,
    ExperimentStochasticControlModel,
)

from aptl.core.archival.seal import SealedArtifactSpec
from aptl.core.correlation.clock import ClockProvider
from aptl.core.evidence.coordinator import AcquisitionResult
from aptl.core.experiment.trial_plan_models import PlannedTrial

#: Map an APTL clock ``timestamp_domain`` onto a RAES ``time_domain`` literal.
_TIME_DOMAIN_MAP: dict[str, str] = {
    "host-utc": "wall-clock",
    "wall-clock": "wall-clock",
    "monotonic": "monotonic",
    "simulated": "simulated",
    "logical": "logical",
}


def clock_context_from_provider(
    clock: ClockProvider, *, source_kind: str = "backend", source_id: str = "range-clock"
) -> ExperimentClockContextModel:
    """Convert a :class:`ClockProvider` reading into the RAES clock context.

    Preserves the source's timestamp domain, authority, and synchronization
    status honestly — it never claims NTP synchronization from a bare host
    timestamp (ADR-050 / OBS-002).
    """
    ctx = clock.clock_context(source_kind=source_kind, source_id=source_id)
    time_domain = _TIME_DOMAIN_MAP.get(ctx.timestamp_domain, "other")
    return ExperimentClockContextModel(
        clock_id=f"{ctx.source_kind}.{ctx.source_id}",
        authority=ctx.clock_source,
        time_domain=time_domain,
        synchronization=ctx.synchronization_status,
    )


def parameter_set_from_trial(trial: PlannedTrial) -> tuple[ExperimentParameterModel, ...]:
    """Project a planned trial's realized parameter bindings into RAES parameters.

    Falls back to a single apparatus parameter recording the trial's condition
    when the trial carries no explicit parameter bindings, because the RAES run
    record requires at least one parameter.
    """
    params = [
        ExperimentParameterModel(
            name=name,
            value=_scalar(value),
            value_kind="configuration",
        )
        for name, value in trial.parameter_bindings
    ]
    if not params:
        params.append(
            ExperimentParameterModel(
                name="condition",
                value=trial.condition_id or "default",
                value_kind="protocol",
            )
        )
    return tuple(params)


def stochastic_controls_from_trial(
    trial: PlannedTrial,
) -> tuple[ExperimentStochasticControlModel, ...]:
    """Project a planned trial's derived seeds into RAES stochastic controls.

    Falls back to a single deterministic-execution control when the trial
    carries no seeds, because the RAES run record requires at least one control.
    """
    controls = [
        ExperimentStochasticControlModel(control_id=control_id, role="seed", value=seed)
        for control_id, seed in trial.stochastic_seeds
    ]
    if not controls:
        controls.append(
            ExperimentStochasticControlModel(
                control_id="deterministic",
                role="other",
                description="No stochastic control was declared for this trial.",
            )
        )
    return tuple(controls)


def evidence_artifacts_from_acquisition(
    acquisition: AcquisitionResult,
) -> tuple[ExperimentArtifactRefModel, ...]:
    """Return the content-addressed artifact refs the evidence records carry.

    Each ``ExperimentEvidenceRecordModel`` produced by the evidence coordinator
    carries its full portable ``ExperimentArtifactRefModel`` in
    ``raw_content.artifact_ref`` (media type, checksum, size, creation time,
    source). Reusing that exact object keeps the run's ``evidence_artifacts``
    identical to what was captured — never re-``stat()``-ed at seal time.
    """
    artifacts: list[ExperimentArtifactRefModel] = []
    for record in acquisition.records:
        artifact = record.raw_content.artifact_ref
        if artifact is not None:
            artifacts.append(artifact)
    return tuple(artifacts)


def sealed_artifacts_from_acquisition(
    acquisition: AcquisitionResult, *, run_relative_prefix: str = ""
) -> tuple[SealedArtifactSpec, ...]:
    """Return sealed-artifact specs (with claimed identity) for captured evidence.

    Each spec binds the on-disk blob path to its RAES artifact reference's
    checksum/size, so the sealer refuses to seal bytes that diverge from what the
    evidence record claims (the seal-time identity join).
    """
    specs: list[SealedArtifactSpec] = []
    for record in acquisition.records:
        artifact = record.raw_content.artifact_ref
        if artifact is None:
            continue
        path = f"{run_relative_prefix}{artifact.uri}" if run_relative_prefix else artifact.uri
        specs.append(
            SealedArtifactSpec.from_artifact_ref(
                run_relative_path=path, artifact_ref=artifact, role="evidence-blob"
            )
        )
    return tuple(specs)


def validate_result_summaries(
    summaries: Mapping[str, ExperimentResultSummaryModel],
) -> dict[str, ExperimentResultSummaryModel]:
    """Return the evaluator's result summaries unchanged, verifying their type.

    The archival layer copies evaluator-supplied summaries verbatim; it never
    derives scores or translates workflow success into a metric value. This is a
    typed pass-through guard, not a transformation.
    """
    for key, summary in summaries.items():
        if not isinstance(summary, ExperimentResultSummaryModel):
            raise TypeError(
                f"result summary {key!r} must be an ExperimentResultSummaryModel, "
                f"got {type(summary)!r}"
            )
    return dict(summaries)


def _scalar(value: object) -> str | int | float | bool | None:
    """Coerce a parameter-binding value to a RAES parameter scalar.

    Non-scalar values are rendered as their string form so a malformed binding
    surfaces as a recorded string rather than a validation crash at seal time.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)
