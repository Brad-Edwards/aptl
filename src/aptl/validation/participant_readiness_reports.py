"""Report construction and provenance helpers for participant readiness."""

from __future__ import annotations

from collections.abc import Mapping

from aptl.validation.participant_readiness_models import (
    ParticipantReadinessReport,
    ParticipantReadinessRequest,
)


def configured_readiness_model(
    request: ParticipantReadinessRequest,
) -> str | None:
    """Return admitted non-secret model provenance without triggering launch."""

    if request.provider_override is not None:
        return request.provider_override.model
    if request.provider_name == "deterministic":
        return None
    return getattr(
        request.config.experiment.participant_models,
        request.provider_name,
        None,
    )


def persist_failed_readiness_report(
    request: ParticipantReadinessRequest,
    run_id: str,
    participant_address: str,
    diagnostics: tuple[str, ...],
    credential_binding: Mapping[str, object] | None = None,
) -> ParticipantReadinessReport:
    """Persist one failed bounded-participant readiness report."""

    report = ParticipantReadinessReport(
        passed=False,
        run_id=run_id,
        provider=request.provider_name,
        model=configured_readiness_model(request),
        behavior=request.behavior_name,
        participant_address=participant_address,
        selected_actions=(),
        completed_turns=0,
        diagnostics=diagnostics,
        credential_binding=credential_binding,
    )
    request.run_store.write_json(
        run_id,
        "participant/readiness-report.json",
        report.to_payload(),
    )
    return report
