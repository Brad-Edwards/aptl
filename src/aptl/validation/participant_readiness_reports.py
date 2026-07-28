"""Report construction and provenance helpers for participant readiness."""

from __future__ import annotations

from typing import TYPE_CHECKING

from aptl.validation.participant_readiness_models import (
    ParticipantReadinessReport,
    ParticipantReadinessRequest,
)

if TYPE_CHECKING:
    from aptl.core.runstore import RunStorageBackend


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
    run_store: RunStorageBackend,
    run_id: str,
    provider: str,
    model: str | None,
    behavior: str,
    participant_address: str,
    *diagnostics: str,
) -> ParticipantReadinessReport:
    """Persist one failed bounded-participant readiness report."""

    report = ParticipantReadinessReport(
        passed=False,
        run_id=run_id,
        provider=provider,
        model=model,
        behavior=behavior,
        participant_address=participant_address,
        selected_actions=(),
        completed_turns=0,
        diagnostics=tuple(diagnostics),
    )
    run_store.write_json(
        run_id,
        "participant/readiness-report.json",
        report.to_payload(),
    )
    return report
