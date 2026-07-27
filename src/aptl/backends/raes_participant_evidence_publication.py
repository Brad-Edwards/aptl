"""Atomic source records and recoverable participant evidence projections."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING

from raes_contracts.diagnostics import Diagnostic, Severity
from raes_contracts.planning import RuntimeDomain

if TYPE_CHECKING:
    from aptl.backends.raes_participant_driver import ParticipantPlanAuthority


def persist_action_evidence(
    authority: ParticipantPlanAuthority,
    *,
    evaluator_record: Mapping[str, object],
    participant_record: Mapping[str, object],
) -> tuple[Diagnostic, ...]:
    """Publish an atomic source record, then recoverable JSONL projections."""

    failures: list[Diagnostic] = []
    if authority.run_store is not None and authority.run_id is not None:
        action_instance_id = evaluator_record.get("action_instance_id")
        if not isinstance(action_instance_id, str) or not action_instance_id:
            failures.append(
                _evidence_publication_diagnostic(
                    "transaction",
                    "action evidence has no action-instance identity",
                )
            )
        else:
            transaction_name = hashlib.sha256(action_instance_id.encode()).hexdigest()
            transaction = {
                "schema": "aptl.participant-action-evidence-transaction/v1",
                "run_id": authority.run_id,
                "action_instance_id": action_instance_id,
                "participant_projection": dict(participant_record),
                "evaluator_projection": dict(evaluator_record),
            }
            publications = _evidence_publications(
                authority,
                transaction_name,
                transaction,
                participant_record,
                evaluator_record,
            )
            failures.extend(_publish_evidence(publications))
    return tuple(failures)


def _evidence_publications(
    authority: ParticipantPlanAuthority,
    transaction_name: str,
    transaction: Mapping[str, object],
    participant_record: Mapping[str, object],
    evaluator_record: Mapping[str, object],
) -> tuple[tuple[str, Callable[[], None]], ...]:
    """Build ordered authoritative and projection publication calls."""

    publications: list[tuple[str, Callable[[], None]]] = []
    if authority.run_store is not None and authority.run_id is not None:
        publications.extend(
            (
                (
                    "transaction",
                    lambda: authority.run_store.create_run_json_once(
                        authority.run_id,
                        (
                            "evaluator/participant-action-transactions/"
                            f"{transaction_name}.json"
                        ),
                        dict(transaction),
                    ),
                ),
                (
                    "participant-projection",
                    lambda: authority.run_store.append_jsonl(
                        authority.run_id,
                        "participant/observations.jsonl",
                        [dict(participant_record)],
                    ),
                ),
                (
                    "evaluator-projection",
                    lambda: authority.run_store.append_jsonl(
                        authority.run_id,
                        "evaluator/participant-action-evidence.jsonl",
                        [dict(evaluator_record)],
                    ),
                ),
            ),
        )
    return tuple(publications)


def _publish_evidence(
    publications: tuple[tuple[str, Callable[[], None]], ...],
) -> list[Diagnostic]:
    """Run all evidence publications and retain phase-specific warnings."""

    failures: list[Diagnostic] = []
    for phase, publication in publications:
        try:
            publication()
        except Exception:
            failures.append(
                _evidence_publication_diagnostic(
                    phase,
                    "accepted participant action evidence was not fully published",
                )
            )
    return failures


def _evidence_publication_diagnostic(phase: str, message: str) -> Diagnostic:
    """Build one recoverable evidence-publication warning."""

    return Diagnostic(
        code="aptl.participant-runtime.evidence-publication-failed",
        domain=RuntimeDomain.PARTICIPANT.value,
        address=f"participant-evidence-publication.{phase}",
        message=f"{message} (phase={phase})",
        severity=Severity.WARNING,
    )
