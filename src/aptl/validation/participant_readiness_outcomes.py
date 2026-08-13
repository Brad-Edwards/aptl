"""Positive terminal-outcome validation for participant readiness."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

_TERMINAL_ACTION_STATUSES = frozenset(
    {"succeeded", "failed", "partial_success", "rejected", "withheld"}
)


def record_positive_terminal_outcome(
    *,
    selected_action: str,
    action_result: Mapping[str, object] | None,
    terminal_status: object,
    admission_diagnostics: Sequence[object],
    selected_actions: list[str],
    terminal_outcomes: list[Mapping[str, object]],
    diagnostics: list[str],
) -> bool:
    """Retain a typed outcome and enforce the positive-readiness contract."""

    accepted = True
    if (
        not isinstance(terminal_status, str)
        or terminal_status not in _TERMINAL_ACTION_STATUSES
        or action_result is None
    ):
        diagnostics.append(
            "admitted participant action did not publish a typed terminal outcome"
        )
        accepted = False
    else:
        selected_actions.append(selected_action)
        terminal_outcomes.append(
            {
                "action_contract_address": selected_action,
                "status": terminal_status,
                "failure_class": action_result.get("failure_class"),
            }
        )
    if accepted and terminal_status != "succeeded":
        diagnostics.append(
            "positive participant readiness requires a succeeded "
            f"terminal outcome; observed {terminal_status}"
        )
        accepted = False
    publication_failed = any(
        getattr(diagnostic, "code", None)
        == "aptl.participant-runtime.evidence-publication-failed"
        for diagnostic in admission_diagnostics
    )
    if accepted and publication_failed:
        diagnostics.append(
            "accepted participant action evidence was not fully published"
        )
        accepted = False
    return accepted
