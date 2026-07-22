"""Named ``DECLARED_RULE`` vocabulary for the OBS-002 correlation builder (#447).

The correlation builder may only cite a ``DECLARED_RULE`` edge with a
``rule_id`` declared here — free-form rule ids are never evaluated (OBS-002
preflight: "Define a small versioned CorrelationRuleSet of named rules; free
form is never evaluated"). Split out of :mod:`aptl.core.correlation.builder`
so that module stays within the repo's per-file line budget (SonarCloud
``python:S104``).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CorrelationRule:
    """One named, documented ``DECLARED_RULE`` rule."""

    rule_id: str
    description: str


RUN_PATH_BINDING = CorrelationRule(
    rule_id="run-path-binding",
    description=(
        "An orchestration workflow address (and its history events) is "
        "associated with this run only because LocalRunStore wrote/read "
        "its result.json and history.jsonl under "
        "<run_id>/orchestration/<address>/ — the workflow's own internal "
        "run_id field (WorkflowExecutionState.run_id) is a distinct, "
        "workflow-scoped identity and is never treated as the APTL run_id."
    ),
)

ADMITTED_PLAN_BINDING = CorrelationRule(
    rule_id="admitted-plan-binding",
    description=(
        "A planned trial is associated with the run admitted from it by "
        "the experiment-admission plan-to-attempt binding, not by any "
        "literal identifier field shared between the plan and the run "
        "record."
    ),
)

ORCHESTRATION_ADDRESS_GROUPING = CorrelationRule(
    rule_id="orchestration-address-grouping",
    description=(
        "A workflow history event is associated with its workflow address "
        "because LocalRunStore grouped it under that address's "
        "history.jsonl — WorkflowHistoryEvent payloads carry no address "
        "field of their own."
    ),
)

MANIFEST_SNAPSHOT_MEMBERSHIP = CorrelationRule(
    rule_id="manifest-snapshot-membership",
    description=(
        "A participant episode, action, or evaluator result is associated "
        "with the run because it was read from the RuntimeSnapshot embedded "
        "in that run's manifest.json — the record carries no run_id field of "
        "its own, so this is a declared containment rule (the same honest "
        "provenance the orchestration files get), not a shared explicit "
        "identifier on the record itself."
    ),
)


@dataclass(frozen=True)
class CorrelationRuleSet:
    """Small, versioned, closed set of named ``DECLARED_RULE`` rules.

    Never free-form: :meth:`require` raises rather than letting a caller
    (or a typo) invent a ``rule_id`` that was never declared here.
    """

    version: str = "aptl-correlation-rules/v1"
    rules: tuple[CorrelationRule, ...] = (
        RUN_PATH_BINDING,
        ADMITTED_PLAN_BINDING,
        ORCHESTRATION_ADDRESS_GROUPING,
        MANIFEST_SNAPSHOT_MEMBERSHIP,
    )

    def __post_init__(self) -> None:
        ids = [rule.rule_id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("CorrelationRuleSet rule_ids must be unique")

    def require(self, rule_id: str) -> str:
        """Return ``rule_id`` if it is declared in this rule set, else raise."""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule.rule_id
        raise ValueError(f"undeclared correlation rule: {rule_id!r}")


DEFAULT_RULE_SET = CorrelationRuleSet()
