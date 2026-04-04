"""Pure workflow semantic rules shared across validation, compilation, and runtime."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

WORKFLOW_STATE_SCHEMA_VERSION = "workflow-step-state/v1"

_OBSERVABLE_OUTCOMES_BY_STEP_TYPE: dict[str, tuple[str, ...]] = {
    "objective": ("succeeded", "failed"),
    "retry": ("succeeded", "exhausted"),
    "parallel": ("succeeded", "failed"),
    "call": ("succeeded", "failed"),
}
_FIXED_ATTEMPTS_BY_STEP_TYPE: dict[str, int] = {
    "objective": 1,
    "parallel": 1,
    "call": 1,
}


@dataclass(frozen=True)
class WorkflowStepSemanticContract:
    """Portable contract for workflow-visible step state."""

    step_type: str
    state_observable: bool = False
    observable_outcomes: tuple[str, ...] = ()
    supports_attempt_counts: bool = False
    fixed_attempts: int | None = None

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, object] | None,
        *,
        default_step_type: str = "",
    ) -> "WorkflowStepSemanticContract":
        if payload is None:
            return workflow_step_semantic_contract(default_step_type)
        return cls(
            step_type=str(payload.get("step_type", default_step_type)),
            state_observable=bool(payload.get("state_observable", False)),
            observable_outcomes=tuple(
                str(outcome) for outcome in payload.get("observable_outcomes", ())
            ),
            supports_attempt_counts=bool(
                payload.get("supports_attempt_counts", False)
            ),
            fixed_attempts=(
                int(payload["fixed_attempts"])
                if payload.get("fixed_attempts") is not None
                else None
            ),
        )


def workflow_step_semantic_contract(step_type: str) -> WorkflowStepSemanticContract:
    """Return the semantic contract for a workflow step type."""

    observable_outcomes = _OBSERVABLE_OUTCOMES_BY_STEP_TYPE.get(step_type, ())
    fixed_attempts = _FIXED_ATTEMPTS_BY_STEP_TYPE.get(step_type)
    state_observable = bool(observable_outcomes)
    return WorkflowStepSemanticContract(
        step_type=step_type,
        state_observable=state_observable,
        observable_outcomes=observable_outcomes,
        supports_attempt_counts=state_observable,
        fixed_attempts=fixed_attempts,
    )


def branch_closure(
    graph: Mapping[str, Iterable[str]],
    *,
    branches: Iterable[str],
    join_step: str,
) -> frozenset[str]:
    """Return the owning parallel's branch closure up to, but excluding, the join."""

    closure: set[str] = set()
    stack = list(branches)
    while stack:
        node = stack.pop()
        if node == join_step or node in closure:
            continue
        closure.add(node)
        for successor in graph.get(node, ()):
            if successor != join_step:
                stack.append(successor)
    return frozenset(closure)


def validate_workflow_step_result(
    contract: WorkflowStepSemanticContract,
    *,
    lifecycle: str,
    outcome: str | None,
    attempts: int,
) -> tuple[str, ...]:
    """Return semantic violations for a workflow step execution state."""

    errors: list[str] = []
    if attempts < 0:
        errors.append("attempts must be >= 0")

    if lifecycle not in {"pending", "running", "completed"}:
        errors.append(f"lifecycle '{lifecycle}' is invalid")
        return tuple(errors)

    if lifecycle != "completed" and outcome is not None:
        errors.append("non-completed steps may not report an outcome")

    if lifecycle == "pending" and attempts != 0:
        errors.append("pending steps must report 0 attempts")

    if lifecycle == "running" and contract.state_observable and attempts < 1:
        errors.append("running observable steps must report at least 1 attempt")

    if lifecycle == "completed" and contract.state_observable:
        if outcome is None:
            errors.append("completed observable steps must report an outcome")
        elif outcome not in contract.observable_outcomes:
            allowed = ", ".join(contract.observable_outcomes)
            errors.append(
                f"outcome '{outcome}' is invalid for step type "
                f"'{contract.step_type}' (allowed: {allowed})"
            )

    if lifecycle == "completed" and contract.fixed_attempts is not None:
        if attempts != contract.fixed_attempts:
            errors.append(
                f"completed '{contract.step_type}' steps must report exactly "
                f"{contract.fixed_attempts} attempts"
            )
    elif contract.fixed_attempts is not None and attempts > contract.fixed_attempts:
        errors.append(
            f"'{contract.step_type}' steps may not exceed {contract.fixed_attempts} "
            "attempts"
        )

    return tuple(errors)
