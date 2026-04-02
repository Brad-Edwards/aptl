"""Pure objective/window semantic helpers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class ParsedWorkflowStepRef:
    """Parsed ``<workflow>.<step>`` reference."""

    raw: str
    workflow_name: str
    step_name: str


@dataclass(frozen=True)
class ObjectiveWindowStepIssue:
    """A normalized objective-window step validation problem."""

    code: str
    step_ref: str
    workflow_name: str | None = None
    step_name: str | None = None


@dataclass(frozen=True)
class ObjectiveWindowStepAnalysis:
    """Result of validating objective window step references."""

    valid_refs: tuple[str, ...] = ()
    referenced_workflows: tuple[str, ...] = ()
    issues: tuple[ObjectiveWindowStepIssue, ...] = ()


def parse_workflow_step_ref(step_ref: str) -> ParsedWorkflowStepRef | None:
    """Parse ``<workflow>.<step>`` syntax used by objective windows."""

    if "." not in step_ref:
        return None
    workflow_name, step_name = step_ref.split(".", 1)
    if not workflow_name or not step_name:
        return None
    return ParsedWorkflowStepRef(
        raw=step_ref,
        workflow_name=workflow_name,
        step_name=step_name,
    )


def analyze_objective_window_step_refs(
    *,
    step_refs: list[str],
    workflows_by_name: Mapping[str, object],
    referenced_workflows: set[str] | None,
) -> ObjectiveWindowStepAnalysis:
    """Validate `<workflow>.<step>` refs against available workflows/steps."""

    valid_refs: list[str] = []
    referenced_workflow_names: list[str] = []
    issues: list[ObjectiveWindowStepIssue] = []

    for step_ref in dict.fromkeys(step_refs):
        parsed = parse_workflow_step_ref(step_ref)
        if parsed is None:
            issues.append(
                ObjectiveWindowStepIssue(
                    code="invalid-format",
                    step_ref=step_ref,
                )
            )
            continue
        workflow = workflows_by_name.get(parsed.workflow_name)
        if workflow is None:
            issues.append(
                ObjectiveWindowStepIssue(
                    code="workflow-unbound",
                    step_ref=step_ref,
                    workflow_name=parsed.workflow_name,
                    step_name=parsed.step_name,
                )
            )
            continue
        if referenced_workflows and parsed.workflow_name not in referenced_workflows:
            issues.append(
                ObjectiveWindowStepIssue(
                    code="workflow-outside-window",
                    step_ref=step_ref,
                    workflow_name=parsed.workflow_name,
                    step_name=parsed.step_name,
                )
            )
        workflow_steps = getattr(workflow, "steps", {})
        if parsed.step_name not in workflow_steps:
            issues.append(
                ObjectiveWindowStepIssue(
                    code="step-unbound",
                    step_ref=step_ref,
                    workflow_name=parsed.workflow_name,
                    step_name=parsed.step_name,
                )
            )
            continue
        valid_refs.append(step_ref)
        referenced_workflow_names.append(parsed.workflow_name)

    return ObjectiveWindowStepAnalysis(
        valid_refs=tuple(valid_refs),
        referenced_workflows=tuple(dict.fromkeys(referenced_workflow_names)),
        issues=tuple(issues),
    )
