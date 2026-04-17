"""Pure objective/window semantic helpers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum


class ObjectiveWindowReferenceKind(str, Enum):
    """Normalized objective-window reference kinds."""

    STORY = "story"
    SCRIPT = "script"
    EVENT = "event"
    WORKFLOW = "workflow"
    WORKFLOW_STEP = "workflow_step"


class ObjectiveDependencyRole(str, Enum):
    """Semantic dependency roles derived from objective/window references."""

    REFRESH = "refresh"


@dataclass(frozen=True)
class ParsedWorkflowStepRef:
    """Parsed ``<workflow>.<step>`` reference."""

    raw: str
    workflow_name: str
    step_name: str


@dataclass(frozen=True)
class ObjectiveWindowReference:
    """A normalized objective/window reference ready for later namespacing."""

    raw: str
    canonical_name: str
    reference_kind: ObjectiveWindowReferenceKind
    dependency_roles: tuple[ObjectiveDependencyRole, ...] = (
        ObjectiveDependencyRole.REFRESH,
    )
    workflow_name: str | None = None
    step_name: str | None = None
    namespace_path: tuple[str, ...] = ()


@dataclass(frozen=True)
class ObjectiveWindowIssue:
    """A normalized objective-window validation problem."""

    code: str
    ref: str
    reference_kind: ObjectiveWindowReferenceKind | None = None
    workflow_name: str | None = None
    step_name: str | None = None
    related_name: str | None = None


@dataclass(frozen=True)
class ObjectiveWindowAnalysis:
    """Result of validating objective window references."""

    references: tuple[ObjectiveWindowReference, ...] = ()
    issues: tuple[ObjectiveWindowIssue, ...] = ()
    reachable_script_names: tuple[str, ...] = ()
    reachable_event_names: tuple[str, ...] = ()
    refresh_workflow_names: tuple[str, ...] = ()

    def references_of_kind(
        self,
        kind: ObjectiveWindowReferenceKind,
    ) -> tuple[ObjectiveWindowReference, ...]:
        return tuple(ref for ref in self.references if ref.reference_kind == kind)

    @property
    def story_names(self) -> tuple[str, ...]:
        return tuple(ref.canonical_name for ref in self.references_of_kind(ObjectiveWindowReferenceKind.STORY))

    @property
    def script_names(self) -> tuple[str, ...]:
        return tuple(ref.canonical_name for ref in self.references_of_kind(ObjectiveWindowReferenceKind.SCRIPT))

    @property
    def event_names(self) -> tuple[str, ...]:
        return tuple(ref.canonical_name for ref in self.references_of_kind(ObjectiveWindowReferenceKind.EVENT))

    @property
    def workflow_names(self) -> tuple[str, ...]:
        return tuple(ref.canonical_name for ref in self.references_of_kind(ObjectiveWindowReferenceKind.WORKFLOW))

    @property
    def workflow_step_refs(self) -> tuple[str, ...]:
        return tuple(ref.raw for ref in self.references_of_kind(ObjectiveWindowReferenceKind.WORKFLOW_STEP))


def _ordered_unique(items: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))


def parse_workflow_step_ref(step_ref: str) -> ParsedWorkflowStepRef | None:
    """Parse ``<workflow>.<step>`` syntax used by objective windows."""

    if "." not in step_ref:
        return None
    workflow_name, step_name = step_ref.rsplit(".", 1)
    if not workflow_name or not step_name:
        return None
    return ParsedWorkflowStepRef(
        raw=step_ref,
        workflow_name=workflow_name,
        step_name=step_name,
    )


def analyze_objective_window(
    *,
    story_refs: list[str],
    script_refs: list[str],
    event_refs: list[str],
    workflow_refs: list[str],
    step_refs: list[str],
    stories_by_name: Mapping[str, object],
    scripts_by_name: Mapping[str, object],
    events_by_name: Mapping[str, object],
    workflows_by_name: Mapping[str, object],
) -> ObjectiveWindowAnalysis:
    """Resolve objective window references and derive shared semantics."""

    references: list[ObjectiveWindowReference] = []
    issues: list[ObjectiveWindowIssue] = []

    referenced_stories: list[str] = []
    reachable_scripts: list[str] = []

    for story_name in dict.fromkeys(story_refs):
        story = stories_by_name.get(story_name)
        if story is None:
            issues.append(
                ObjectiveWindowIssue(
                    code="story-unbound",
                    ref=story_name,
                    reference_kind=ObjectiveWindowReferenceKind.STORY,
                )
            )
            continue
        references.append(
            ObjectiveWindowReference(
                raw=story_name,
                canonical_name=story_name,
                reference_kind=ObjectiveWindowReferenceKind.STORY,
            )
        )
        referenced_stories.append(story_name)
        reachable_scripts.extend(getattr(story, "scripts", []))

    reachable_scripts = list(_ordered_unique(reachable_scripts))

    referenced_scripts: list[str] = []
    explicit_or_reachable_scripts = reachable_scripts
    for script_name in dict.fromkeys(script_refs):
        script = scripts_by_name.get(script_name)
        if script is None:
            issues.append(
                ObjectiveWindowIssue(
                    code="script-unbound",
                    ref=script_name,
                    reference_kind=ObjectiveWindowReferenceKind.SCRIPT,
                )
            )
            continue
        if reachable_scripts and script_name not in reachable_scripts:
            issues.append(
                ObjectiveWindowIssue(
                    code="script-outside-window-stories",
                    ref=script_name,
                    reference_kind=ObjectiveWindowReferenceKind.SCRIPT,
                )
            )
        references.append(
            ObjectiveWindowReference(
                raw=script_name,
                canonical_name=script_name,
                reference_kind=ObjectiveWindowReferenceKind.SCRIPT,
            )
        )
        referenced_scripts.append(script_name)

    if referenced_scripts:
        explicit_or_reachable_scripts = list(_ordered_unique(referenced_scripts))

    reachable_events: list[str] = []
    for script_name in explicit_or_reachable_scripts:
        script = scripts_by_name.get(script_name)
        if script is None:
            continue
        reachable_events.extend(getattr(script, "events", {}).keys())
    reachable_events = list(_ordered_unique(reachable_events))

    for event_name in dict.fromkeys(event_refs):
        event = events_by_name.get(event_name)
        if event is None:
            issues.append(
                ObjectiveWindowIssue(
                    code="event-unbound",
                    ref=event_name,
                    reference_kind=ObjectiveWindowReferenceKind.EVENT,
                )
            )
            continue
        if reachable_events and event_name not in reachable_events:
            issues.append(
                ObjectiveWindowIssue(
                    code="event-outside-window-scripts",
                    ref=event_name,
                    reference_kind=ObjectiveWindowReferenceKind.EVENT,
                )
            )
        references.append(
            ObjectiveWindowReference(
                raw=event_name,
                canonical_name=event_name,
                reference_kind=ObjectiveWindowReferenceKind.EVENT,
            )
        )

    referenced_workflows: list[str] = []
    valid_workflows: set[str] = set()
    for workflow_name in dict.fromkeys(workflow_refs):
        workflow = workflows_by_name.get(workflow_name)
        if workflow is None:
            issues.append(
                ObjectiveWindowIssue(
                    code="workflow-unbound",
                    ref=workflow_name,
                    reference_kind=ObjectiveWindowReferenceKind.WORKFLOW,
                    workflow_name=workflow_name,
                )
            )
            continue
        references.append(
            ObjectiveWindowReference(
                raw=workflow_name,
                canonical_name=workflow_name,
                reference_kind=ObjectiveWindowReferenceKind.WORKFLOW,
                workflow_name=workflow_name,
            )
        )
        referenced_workflows.append(workflow_name)
        valid_workflows.add(workflow_name)

    if step_refs and not workflow_refs:
        issues.append(
            ObjectiveWindowIssue(
                code="step-requires-workflow-window",
                ref="steps",
                reference_kind=ObjectiveWindowReferenceKind.WORKFLOW_STEP,
            )
        )

    refresh_workflows = list(referenced_workflows)
    for step_ref in dict.fromkeys(step_refs):
        parsed = parse_workflow_step_ref(step_ref)
        if parsed is None:
            issues.append(
                ObjectiveWindowIssue(
                    code="step-invalid-format",
                    ref=step_ref,
                    reference_kind=ObjectiveWindowReferenceKind.WORKFLOW_STEP,
                )
            )
            continue

        workflow = workflows_by_name.get(parsed.workflow_name)
        if workflow is None:
            issues.append(
                ObjectiveWindowIssue(
                    code="step-workflow-unbound",
                    ref=step_ref,
                    reference_kind=ObjectiveWindowReferenceKind.WORKFLOW_STEP,
                    workflow_name=parsed.workflow_name,
                    step_name=parsed.step_name,
                )
            )
            continue

        if valid_workflows and parsed.workflow_name not in valid_workflows:
            issues.append(
                ObjectiveWindowIssue(
                    code="step-workflow-outside-window",
                    ref=step_ref,
                    reference_kind=ObjectiveWindowReferenceKind.WORKFLOW_STEP,
                    workflow_name=parsed.workflow_name,
                    step_name=parsed.step_name,
                )
            )

        workflow_steps = getattr(workflow, "steps", {})
        if parsed.step_name not in workflow_steps:
            issues.append(
                ObjectiveWindowIssue(
                    code="step-unbound",
                    ref=step_ref,
                    reference_kind=ObjectiveWindowReferenceKind.WORKFLOW_STEP,
                    workflow_name=parsed.workflow_name,
                    step_name=parsed.step_name,
                )
            )
            continue

        references.append(
            ObjectiveWindowReference(
                raw=step_ref,
                canonical_name=step_ref,
                reference_kind=ObjectiveWindowReferenceKind.WORKFLOW_STEP,
                workflow_name=parsed.workflow_name,
                step_name=parsed.step_name,
            )
        )
        refresh_workflows.append(parsed.workflow_name)

    return ObjectiveWindowAnalysis(
        references=tuple(references),
        issues=tuple(issues),
        reachable_script_names=_ordered_unique(reachable_scripts),
        reachable_event_names=_ordered_unique(reachable_events),
        refresh_workflow_names=_ordered_unique(refresh_workflows),
    )


def analyze_objective_window_step_refs(
    *,
    step_refs: list[str],
    workflows_by_name: Mapping[str, object],
    referenced_workflows: set[str] | None,
) -> ObjectiveWindowAnalysis:
    """Backwards-compatible wrapper for the window-step-only subset."""

    workflow_refs = sorted(referenced_workflows) if referenced_workflows else []
    return analyze_objective_window(
        story_refs=[],
        script_refs=[],
        event_refs=[],
        workflow_refs=workflow_refs,
        step_refs=step_refs,
        stories_by_name={},
        scripts_by_name={},
        events_by_name={},
        workflows_by_name=workflows_by_name,
    )
