"""Shared objective/window semantic tests."""

from __future__ import annotations

from types import SimpleNamespace

from hypothesis import given
from hypothesis import strategies as st

from aptl.core.semantics.objectives import (
    ObjectiveWindowReferenceKind,
    analyze_objective_window,
)


def _workflow(*step_names: str) -> SimpleNamespace:
    return SimpleNamespace(steps={name: object() for name in step_names})


class TestObjectiveWindowSemantics:
    def test_window_analysis_normalizes_references_and_reachability(self):
        analysis = analyze_objective_window(
            story_refs=["exercise"],
            script_refs=["timeline"],
            event_refs=["kickoff"],
            workflow_refs=["flow"],
            step_refs=["flow.branch"],
            stories_by_name={
                "exercise": SimpleNamespace(scripts=["timeline"]),
            },
            scripts_by_name={
                "timeline": SimpleNamespace(events={"kickoff": 10}),
            },
            events_by_name={"kickoff": SimpleNamespace()},
            workflows_by_name={"flow": _workflow("start", "branch", "end")},
        )

        assert not analysis.issues
        assert analysis.story_names == ("exercise",)
        assert analysis.script_names == ("timeline",)
        assert analysis.event_names == ("kickoff",)
        assert analysis.workflow_names == ("flow",)
        assert analysis.workflow_step_refs == ("flow.branch",)
        assert analysis.reachable_script_names == ("timeline",)
        assert analysis.reachable_event_names == ("kickoff",)
        assert analysis.refresh_workflow_names == ("flow",)
        assert [ref.reference_kind for ref in analysis.references] == [
            ObjectiveWindowReferenceKind.STORY,
            ObjectiveWindowReferenceKind.SCRIPT,
            ObjectiveWindowReferenceKind.EVENT,
            ObjectiveWindowReferenceKind.WORKFLOW,
            ObjectiveWindowReferenceKind.WORKFLOW_STEP,
        ]

    def test_window_analysis_reports_fail_closed_issues(self):
        analysis = analyze_objective_window(
            story_refs=["missing-story"],
            script_refs=["side"],
            event_refs=["cleanup"],
            workflow_refs=["flow"],
            step_refs=["bad", "other.done", "flow.missing"],
            stories_by_name={},
            scripts_by_name={
                "side": SimpleNamespace(events={"kickoff": 10}),
            },
            events_by_name={"cleanup": SimpleNamespace()},
            workflows_by_name={
                "flow": _workflow("start"),
                "other": _workflow("done"),
            },
        )

        assert {
            issue.code
            for issue in analysis.issues
        } == {
            "story-unbound",
            "event-outside-window-scripts",
            "step-invalid-format",
            "step-workflow-outside-window",
            "step-unbound",
        }

    @given(st.lists(st.sampled_from(["flow.start", "flow.branch"]), max_size=12))
    def test_workflow_step_normalization_is_stable(self, step_refs: list[str]):
        analysis = analyze_objective_window(
            story_refs=[],
            script_refs=[],
            event_refs=[],
            workflow_refs=["flow"],
            step_refs=step_refs,
            stories_by_name={},
            scripts_by_name={},
            events_by_name={},
            workflows_by_name={"flow": _workflow("start", "branch")},
        )

        assert analysis.workflow_step_refs == tuple(dict.fromkeys(step_refs))
