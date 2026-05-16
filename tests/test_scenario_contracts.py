"""Tests for stable-query contract guards on `aptl.core.sdl.Scenario`.

These contracts are the ADR-014 §"Contract Guards" surface: small
`icontract` preconditions/postconditions on `Scenario.get_objective`,
`Scenario.get_workflow`, and `Scenario.get_workflow_step` that make
"the returned objective/step belongs to this scenario" explicit at the
boundary. Structural and semantic validation stay in Pydantic and
`SemanticValidator` respectively — contracts are not a third schema.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import icontract
import pytest

from aptl.core.sdl.objectives import Objective, ObjectiveSuccess
from aptl.core.sdl.orchestration import Workflow, WorkflowStep
from aptl.core.sdl.scenario import Scenario


# ---------------------------------------------------------------------------
# Builders for minimal in-memory Scenarios. No filesystem / SemanticValidator
# / parser involvement — contracts are query-time guards.
# ---------------------------------------------------------------------------


def _make_objective(name: str = "o1") -> Objective:
    return Objective(
        name=name,
        agent="a1",
        success=ObjectiveSuccess(conditions=["c1"]),
    )


def _make_workflow_step(name: str = "s1") -> WorkflowStep:
    return WorkflowStep(type="objective", objective=name)


def _make_workflow(start: str = "s1") -> Workflow:
    return Workflow(start=start, steps={start: _make_workflow_step(start)})


def _make_scenario_with_objective() -> Scenario:
    return Scenario(name="t", objectives={"o1": _make_objective("o1")})


def _make_scenario_with_workflow() -> Scenario:
    return Scenario(name="t", workflows={"w1": _make_workflow("s1")})


# ---------------------------------------------------------------------------
# get_objective
# ---------------------------------------------------------------------------


class TestGetObjective:
    def test_returns_declared_objective_by_identity(self) -> None:
        s = _make_scenario_with_objective()
        assert s.get_objective("o1") is s.objectives["o1"]

    def test_unknown_objective_raises_violation(self) -> None:
        s = _make_scenario_with_objective()
        with pytest.raises(icontract.ViolationError):
            s.get_objective("missing")

    def test_empty_objectives_dict_raises_violation(self) -> None:
        s = Scenario(name="t")
        with pytest.raises(icontract.ViolationError):
            s.get_objective("o1")


# ---------------------------------------------------------------------------
# get_workflow
# ---------------------------------------------------------------------------


class TestGetWorkflow:
    def test_returns_declared_workflow_by_identity(self) -> None:
        s = _make_scenario_with_workflow()
        assert s.get_workflow("w1") is s.workflows["w1"]

    def test_unknown_workflow_raises_violation(self) -> None:
        s = _make_scenario_with_workflow()
        with pytest.raises(icontract.ViolationError):
            s.get_workflow("missing")

    def test_empty_workflows_dict_raises_violation(self) -> None:
        s = Scenario(name="t")
        with pytest.raises(icontract.ViolationError):
            s.get_workflow("w1")


# ---------------------------------------------------------------------------
# get_workflow_step
# ---------------------------------------------------------------------------


class TestGetWorkflowStep:
    def test_returns_declared_step_by_identity(self) -> None:
        s = _make_scenario_with_workflow()
        assert s.get_workflow_step("w1", "s1") is s.workflows["w1"].steps["s1"]

    def test_unknown_workflow_raises_violation(self) -> None:
        s = _make_scenario_with_workflow()
        with pytest.raises(icontract.ViolationError):
            s.get_workflow_step("missing", "s1")

    def test_unknown_step_in_known_workflow_raises_violation(self) -> None:
        s = _make_scenario_with_workflow()
        with pytest.raises(icontract.ViolationError):
            s.get_workflow_step("w1", "missing")


# ---------------------------------------------------------------------------
# Secret-safety: violation messages must not interpolate Scenario `repr()`.
# Mirrors the issue #214 / ADR-031 reasoning: the bound argument to the
# contract is a large model that may carry author free-text and (for the lab
# context) secret env values. The SDL surface does not carry secrets today,
# but the no-repr-leak invariant is what keeps it that way.
# ---------------------------------------------------------------------------


_SENTINEL_NAME = "sentinel-scenario-name-7c1b9d"
_SENTINEL_DESCRIPTION = "sentinel-scenario-description-9f3a44"


class TestViolationMessageDoesNotLeakReprState:
    """The narrow `error=` factory must produce a fixed description string,
    not `icontract`'s default bound-argument-repr rendering.

    All three accessor methods carry the same secret-safety invariant, so
    every test in this class checks that the violation message contains the
    narrow label AND that neither the `name` nor `description` sentinel
    fields leak through. Symmetry is enforced by construction (same
    builder, same assertions per variant)."""

    def _assert_message_is_narrow(
        self, msg: str, expected_label: str
    ) -> None:
        # The narrow description must be present.
        assert expected_label in msg
        # The bound Scenario's `repr()` fields must NOT leak through.
        assert _SENTINEL_NAME not in msg
        assert _SENTINEL_DESCRIPTION not in msg

    def test_description_is_narrow_label_for_objective(self) -> None:
        s = Scenario(
            name=_SENTINEL_NAME,
            description=_SENTINEL_DESCRIPTION,
            objectives={"o1": _make_objective("o1")},
        )
        with pytest.raises(icontract.ViolationError) as exc_info:
            s.get_objective("missing")
        self._assert_message_is_narrow(
            str(exc_info.value), "objective_is_declared"
        )

    def test_description_is_narrow_label_for_workflow(self) -> None:
        s = Scenario(
            name=_SENTINEL_NAME,
            description=_SENTINEL_DESCRIPTION,
            workflows={"w1": _make_workflow("s1")},
        )
        with pytest.raises(icontract.ViolationError) as exc_info:
            s.get_workflow("missing")
        self._assert_message_is_narrow(
            str(exc_info.value), "workflow_is_declared"
        )

    def test_description_is_narrow_label_for_workflow_step(self) -> None:
        s = Scenario(
            name=_SENTINEL_NAME,
            description=_SENTINEL_DESCRIPTION,
            workflows={"w1": _make_workflow("s1")},
        )
        with pytest.raises(icontract.ViolationError) as exc_info:
            s.get_workflow_step("w1", "missing")
        self._assert_message_is_narrow(
            str(exc_info.value), "workflow_step_is_declared"
        )


# ---------------------------------------------------------------------------
# Survives `python -O`. `icontract.require`'s default `enabled=__debug__`
# turns the decorator into a no-op under an optimized interpreter — the same
# bug class issue #214 / ADR-031's `_runtime_require` was built to close.
# ---------------------------------------------------------------------------


def _run_under_dash_O(script_body: str) -> subprocess.CompletedProcess:
    """Execute ``script_body`` in a fresh `python -O` subprocess.

    The subprocess does not inherit pytest's `pythonpath = ["src"]` config,
    so we force the repo's `src/` onto `PYTHONPATH` explicitly. Otherwise
    the test would pass only when `aptl` is already installed in the active
    environment and fail in a bare `python -O` shell — the very
    environment-dependence this regression test is meant to rule out.
    """
    repo_root = Path(__file__).resolve().parent.parent
    src_path = str(repo_root / "src")
    env = os.environ.copy()
    env["PYTHONPATH"] = (
        src_path + os.pathsep + env["PYTHONPATH"]
        if env.get("PYTHONPATH")
        else src_path
    )
    return subprocess.run(
        [sys.executable, "-O", "-c", script_body],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


_OBJECTIVE_SCRIPT = textwrap.dedent(
    """
    import icontract
    from aptl.core.sdl.objectives import Objective, ObjectiveSuccess
    from aptl.core.sdl.scenario import Scenario

    s = Scenario(
        name="t",
        objectives={
            "o1": Objective(
                name="o1",
                agent="a1",
                success=ObjectiveSuccess(conditions=["c1"]),
            ),
        },
    )

    try:
        s.get_objective("missing")
    except icontract.ViolationError:
        raise SystemExit(0)
    raise SystemExit(1)
    """
)


_WORKFLOW_SCRIPT = textwrap.dedent(
    """
    import icontract
    from aptl.core.sdl.orchestration import Workflow, WorkflowStep
    from aptl.core.sdl.scenario import Scenario

    s = Scenario(
        name="t",
        workflows={
            "w1": Workflow(
                start="s1",
                steps={"s1": WorkflowStep(type="objective", objective="s1")},
            ),
        },
    )

    try:
        s.get_workflow("missing")
    except icontract.ViolationError:
        raise SystemExit(0)
    raise SystemExit(1)
    """
)


_WORKFLOW_STEP_SCRIPT = textwrap.dedent(
    """
    import icontract
    from aptl.core.sdl.orchestration import Workflow, WorkflowStep
    from aptl.core.sdl.scenario import Scenario

    s = Scenario(
        name="t",
        workflows={
            "w1": Workflow(
                start="s1",
                steps={"s1": WorkflowStep(type="objective", objective="s1")},
            ),
        },
    )

    try:
        s.get_workflow_step("w1", "missing")
    except icontract.ViolationError:
        raise SystemExit(0)
    raise SystemExit(1)
    """
)


@pytest.mark.integration
class TestContractsSurviveOptimizedInterpreter:
    """Each accessor method gets its own `python -O` subprocess regression.

    A plain `icontract.require`'s default `enabled=__debug__` makes the
    decorator a no-op under an optimized interpreter — the same bug class
    issue #214 / ADR-031's `_runtime_require` was built to close. Covering
    every guarded method individually catches a per-method regression
    (e.g. one accessor accidentally rewired to plain `icontract.require`)
    that would otherwise hide behind the normal-Python contract tests.
    """

    @pytest.mark.parametrize(
        ("accessor_name", "script"),
        [
            ("get_objective", _OBJECTIVE_SCRIPT),
            ("get_workflow", _WORKFLOW_SCRIPT),
            ("get_workflow_step", _WORKFLOW_STEP_SCRIPT),
        ],
    )
    def test_violation_fires_under_dash_O(
        self, accessor_name: str, script: str
    ) -> None:
        result = _run_under_dash_O(script)
        assert result.returncode == 0, (
            f"Contract did not raise under `python -O` for "
            f"{accessor_name}. stdout={result.stdout!r} "
            f"stderr={result.stderr!r}"
        )


# ---------------------------------------------------------------------------
# Parse path is uncoupled from the contract layer.
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLoaderDoesNotInvokeQueryContracts:
    """Loading a valid SDL scenario must not trip the new accessor contracts.

    Contracts are query-time guards, not parse-time invariants — a regression
    that hooked them into the load path would couple two layers ADR-014 keeps
    separate. Marked `integration` because both tests write to `tmp_path`
    and exercise the real YAML parser + `load_scenario` pipeline, not the
    pure in-memory contract layer above.
    """

    def test_load_minimal_yaml_succeeds(self, tmp_path) -> None:
        from aptl.core.scenarios import load_scenario

        scenario_yaml = textwrap.dedent(
            """
            name: minimal
            """
        ).strip()
        path = tmp_path / "minimal.yaml"
        path.write_text(scenario_yaml)
        scenario = load_scenario(path)
        assert scenario.name == "minimal"

    def test_loaded_scenario_query_contract_fires_only_at_query_time(
        self, tmp_path
    ) -> None:
        """A scenario loaded with no objectives parses successfully; the
        contract on `get_objective` only fires when the loaded scenario is
        actually queried for one. This proves the load path is uncoupled
        from the new query-time guards."""
        from aptl.core.scenarios import load_scenario

        scenario_yaml = textwrap.dedent(
            """
            name: minimal-no-objectives
            """
        ).strip()
        path = tmp_path / "minimal-no-objectives.yaml"
        path.write_text(scenario_yaml)
        scenario = load_scenario(path)
        with pytest.raises(icontract.ViolationError):
            scenario.get_objective("missing")
