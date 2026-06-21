"""Tests for tools.sonar.assert_no_new_issues."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "assert_no_new_issues",
    _REPO_ROOT / "tools/sonar/assert_no_new_issues.py",
)
assert _SPEC and _SPEC.loader
gate = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = gate
_SPEC.loader.exec_module(gate)


def test_resolve_scope_from_pull_request_arg() -> None:
    scope = gate.resolve_scope(gate.parse_args(["--project-key", "proj", "--pull-request", "42"]))
    assert scope.query_key == "pullRequest"
    assert scope.query_value == "42"
    assert scope.label == "PR 42"


def test_resolve_scope_from_branch_arg() -> None:
    scope = gate.resolve_scope(gate.parse_args(["--project-key", "proj", "--branch", "dev"]))
    assert scope.query_key == "branch"
    assert scope.query_value == "dev"


def test_resolve_scope_from_github_event(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({"pull_request": {"number": 99}}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    scope = gate.resolve_scope(gate.parse_args(["--project-key", "proj"]))
    assert scope.query_key == "pullRequest"
    assert scope.query_value == "99"


def test_render_issue_includes_rule_and_location() -> None:
    rendered = gate.render_issue(
        {
            "severity": "MAJOR",
            "type": "CODE_SMELL",
            "rule": "python:S1234",
            "component": "src/aptl/core/lab.py",
            "line": 10,
            "message": "example",
        }
    )
    assert "MAJOR" in rendered
    assert "python:S1234" in rendered
    assert "src/aptl/core/lab.py:10" in rendered
    assert "example" in rendered
