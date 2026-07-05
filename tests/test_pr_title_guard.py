"""Tests for the repository-side PR title guard (tools/check_pr_title.py).

The guard is loaded by path because it lives under ``tools/`` (outside the
``src`` package) so the CI job can run it stdlib-only. Keeping these tests in
the suite makes the guard's policy a first-class, drift-proof contract: the
allowed type set here is asserted to match the release engine's
``allowed_tags`` in ``pyproject.toml`` (ADR 0006).
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
# The guard lives under tools/ (outside the src package) so the CI job can run
# it stdlib-only. Import it as a normal module so it is registered in
# sys.modules (dataclasses introspection needs that).
sys.path.insert(0, str(_REPO_ROOT / "tools"))

import check_pr_title  # noqa: E402

validate_pr_title = check_pr_title.validate_pr_title


@pytest.mark.parametrize(
    "title",
    [
        "feat: add pipx install path",
        "fix(env): hydrate placeholder secrets",
        "added: new curated scenario",
        "changed: bump wazuh image",
        "security: rotate lab ca",
        "ci: add pypi release automation",
        "feat!: drop legacy realization fields",
    ],
)
def test_accepts_valid_titles(title: str) -> None:
    assert validate_pr_title(title) == []


@pytest.mark.parametrize(
    "title",
    [
        "[codex] add a feature",
        "  [claude] fix a bug",
        "[OpenAI] chore: something",
    ],
)
def test_rejects_agent_branding(title: str) -> None:
    violations = validate_pr_title(title)
    assert any(v.rule_id == check_pr_title.RULE_AGENT_BRAND for v in violations)


@pytest.mark.parametrize(
    "title",
    [
        "add a thing without a type",
        "Feature: uppercase type",
        "fix/refactor: compound type",
        "wip: not an allowed type",
    ],
)
def test_rejects_non_conventional(title: str) -> None:
    violations = validate_pr_title(title)
    assert any(v.rule_id == check_pr_title.RULE_CONVENTIONAL for v in violations)


def test_rejects_uppercase_subject() -> None:
    violations = validate_pr_title("feat: Add a capitalized subject")
    assert any(v.rule_id == check_pr_title.RULE_SUBJECT_LOWERCASE for v in violations)


def test_rejects_empty() -> None:
    assert any(v.rule_id == check_pr_title.RULE_EMPTY for v in validate_pr_title(""))
    assert any(v.rule_id == check_pr_title.RULE_EMPTY for v in validate_pr_title("   "))


def test_guard_types_match_release_allowed_tags() -> None:
    """The guard's allowed types must equal PSR's allowed_tags (no drift)."""
    pyproject = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    allowed_tags = pyproject["tool"]["semantic_release"]["commit_parser_options"]["allowed_tags"]
    assert set(check_pr_title.CONVENTIONAL_TYPES) == set(allowed_tags)
