"""Keep local commits fast while retaining substantive CI checks."""

import re
from pathlib import Path

import pytest

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _hooks(path: str = ".pre-commit-config.yaml") -> dict:
    config = yaml.safe_load((PROJECT_ROOT / path).read_text(encoding="utf-8"))
    return {hook["id"]: hook for repo in config["repos"] for hook in repo["hooks"]}


def test_local_commit_runs_only_secrets_and_fast_hygiene() -> None:
    hooks = _hooks(".pre-commit-config.yaml")
    assert set(hooks) == {
        "trailing-whitespace",
        "end-of-file-fixer",
        "check-yaml",
        "check-json",
        "check-added-large-files",
        "check-merge-conflict",
        "detect-private-key",
    }
    assert all(hook.get("pass_filenames", True) for hook in hooks.values())


def test_ci_retains_dependency_and_complexity_checks() -> None:
    hooks = _hooks(".pre-commit-ci.yaml")
    assert {"uv-lock", "uv-export", "ruff-complexity", "ts-complexity"} <= hooks.keys()
    workflow = yaml.safe_load(
        (PROJECT_ROOT / ".github/workflows/checks.yml").read_text()
    )
    jobs = workflow["jobs"]
    assert {"python-tests", "mcp-tests", "web-tests", "docs"} <= jobs.keys()
    commands = [step.get("run", "") for step in jobs["pre-commit"]["steps"]]
    assert any(
        "--config .pre-commit-ci.yaml --all-files" in command for command in commands
    )
    assert not any(
        "SKIP" in step.get("env", {}) for step in jobs["pre-commit"]["steps"]
    )


_REQUIRED_HOOKS = frozenset(
    {
        "trailing-whitespace",
        "end-of-file-fixer",
        "check-yaml",
        "check-json",
        "check-added-large-files",
        "check-merge-conflict",
        "detect-private-key",
    }
)

# Ordinary source files the safety hooks must never exclude. A hook can keep its
# id while a blanket `exclude` or a `stages` restriction takes it off the commit
# path, so presence alone is not assurance.
_ORDINARY_PATHS = (
    "src/aptl/core/lab.py",
    "containers/generic-samba-ad-base/provision-domain.sh",
    "config/wazuh_cluster/wazuh_manager.conf",
    "docker-compose.yml",
    ".env.example",
)


@pytest.mark.parametrize("hook_id", sorted(_REQUIRED_HOOKS))
def test_required_hook_runs_on_the_commit_stage(hook_id: str) -> None:
    """A required hook must fire on an ordinary commit, not only on demand."""
    hook = _hooks()[hook_id]
    stages = hook.get("stages")
    assert stages is None or {"pre-commit", "commit"} & set(stages), (
        f"{hook_id} is restricted to stages {stages} and never runs on commit"
    )
    assert hook.get("always_run") is not False or hook.get("files"), (
        f"{hook_id} is disabled for ordinary changes"
    )


@pytest.mark.parametrize(
    "hook_id",
    ["detect-private-key", "check-added-large-files", "check-merge-conflict"],
)
def test_safety_hook_is_not_excluded_from_ordinary_sources(hook_id: str) -> None:
    """Secret and hygiene gates may carve out fixtures, never real sources."""
    exclude = _hooks()[hook_id].get("exclude")
    if exclude is None:
        return
    pattern = re.compile(exclude)
    excluded = [path for path in _ORDINARY_PATHS if pattern.search(path)]
    assert not excluded, f"{hook_id} exclude covers ordinary sources: {excluded}"


def test_private_key_exclusions_are_only_the_known_fixtures() -> None:
    """detect-private-key may skip test fixtures and the redaction code only."""
    pattern = re.compile(_hooks()["detect-private-key"]["exclude"])
    assert pattern.search("tests/fixtures/key.pem")
    assert pattern.search("src/aptl/utils/redaction.py")
    assert not pattern.search("src/aptl/utils/other.py")
    assert not pattern.search("keys/aptl_lab_key")


def test_large_file_gate_keeps_its_size_limit() -> None:
    """The size limit is the gate; removing the arg would silently loosen it."""
    assert "--maxkb=500" in _hooks()["check-added-large-files"].get("args", [])
