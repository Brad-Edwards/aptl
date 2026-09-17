"""Keep local commits fast while retaining substantive CI checks."""

from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _hooks(path: str) -> dict:
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
