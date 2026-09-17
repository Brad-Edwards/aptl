"""Regression checks for contributor-facing pre-commit behavior."""

import re
from pathlib import Path

import pytest
import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent

# The commit path is fast hygiene, secrets, supply-chain export freshness, the
# complexity gates and prose lint. Test suites run in CI
# (`.github/workflows/checks.yml`), so committing does not pay for them twice.
_TEST_SUITE_HOOKS = frozenset(
    {
        "pytest",
        "vitest-mcp-common",
        "vitest-mcp-red",
        "vitest-web",
        "raes-scenario-gate",
    }
)
_REQUIRED_HOOKS = frozenset(
    {
        "trailing-whitespace",
        "end-of-file-fixer",
        "check-yaml",
        "check-json",
        "check-added-large-files",
        "check-merge-conflict",
        # Secrets stay on the commit path: a committed key is not something CI
        # can take back.
        "detect-private-key",
        # Hash-pinned requirement exports must not drift from uv.lock.
        "uv-lock",
        "uv-export",
    }
)


def _hooks() -> dict[str, dict]:
    config = yaml.safe_load(
        (PROJECT_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    )
    return {hook["id"]: hook for repo in config["repos"] for hook in repo["hooks"]}


def test_vale_bootstrap_runs_serially() -> None:
    """A fresh Vale install must not race across pre-commit file batches."""
    assert _hooks()["vale-prose-lint"].get("require_serial") is True


def test_commit_path_keeps_hygiene_and_secret_checks() -> None:
    missing = _REQUIRED_HOOKS - set(_hooks())
    assert not missing, f"commit-path hooks are missing: {sorted(missing)}"


def test_commit_path_runs_no_test_suite() -> None:
    """Test suites belong to CI, not to every commit."""
    present = _TEST_SUITE_HOOKS & set(_hooks())
    assert not present, f"test suites back on the commit path: {sorted(present)}"


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
