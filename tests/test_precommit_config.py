"""Regression checks for contributor-facing pre-commit behavior."""

from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_vale_bootstrap_runs_serially() -> None:
    """A fresh Vale install must not race across pre-commit file batches."""
    config = yaml.safe_load(
        (PROJECT_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    )
    hooks = {
        hook["id"]: hook
        for repo in config["repos"]
        for hook in repo["hooks"]
    }

    assert hooks["vale-prose-lint"].get("require_serial") is True
