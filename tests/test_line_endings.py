"""Line-ending policy tests for cross-platform lab artifacts."""

from pathlib import Path


def test_gitattributes_locks_lab_artifacts_to_lf():
    attrs = Path(".gitattributes").read_text(encoding="utf-8")

    required_rules = {
        "docker-compose*.yml text eol=lf",
        "config/**/*.yml text eol=lf",
        "config/**/*.xml text eol=lf",
        "containers/**/*.sh text eol=lf",
        "containers/**/*.ps1 text eol=lf",
        "scripts/**/*.sh text eol=lf",
        ".aptl/config/** text eol=lf",
        ".aptl/realization/** text eol=lf",
    }

    missing = sorted(rule for rule in required_rules if rule not in attrs)
    assert missing == []
