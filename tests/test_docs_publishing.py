"""Contracts for issue #1114 documentation publishing and badge evidence."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]


def _yaml(relative_path: str) -> dict[str, object]:
    return yaml.safe_load((ROOT / relative_path).read_text(encoding="utf-8"))


def test_read_the_docs_reuses_the_strict_canonical_mkdocs_build() -> None:
    config = _yaml(".readthedocs.yaml")

    assert config["version"] == 2
    assert config["mkdocs"] == {
        "configuration": "mkdocs.yml",
        "fail_on_warning": True,
    }
    assert config["python"]["install"] == [
        {"requirements": "requirements/docs.txt"}
    ]

    jobs = config["build"]["jobs"]
    assert any("--unshallow" in command for command in jobs["post_checkout"])
    assert jobs["post_install"] == [
        "pip install -e . --no-deps --no-build-isolation"
    ]


def test_both_publishers_require_full_history_and_one_source_tree() -> None:
    pages = _yaml(".github/workflows/docs-deploy.yml")
    checkout = pages["jobs"]["build"]["steps"][0]
    assert checkout["with"]["fetch-depth"] == 0

    read_the_docs = _yaml(".readthedocs.yaml")
    assert read_the_docs["mkdocs"]["configuration"] == "mkdocs.yml"
    assert "requirements/docs.txt" in json.dumps(read_the_docs)


def test_badge_proposals_link_to_real_public_evidence() -> None:
    proposals = json.loads(
        (ROOT / ".bestpractices.json").read_text(encoding="utf-8")
    )

    required = {
        "description_good_justification": "https://brad-edwards.github.io/aptl/",
        "contribution_justification": (
            "https://github.com/Brad-Edwards/aptl/blob/main/CONTRIBUTING.md"
        ),
        "documentation_basics_justification": (
            "https://brad-edwards.github.io/aptl/getting-started/"
        ),
        "documentation_interface_justification": (
            "https://brad-edwards.github.io/aptl/reference/cli/"
        ),
        "report_process_justification": (
            "https://github.com/Brad-Edwards/aptl/blob/main/SUPPORT.md"
        ),
    }
    assert {key: proposals.get(key) for key in required} == required

    for key in required:
        assert proposals[key].startswith("https://")
