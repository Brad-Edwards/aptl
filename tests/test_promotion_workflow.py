"""The `dev` -> `main` promotion path stays standardized and gated (issue #852).

Two halves of one contract:

* `make devmain` opens the preferred promotion PR with a conventional title.
* `pr-title-lint.yml` runs on `main` and recognizes only the exact branch-pair
  fallback pinned in `test_pr_title_guard.py`.
* the substantive checks workflow continues to run for promotions.

They are tested together because each is what justifies the other. The workflow
previously exempted `main` on the stated grounds that a promotion would carry a
non-conventional title. The Make target avoids that failure by construction,
while the event-aware fallback covers other creation paths without exempting
ordinary PRs. The target's title is asserted against the *real* validator rather
than against a copy of its regex.

Note what this does NOT claim: a workflow trigger makes the check run, not merge.
Whether `PR title lint` blocks a merge is live branch-protection configuration,
which no test in this repository can observe.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "pr-title-lint.yml"
CHECKS_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "checks.yml"
MAKEFILE = REPO_ROOT / "Makefile"

# Reuse the repository's single title validator rather than reimplementing its
# policy here - two copies of a regex is exactly the drift this guards against.
sys.path.insert(0, str(REPO_ROOT / "tools"))

import check_pr_title  # noqa: E402


@pytest.fixture(scope="module")
def makefile_text() -> str:
    assert MAKEFILE.is_file(), "Makefile is missing"
    return MAKEFILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def devmain_recipe(makefile_text: str) -> str:
    """The body of the `devmain` target, with line continuations joined."""
    match = re.search(r"^devmain:.*?\n((?:\t.*\n|\n)*)", makefile_text, re.MULTILINE)
    assert match, "Makefile defines no `devmain` target"
    return re.sub(r"\\\n\s*", " ", match.group(0))


def test_devmain_is_declared_phony(makefile_text: str) -> None:
    """Without .PHONY, a file named `devmain` would silently disable the target."""
    phony = re.findall(r"^\.PHONY:(.*(?:\\\n.*)*)", makefile_text, re.MULTILINE)
    assert phony, "Makefile declares no .PHONY"
    declared = re.sub(r"\\\n", " ", " ".join(phony)).split()
    assert "devmain" in declared


def test_devmain_promotes_dev_into_main_explicitly(devmain_recipe: str) -> None:
    """Explicit --base/--head; never infer the head from the current checkout."""
    assert "gh pr create" in devmain_recipe
    assert "--base main" in devmain_recipe
    assert "--head dev" in devmain_recipe


def test_devmain_title_satisfies_the_repository_title_guard(devmain_recipe: str) -> None:
    """The whole point: the promotion title complies, so `main` needs no exemption."""
    title_match = re.search(r'--title\s+"([^"]+)"', devmain_recipe)
    assert title_match, "devmain does not pass an explicit --title"
    title = title_match.group(1)

    violations = check_pr_title.validate_pr_title(title)
    assert violations == [], (
        f"devmain's title {title!r} is rejected by tools/check_pr_title.py: "
        f"{[v.render() for v in violations]}"
    )


def test_devmain_title_does_not_trigger_a_release(devmain_recipe: str) -> None:
    """A promotion must not itself compute a version bump.

    Release Please bumps on `feat` (minor) and `fix`/`perf` (patch). The
    promotion carries the underlying feature commits; its own title must be a
    no-release type or it would double-count.
    """
    title = re.search(r'--title\s+"([^"]+)"', devmain_recipe).group(1)
    release_type = re.match(r"^(feat|fix|perf)(\(|!|:)", title)
    assert release_type is None, (
        f"devmain's title {title!r} uses a release-triggering type; promotion "
        "should be a no-release type such as `chore`"
    )


def test_devmain_warns_against_squashing(devmain_recipe: str) -> None:
    """The load-bearing part.

    Release Please reads the Conventional Commit subjects on `main`. Squashing a
    promotion collapses the whole batch into one subject, losing the release's
    changelog entries. The PR body is where a human sees that warning.
    """
    body = re.search(r'--body\s+"(.*?)"\s*$', devmain_recipe, re.DOTALL)
    assert body, "devmain passes no --body"
    text = body.group(1).lower()
    assert "merge commit" in text
    assert "squash" in text


def test_pr_title_lint_gates_main_as_well_as_dev() -> None:
    """The carve-out this issue closes; this is what stops it coming back."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    # `on:` parses to Python True under YAML 1.1.
    branches = workflow[True]["pull_request"]["branches"]
    assert set(branches) == {"main", "dev"}, (
        f"pr-title-lint must gate both branches, got {branches}. Exempting `main` "
        "leaves promotion PRs with no title validation at all."
    )


def test_pr_title_lint_reads_the_title_without_shell_interpolation() -> None:
    """The PR title is untrusted event data; keep it out of the shell.

    Both assertions read parsed structure, not raw text: the workflow's own
    header comment names `pull_request_target` to say it deliberately avoids it,
    so a substring scan would fail on prose that proves the opposite point.
    """
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    triggers = workflow[True]
    assert "pull_request_target" not in triggers, (
        "pull_request_target would run with write scope against fork head code"
    )
    assert "pull_request" in triggers

    run_steps = " ".join(
        step.get("run", "") for job in workflow["jobs"].values() for step in job["steps"]
    )
    assert "github.event.pull_request.title" not in run_steps, (
        "the title must reach the checker via $GITHUB_EVENT_PATH, never a "
        "workflow expression interpolated into a shell command"
    )


def test_substantive_checks_stay_enabled_for_promotions() -> None:
    """Promotion title handling must not bypass the repository's real gates."""
    workflow = yaml.safe_load(CHECKS_WORKFLOW.read_text(encoding="utf-8"))
    branches = workflow[True]["pull_request"]["branches"]
    assert set(branches) == {"main", "dev"}

    expected_jobs = {
        "pre-commit",
        "docs",
        "python-tests",
        "python-cross-platform",
        "mcp-tests",
        "web-tests",
        "dependency-audit",
        "trivy-fs",
        "trivy-iac",
        "trivy-image",
        "osv-scanner",
        "sonarcloud",
    }
    assert expected_jobs <= set(workflow["jobs"])
