"""Publisher contract for the OpenSSF Scorecard workflow (issue #847).

``ossf/scorecard-action`` with ``publish_results: true`` signs its result with a
GitHub OIDC token and publishes it to ``api.scorecard.dev``, which is what backs
the README badge. That capability makes the job's shape security-relevant in a
way an ordinary CI job is not:

* ``id-token: write`` mints an OIDC token that speaks for this repository. If it
  were granted at workflow scope, every job in the file would hold it.
* ``security-events: write`` can write to the Code Scanning alert queue.
* A checkout that persists credentials leaves a usable token in ``.git/config``
  for any later step in the same job.

The preflight note (``docs/architecture/issue-847-openssf-scorecard-preflight.md``)
fixes those guardrails. This test pins them so a future edit cannot quietly widen
the token boundary, add an untrusted trigger, or unpin an action, all of which
would still "work" in CI while handing the publishing job more authority than it
needs.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "scorecard.yml"

# A full 40-character git commit SHA. Tags and branch names are mutable refs, so
# a pin that is not a SHA is not a pin.
_SHA_PIN = re.compile(r"^[^@]+@[0-9a-f]{40}$")

# Triggers that would run the publishing job against code the repository does
# not control, or off the default branch. `pull_request_target` is the classic
# privilege-escalation trigger: it runs with repository write scope while
# checking out a fork's head.
_FORBIDDEN_TRIGGERS = {"pull_request_target", "pull_request", "workflow_call"}


@pytest.fixture(scope="module")
def workflow() -> dict:
    assert WORKFLOW.is_file(), f"{WORKFLOW.relative_to(REPO_ROOT)} is missing"
    # `yaml.safe_load` maps the unquoted `on:` key to Python True (the YAML 1.1
    # boolean), so the trigger block is read back via that key, not the string.
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def scorecard_job(workflow: dict) -> dict:
    jobs = workflow["jobs"]
    assert len(jobs) == 1, f"the publisher workflow must hold exactly one job, got {sorted(jobs)}"
    return next(iter(jobs.values()))


def _uses_steps(job: dict) -> list[str]:
    return [step["uses"] for step in job["steps"] if "uses" in step]


def test_triggers_are_default_branch_push_and_schedule_only(workflow: dict) -> None:
    triggers = workflow[True]
    assert set(triggers) == {"push", "schedule"}, sorted(triggers)
    assert triggers["push"]["branches"] == ["main"]
    assert triggers["schedule"], "a weekly schedule keeps the published result from going stale"
    assert not _FORBIDDEN_TRIGGERS & set(triggers)


def test_workflow_scope_holds_no_write_permission(workflow: dict) -> None:
    # `read-all` is the documented least-privilege default for the publisher.
    assert workflow["permissions"] == "read-all"


def test_write_permissions_are_scoped_to_the_publishing_job(scorecard_job: dict) -> None:
    permissions = scorecard_job["permissions"]
    assert permissions.get("id-token") == "write"
    assert permissions.get("security-events") == "write"
    # Anything beyond those two writes is authority the publisher does not need.
    writes = {name for name, level in permissions.items() if level == "write"}
    assert writes == {"id-token", "security-events"}, sorted(writes)


def test_checkout_does_not_persist_credentials(scorecard_job: dict) -> None:
    checkout = next(
        step for step in scorecard_job["steps"] if step.get("uses", "").startswith("actions/checkout@")
    )
    assert checkout["with"]["persist-credentials"] is False


def test_results_are_published(scorecard_job: dict) -> None:
    action = next(
        step for step in scorecard_job["steps"] if step.get("uses", "").startswith("ossf/scorecard-action@")
    )
    assert action["with"]["publish_results"] is True
    # A fixed SARIF filename is what lets the upload steps reference the exact
    # file the action produced, with no shell post-processing in between.
    assert action["with"]["results_format"] == "sarif"
    assert action["with"]["results_file"] == "results.sarif"


def test_runs_on_a_github_hosted_ubuntu_runner(scorecard_job: dict) -> None:
    # Scorecard refuses to publish from a self-hosted runner, and a self-hosted
    # runner would expose the OIDC token to a persistent host.
    assert scorecard_job["runs-on"].startswith("ubuntu-")


def test_every_action_is_sha_pinned(scorecard_job: dict) -> None:
    unpinned = [uses for uses in _uses_steps(scorecard_job) if not _SHA_PIN.match(uses)]
    assert not unpinned, f"actions must be pinned to a full commit SHA: {unpinned}"


def test_only_upstream_approved_actions_are_used(scorecard_job: dict) -> None:
    # Scorecard's publisher validation rejects unapproved actions in the job.
    approved = {
        "actions/checkout",
        "ossf/scorecard-action",
        "actions/upload-artifact",
        "github/codeql-action/upload-sarif",
    }
    used = {uses.split("@", 1)[0] for uses in _uses_steps(scorecard_job)}
    assert used <= approved, f"unapproved actions in the publishing job: {sorted(used - approved)}"


def test_job_runs_no_shell_step(scorecard_job: dict) -> None:
    # The job holds OIDC and Code Scanning write. Keeping it free of `run:` steps
    # means checked-out repository content never executes with that authority.
    assert not [step for step in scorecard_job["steps"] if "run" in step]


def test_workflow_declares_no_env_or_defaults(workflow: dict, scorecard_job: dict) -> None:
    # Scorecard's publisher validator rejects both at either scope.
    for scope, block in (("workflow", workflow), ("job", scorecard_job)):
        assert "env" not in block, f"{scope}-level env is rejected by the publisher validator"
        assert "defaults" not in block, f"{scope}-level defaults is rejected by the publisher validator"


def test_readme_carries_the_scorecard_badge() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "api.scorecard.dev/projects/github.com/Brad-Edwards/aptl/badge" in readme
    assert "scorecard.dev/viewer/?uri=github.com/Brad-Edwards/aptl" in readme
