"""The Ground Control Phase E workflow keeps the shape its trust rests on.

When a delivery pull request merges, this job replays the recorded completion
payload through Ground Control's finalizer, which posts the final report and
closes the issue. The close gate trusts that report only because of properties
of this file: its path, its run name, what it checks out, and what it may write.
Each is pinned here, so an edit that would break automated finalization, or
widen what an automated job can do, fails in CI rather than on the next merge.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ground-control-phase-e.yml"
_SHA = re.compile(r"^[0-9a-f]{40}$")


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _triggers() -> dict:
    # PyYAML reads the bare key `on` as the boolean True.
    workflow = _workflow()
    return workflow.get("on", workflow.get(True))


def _job() -> dict:
    return _workflow()["jobs"]["finalize"]


def _steps() -> list[dict]:
    return _job()["steps"]


def test_the_close_gate_can_find_this_workflow_by_its_path():
    """The gate trusts a report only from this repository's file at this path."""

    assert WORKFLOW.is_file()


def test_the_run_name_binds_both_triggers_to_their_pull_request():
    """The gate matches this exact text; a missing half unbinds one trigger, and
    an omitted run-name lets GitHub substitute arbitrary pull-request text."""

    assert _workflow()["run-name"] == (
        "Ground Control Phase E for PR "
        "${{ github.event.pull_request.number || inputs.pr }}"
    )


def test_it_runs_only_for_merged_pull_requests_and_maintainer_repair():
    triggers = _triggers()

    assert set(triggers) == {"pull_request", "workflow_dispatch"}
    assert triggers["pull_request"]["types"] == ["closed"]
    assert "pull_request_target" not in triggers
    assert "merged == true" in _job()["if"]


def test_its_only_write_is_to_issues():
    """Reports and closes need issues; nothing else may be writable."""

    permissions = _workflow()["permissions"]
    writes = {scope for scope, level in permissions.items() if level == "write"}

    assert writes == {"issues"}
    assert permissions["actions"] == "read"
    assert "permissions" not in _job()


def test_it_checks_out_the_merge_revision_not_the_pull_request_head():
    """Phase E reads the merged tree; the head is not what merged."""

    aptl = _steps()[0]["with"]

    assert aptl["ref"] == (
        "${{ github.event.pull_request.merge_commit_sha || github.sha }}"
    )
    assert aptl["persist-credentials"] is False


def test_ground_control_runs_from_an_immutable_commit():
    """A branch or tag could change what runs with this job's token."""

    ground_control = next(
        step["with"]
        for step in _steps()
        if step.get("with", {}).get("repository") == "autarchy-ai/Ground-Control"
    )

    assert ground_control["ref"] == "${{ env.GROUND_CONTROL_COMMIT }}"
    assert _SHA.fullmatch(_job()["env"]["GROUND_CONTROL_COMMIT"])
    assert ground_control["persist-credentials"] is False


def test_the_finalizer_installs_from_its_lockfile_without_install_scripts():
    install = next(step["run"] for step in _steps() if "npm" in step.get("run", ""))

    assert " ci " in f" {install} "
    assert "--ignore-scripts" in install


def test_the_finalizer_runs_against_the_aptl_checkout():
    """It treats its working directory as the repository it finalizes."""

    finalize = next(
        step for step in _steps() if "finalize-merged-pr" in step.get("run", "")
    )

    assert finalize["working-directory"] == "aptl"
    assert finalize["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert '--pr "$PR"' in finalize["run"]


def test_a_replay_is_serialized_and_never_cancelled():
    """A cancelled finalization leaves neither a report nor a failure record."""

    concurrency = _workflow()["concurrency"]

    assert "number || inputs.pr" in concurrency["group"]
    assert concurrency["cancel-in-progress"] is False
