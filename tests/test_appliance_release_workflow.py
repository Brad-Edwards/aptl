"""Structural gates for the release workflow's container publication."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release-please.yml"
RETRY_WORKFLOW = ROOT / ".github/workflows/publish-seat-image.yml"


def _jobs() -> dict[str, dict]:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


def test_large_image_jobs_use_a_dedicated_runner() -> None:
    # Docker images, the offline payload, and the VM disk do not fit on a
    # standard hosted Ubuntu runner's 14 GB volume.
    jobs = _jobs()
    for name in ("publish-appliance-images", "publish-seat-image"):
        assert jobs[name]["runs-on"] == [
            "self-hosted", "linux", "x64", "aptl-seat-image"
        ]
    for name, job in jobs.items():
        if name not in {"publish-appliance-images", "publish-seat-image"}:
            assert "self-hosted" not in str(job.get("runs-on")), name


def test_release_publishes_images_and_back_merges_behind_them() -> None:
    jobs = _jobs()
    assert jobs["publish-appliance-images"]["needs"] == ["release-please"]
    assert set(jobs["backmerge"]["needs"]) == {
        "release-please",
        "publish",
        "publish-appliance-images",
        "publish-seat-image",
    }
    # The seat image is what a participant boots, so a release that did not
    # publish one must not be back-merged as complete.
    assert jobs["publish-seat-image"]["needs"] == [
        "release-please",
        "publish-appliance-images",
    ]


def test_every_project_owned_image_is_still_published() -> None:
    # The seat image is what a participant boots, but the lab's own container
    # images are still published; deleting the golden pipeline must not have
    # taken them with it.
    publisher = (ROOT / "scripts/appliance/publish-images.sh").read_text()
    published = set(re.findall(r"^build_image ([a-z0-9-]+) ", publisher, re.MULTILINE))
    assert len(published) == 13
    assert "docker build --provenance=false" in publisher


def test_existing_release_can_retry_after_package_visibility_changes() -> None:
    document = yaml.safe_load(RETRY_WORKFLOW.read_text())
    job = document["jobs"]["publish-seat-image"]
    assert job["runs-on"] == ["self-hosted", "linux", "x64", "aptl-seat-image"]
    steps = {step.get("name"): step for step in job["steps"] if step.get("name")}
    assert "/releases/tags/${RELEASE_TAG}" in steps["Verify the existing release"]["run"]
    assert "build-seat-image.sh" in steps["Bake the seat image"]["run"]
    assert "qualify-seat-image.sh" in steps["Boot and qualify the baked seat"]["run"]
    assert "publish-seat-image.sh" in steps["Publish and verify anonymous pull"]["run"]
