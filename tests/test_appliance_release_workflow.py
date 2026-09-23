"""Structural gates for the release workflow's container publication."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release-please.yml"


def _jobs() -> dict[str, dict]:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


def test_release_needs_no_self_hosted_runner() -> None:
    # Baking, qualifying and sealing a golden disk were the only reasons this
    # workflow needed dedicated machines. A seat now boots a published image,
    # so a release must complete on ordinary hosted runners.
    for name, job in _jobs().items():
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
