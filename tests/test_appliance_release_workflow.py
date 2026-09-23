"""Structural gates for the release workflow's container publication."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release-please.yml"
RETRY_WORKFLOW = ROOT / ".github/workflows/publish-seat-image.yml"
PUBLISHER = ROOT / "scripts/appliance/publish-seat-image.sh"


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


def test_private_candidate_does_not_move_latest(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "seat-disk.qcow2").write_bytes(b"disk")
    (out / "seat-image-config.json").write_bytes(b"{}")
    binary = tmp_path / "bin"
    binary.mkdir()
    stubs = {
        "oras": """#!/bin/sh
case "$1" in
  login) cat >/dev/null ;;
  resolve)
    case "$2" in *:v5.6.0) exit 1 ;; esac
    printf 'sha256:candidate\\n' ;;
  tag) printf 'tag\\n' >> "$APTL_TEST_ORAS_LOG" ;;
esac
""",
        "curl": """#!/bin/sh
case "${*}" in
  *'/token?'*) printf '{"token":"anonymous"}\\n' ;;
  *) printf '401' ;;
esac
""",
        "jq": "#!/bin/sh\ncat >/dev/null\nprintf 'anonymous\\n'\n",
        "sleep": "#!/bin/sh\nexit 0\n",
    }
    for name, body in stubs.items():
        path = binary / name
        path.write_text(body)
        path.chmod(0o755)
    log = tmp_path / "oras.log"
    result = subprocess.run(
        ["bash", str(PUBLISHER), str(out)],
        env={
            "PATH": f"{binary}:{os.environ['PATH']}",
            "RELEASE_TAG": "v5.6.0",
            "REPOSITORY_OWNER": "Brad-Edwards",
            "GHCR_TOKEN": "test-token",
            "GITHUB_ACTOR": "test-actor",
            "APTL_TEST_ORAS_LOG": str(log),
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode != 0
    assert "key-" in result.stderr and "not anonymously pullable" in result.stderr
    assert not log.exists()
