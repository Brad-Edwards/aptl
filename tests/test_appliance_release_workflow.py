"""Structural gates for the release workflow's container publication."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release-please.yml"
RETRY_WORKFLOW = ROOT / ".github/workflows/publish-seat-image.yml"
PUBLISHER = ROOT / "scripts/appliance/publish-seat-image.sh"


def _jobs() -> dict[str, dict]:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


def test_package_release_only_publishes_python_artifacts() -> None:
    jobs = _jobs()
    assert set(jobs) == {"release-please", "publish", "backmerge"}
    assert set(jobs["backmerge"]["needs"]) == {"release-please", "publish"}


def test_every_project_owned_image_is_still_published() -> None:
    # The seat image is what a participant boots, but the lab's own container
    # images are still published; deleting the golden pipeline must not have
    # taken them with it.
    publisher = (ROOT / "scripts/appliance/publish-images.sh").read_text()
    published = set(re.findall(r"^build_image ([a-z0-9-]+) ", publisher, re.MULTILINE))
    assert len(published) == 13
    assert "docker build --provenance=false" in publisher


def test_private_candidate_does_not_move_latest(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "seat-disk.qcow2").write_bytes(b"disk")
    (out / "seat-image-config.json").write_bytes(b"{}")
    subprocess.run([sys.executable, str(ROOT / "scripts/appliance/seat-build-record.py"),
                    "write", str(out), "--commit", "a" * 40, "--dirty", "0"], check=True)
    manifest = {
        "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.aptl.seat.config.v1+json",
                   "digest": "sha256:" + hashlib.sha256(b"{}").hexdigest(), "size": 2},
        "layers": [{"mediaType": "application/vnd.aptl.seat.disk.v1+qcow2",
                    "digest": "sha256:" + hashlib.sha256(b"disk").hexdigest(), "size": 4}],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_bytes = json.dumps(manifest).encode()
    manifest_path.write_bytes(manifest_bytes)
    manifest_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    binary = tmp_path / "bin"
    binary.mkdir()
    stubs = {
        "oras": """#!/bin/sh
case "$1" in
  login) cat >/dev/null ;;
  resolve)
    case "$2" in *:v5.6.0) exit 1 ;; esac
    printf '%s\\n' "$APTL_TEST_MANIFEST_DIGEST" ;;
  manifest) cp "$APTL_TEST_MANIFEST" "$5" ;;
  tag) printf 'tag\\n' >> "$APTL_TEST_ORAS_LOG" ;;
esac
""",
        "curl": """#!/bin/sh
printf 'request\\n' >> "$APTL_TEST_CURL_LOG"
case "${*}" in
  *'/token?'*) printf '{"token":"anonymous"}\\n' ;;
  *) printf '401' ;;
esac
""",
        "jq": "#!/bin/sh\ncat >/dev/null\nprintf 'anonymous\\n'\n",
        "sha256sum": "#!/bin/sh\nif test \"$#\" -eq 0; then cat >/dev/null; fi\nprintf '%064d  -\\n' 0\n",
        "cosign": "#!/bin/sh\nprintf 'unexpected signature attempt' > \"$APTL_TEST_COSIGN_LOG\"\nexit 1\n",
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
            "APTL_SEAT_SIGNING_KEY": str(tmp_path / "fixture.key"),
            "REPOSITORY_OWNER": "Brad-Edwards",
            "GHCR_TOKEN": "test-token",
            "GITHUB_ACTOR": "test-actor",
            "APTL_TEST_ORAS_LOG": str(log),
            "APTL_TEST_MANIFEST": str(manifest_path),
            "APTL_TEST_MANIFEST_DIGEST": manifest_digest,
            "APTL_TEST_COSIGN_LOG": str(tmp_path / "cosign.log"),
            "APTL_TEST_CURL_LOG": str(tmp_path / "curl.log"),
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode != 0
    assert "key-" in result.stderr
    assert "not anonymously pullable" in result.stderr
    assert not log.exists()
    assert not (tmp_path / "cosign.log").exists()
    assert len((tmp_path / "curl.log").read_text().splitlines()) <= 4
