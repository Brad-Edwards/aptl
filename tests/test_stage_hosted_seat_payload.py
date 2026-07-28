"""Tests for deterministic hosted-seat source staging."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest


pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[1]
STAGER_PATH = REPO_ROOT / "tools" / "workshop" / "stage_hosted_seat_payload.py"


def _load_stager():
    spec = importlib.util.spec_from_file_location(
        "stage_hosted_seat_payload", STAGER_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_stage_payload_materializes_pinned_layers_and_repairs(tmp_path: Path) -> None:
    stager = _load_stager()
    output = tmp_path / "payload"

    manifest_path = stager.stage_payload(REPO_ROOT, output)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema"] == "aptl.hosted-seat-payload/v1"
    assert manifest["lab_commit"] == stager.LAB_COMMIT
    assert manifest["profile_commit"] == stager.PROFILE_COMMIT
    assert manifest["kali_patch"]["sha256"] == stager.PATCH_SHA256
    assert manifest["hosted_seat_helper"]["sha256"] == stager.HELPER_SHA256
    assert (
        output / "profile-source" / "participant-profiles" / "guided-purple-v1"
    ).is_dir()
    kali_dockerfile = (
        output / "lab-source" / "containers" / "kali" / "Dockerfile"
    ).read_text(encoding="utf-8")
    assert "apt-get install -y nodejs npm" in kali_dockerfile
    assert "deb.nodesource.com/node_20.x" not in kali_dockerfile
    cert_helper = output / "lab-source" / stager.CERT_HELPER_PATH
    assert stager._sha256(cert_helper) == manifest["certificate_helper"]["sha256"]
    assert (output / "hosted_seat.py").is_file()

    with pytest.raises(FileExistsError):
        stager.stage_payload(REPO_ROOT, output)


def test_stage_payload_accepts_owner_only_mode_from_secure_umask(
    tmp_path: Path,
) -> None:
    stager = _load_stager()
    output = tmp_path / "private-payload"
    prior_umask = os.umask(0o077)
    try:
        stager.stage_payload(REPO_ROOT, output)
    finally:
        os.umask(prior_umask)

    assert output.stat().st_mode & 0o777 == 0o700


def test_stage_payload_rejects_a_changed_helper_digest(tmp_path: Path) -> None:
    stager = _load_stager()
    stager.HELPER_SHA256 = "0" * 64

    with pytest.raises(ValueError, match="helper does not match"):
        stager.stage_payload(REPO_ROOT, tmp_path / "payload")


def test_stage_payload_rejects_a_changed_patch_digest(tmp_path: Path) -> None:
    stager = _load_stager()
    stager.PATCH_SHA256 = "0" * 64

    with pytest.raises(ValueError, match="Kali patch does not match"):
        stager.stage_payload(REPO_ROOT, tmp_path / "payload")


def test_stage_payload_refuses_a_repository_subdirectory(tmp_path: Path) -> None:
    stager = _load_stager()

    with pytest.raises(ValueError, match="must be the APTL Git top-level directory"):
        stager.stage_payload(REPO_ROOT / "tools", tmp_path / "payload")


def test_stage_payload_refuses_a_non_repository_root(tmp_path: Path) -> None:
    stager = _load_stager()

    with pytest.raises(subprocess.CalledProcessError):
        stager.stage_payload(tmp_path, tmp_path / "payload")
