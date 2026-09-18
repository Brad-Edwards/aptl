"""Structural gates for exact-source appliance publication and acceptance."""

from __future__ import annotations

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release-please.yml"


def _jobs() -> dict[str, object]:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


def test_release_requires_two_distinct_kvm_qualifiers_and_separate_sealing() -> None:
    jobs = _jobs()
    machine_a = jobs["qualify-appliance-a"]
    machine_b = jobs["qualify-appliance-b"]
    assert machine_a["runs-on"] != machine_b["runs-on"]
    assert "aptl-appliance-a" in machine_a["runs-on"]
    assert "aptl-appliance-b" in machine_b["runs-on"]
    assert machine_a["steps"][2]["env"]["APTL_QUALIFICATION_SEATS"] == "2"
    assert machine_b["steps"][2]["env"]["APTL_QUALIFICATION_SEATS"] == "1"
    assert set(jobs["seal-appliance"]["needs"]) >= {
        "build-appliance-candidate",
        "qualify-appliance-a",
        "qualify-appliance-b",
    }


def test_public_acceptance_has_no_repository_or_package_permission() -> None:
    job = _jobs()["accept-public-appliance"]
    assert job["permissions"] == {}
    assert set(job["needs"]) == {
        "release-please",
        "publish-appliance",
        "publish-public-appliance-images",
    }
    assert "kvm" in job["runs-on"]
    script = (ROOT / "scripts/appliance/accept-public-release.sh").read_text()
    assert "docker logout ghcr.io" in script
    assert "unset GH_TOKEN GITHUB_TOKEN" in script
    assert "appliance fetch-distribution" in script
    assert "probe-native-client.py" in script
    assert "THIRD-PARTY-NOTICES.md" in script
    assert "APTL_RELEASE_PUBLIC_KEY_PEM" in job["steps"][1]["env"]
    assert "APTL_QUALIFICATION_PUBLIC_KEY_PEM" in job["steps"][1]["env"]


def test_public_images_and_release_assets_are_both_mandatory() -> None:
    jobs = _jobs()
    assert jobs["build-appliance-candidate"]["needs"] == [
        "release-please",
        "publish-appliance-images",
    ]
    assert jobs["publish-appliance"]["needs"] == ["release-please", "seal-appliance"]
    assert jobs["publish-public-appliance-images"]["needs"] == [
        "release-please",
        "seal-appliance",
    ]
    assert "accept-public-appliance" in jobs["backmerge"]["needs"]
    image_verifier = (ROOT / "scripts/appliance/verify-public-images.sh").read_text()
    image_publisher = (ROOT / "scripts/appliance/publish-images.sh").read_text()
    assert "visibility=public" in image_verifier
    assert "aptl-candidate" in image_verifier
    assert "docker tag" in image_verifier
    assert "docker logout ghcr.io" in image_verifier
    assert "aptl-candidate" in image_publisher
    assert "visibility) != private" in image_publisher
    assert "refusing to replace existing GHCR tag" in image_publisher
    candidate_env = jobs["build-appliance-candidate"]["steps"][3]["env"]
    assert candidate_env["APTL_IMAGE_NAMESPACE"].endswith("/aptl-candidate")


def test_sealing_requires_exact_redistribution_review_and_publishes_notices() -> None:
    seal = _jobs()["seal-appliance"]
    env = seal["steps"][2]["env"]
    assert "APTL_REDISTRIBUTION_REVIEW_JSON" in env
    script = (ROOT / "scripts/appliance/seal-release.sh").read_text()
    assert "verify-redistribution-review" in script
    assert "THIRD-PARTY-NOTICES.md" in script


def test_private_build_public_promotion_and_candidate_acquisition_sets_match() -> None:
    publisher = (ROOT / "scripts/appliance/publish-images.sh").read_text()
    builder = (ROOT / "scripts/appliance/build-candidate.sh").read_text()
    local_builder = (ROOT / "scripts/appliance/build-local-images.sh").read_text()
    promoter = (ROOT / "scripts/appliance/verify-public-images.sh").read_text()
    published = set(re.findall(r"^build_image ([a-z0-9-]+) ", publisher, re.MULTILINE))
    acquired = set(re.findall(r"^  '([a-z0-9-]+) [^']+'$", builder, re.MULTILINE))
    image_block = promoter.split("images=(", 1)[1].split(")", 1)[0]
    promoted = set(re.findall(r"^  ([a-z0-9-]+)$", image_block, re.MULTILINE))
    assert published == acquired == promoted
    assert len(published) == 13
    local_images = set(
        re.findall(r"^build_image ([^ ]+) ", local_builder, re.MULTILINE)
    )
    assert len(local_images) == 13


def test_local_candidate_path_uses_exact_commit_and_no_registry_dependency() -> None:
    wrapper = (ROOT / "scripts/appliance/build-local-candidate.sh").read_text()
    builder = (ROOT / "scripts/appliance/build-candidate.sh").read_text()
    assert "git status --porcelain --untracked-files=no" in wrapper
    assert "APTL_CANDIDATE_MODE=local" in wrapper
    assert "scripts/appliance/build-local-images.sh" in wrapper
    assert "scripts/appliance/build-candidate.sh" in wrapper
    assert "source_revision" in builder
    assert 'docker image inspect "$canonical"' in builder
    assert "APTL_IMAGE_NAMESPACE" not in wrapper
