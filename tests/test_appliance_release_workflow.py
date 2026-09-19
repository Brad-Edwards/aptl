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
    assert "docker build --provenance=false" in publisher
    assert "docker build --provenance=false" in local_builder


def test_local_candidate_path_uses_exact_commit_and_no_registry_dependency() -> None:
    wrapper = (ROOT / "scripts/appliance/build-local-candidate.sh").read_text()
    builder = (ROOT / "scripts/appliance/build-candidate.sh").read_text()
    assert "git status --porcelain --untracked-files=no" in wrapper
    assert "APTL_CANDIDATE_MODE=local" in wrapper
    assert "scripts/appliance/build-local-images.sh" in wrapper
    assert "scripts/appliance/build-candidate.sh" in wrapper
    assert "source_revision" in builder
    assert '"$target_python" -m venv "$root/venv"' in builder
    assert "\npython -m venv " not in builder
    assert 'pip download --require-hashes -r requirements/web.txt' in builder
    assert "acquire-guest-system-packages.sh" in builder
    assert "--system-packages system-packages" in builder
    assert "--system-packages-lock" in builder
    assert "--local-image-lock" in builder
    assert "APTL_LOCAL_IMAGE_LOCK_FILE" in wrapper
    assert "APTL_LOCAL_IMAGE_TAG_SUFFIX" in wrapper
    assert "APTL_IMAGE_NAMESPACE" not in wrapper


def test_local_image_builds_pin_unique_tags_and_exact_parent_images() -> None:
    builder = (ROOT / "scripts/appliance/build-local-images.sh").read_text()
    assert '"${canonical%:*}" "$APTL_LOCAL_IMAGE_TAG_SUFFIX"' in builder
    assert 'docker image inspect --format \'{{.Id}}\' "$output_ref"' in builder
    assert 'build+=(--build-arg "APTL_PARENT_IMAGE=$parent_image")' in builder
    for name in (
        "generic-samba-ad-wazuh-agent-base",
        "generic-systemd-wazuh-agent-base",
        "generic-systemd-wazuh-agent-base-debian",
    ):
        dockerfile = (ROOT / "containers" / name / "Dockerfile").read_text()
        assert "ARG APTL_PARENT_IMAGE=" in dockerfile
        assert "FROM ${APTL_PARENT_IMAGE}" in dockerfile


def test_node22_image_preloads_exact_mcp_locks_for_offline_materialization() -> None:
    dockerfile = (
        ROOT / "containers/generic-systemd-node22-base/Dockerfile"
    ).read_text()
    assert "COPY requirements/runtime.txt /opt/aptl/runtime-requirements.txt" in dockerfile
    assert "python3 -m pip download --no-deps --require-hashes" in dockerfile
    assert "mcp-red-sources.tar" in dockerfile
    assert "mcp-blue-sources.tar" in dockerfile
    assert "npm_config_cache=/opt/aptl/npm-cache" in dockerfile
    assert "aptl-mcp-common mcp-casemgmt mcp-indexer mcp-network" in dockerfile
    assert "mcp-red mcp-reverse mcp-soar mcp-threatintel mcp-wazuh" in dockerfile
    assert "--ignore-scripts --no-audit --no-fund" in dockerfile
    assert "**/node_modules" in (ROOT / ".dockerignore").read_text()


def test_qualification_venv_installs_the_locked_runtime_closure() -> None:
    qualifier = (ROOT / "scripts/appliance/qualify-candidate.sh").read_text()

    ci_install = 'pip" install --require-hashes -r requirements/ci.txt'
    runtime_install = 'pip" install --require-hashes -r requirements/runtime.txt'
    local_install = 'pip" install --no-deps .'
    assert qualifier.index(ci_install) < qualifier.index(runtime_install)
    assert qualifier.index(runtime_install) < qualifier.index(local_install)
    assert 'release_dir="$seat_root/launch/release"' in qualifier
    assert '"$seat_root/release"' not in qualifier
    assert '"$work/seat-1/release"' not in qualifier


def test_resource_sampler_handles_seats_before_their_pid_files_exist() -> None:
    sampler = (ROOT / "scripts/appliance/sample-seat-resources.py").read_text()

    assert "max((item[1] for item in samples), default=0)" in sampler
    assert "max((_disk(root) for root in args.seat_root), default=0)" in sampler
