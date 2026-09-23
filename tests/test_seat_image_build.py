"""Gates on the seat image bake and its publication."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release-please.yml"
KEY_SCRIPT = ROOT / "scripts/appliance/seat-image-key.sh"
BAKE = ROOT / "scripts/appliance/build-seat-image.sh"
PUBLISH = ROOT / "scripts/appliance/publish-seat-image.sh"
PROVISION = ROOT / "appliance/guest/provision-seat.sh"


def _script(name: str):
    """Load one hyphenated build script as a module."""

    import importlib.util

    path = ROOT / "scripts/appliance" / name
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


KEY_ENVIRONMENT = {
    "APTL_BASE_IMAGE_SHA256": "sha256:" + "a" * 64,
    "APTL_GUEST_PYTHON_VERSION": "3.14",
}


def _key(**overrides: str) -> str:
    return subprocess.run(
        [str(KEY_SCRIPT)],
        cwd=ROOT,
        env={**os.environ, **KEY_ENVIRONMENT, **overrides},
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def test_content_key_is_deterministic() -> None:
    first = _key()
    second = _key()

    assert first == second
    assert len(first) == 64


def test_content_key_follows_the_pinned_base_image() -> None:
    # A different base produces a different image, so it must not reuse the
    # one already published.
    assert _key(APTL_BASE_IMAGE_SHA256="sha256:" + "b" * 64) != _key()


def test_content_key_tracks_what_goes_into_the_image(tmp_path: Path) -> None:
    dockerfile = ROOT / "containers/kali-capture/Dockerfile"
    original = dockerfile.read_bytes()
    baseline = _key()
    try:
        dockerfile.write_bytes(original + b"\n# probe\n")
        assert _key() != baseline
    finally:
        dockerfile.write_bytes(original)
    assert _key() == baseline


def test_content_key_ignores_what_does_not(tmp_path: Path) -> None:
    readme = ROOT / "README.md"
    original = readme.read_bytes()
    baseline = _key()
    try:
        readme.write_bytes(original + b"\n<!-- probe -->\n")
        # Rebaking an identical image because a doc changed is the waste this
        # key exists to prevent.
        assert _key() == baseline
    finally:
        readme.write_bytes(original)


def test_third_party_images_come_from_the_compose_definition() -> None:
    module = _script("seat-image-third-party.py")

    document = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    references = module.third_party_images(document)

    assert references == sorted(set(references))
    # Project-built images are exported from the exact local build instead.
    assert not [item for item in references if item.startswith(("aptl/", "aptl-"))]
    assert "wazuh/wazuh-manager:4.12.0" in references


def test_unpinned_or_templated_images_are_refused() -> None:
    module = _script("seat-image-third-party.py")

    with pytest.raises(SystemExit):
        module.third_party_images(
            {"services": {"misp": {"image": "${MISP_IMAGE}"}}},
        )
    with pytest.raises(SystemExit):
        module.third_party_images({"services": {}})


def test_generated_config_validates_against_the_launcher_contract() -> None:
    # The bake writes this and the launcher parses it; a declaration the
    # launcher would refuse must fail the bake, not a participant's start.
    from aptl.appliance.policy import full_techvault_boundary_policy
    from aptl.appliance.seat.image_config import parse_seat_image_config

    resources = _script("write-seat-image-config.py").RESOURCES

    payload = json.dumps(
        {
            "schema_version": "aptl.seat-image/v1",
            "resources": resources,
            "boundary": full_techvault_boundary_policy().model_dump(mode="json"),
            "binding": {
                "boundary_helper_image": "aptl-network-boundary-helper@sha256:"
                + "c" * 64,
                "egress_proxy_image": "aptl-appliance-egress-proxy@sha256:" + "d" * 64,
                "raes_plan_digest": "sha256:" + "e" * 64,
            },
        }
    ).encode()

    config = parse_seat_image_config(payload)

    assert config.resources.vcpus == 8
    assert config.participant.port == 3000


def test_bake_preloads_images_and_leaves_no_payload_behind() -> None:
    provision = PROVISION.read_text()
    bake = BAKE.read_text()
    # The whole point of baking: the guest holds the images already. The store
    # is built on the host, because a build appliance has no cgroups to run a
    # daemon, and restored whole in the guest.
    assert "guest-docker.tar" in bake
    assert "guest-docker.tar" in provision
    assert "/var/lib/docker" in provision
    assert "--no-index" in provision
    assert 'rm -rf "$stage"' in provision
    # A guest that silently restored nothing would look fine until first boot.
    assert "no restored Docker image store" in provision
    assert "guest image store holds only" in bake


def test_bake_pins_its_base_image_by_digest() -> None:
    bake = BAKE.read_text()
    assert "sha256sum" in bake
    assert "base image digest does not match the pin" in bake
    assert "chmod 0444" in bake


def test_publication_proves_an_anonymous_pull() -> None:
    publish = PUBLISH.read_text()
    assert "is not anonymously pullable" in publish
    assert "ghcr.io/token?service=ghcr.io" in publish
    # The content key is the immutable tag; latest only points at it.
    assert 'key_tag="key-${APTL_SEAT_IMAGE_KEY}"' in publish
    assert "oras tag" in publish


def test_release_bakes_only_when_the_key_is_unpublished() -> None:
    job = yaml.safe_load(WORKFLOW.read_text())["jobs"]["publish-seat-image"]
    assert "self-hosted" not in str(job["runs-on"])
    steps = {step.get("name"): step for step in job["steps"] if step.get("name")}
    assert (
        steps["Bake the seat image"]["if"]
        == "${{ steps.existing.outputs.published != 'true' }}"
    )
    # Publication always runs: an already-published key still needs the
    # release tag and latest moved onto it.
    assert "if" not in steps["Publish the seat image"]
