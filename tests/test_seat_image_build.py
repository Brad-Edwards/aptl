"""Gates on the seat image bake and its publication."""

from __future__ import annotations

import json
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release-please.yml"
BAKE = ROOT / "scripts/appliance/build-seat-image.sh"
PUBLISH = ROOT / "scripts/appliance/publish-seat-image.sh"
PROVISION = ROOT / "appliance/guest/provision-offline.sh"


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


def test_realized_techvault_image_inventory_includes_helpers_and_children(
    tmp_path: Path,
) -> None:
    from aptl.appliance.input_images import canonical_image_references
    from aptl.core.scenario_bundle import env_pack_bundle
    from aptl.validation.curated_live_proof import expected_bundle_matrix
    from aptl.core.config import AptlConfig

    bundle = env_pack_bundle(tmp_path / "packs")
    references = canonical_image_references(ROOT, bundle)
    matrix = expected_bundle_matrix(ROOT, AptlConfig(), bundle)

    assert {
        "scenario." + service for service in matrix.expected_services
    } <= references.keys()
    assert references["scenario.ad"].startswith("aptl/")
    assert references["child.shuffle-worker"].startswith("ghcr.io/")
    assert references["helper.certs"].startswith("wazuh/")
    assert "@sha256:" in references["scenario.misp"]


def test_saved_archive_must_match_inspected_image_roles(tmp_path: Path) -> None:
    import io

    module = _script("assemble-seat-inputs.py")
    image_id = "sha256:" + "a" * 64
    saved_id = "sha256:" + "b" * 64
    archive_path = tmp_path / "images.tar"
    manifest = json.dumps(
        [{"Config": "blobs/sha256/" + "b" * 64, "RepoTags": ["aptl/base:latest"]}]
    ).encode()
    index = json.dumps({"manifests": [{"digest": image_id}]}).encode()
    blob = json.dumps({"config": {"digest": saved_id}}).encode()
    with tarfile.open(archive_path, "w") as archive:
        for name, payload in (
            ("manifest.json", manifest),
            ("index.json", index),
            ("blobs/sha256/" + "a" * 64, blob),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))

    assert module.verify_archive(
        archive_path, {"scenario.ad": image_id}, {"aptl/base:latest": image_id}
    ) == {"scenario.ad": saved_id}
    with pytest.raises(ValueError, match="omits"):
        module.verify_archive(
            archive_path,
            {"scenario.ad": "sha256:" + "c" * 64},
            {"aptl/base:latest": image_id},
        )


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


def test_generated_config_reserves_the_baked_disks_virtual_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _script("write-seat-image-config.py")
    disk = tmp_path / "seat.qcow2"
    disk.write_bytes(b"fixture")
    output = tmp_path / "config.json"
    monkeypatch.setattr(module, "image_digest", lambda _ref: "image@sha256:" + "a" * 64)
    monkeypatch.setattr(module, "file_digest", lambda _path: "sha256:" + "b" * 64)
    monkeypatch.setattr(
        module.subprocess,
        "check_output",
        lambda *_args, **_kwargs: json.dumps({"virtual-size": 210 * 1024**3}),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["write-seat-image-config", "--disk", str(disk), "--output", str(output)],
    )

    assert module.main() == 0
    assert json.loads(output.read_bytes())["resources"]["disk_bytes"] == 210 * 1024**3


def test_bake_uses_the_proven_offline_guest_provisioning() -> None:
    bake = BAKE.read_text()
    provision = PROVISION.read_text()
    first_boot = (ROOT / "appliance/guest/aptl-appliance-first-boot").read_text()
    stage_cleanup = 'rm -rf "$stage"'

    # This is the provisioning that built the seats run in the field. Docker
    # arrives as digest-locked .deb files staged on the host, because the guest
    # reaches no package repository; maintainer-script service starts are
    # suppressed during the offline install and enabled for first boot.
    assert "provision-offline.sh" in bake
    assert "acquire-guest-system-packages.sh" in bake
    assert "system-packages.sha256" in provision
    assert "policy-rc.d" in provision
    assert "systemctl enable docker.service" in provision
    assert "aptl_labs-*.whl" in provision
    assert "aptl-wheel-requirements.txt" in bake
    assert "aptl-wheel-requirements.txt" in provision
    assert "--require-hashes --find-links" in provision
    assert "npm ci --no-audit --no-fund && npm run build" in bake
    assert "aptl appliance" not in first_boot
    # The real Compose web services own these policy ports. A placeholder
    # listener would take the loopback sockets before Docker could publish.
    assert "guest_services surfaces" not in first_boot
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    local_images = (ROOT / "scripts/appliance/build-local-images.sh").read_text()
    for name in ("aptl-web-api", "aptl-web-ui"):
        assert compose["services"][name]["image"] == f"{name}:1"
        assert f"build_image {name}:1" in local_images
    assert "up --detach --no-build --pull never aptl-web-api aptl-web-ui" in first_boot
    assert "APTL_WEB_LAUNCH_TOKEN" in first_boot

    # The image archive ships on disk and first boot loads it once per
    # overlay, so a participant's seat pulls nothing. Loading at bake time is
    # not an option: a build appliance has no cgroups to run a daemon.
    assert "oci-images.tar" in bake
    assert "/opt/aptl/offline/oci-images.tar" in provision
    assert "docker load --input /opt/aptl/offline/oci-images.tar" in first_boot
    assert "images_loaded" in first_boot

    # Nothing staged may remain in the published image.
    assert stage_cleanup in provision


def test_bake_pins_its_base_image_by_digest() -> None:
    bake = BAKE.read_text()
    assert "sha256sum" in bake
    assert "base image digest does not match the pin" in bake
    assert "virt-sparsify --in-place" in bake
    assert "chmod 0444" in bake


def test_publication_proves_an_anonymous_pull() -> None:
    publish = PUBLISH.read_text()
    assert "is not anonymously pullable" in publish
    assert "ghcr.io/token?service=ghcr.io" in publish
    # Disk and config bytes define the immutable tag; latest points at it.
    assert 'key_tag="key-${key}"' in publish
    assert 'sha256sum "$disk" "$config"' in publish
    assert "oras tag" in publish


def test_release_bakes_before_every_publication() -> None:
    job = yaml.safe_load(WORKFLOW.read_text())["jobs"]["publish-seat-image"]
    assert job["runs-on"] == ["self-hosted", "linux", "x64", "aptl-seat-image"]
    steps = {step.get("name"): step for step in job["steps"] if step.get("name")}
    # Compose still contains mutable third-party tags. The digest of the
    # resulting disk and config can only be known after the bake.
    assert "if" not in steps["Bake the seat image"]
    assert "if" not in steps["Publish the seat image"]
    names = [step.get("name") for step in job["steps"]]
    assert names.index("Bake the seat image") < names.index(
        "Boot and qualify the baked seat"
    ) < names.index("Publish the seat image")
    assert "qualify-seat-image.sh" in steps["Boot and qualify the baked seat"]["run"]
