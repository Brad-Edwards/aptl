"""Runtime contracts that an image bake must satisfy at first boot."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import rfc8785

from aptl.appliance.policy import full_techvault_boundary_policy
from aptl.appliance.seat import image as seat_image
from aptl.appliance.seat.image import SeatDiskDescriptor, SeatImageReference
from aptl.appliance.seat.image_selection import SeatImageSelection
from aptl.appliance.seat.image_selection import load_selection, select_seat_image
from aptl.appliance.seat.launch_descriptor import (
    SeatLaunchDescriptor,
    canonical_launch_bytes,
)
from aptl.appliance.seat.lifecycle import _load_seat_image, _seat_paths
from aptl.utils.mcp_packaging import archive_project
from tests.test_seat_image_config import _config


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def test_first_selection_requires_the_manifest_launch_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reference = SeatImageReference("ghcr.io", "owner/seat", "latest", None)
    descriptor = SeatDiskDescriptor(
        reference=reference,
        digest=_digest(b"disk"),
        size_bytes=4,
        manifest_digest=_digest(b"manifest"),
        token=None,
    )
    monkeypatch.setattr(seat_image, "resolve_disk_descriptor", lambda _ref: descriptor)
    monkeypatch.setattr(
        seat_image,
        "fetch_seat_disk",
        lambda *_a, **_k: pytest.fail("disk fetched before config validation"),
    )

    with pytest.raises(seat_image.SeatImageError, match="no launch config"):
        select_seat_image(reference, cache_dir=tmp_path)
    assert load_selection(tmp_path, reference) == {}


def test_cached_config_stays_with_selected_disk_when_tag_moves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _config()
    disk_digest = "sha256:" + "a" * 64
    reference = SeatImageReference("ghcr.io", "owner/seat", "latest", None)
    descriptor = SeatDiskDescriptor(
        reference=reference,
        digest=disk_digest,
        size_bytes=4,
        manifest_digest="sha256:" + "b" * 64,
        token=None,
        config_digest=_digest(payload),
        config_size_bytes=len(payload),
    )
    monkeypatch.setattr(seat_image, "fetch_https_metadata", lambda *_a, **_k: payload)
    cache = tmp_path / "cache"
    seat_image.cache_seat_image_config(descriptor, cache)
    selection = SeatImageSelection(reference, disk_digest, 4, tmp_path / "disk")
    from aptl.appliance.seat import lifecycle

    monkeypatch.setattr(lifecycle, "select_seat_image", lambda *_a, **_k: selection)
    monkeypatch.setattr(
        lifecycle,
        "resolve_disk_descriptor",
        lambda *_a, **_k: pytest.fail("warm start contacted the moved tag"),
    )
    paths = _seat_paths(
        tmp_path / "seat",
        seat_id="seat-01",
        image_reference=str(reference),
        image_cache_dir=cache,
    )
    result = _load_seat_image(paths)
    assert result.config_digest == _digest(payload)
    assert result.config.participant.port == 3000

    (cache / disk_digest.removeprefix("sha256:") / "seat-config.json").write_bytes(
        b"tampered"
    )
    with pytest.raises(Exception, match="config does not match"):
        _load_seat_image(paths)


def test_guest_services_use_verified_launch_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aptl.appliance import guest_services

    policy = full_techvault_boundary_policy()
    policy_bytes = rfc8785.dumps(policy.model_dump(mode="json"))
    descriptor = SeatLaunchDescriptor(
        schema_version="aptl.appliance-launch/v2",
        image_reference="ghcr.io/owner/seat:latest",
        image_digest="sha256:" + "a" * 64,
        image_config_digest="sha256:" + "b" * 64,
        boundary_policy_digest=_digest(policy_bytes),
        boundary_helper_image="aptl-network-boundary-helper@sha256:" + "c" * 64,
        egress_proxy_image="aptl-appliance-egress-proxy@sha256:" + "d" * 64,
        participant_routes_digest="sha256:" + "e" * 64,
        host_mcp_contract="aptl.restricted-ssh-mcp/v1",
        host_observation_id="observed",
    )
    path = tmp_path / "appliance-launch.json"
    path.write_bytes(canonical_launch_bytes(descriptor))
    (tmp_path / "boundary-policy.json").write_bytes(policy_bytes)
    observed = []
    monkeypatch.setattr(
        guest_services, "serve_proxy_bindings", lambda bindings: observed.extend(bindings)
    )
    monkeypatch.setattr(
        sys, "argv", ["guest-services", "proxy"]
    )
    monkeypatch.setattr(guest_services, "_LAUNCH_DESCRIPTOR", path)
    guest_services.main()
    assert {binding.listen_port for binding in observed} == {3000, 8400, 2222}


def test_readiness_calls_the_current_guest_access_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aptl.appliance import access_service
    from aptl.appliance.seat import readiness
    from aptl.core.lab import _publish_appliance_guest_readiness

    observed: list[object] = []
    backend = SimpleNamespace(observe_appliance_boundary=lambda deployment: deployment)
    context = SimpleNamespace(
        appliance_readiness_challenge=tmp_path / "challenge.json",
        appliance_readiness_device=tmp_path / "readiness",
        appliance_access_request=tmp_path / "request.json",
        appliance_access_device=tmp_path / "access",
        appliance_access_output_dir=tmp_path / "mcp",
        appliance_launch_descriptor=tmp_path / "descriptor.json",
        run_id="run-1",
        project_dir=tmp_path,
        selected_profiles=set(),
        admitted_start=SimpleNamespace(
            realization=SimpleNamespace(deployment_spec=lambda profiles: profiles)
        ),
        backend=backend,
    )
    monkeypatch.setattr(readiness, "publish_guest_readiness", lambda *_a: None)

    def access(
        *, request_path, descriptor_path, device_path, output_dir,
        run_id, project_dir, observe_boundary,
    ):
        observed.append(observe_boundary())

    monkeypatch.setattr(access_service, "serve_appliance_access", access)
    assert _publish_appliance_guest_readiness(context) is None
    assert observed == [[]]


def test_project_archive_keeps_built_mcp_without_mutating_checkout(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    common = project / "mcp/aptl-mcp-common"
    common.mkdir(parents=True)
    (common / "index.js").write_text("module.exports = 1")
    consumer = project / "mcp/mcp-red/node_modules"
    consumer.mkdir(parents=True)
    link = consumer / "aptl-mcp-common"
    link.symlink_to("../../aptl-mcp-common", target_is_directory=True)
    subprocess.run(["git", "init", "-q", str(project)], check=True)
    subprocess.run(
        ["git", "add", "mcp/aptl-mcp-common/index.js"], cwd=project, check=True
    )
    (project / ".git/sentinel").write_text("unpackaged")
    (project / "build").mkdir()
    (project / "build/sentinel").write_text("unpackaged")
    (project / ".env").write_text("unpackaged")
    output = tmp_path / "project.tar"

    archive_project(project, output)

    with tarfile.open(output) as archive:
        names = set(archive.getnames())
    assert "mcp/mcp-red/node_modules/aptl-mcp-common/index.js" in names
    assert not any(name.startswith((".git/", "build/")) for name in names)
    assert ".env" not in names
    assert link.is_symlink()


def test_project_archive_excludes_untracked_local_configuration(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    config = project / "config"
    config.mkdir(parents=True)
    (config / "tracked.txt").write_text("release input")
    (config / "local-credentials.txt").write_text("local-only")
    subprocess.run(["git", "init", "-q", str(project)], check=True)
    subprocess.run(
        ["git", "add", "config/tracked.txt"], cwd=project, check=True
    )
    output = tmp_path / "project.tar"

    archive_project(project, output)

    with tarfile.open(output) as archive:
        assert archive.getnames() == ["config/tracked.txt"]


def test_release_smoke_uses_the_same_home_as_first_boot() -> None:
    guest = Path(__file__).resolve().parents[1] / "appliance/guest"
    first_boot = (guest / "aptl-appliance-first-boot.service").read_text()
    release_smoke = (guest / "seat-qualification-smoke.service").read_text()
    assert "Environment=HOME=/var/lib/aptl" in first_boot.splitlines()
    assert "Environment=HOME=/var/lib/aptl" in release_smoke.splitlines()
