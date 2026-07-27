"""Tests for immutable golden-image construction and overlay bootstrap."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from aptl.appliance.bootstrap import (
    ApplianceBootstrapError,
    initialize_overlay_state,
)
from aptl.appliance.build import (
    ApplianceBuildError,
    GoldenImageBuildRequest,
    OverlayCreateRequest,
    build_golden_image,
    create_disposable_overlay,
)
from aptl.appliance.launch import canonical_launch_bytes
from aptl.appliance.models import GoldenImageInventory
from aptl.appliance.release_models import ApplianceLaunchDescriptor


class RecordingRunner:
    """Subprocess double that materializes qemu-img's candidate output."""

    def __init__(self, *, fail_program: str | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.fail_program = fail_program

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(tuple(argv))
        if argv[0] == self.fail_program:
            raise subprocess.CalledProcessError(1, argv, stderr="unsafe raw detail")
        if argv[:3] == ["qemu-img", "convert", "-f"]:
            Path(argv[-1]).write_bytes(b"immutable golden image")
        if argv[:3] == ["qemu-img", "create", "-f"]:
            Path(argv[-1]).write_bytes(b"disposable overlay")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


def _request(root: Path) -> GoldenImageBuildRequest:
    base = root / "inputs/base.qcow2"
    payload = root / "inputs/offline-payload.tar"
    provisioner = root / "inputs/provision-offline.sh"
    scanner = root / "inputs/scan-golden.sh"
    base.parent.mkdir(parents=True)
    base.write_bytes(b"pinned ubuntu base")
    payload.write_bytes(b"offline payload")
    provisioner.write_text("#!/bin/sh\nset -eu\n")
    scanner.write_text("#!/bin/sh\nset -eu\n")
    return GoldenImageBuildRequest(
        schema_version="aptl.golden-image-build/v1",
        base_image_path="inputs/base.qcow2",
        base_image_digest=f"sha256:{hashlib.sha256(base.read_bytes()).hexdigest()}",
        offline_payload_path="inputs/offline-payload.tar",
        offline_payload_digest=(
            f"sha256:{hashlib.sha256(payload.read_bytes()).hexdigest()}"
        ),
        provisioner_path="inputs/provision-offline.sh",
        provisioner_digest=(
            f"sha256:{hashlib.sha256(provisioner.read_bytes()).hexdigest()}"
        ),
        scanner_path="inputs/scan-golden.sh",
        scanner_digest=(f"sha256:{hashlib.sha256(scanner.read_bytes()).hexdigest()}"),
        output_image_path="output/aptl-golden.qcow2",
        inventory_output_path="output/golden-inventory.json",
        virtual_size_bytes=120 * 1024**3,
    )


def _overlay_request(
    root: Path,
    *,
    golden_path: str,
    golden_digest: str,
    overlay_path: str,
) -> OverlayCreateRequest:
    descriptor = ApplianceLaunchDescriptor(
        schema_version="aptl.appliance-launch/v1",
        release_dir="release",
        release_id="aptl-v5.1.1-x86_64",
        aptl_version="5.1.1",
        manifest_digest="sha256:" + "1" * 64,
        payload_digest="sha256:" + "2" * 64,
        golden_image_digest=golden_digest,
        boundary_policy_path="evidence/boundary-policy.json",
        boundary_policy_digest="sha256:" + "3" * 64,
        boundary_helper_image="example/helper@sha256:" + "4" * 64,
        egress_proxy_image="example/proxy@sha256:" + "5" * 64,
        participant_routes_digest="sha256:" + "6" * 64,
        host_observation_id="sha256:" + "7" * 64,
    )
    payload = canonical_launch_bytes(descriptor)
    (root / "launch.json").write_bytes(payload)
    return OverlayCreateRequest(
        schema_version="aptl.overlay-create/v1",
        golden_image_path=golden_path,
        golden_image_digest=golden_digest,
        launch_descriptor_path="launch.json",
        launch_descriptor_digest=f"sha256:{hashlib.sha256(payload).hexdigest()}",
        overlay_path=overlay_path,
    )


def test_golden_image_build_uses_fixed_offline_commands_and_read_only_output(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    runner = RecordingRunner()

    result = build_golden_image(tmp_path, request, runner=runner)

    output = tmp_path / request.output_image_path
    assert result.output_path == output
    assert result.inventory_path == tmp_path / request.inventory_output_path
    inventory = GoldenImageInventory.model_validate_json(
        result.inventory_path.read_bytes()
    )
    assert inventory.scan_complete is True
    assert result.sha256 == (
        f"sha256:{hashlib.sha256(output.read_bytes()).hexdigest()}"
    )
    assert output.stat().st_mode & 0o777 == 0o444
    assert [call[0] for call in runner.calls] == [
        "qemu-img",
        "qemu-img",
        "virt-customize",
        "virt-sysprep",
        "virt-customize",
        "qemu-img",
    ]
    customize = runner.calls[2]
    assert "--no-network" in customize
    assert "--run" in customize
    assert all(
        "http://" not in value and "https://" not in value for value in customize
    )
    assert all("/bin/sh" not in value and "bash" not in value for value in customize)
    scanner = runner.calls[4]
    assert "--no-network" in scanner
    assert "--run" in scanner


def test_golden_image_build_rejects_tampered_input_and_existing_release(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    (tmp_path / request.base_image_path).write_bytes(b"tampered")
    runner = RecordingRunner()

    with pytest.raises(ApplianceBuildError, match="base image digest"):
        build_golden_image(tmp_path, request, runner=runner)
    assert runner.calls == []

    request = _request(tmp_path / "second")
    output = tmp_path / "second" / request.output_image_path
    output.parent.mkdir()
    output.write_bytes(b"existing immutable release")
    with pytest.raises(ApplianceBuildError, match="already exists"):
        build_golden_image(tmp_path / "second", request, runner=runner)
    assert output.read_bytes() == b"existing immutable release"


def test_failed_build_never_replaces_or_leaves_a_candidate(tmp_path: Path) -> None:
    request = _request(tmp_path)
    runner = RecordingRunner(fail_program="virt-customize")

    with pytest.raises(ApplianceBuildError) as exc_info:
        build_golden_image(tmp_path, request, runner=runner)

    assert str(exc_info.value) == "golden image build failed"
    assert "unsafe raw detail" not in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, subprocess.CalledProcessError)
    assert exc_info.value.__cause__.stderr == "unsafe raw detail"
    assert not (tmp_path / request.output_image_path).exists()
    assert not (tmp_path / request.inventory_output_path).exists()
    assert list((tmp_path / "output").glob("*.candidate-*")) == []


def test_build_request_requires_guest_asset_basenames(tmp_path: Path) -> None:
    request = _request(tmp_path).model_dump()
    request["offline_payload_path"] = "inputs/renamed.tar"

    with pytest.raises(ValueError, match="offline payload path"):
        GoldenImageBuildRequest.model_validate(request)


def test_disposable_overlay_uses_verified_read_only_backing_file(
    tmp_path: Path,
) -> None:
    golden = tmp_path / "release/aptl-golden.qcow2"
    golden.parent.mkdir()
    golden.write_bytes(b"immutable golden image")
    golden.chmod(0o444)
    request = _overlay_request(
        tmp_path,
        golden_path="release/aptl-golden.qcow2",
        golden_digest=f"sha256:{hashlib.sha256(golden.read_bytes()).hexdigest()}",
        overlay_path="instances/seat-01.qcow2",
    )
    runner = RecordingRunner()

    result = create_disposable_overlay(tmp_path, request, runner=runner)

    assert result.overlay_path == tmp_path / "instances/seat-01.qcow2"
    assert result.overlay_path.stat().st_mode & 0o777 == 0o600
    create = runner.calls[0]
    assert create[:8] == (
        "qemu-img",
        "create",
        "-f",
        "qcow2",
        "-F",
        "qcow2",
        "-b",
        str(golden),
    )
    candidate = Path(create[-1])
    assert candidate.name.startswith("seat-01.qcow2.candidate-")
    assert runner.calls[1] == ("qemu-img", "check", "-q", str(candidate))
    assert golden.read_bytes() == b"immutable golden image"
    assert golden.stat().st_mode & 0o222 == 0


def test_disposable_overlay_rejects_writable_or_tampered_golden(
    tmp_path: Path,
) -> None:
    golden = tmp_path / "golden.qcow2"
    golden.write_bytes(b"golden")
    request = _overlay_request(
        tmp_path,
        golden_path="golden.qcow2",
        golden_digest=f"sha256:{hashlib.sha256(b'golden').hexdigest()}",
        overlay_path="overlay.qcow2",
    )

    runner = RecordingRunner()
    with pytest.raises(ApplianceBuildError, match="read-only"):
        create_disposable_overlay(tmp_path, request, runner=runner)

    golden.chmod(0o644)
    golden.write_bytes(b"tampered")
    golden.chmod(0o444)
    runner = RecordingRunner()
    with pytest.raises(ApplianceBuildError, match="digest"):
        create_disposable_overlay(tmp_path, request, runner=runner)


def test_disposable_overlay_never_replaces_existing_output(tmp_path: Path) -> None:
    golden = tmp_path / "golden.qcow2"
    golden.write_bytes(b"golden")
    golden.chmod(0o444)
    overlay = tmp_path / "overlay.qcow2"
    overlay.write_bytes(b"active state")
    request = _overlay_request(
        tmp_path,
        golden_path="golden.qcow2",
        golden_digest=f"sha256:{hashlib.sha256(b'golden').hexdigest()}",
        overlay_path="overlay.qcow2",
    )

    runner = RecordingRunner()
    with pytest.raises(ApplianceBuildError, match="already exists"):
        create_disposable_overlay(tmp_path, request, runner=runner)

    assert overlay.read_bytes() == b"active state"


def test_first_boot_identity_is_unique_per_overlay_and_stable_on_reboot(
    tmp_path: Path,
) -> None:
    values = iter((b"a" * 32, b"b" * 32, b"c" * 32, b"d" * 32))

    first = initialize_overlay_state(
        tmp_path / "overlay-a",
        entropy=lambda size: next(values),
    )
    reboot = initialize_overlay_state(
        tmp_path / "overlay-a",
        entropy=lambda size: pytest.fail("ordinary reboot regenerated state"),
    )
    second = initialize_overlay_state(
        tmp_path / "overlay-b",
        entropy=lambda size: next(values),
    )

    assert reboot == first
    assert second.instance_id != first.instance_id
    assert second.bootstrap_credential != first.bootstrap_credential
    assert (tmp_path / "overlay-a").stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "overlay-a" / "identity.json").stat().st_mode & 0o777 == 0o600


def test_first_boot_rejects_symlink_state_and_recovers_from_interrupted_temp(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    state.symlink_to(target, target_is_directory=True)

    with pytest.raises(ApplianceBootstrapError, match="symlink"):
        initialize_overlay_state(state)

    clean = tmp_path / "clean"
    clean.mkdir(mode=0o700)
    (clean / ".identity.interrupted").write_bytes(b"partial secret")
    identity = initialize_overlay_state(clean, entropy=lambda size: b"z" * size)
    assert identity.instance_id.startswith("sha256:")
    assert (clean / ".identity.interrupted").read_bytes() == b"partial secret"


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes are required")
def test_first_boot_rejects_world_accessible_existing_identity(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    identity = state / "identity.json"
    identity.write_text(
        '{"schema_version":"aptl.overlay-identity/v1",'
        '"instance_id":"sha256:'
        + "a" * 64
        + '","bootstrap_credential":"'
        + "b" * 43
        + '"}'
    )
    identity.chmod(0o644)

    with pytest.raises(ApplianceBootstrapError, match="owner-only"):
        initialize_overlay_state(state)
