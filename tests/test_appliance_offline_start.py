"""Offline first-boot gates for a fully staged appliance payload."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from aptl.appliance.manifest import ApplianceManifestError
from aptl.backends.raes_base_substrate import BaseContainerSpec
from aptl.core.deployment._compose_boundary import _helper_command
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment.realization import (
    DeploymentImageRealization,
    DeploymentRealizationSpec,
)
from aptl.core.lab import (
    _LabStartContext,
    _attest_private_appliance_daemon,
    _configure_verified_appliance_launch,
    _publish_appliance_guest_readiness,
    _step_pull_images,
    _step_seed_suricata_volumes,
)
from aptl.core.lab_types import LabResult
from aptl.core.seed_spec import NamedVolumeSeed, SeedFile


def _spec() -> DeploymentRealizationSpec:
    digest = "sha256:" + "a" * 64
    return DeploymentRealizationSpec(
        profiles=("enterprise",),
        nodes=(),
        networks=(),
        images=(
            DeploymentImageRealization(
                address="provision.node.db",
                service_name="db",
                source_name="postgres",
                source_version=f"postgres@{digest}",
                image_ref=f"postgres@{digest}",
                mode="pull",
                policy_rule="digest-pinned",
            ),
        ),
    )


def test_offline_staged_realization_inspects_images_and_forbids_pull_or_build(
    tmp_path: Path,
) -> None:
    (tmp_path / "docker-compose.yml").write_text("services: {}\n")
    backend = DockerComposeBackend(tmp_path, offline_staged=True)
    backend._docker_daemon_id = "test-daemon"
    backend._verify_compose_namespace_is_owned = lambda *_args, **_kwargs: None  # type: ignore[method-assign]
    backend._record_compose_network_receipts = lambda *_args, **_kwargs: None  # type: ignore[method-assign]
    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        del kwargs
        commands.append(command)
        stdout = "aptl_default\n" if command[:3] == ["docker", "network", "ls"] else ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        result = backend.realize(_spec(), scenario_root=tmp_path)

    assert result.success is True
    assert any(command[:3] == ["docker", "image", "inspect"] for command in commands)
    assert not any(command[:2] == ["docker", "pull"] for command in commands)
    assert not any(command[:2] == ["docker", "build"] for command in commands)
    up = next(command for command in commands if "up" in command)
    assert "--pull" in up
    assert up[up.index("--pull") + 1] == "never"
    assert "--build" not in up


def test_offline_staged_realization_fails_before_start_when_image_is_missing(
    tmp_path: Path,
) -> None:
    (tmp_path / "docker-compose.yml").write_text("services: {}\n")
    backend = DockerComposeBackend(tmp_path, offline_staged=True)
    backend._docker_daemon_id = "test-daemon"
    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        del kwargs
        commands.append(command)
        return subprocess.CompletedProcess(
            command,
            1 if command[:3] == ["docker", "image", "inspect"] else 0,
            stdout="",
            stderr="not found",
        )

    with patch("subprocess.run", side_effect=fake_run):
        result = backend.realize(_spec(), scenario_root=tmp_path)

    assert result.success is False
    assert result.error == "Staged image missing for RAES node provision.node.db."
    assert not any("up" in command for command in commands)


def test_offline_staged_wazuh_preflight_fails_when_an_image_is_missing(
    tmp_path: Path,
) -> None:
    backend = MagicMock()
    backend.pull_images.return_value = [
        "Required staged image is missing: wazuh/example"
    ]
    context = _LabStartContext(
        project_dir=tmp_path,
        skip_seed=False,
        offline_staged=True,
        backend=backend,
    )

    result = _step_pull_images(context)

    assert result is not None
    assert result.success is False
    assert result.error == "Offline staged image verification failed."
    assert context.diagnostics == []


def test_offline_staged_suricata_seed_fails_before_running_a_container(
    tmp_path: Path,
) -> None:
    backend = MagicMock(spec=DockerComposeBackend)
    backend.pull_images.return_value = [
        "Required staged image is missing: jasonish/suricata"
    ]
    context = _LabStartContext(
        project_dir=tmp_path,
        skip_seed=False,
        offline_staged=True,
        backend=backend,
    )

    result = _step_seed_suricata_volumes(context)

    assert result is not None
    assert result.success is False
    assert result.error == "Offline staged Suricata image verification failed."
    backend.seed_named_volumes.assert_not_called()


def test_offline_staged_direct_docker_runs_forbid_implicit_pulls(
    tmp_path: Path,
) -> None:
    source = tmp_path / "seed"
    source.mkdir()
    (source / "input").write_text("data")
    backend = DockerComposeBackend(tmp_path, offline_staged=True)
    backend._docker_daemon_id = "test-daemon"
    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        del kwargs
        commands.append(command)
        stdout = "a" * 64 if command[:2] == ["docker", "run"] else ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    seed = NamedVolumeSeed(
        volume_suffix="seed",
        source_dir=source,
        files=(SeedFile(src="input", dest="output"),),
    )
    node = BaseContainerSpec(
        node_address="provision.node.victim",
        container_name="aptl-victim",
        image_ref="debian:13-slim",
        runs_services=False,
    )
    with patch("subprocess.run", side_effect=fake_run):
        backend._seed_one_named_volume(seed, "seeder:staged")
        backend.start_base_container(node)

    docker_runs = [command for command in commands if command[:2] == ["docker", "run"]]
    assert len(docker_runs) == 2
    assert all("--pull=never" in command for command in docker_runs)
    assert "--pull=never" in _helper_command("apply", pull_never=True)


def test_offline_staged_generic_base_requires_a_staged_image(
    tmp_path: Path,
) -> None:
    backend = DockerComposeBackend(tmp_path, offline_staged=True)

    with patch("subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess(
            ["docker", "image", "inspect"],
            1,
            stdout="",
            stderr="missing",
        )
        failures = backend.ensure_generic_base_image("debian:13-slim")

    assert failures == ["required staged generic base image is missing: debian:13-slim"]
    assert not any(
        call.args[0][:2] == ["docker", "build"] for call in run.call_args_list
    )


@pytest.mark.parametrize("candidate_trust", [False, True])
def test_verified_launch_payload_is_bound_before_scenario_realization(
    tmp_path: Path,
    monkeypatch,
    candidate_trust: bool,
) -> None:
    backend = MagicMock()
    from aptl.appliance.policy import full_techvault_boundary_policy

    policy = full_techvault_boundary_policy()
    backend.daemon_identity.return_value = "guest-daemon"
    descriptor = SimpleNamespace(
        boundary_policy_digest="sha256:" + "1" * 64,
        payload_digest="sha256:" + "2" * 64,
        participant_routes_digest="sha256:" + "3" * 64,
        boundary_helper_image="example/helper@sha256:" + "4" * 64,
        egress_proxy_image="example/proxy@sha256:" + "5" * 64,
        host_observation_id="sha256:" + "6" * 64,
    )
    monkeypatch.setattr(
        "aptl.appliance.launch.verify_launch_descriptor",
        lambda *args: SimpleNamespace(
            descriptor=descriptor,
            boundary_policy=policy,
        ),
    )
    monkeypatch.setattr(
        "aptl.appliance.candidate.verify_candidate_launch_descriptor",
        lambda *args: SimpleNamespace(
            descriptor=descriptor,
            boundary_policy=policy,
        ),
    )
    context = _LabStartContext(
        project_dir=tmp_path,
        skip_seed=False,
        offline_staged=True,
        appliance_launch_descriptor=tmp_path / "launch.json",
        appliance_release_public_key=tmp_path / "release-public.pem",
        appliance_qualification_public_key=tmp_path / "qualification-public.pem",
        appliance_candidate_trust=candidate_trust,
        backend=backend,
    )
    monkeypatch.setattr(
        "aptl.core.lab._read_appliance_boot_id",
        lambda: "guest-boot",
    )
    monkeypatch.setattr(
        "aptl.core.lab._attest_private_appliance_daemon",
        lambda _: True,
    )
    backend.bind_local_docker_socket.return_value = LabResult(success=True)
    backend.bound_docker_daemon_id = "guest-daemon"

    with patch("aptl.core.lab.subprocess.run") as run:
        result = _configure_verified_appliance_launch(context)

    assert result is None
    configured_policy, binding = backend.configure_appliance_boundary.call_args.args
    assert configured_policy is policy
    assert binding.raes_boundary_required is False
    assert binding.payload_digest == descriptor.payload_digest
    assert binding.policy_digest == descriptor.boundary_policy_digest
    backend.daemon_identity.assert_called_once_with()
    run.assert_not_called()
    assert backend.configure_appliance_boundary.call_args.kwargs == {
        "isolated_daemon": True
    }


def test_verified_launch_refuses_unattested_guest_daemon(
    tmp_path: Path, monkeypatch
) -> None:
    backend = MagicMock()
    monkeypatch.setattr(
        "aptl.appliance.launch.verify_launch_descriptor",
        lambda *args: SimpleNamespace(descriptor=object(), boundary_policy=object()),
    )
    context = _LabStartContext(
        project_dir=tmp_path,
        skip_seed=False,
        offline_staged=True,
        appliance_launch_descriptor=tmp_path / "copied-launch.json",
        appliance_release_public_key=tmp_path / "release-public.pem",
        appliance_qualification_public_key=tmp_path / "qualification-public.pem",
        backend=backend,
    )

    result = _configure_verified_appliance_launch(context)

    assert result is not None and not result.success
    assert result.error == "Verified appliance launch binding failed."
    backend.bind_local_docker_socket.assert_not_called()
    backend.configure_appliance_boundary.assert_not_called()


def test_appliance_daemon_isolation_requires_read_only_virtio_launch_mount(
    tmp_path: Path,
) -> None:
    launch_root = tmp_path / "aptl-launch"
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        f"47 32 0:49 / {launch_root} ro,relatime - 9p aptl-launch ro,trans=virtio\n"
    )
    descriptor = launch_root / "appliance-launch.json"

    assert _attest_private_appliance_daemon(
        descriptor, launch_root=launch_root, mountinfo_path=mountinfo
    )
    for unsafe in (
        f"47 32 0:49 / {launch_root} rw,relatime - 9p aptl-launch rw,trans=virtio\n",
        f"47 32 0:49 / {launch_root} ro,relatime - ext4 /dev/sda ro\n",
        f"47 32 0:49 / {launch_root} ro,relatime - 9p aptl-launch ro,trans=tcp\n",
    ):
        mountinfo.write_text(unsafe)
        assert not _attest_private_appliance_daemon(
            descriptor, launch_root=launch_root, mountinfo_path=mountinfo
        )
    mountinfo.write_text(
        f"47 32 0:49 / {launch_root} ro,relatime - 9p aptl-launch ro,trans=virtio\n"
    )
    assert not _attest_private_appliance_daemon(
        tmp_path / "copied-launch.json",
        launch_root=launch_root,
        mountinfo_path=mountinfo,
    )


@pytest.mark.parametrize(
    "missing_input",
    [
        "offline_staged",
        "appliance_release_public_key",
        "appliance_qualification_public_key",
        "backend",
    ],
)
def test_verified_launch_rejects_each_incomplete_runtime_input(
    tmp_path: Path,
    missing_input: str,
) -> None:
    backend = MagicMock()
    inputs = {
        "offline_staged": True,
        "appliance_release_public_key": tmp_path / "release-public.pem",
        "appliance_qualification_public_key": tmp_path / "qualification-public.pem",
        "backend": backend,
    }
    inputs[missing_input] = False if missing_input == "offline_staged" else None
    context = _LabStartContext(
        project_dir=tmp_path,
        skip_seed=False,
        appliance_launch_descriptor=tmp_path / "launch.json",
        **inputs,
    )

    result = _configure_verified_appliance_launch(context)

    assert result is not None
    assert result.success is False
    assert result.error == "Appliance launch inputs are incomplete."
    backend.configure_appliance_boundary.assert_not_called()


def test_verified_launch_reverification_failure_is_a_hard_stop(
    tmp_path: Path,
    monkeypatch,
) -> None:
    backend = MagicMock()

    def reject_descriptor(*args) -> None:
        raise ApplianceManifestError("unsafe verification detail")

    monkeypatch.setattr(
        "aptl.appliance.launch.verify_launch_descriptor",
        reject_descriptor,
    )
    context = _LabStartContext(
        project_dir=tmp_path,
        skip_seed=False,
        offline_staged=True,
        appliance_launch_descriptor=tmp_path / "launch.json",
        appliance_release_public_key=tmp_path / "release-public.pem",
        appliance_qualification_public_key=tmp_path / "qualification-public.pem",
        backend=backend,
    )

    with patch("aptl.core.lab.subprocess.run") as run:
        result = _configure_verified_appliance_launch(context)

    assert result is not None
    assert result.success is False
    assert result.error == "Verified appliance launch binding failed."
    assert "unsafe verification detail" not in result.error
    run.assert_not_called()
    backend.configure_appliance_boundary.assert_not_called()


def test_guest_readiness_and_access_are_published_from_one_observation(
    tmp_path: Path,
) -> None:
    deployment = object()
    observation = object()
    realization = SimpleNamespace(
        deployment_spec=lambda profiles: deployment,
    )
    backend = SimpleNamespace(
        observe_appliance_boundary=lambda value: observation,
    )
    context = _LabStartContext(
        project_dir=tmp_path,
        skip_seed=False,
        backend=backend,
        selected_profiles={"red", "blue"},
        admitted_start=SimpleNamespace(realization=realization),
        appliance_readiness_challenge=tmp_path / "readiness.json",
        appliance_readiness_device=tmp_path / "readiness.sock",
        appliance_access_request=tmp_path / "access-request.json",
        appliance_access_device=tmp_path / "access.sock",
        appliance_access_output_dir=tmp_path / "access",
        appliance_launch_descriptor=tmp_path / "launch.json",
        appliance_release_public_key=tmp_path / "release.pem",
        appliance_qualification_public_key=tmp_path / "qualification.pem",
        appliance_candidate_trust=True,
    )

    with (
        patch(
            "aptl.appliance.seat.readiness.publish_guest_readiness"
        ) as publish_readiness,
        patch("aptl.appliance.access_service.serve_appliance_access") as serve_access,
    ):
        result = _publish_appliance_guest_readiness(context)

    assert result is None
    publish_readiness.assert_called_once_with(
        context.appliance_readiness_challenge,
        context.appliance_readiness_device,
        observation,
    )
    assert serve_access.call_args.kwargs["candidate_trust"] is True
    assert serve_access.call_args.kwargs["observe_boundary"]() is observation
