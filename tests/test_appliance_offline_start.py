"""Offline first-boot gates for a fully staged appliance payload."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from aptl.appliance.manifest import ApplianceManifestError
from aptl.backends.aces_base_substrate import BaseContainerSpec
from aptl.core.deployment._compose_boundary import _helper_command
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment.realization import (
    DeploymentImageRealization,
    DeploymentRealizationSpec,
)
from aptl.core.lab import (
    _LabStartContext,
    _configure_verified_appliance_launch,
    _step_pull_images,
    _step_seed_suricata_volumes,
)
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
    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        del kwargs
        commands.append(command)
        stdout = "aptl_default\n" if command[:3] == ["docker", "network", "ls"] else ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        result = backend.realize(_spec())

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
        result = backend.realize(_spec())

    assert result.success is False
    assert result.error == "Staged image missing for ACES node provision.node.db."
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
    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        del kwargs
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    seed = NamedVolumeSeed(
        volume_suffix="seed",
        source_dir=source,
        files=(SeedFile(src="input", dest="output"),),
    )
    node = BaseContainerSpec(
        node_address="provision.node.victim",
        container_name="aptl-victim",
        image_ref="debian:12-slim",
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
        failures = backend.ensure_generic_base_image("debian:12-slim")

    assert failures == ["required staged generic base image is missing: debian:12-slim"]
    assert not any(
        call.args[0][:2] == ["docker", "build"] for call in run.call_args_list
    )


def test_verified_launch_payload_is_bound_before_scenario_realization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    backend = MagicMock()
    policy = MagicMock()
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
        run.return_value = subprocess.CompletedProcess(
            ["docker", "info"],
            0,
            stdout="guest-daemon\n",
            stderr="",
        )
        result = _configure_verified_appliance_launch(context)

    assert result is None
    configured_policy, binding = backend.configure_appliance_boundary.call_args.args
    assert configured_policy is policy
    assert binding.payload_digest == descriptor.payload_digest
    assert binding.policy_digest == descriptor.boundary_policy_digest


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
