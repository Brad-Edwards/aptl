"""Tests for the Compose backend's generic base-container mixin (ADR-048).

start_base_container runs a plain `docker run`, never `docker compose up` -
so every project-ownership check that filters containers by the
`com.docker.compose.project` label (container_exists, the host snapshot
listing, observation) would otherwise never see a node the generic
materializer realized directly. Caught by a real local live-gate boot of
the full TechVault range, not by any unit test - this file exists so it
cannot regress silently again.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from aptl.backends.aces_base_substrate import BaseContainerSpec, InitRequirements
from aptl.core.deployment import DockerComposeBackend


def _backend(tmp_path: Path) -> DockerComposeBackend:
    return DockerComposeBackend(project_dir=tmp_path, project_name="test-proj")


def test_start_base_container_carries_the_compose_project_ownership_label(tmp_path):
    backend = _backend(tmp_path)
    spec = BaseContainerSpec(
        node_address="provision.node.victim",
        container_name="aptl-victim",
        image_ref="debian:12-slim",
        runs_services=False,
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        backend.start_base_container(spec)

    run_call = next(c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"])
    argv = run_call.args[0]
    assert "--label" in argv
    assert "com.docker.compose.project=test-proj" in argv
    # container_exists/host snapshot listing key on this exact label+value -
    # any other project's containers on a shared daemon must not match.
    assert f"com.docker.compose.project={backend.project_name}" in argv


def test_start_base_container_keeps_the_aptl_lifecycle_labels(tmp_path):
    backend = _backend(tmp_path)
    spec = BaseContainerSpec(
        node_address="provision.node.victim",
        container_name="aptl-victim",
        image_ref="debian:12-slim",
        runs_services=False,
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        backend.start_base_container(spec)

    run_call = next(c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"])
    argv = run_call.args[0]
    assert "aptl.lifecycle.project=test-proj" in argv
    assert "aptl.node.address=provision.node.victim" in argv


def test_start_base_container_with_init_still_carries_the_label(tmp_path):
    backend = _backend(tmp_path)
    spec = BaseContainerSpec(
        node_address="provision.node.kali",
        container_name="aptl-kali",
        image_ref="aptl/generic-systemd-base-debian:latest",
        runs_services=True,
        init=InitRequirements(),
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        backend.start_base_container(spec)

    run_call = next(c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"])
    argv = run_call.args[0]
    assert "com.docker.compose.project=test-proj" in argv
