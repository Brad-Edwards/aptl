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

from aptl.backends.aces_base_substrate import (
    BaseContainerSpec,
    InitRequirements,
    PublishedPort,
    VolumeMount,
)
from aptl.core.deployment import DockerComposeBackend


def _backend(tmp_path: Path) -> DockerComposeBackend:
    return DockerComposeBackend(project_dir=tmp_path, project_name="test-proj")


class TestEnsureGenericBaseImage:
    """A fresh machine has none of the locally-built generic base images in
    its Docker cache — a developer's own long-lived cache silently masked
    this gap since ADR-048 shipped, until a real fresh-machine boot (issue
    #581) surfaced it as a hard `aptl lab start` failure on node 'db'."""

    def test_builds_the_image_when_missing(self, tmp_path):
        backend = _backend(tmp_path)

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:3] == ["docker", "image", "inspect"]:
                return MagicMock(returncode=1, stdout="", stderr="No such image")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run) as mock_run:
            failures = backend.ensure_generic_base_image(
                "aptl/generic-systemd-base-debian:latest"
            )

        assert failures == []
        build_call = next(c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "build"])
        argv = build_call.args[0]
        assert argv[:4] == ["docker", "build", "-t", "aptl/generic-systemd-base-debian:latest"]
        assert argv[4] == str(tmp_path / "containers" / "generic-systemd-base-debian")

    def test_no_op_when_the_image_already_exists(self, tmp_path):
        backend = _backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            failures = backend.ensure_generic_base_image(
                "aptl/generic-systemd-base-debian:latest"
            )

        assert failures == []
        assert not any(c.args[0][:2] == ["docker", "build"] for c in mock_run.call_args_list)

    def test_no_op_for_a_real_registry_image(self, tmp_path):
        # debian:12-slim / rockylinux:9 are real registry references; `docker
        # run` pulls them on demand, so this must never attempt to build them.
        backend = _backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            failures = backend.ensure_generic_base_image("debian:12-slim")

        assert failures == []
        mock_run.assert_not_called()

    def test_build_failure_is_reported_not_raised(self, tmp_path):
        backend = _backend(tmp_path)

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:3] == ["docker", "image", "inspect"]:
                return MagicMock(returncode=1, stdout="", stderr="No such image")
            return MagicMock(returncode=1, stdout="", stderr="Dockerfile not found")

        with patch("subprocess.run", side_effect=fake_run):
            failures = backend.ensure_generic_base_image(
                "aptl/generic-systemd-base-debian:latest"
            )

        assert failures and "aptl/generic-systemd-base-debian:latest" in failures[0]


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


class TestStartBaseContainerVolumesAndPorts:
    """ADR-048/#581: a node materialized directly (never Compose-started)
    can still need a shared named volume or a host-published port — both
    come from typed SDL fields (``runtime.mounts`` / ``runtime.network.
    published_ports``), lowered onto ``BaseContainerSpec`` and then into
    ``docker run`` flags here."""

    def test_volume_mount_uses_the_project_scoped_volume_name(self, tmp_path):
        backend = _backend(tmp_path)
        spec = BaseContainerSpec(
            node_address="provision.node.misp-suricata-sync",
            container_name="aptl-misp-suricata-sync",
            image_ref="debian:12-slim",
            runs_services=False,
            volume_mounts=(
                VolumeMount(target="/var/lib/suricata/rules/misp", source="suricata_misp_rules"),
            ),
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.start_base_container(spec)

        run_call = next(c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"])
        argv = run_call.args[0]
        assert "-v" in argv
        assert "test-proj_suricata_misp_rules:/var/lib/suricata/rules/misp" in argv

    def test_read_only_volume_mount_appends_ro_suffix(self, tmp_path):
        backend = _backend(tmp_path)
        spec = BaseContainerSpec(
            node_address="provision.node.misp-suricata-sync",
            container_name="aptl-misp-suricata-sync",
            image_ref="debian:12-slim",
            runs_services=False,
            volume_mounts=(
                VolumeMount(
                    target="/var/run/suricata", source="suricata_command_socket", read_only=True
                ),
            ),
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.start_base_container(spec)

        run_call = next(c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"])
        argv = run_call.args[0]
        assert "test-proj_suricata_command_socket:/var/run/suricata:ro" in argv

    def test_published_port_defaults_host_port_to_container_port(self, tmp_path):
        backend = _backend(tmp_path)
        spec = BaseContainerSpec(
            node_address="provision.node.webapp",
            container_name="aptl-webapp",
            image_ref="debian:12-slim",
            runs_services=False,
            published_ports=(PublishedPort(container_port=8080),),
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.start_base_container(spec)

        run_call = next(c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"])
        argv = run_call.args[0]
        assert "-p" in argv
        assert "8080:8080/tcp" in argv

    def test_published_port_honours_explicit_host_ip_and_host_port(self, tmp_path):
        backend = _backend(tmp_path)
        spec = BaseContainerSpec(
            node_address="provision.node.dns",
            container_name="aptl-dns",
            image_ref="debian:12-slim",
            runs_services=False,
            published_ports=(
                PublishedPort(
                    container_port=53, protocol="udp", host_ip="127.0.0.1", host_port=5353
                ),
            ),
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.start_base_container(spec)

        run_call = next(c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"])
        argv = run_call.args[0]
        assert "127.0.0.1:5353:53/udp" in argv


class TestRemoveGenericMaterializerContainers:
    """`docker compose down`/`kill` never touch these - stop/kill must (P7).

    Discovered by a real live-gate boot: stopping the lab left every
    generic-materializer container running, attached to the project's
    networks, which then failed to remove with "network has active
    endpoints" - the whole stop/kill operation failed, not just a warning.
    """

    def test_removes_containers_matching_the_lifecycle_label(self, tmp_path):
        backend = _backend(tmp_path)

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:3] == ["docker", "ps", "-aq"]:
                return MagicMock(returncode=0, stdout="abc123\ndef456\n", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run) as mock_run:
            failures = backend.remove_generic_materializer_containers()

        assert failures == []
        list_call = next(c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "ps"])
        assert "label=aptl.lifecycle.project=test-proj" in list_call.args[0]
        rm_call = next(c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "rm"])
        assert rm_call.args[0] == ["docker", "rm", "-f", "abc123", "def456"]

    def test_no_containers_is_a_clean_noop(self, tmp_path):
        backend = _backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            failures = backend.remove_generic_materializer_containers()

        assert failures == []
        # No `docker rm` call at all when there is nothing to remove.
        assert not any(c.args[0][:2] == ["docker", "rm"] for c in mock_run.call_args_list)

    def test_removal_failure_is_reported_not_raised(self, tmp_path):
        backend = _backend(tmp_path)

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:3] == ["docker", "ps", "-aq"]:
                return MagicMock(returncode=0, stdout="abc123\n", stderr="")
            return MagicMock(returncode=1, stdout="", stderr="container in use")

        with patch("subprocess.run", side_effect=fake_run):
            failures = backend.remove_generic_materializer_containers()

        assert failures and "container in use" in failures[0]

    def test_docker_unavailable_is_reported_not_raised(self, tmp_path):
        # kill_compose_lab's own tests hit this exact path: every subprocess
        # call fails, and the whole operation must still return gracefully.
        backend = _backend(tmp_path)

        with patch("subprocess.run", side_effect=FileNotFoundError("docker not found")):
            failures = backend.remove_generic_materializer_containers()

        assert failures and "docker not found" in failures[0]
