"""Tests for the deployment backend abstraction layer.

Tests cover the DeploymentBackend Protocol, DockerComposeBackend,
SSHComposeBackend, config model, and factory function.
"""

import json
import logging
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from aptl.core.config import AptlConfig, DeploymentConfig
from aptl.core.deployment import (
    DockerComposeBackend,
    DeploymentImageRealization,
    DeploymentNetworkAttachment,
    DeploymentNetworkRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
    SSHComposeBackend,
    get_backend,
)
from aptl.core.deployment._compose_realization import (
    _container_networks,
    _network_name_candidates,
    _resolve_realization_networks,
)
from aptl.core.deployment._compose_queries import _select_shell
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.lab import LabResult, LabStatus

# SSHComposeBackend validates the *local* ssh identity path with
# Path.is_absolute(), which is platform-specific: a POSIX "/home/..." path is
# not absolute on Windows (it lacks a drive), and vice versa. Use a host-
# appropriate absolute path so the validation is exercised on every platform
# instead of tripping the absolute-path guard with the wrong path flavour.
_IS_WINDOWS = os.name == "nt"
_ABS_SSH_KEY = (
    "C:\\Users\\user\\.ssh\\lab_key" if _IS_WINDOWS else "/home/user/.ssh/lab_key"
)
_ABS_SSH_KEY_TRAVERSAL = (
    "C:\\Users\\..\\etc\\passwd" if _IS_WINDOWS else "/home/../etc/passwd"
)


def _network_inspect_payload(
    name: str,
    compose_network: str,
    *,
    internal: bool = False,
    subnet: str = "",
    gateway: str = "",
    realization: bool = True,
) -> str:
    labels = {
        "com.docker.compose.project": "test",
        "com.docker.compose.network": compose_network,
    }
    if realization:
        labels["org.aptl.realization.network"] = "true"
    return json.dumps(
        [
            {
                "Name": name,
                "Internal": internal,
                "IPAM": {"Config": [{"Subnet": subnet, "Gateway": gateway}]},
                "Labels": labels,
                "Containers": {},
            }
        ]
    )


class TestSelectShell:
    """Pure-logic tests for the bash/sh selection table.

    Covers the four interesting branches:
    - probe rc 0  -> bash (canonical happy path)
    - probe rc 126/127 -> sh (bash is missing or not-executable)
    - other rc -> caller surfaces the probe error instead of running a shell
    """

    @pytest.mark.parametrize(
        "probe_rc, expected",
        [
            (0, ("/bin/bash", True)),
            (126, ("/bin/sh", True)),
            (127, ("/bin/sh", True)),
        ],
        ids=["bash-available", "126-not-executable", "127-not-found"],
    )
    def test_runs_shell(self, probe_rc, expected):
        assert _select_shell(probe_rc) == expected

    @pytest.mark.parametrize("probe_rc", [1, 2, 125, -1])
    def test_does_not_run_on_other_returncodes(self, probe_rc):
        shell, should_run = _select_shell(probe_rc)
        assert should_run is False


class TestRunRaisesBackendTimeoutError:
    """``_run`` and ``_run_streaming`` translate ``subprocess.TimeoutExpired``
    into ``BackendTimeoutError`` so callers don't depend on subprocess."""

    def test_run_raises_backend_timeout(self, tmp_path):
        backend = DockerComposeBackend(project_dir=tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=5)
            with pytest.raises(BackendTimeoutError):
                backend._run(["docker", "ps"], timeout=5)

    def test_run_streaming_raises_backend_timeout(self, tmp_path):
        backend = DockerComposeBackend(project_dir=tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=5)
            with pytest.raises(BackendTimeoutError):
                backend._run_streaming(["docker", "logs", "x"], timeout=5)


# ---------------------------------------------------------------------------
# DeploymentConfig model tests
# ---------------------------------------------------------------------------


class TestDeploymentConfig:
    """Tests for the DeploymentConfig Pydantic model."""

    def test_default_provider_is_docker_compose(self):
        cfg = DeploymentConfig()
        assert cfg.provider == "docker-compose"
        assert cfg.project_name == "aptl"

    def test_accepts_docker_compose(self):
        cfg = DeploymentConfig(provider="docker-compose")
        assert cfg.provider == "docker-compose"

    def test_accepts_ssh_compose(self):
        cfg = DeploymentConfig(provider="ssh-compose")
        assert cfg.provider == "ssh-compose"

    def test_rejects_unknown_provider(self):
        with pytest.raises(ValueError, match="Unknown deployment provider"):
            DeploymentConfig(provider="kubernetes")

    def test_ssh_fields_default_to_none(self):
        cfg = DeploymentConfig()
        assert cfg.ssh_host is None
        assert cfg.ssh_user is None
        assert cfg.ssh_key is None
        assert cfg.ssh_port == 22
        assert cfg.remote_dir is None

    def test_ssh_fields_populated(self):
        cfg = DeploymentConfig(
            provider="ssh-compose",
            ssh_host="lab.example.com",
            ssh_user="admin",
            ssh_key="~/.ssh/lab_key",
            ssh_port=2222,
            remote_dir="/opt/aptl",
        )
        assert cfg.ssh_host == "lab.example.com"
        assert cfg.ssh_user == "admin"
        assert cfg.ssh_key == "~/.ssh/lab_key"
        assert cfg.ssh_port == 2222
        assert cfg.remote_dir == "/opt/aptl"


class TestAptlConfigDeployment:
    """Tests for DeploymentConfig in AptlConfig."""

    def test_default_config_has_deployment(self):
        cfg = AptlConfig(lab={"name": "test"})
        assert cfg.deployment.provider == "docker-compose"

    def test_config_with_explicit_deployment(self):
        cfg = AptlConfig(
            lab={"name": "test"},
            deployment={"provider": "ssh-compose", "ssh_host": "server"},
        )
        assert cfg.deployment.provider == "ssh-compose"
        assert cfg.deployment.ssh_host == "server"

    def test_config_without_deployment_key(self):
        """Config JSON without deployment key uses defaults."""
        cfg = AptlConfig(
            lab={"name": "test"},
            containers={"wazuh": True, "kali": False},
        )
        assert cfg.deployment.provider == "docker-compose"

    def test_load_config_with_deployment(self, tmp_path):
        from aptl.core.config import load_config

        config_file = tmp_path / "aptl.json"
        config_file.write_text(
            json.dumps(
                {
                    "lab": {"name": "test"},
                    "deployment": {
                        "provider": "docker-compose",
                        "project_name": "mylab",
                    },
                }
            )
        )

        cfg = load_config(config_file)
        assert cfg.deployment.project_name == "mylab"


# ---------------------------------------------------------------------------
# DockerComposeBackend tests
# ---------------------------------------------------------------------------


class TestDockerComposeBackend:
    """Tests for the Docker Compose deployment backend."""

    def _make_backend(self, tmp_path: Path) -> DockerComposeBackend:
        return DockerComposeBackend(project_dir=tmp_path, project_name="test")

    def test_start_calls_compose_up(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = backend.start(["wazuh", "kali"])

        assert result.success is True
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "docker"
        assert cmd[1] == "compose"
        # Project name pinned so start/stop act on the same project as
        # status/orphan-cleanup regardless of the worktree directory name.
        assert cmd[2] == "-p"
        assert cmd[3] == "test"
        assert "--profile" in cmd
        assert "wazuh" in cmd
        assert "kali" in cmd
        assert "up" in cmd
        assert "--build" in cmd
        assert "-d" in cmd
        assert mock_run.call_args[1]["cwd"] == tmp_path

    def test_start_without_build(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = backend.start(["wazuh"], build=False)

        assert result.success is True
        cmd = mock_run.call_args[0][0]
        assert "--build" not in cmd

    def test_start_dedupes_duplicate_local_build_tags(self, tmp_path):
        (tmp_path / "docker-compose.yml").write_text(
            """
services:
  sidecar-one:
    image: aptl-sidecar:local
    build:
      context: .
      dockerfile: containers/sidecar/Dockerfile
  sidecar-two:
    image: aptl-sidecar:local
    build:
      context: .
      dockerfile: containers/sidecar/Dockerfile
  unique:
    image: aptl-unique:local
    build:
      context: .
      dockerfile: containers/unique/Dockerfile
""",
            encoding="utf-8",
        )
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = backend.start(["soc"])

        assert result.success is True
        override_path = tmp_path / ".aptl" / "compose-build-dedupe.yml"
        override = override_path.read_text(encoding="utf-8")
        assert "sidecar-two:" in override
        assert "build: !reset null" in override
        assert "pull_policy: never" in override
        assert "sidecar-one:" not in override
        assert "unique:" not in override
        cmd = mock_run.call_args[0][0]
        assert cmd[:4] == ["docker", "compose", "-p", "test"]
        assert ["-f", str(tmp_path / "docker-compose.yml")] == cmd[4:6]
        assert ["-f", str(override_path)] == cmd[6:8]
        assert "--build" in cmd

    def test_start_returns_failure_on_error(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="compose up failed"
            )
            result = backend.start(["wazuh"])

        assert result.success is False
        assert "compose up failed" in result.error

    def test_realize_reconciles_project_networks_after_start(self, tmp_path):
        backend = self._make_backend(tmp_path)
        spec = DeploymentRealizationSpec(
            profiles=("kali",),
            nodes=(
                DeploymentNodeRealization(
                    address="provision.node.red-workbench",
                    name="red-workbench",
                    service_name="kali",
                    container_name="aptl-kali",
                    networks=("redteam-net", "dmz-net"),
                ),
            ),
            networks=(
                DeploymentNetworkRealization(name="redteam-net"),
                DeploymentNetworkRealization(name="dmz-net"),
            ),
        )
        inspect_payload = json.dumps(
            [
                {
                    "NetworkSettings": {
                        "Networks": {
                            "test_aptl-redteam": {},
                            "test_aptl-dmz": {},
                            "test_aptl-internal": {},
                            "unmanaged": {},
                        }
                    }
                }
            ]
        )

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:4] == ["docker", "compose", "-p", "test"]:
                return MagicMock(returncode=0, stdout="", stderr="")
            if cmd[:3] == ["docker", "network", "ls"]:
                return MagicMock(
                    returncode=0,
                    stdout=("test_aptl-redteam\ntest_aptl-dmz\ntest_aptl-internal\n"),
                    stderr="",
                )
            if cmd[:3] == ["docker", "network", "inspect"]:
                compose_network = (
                    "aptl-redteam" if cmd[3] == "test_aptl-redteam" else "aptl-dmz"
                )
                return MagicMock(
                    returncode=0,
                    stdout=_network_inspect_payload(cmd[3], compose_network),
                    stderr="",
                )
            if cmd[:2] == ["docker", "inspect"]:
                return MagicMock(returncode=0, stdout=inspect_payload, stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run) as mock_run:
            result = backend.realize(spec, build=False)

        assert result.success is True
        commands = [call.args[0] for call in mock_run.call_args_list]
        assert [
            "docker",
            "network",
            "disconnect",
            "test_aptl-internal",
            "aptl-kali",
        ] in commands
        assert all("unmanaged" not in command for command in commands)

    def test_realize_creates_declared_networks_and_connects_static_ip(self, tmp_path):
        backend = self._make_backend(tmp_path)
        spec = DeploymentRealizationSpec(
            profiles=("enterprise",),
            nodes=(
                DeploymentNodeRealization(
                    address="provision.node.customer-portal",
                    name="customer-portal",
                    service_name="webapp",
                    container_name="aptl-webapp",
                    networks=("dmz-net",),
                    network_attachments=(
                        DeploymentNetworkAttachment(
                            network="dmz-net",
                            ipv4_address="172.20.1.20",
                        ),
                    ),
                ),
            ),
            networks=(
                DeploymentNetworkRealization(
                    name="dmz-net",
                    cidr="172.20.1.0/24",
                    gateway="172.20.1.1",
                    internal=True,
                ),
            ),
        )
        inspect_payload = json.dumps([{"NetworkSettings": {"Networks": {}}}])
        network_ls_calls = 0

        def fake_run(cmd, **kwargs):
            nonlocal network_ls_calls
            del kwargs
            if cmd[:3] == ["docker", "network", "ls"]:
                network_ls_calls += 1
                stdout = "" if network_ls_calls == 1 else "test_aptl-dmz\n"
                return MagicMock(returncode=0, stdout=stdout, stderr="")
            if cmd[:4] == ["docker", "compose", "-p", "test"]:
                return MagicMock(returncode=0, stdout="", stderr="")
            if cmd[:2] == ["docker", "inspect"]:
                return MagicMock(returncode=0, stdout=inspect_payload, stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run) as mock_run:
            result = backend.realize(spec, build=False)

        assert result.success is True
        commands = [call.args[0] for call in mock_run.call_args_list]
        create_command = [
            "docker",
            "network",
            "create",
            "--driver",
            "bridge",
            "--label",
            "com.docker.compose.project=test",
            "--label",
            "com.docker.compose.network=aptl-dmz",
            "--label",
            "org.aptl.realization.network=true",
            "--internal",
            "--subnet",
            "172.20.1.0/24",
            "--gateway",
            "172.20.1.1",
            "test_aptl-dmz",
        ]
        assert create_command in commands
        compose_up = next(
            command for command in commands if command[-2:] == ["up", "-d"]
        )
        assert commands.index(create_command) < commands.index(compose_up)
        assert [
            "docker",
            "network",
            "connect",
            "--ip",
            "172.20.1.20",
            "--alias",
            "webapp",
            "--alias",
            "customer-portal",
            "test_aptl-dmz",
            "aptl-webapp",
        ] in commands

    def test_realize_reports_overlapping_external_network_before_create(self, tmp_path):
        backend = self._make_backend(tmp_path)
        spec = DeploymentRealizationSpec(
            profiles=("enterprise",),
            nodes=(),
            networks=(
                DeploymentNetworkRealization(
                    name="dmz-net",
                    cidr="172.20.1.0/24",
                    gateway="172.20.1.1",
                ),
            ),
        )
        inspect_payload = json.dumps(
            [
                {
                    "IPAM": {
                        "Config": [
                            {
                                "Subnet": "172.20.0.0/16",
                                "Gateway": "172.20.0.1",
                            }
                        ]
                    },
                    "Containers": {},
                    "Labels": {},
                }
            ]
        )

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:3] == ["docker", "network", "ls"] and "--filter" in cmd:
                return MagicMock(returncode=0, stdout="", stderr="")
            if cmd[:3] == ["docker", "network", "ls"]:
                return MagicMock(
                    returncode=0,
                    stdout="aptl-workshop-main_default\n",
                    stderr="",
                )
            if cmd[:3] == ["docker", "network", "inspect"]:
                return MagicMock(returncode=0, stdout=inspect_payload, stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run) as mock_run:
            result = backend.realize(spec, build=False)

        assert result.success is False
        assert "dmz-net (172.20.1.0/24)" in result.error
        assert "aptl-workshop-main_default" in result.error
        assert "172.20.0.0/16" in result.error
        assert "docker network rm aptl-workshop-main_default" in result.error
        assert "aptl lab start" in result.error
        commands = [call.args[0] for call in mock_run.call_args_list]
        assert all(
            command[:3] != ["docker", "network", "create"] for command in commands
        )
        assert all(
            command[:4] != ["docker", "compose", "-p", "test"] for command in commands
        )

    def test_realize_reconnects_network_when_static_ip_drifts(self, tmp_path):
        backend = self._make_backend(tmp_path)
        spec = DeploymentRealizationSpec(
            profiles=("enterprise",),
            nodes=(
                DeploymentNodeRealization(
                    address="provision.node.customer-portal",
                    name="customer-portal",
                    service_name="webapp",
                    container_name="aptl-webapp",
                    networks=("dmz-net",),
                    network_attachments=(
                        DeploymentNetworkAttachment(
                            network="dmz-net",
                            ipv4_address="172.20.1.20",
                        ),
                    ),
                ),
            ),
            networks=(DeploymentNetworkRealization(name="dmz-net"),),
        )
        inspect_payload = json.dumps(
            [
                {
                    "NetworkSettings": {
                        "Networks": {"test_aptl-dmz": {"IPAddress": "172.20.1.99"}}
                    }
                }
            ]
        )

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:4] == ["docker", "compose", "-p", "test"]:
                return MagicMock(returncode=0, stdout="", stderr="")
            if cmd[:3] == ["docker", "network", "ls"]:
                return MagicMock(returncode=0, stdout="test_aptl-dmz\n", stderr="")
            if cmd[:3] == ["docker", "network", "inspect"]:
                return MagicMock(
                    returncode=0,
                    stdout=_network_inspect_payload("test_aptl-dmz", "aptl-dmz"),
                    stderr="",
                )
            if cmd[:2] == ["docker", "inspect"]:
                return MagicMock(returncode=0, stdout=inspect_payload, stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run) as mock_run:
            result = backend.realize(spec, build=False)

        assert result.success is True
        commands = [call.args[0] for call in mock_run.call_args_list]
        assert [
            "docker",
            "network",
            "disconnect",
            "test_aptl-dmz",
            "aptl-webapp",
        ] in commands
        assert [
            "docker",
            "network",
            "connect",
            "--ip",
            "172.20.1.20",
            "--alias",
            "webapp",
            "--alias",
            "customer-portal",
            "test_aptl-dmz",
            "aptl-webapp",
        ] in commands

    def test_realize_rejects_existing_network_policy_mismatch(self, tmp_path):
        backend = self._make_backend(tmp_path)
        spec = DeploymentRealizationSpec(
            profiles=("enterprise",),
            nodes=(
                DeploymentNodeRealization(
                    address="provision.node.customer-portal",
                    name="customer-portal",
                    service_name="webapp",
                    container_name="aptl-webapp",
                    networks=("dmz-net",),
                ),
            ),
            networks=(
                DeploymentNetworkRealization(
                    name="dmz-net",
                    cidr="172.20.1.0/24",
                    gateway="172.20.1.1",
                    internal=True,
                ),
            ),
        )

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:3] == ["docker", "network", "ls"]:
                return MagicMock(returncode=0, stdout="test_aptl-dmz\n", stderr="")
            if cmd[:3] == ["docker", "network", "inspect"]:
                return MagicMock(
                    returncode=0,
                    stdout=_network_inspect_payload(
                        "test_aptl-dmz",
                        "aptl-dmz",
                        internal=False,
                        subnet="172.20.1.0/24",
                        gateway="172.20.1.1",
                        realization=False,
                    ),
                    stderr="",
                )
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run) as mock_run:
            result = backend.realize(spec, build=False)

        assert result.success is False
        assert "does not match realized network dmz-net" in result.error
        assert "org.aptl.realization.network" in result.error
        assert "internal expected True" in result.error
        commands = [call.args[0] for call in mock_run.call_args_list]
        assert all(
            command[:4] != ["docker", "compose", "-p", "test"] for command in commands
        )

    def test_realize_skips_nodes_without_declared_networks(self, tmp_path):
        backend = self._make_backend(tmp_path)
        spec = DeploymentRealizationSpec(
            profiles=("kali",),
            nodes=(
                DeploymentNodeRealization(
                    address="provision.node.legacy",
                    name="legacy",
                    service_name="kali",
                    container_name="aptl-kali",
                    networks=(),
                ),
            ),
            networks=(),
        )

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:4] == ["docker", "compose", "-p", "test"]:
                return MagicMock(returncode=0, stdout="", stderr="")
            if cmd[:3] == ["docker", "network", "ls"]:
                return MagicMock(
                    returncode=0,
                    stdout="test_aptl-internal\n",
                    stderr="",
                )
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run) as mock_run:
            result = backend.realize(spec, build=False)

        assert result.success is True
        commands = [call.args[0] for call in mock_run.call_args_list]
        assert all(
            command[:3] != ["docker", "network", "disconnect"] for command in commands
        )

    def test_realize_returns_start_failure_without_reconciliation(self, tmp_path):
        backend = self._make_backend(tmp_path)
        spec = DeploymentRealizationSpec(profiles=("kali",), nodes=(), networks=())

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="compose failed"
            )
            result = backend.realize(spec, build=False)

        assert result.success is False
        assert result.error == "compose failed"
        assert mock_run.call_count == 1

    def test_realize_reports_missing_managed_networks(self, tmp_path):
        backend = self._make_backend(tmp_path)
        spec = DeploymentRealizationSpec(
            profiles=("kali",),
            nodes=(
                DeploymentNodeRealization(
                    address="provision.node.red-workbench",
                    name="red-workbench",
                    service_name="kali",
                    container_name="aptl-kali",
                    networks=("dmz-net",),
                ),
            ),
            networks=(DeploymentNetworkRealization(name="dmz-net"),),
        )

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:4] == ["docker", "compose", "-p", "test"]:
                return MagicMock(returncode=0, stdout="", stderr="")
            if cmd[:3] == ["docker", "network", "ls"]:
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            result = backend.realize(spec, build=False)

        assert result.success is False
        assert "managed networks were not visible" in result.error

    def test_realize_reports_unmatched_and_uninspectable_nodes(self, tmp_path):
        backend = self._make_backend(tmp_path)
        spec = DeploymentRealizationSpec(
            profiles=("kali",),
            nodes=(
                DeploymentNodeRealization(
                    address="provision.node.portal",
                    name="portal",
                    service_name="webapp",
                    container_name="aptl-webapp",
                    networks=("unknown-net",),
                ),
                DeploymentNodeRealization(
                    address="provision.node.red-workbench",
                    name="red-workbench",
                    service_name="kali",
                    container_name="aptl-kali",
                    networks=("dmz-net",),
                ),
            ),
            networks=(DeploymentNetworkRealization(name="dmz-net"),),
        )

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:4] == ["docker", "compose", "-p", "test"]:
                return MagicMock(returncode=0, stdout="", stderr="")
            if cmd[:3] == ["docker", "network", "ls"]:
                return MagicMock(returncode=0, stdout="test_aptl-dmz\n", stderr="")
            if cmd[:3] == ["docker", "network", "inspect"]:
                return MagicMock(
                    returncode=0,
                    stdout=_network_inspect_payload("test_aptl-dmz", "aptl-dmz"),
                    stderr="",
                )
            if cmd[:2] == ["docker", "inspect"]:
                return MagicMock(returncode=1, stdout="", stderr="missing")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            result = backend.realize(spec, build=False)

        assert result.success is False
        assert "No managed Docker network matched" in result.error
        assert "aptl-kali" in result.error

    def test_realize_reports_network_reconciliation_command_failures(self, tmp_path):
        backend = self._make_backend(tmp_path)
        spec = DeploymentRealizationSpec(
            profiles=("kali",),
            nodes=(
                DeploymentNodeRealization(
                    address="provision.node.red-workbench",
                    name="red-workbench",
                    service_name="kali",
                    container_name="aptl-kali",
                    networks=("dmz-net",),
                ),
            ),
            networks=(DeploymentNetworkRealization(name="dmz-net"),),
        )
        inspect_payload = json.dumps(
            [
                {
                    "NetworkSettings": {
                        "Networks": {
                            "test_aptl-internal": {},
                        }
                    }
                }
            ]
        )

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:4] == ["docker", "compose", "-p", "test"]:
                return MagicMock(returncode=0, stdout="", stderr="")
            if cmd[:3] == ["docker", "network", "ls"]:
                return MagicMock(
                    returncode=0,
                    stdout="test_aptl-dmz\ntest_aptl-internal\n",
                    stderr="",
                )
            if cmd[:3] == ["docker", "network", "inspect"]:
                return MagicMock(
                    returncode=0,
                    stdout=_network_inspect_payload("test_aptl-dmz", "aptl-dmz"),
                    stderr="",
                )
            if cmd[:2] == ["docker", "inspect"]:
                return MagicMock(returncode=0, stdout=inspect_payload, stderr="")
            if cmd[:3] == ["docker", "network", "disconnect"]:
                return MagicMock(returncode=1, stdout="", stderr="disconnect failed")
            if cmd[:3] == ["docker", "network", "connect"]:
                return MagicMock(returncode=1, stdout="", stderr="connect failed")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            result = backend.realize(spec, build=False)

        assert result.success is False
        assert "Failed to disconnect aptl-kali" in result.error
        assert "Failed to connect aptl-kali" in result.error

    def test_realization_network_helpers_handle_edge_cases(self):
        assert _container_networks({"NetworkSettings": {"Networks": None}}) == set()
        assert _network_name_candidates("   ", "test") == ()
        assert "test_web" in _network_name_candidates("aptl-web", "test")
        desired, missing = _resolve_realization_networks(
            ("dmz-net", "unknown-net"),
            {"test_aptl-dmz"},
            "test",
        )
        assert desired == {"test_aptl-dmz"}
        assert missing == ["unknown-net"]

    def test_realize_pulls_builds_and_overrides_images(self, tmp_path):
        backend = self._make_backend(tmp_path)
        digest = "sha256:" + "a" * 64
        spec = DeploymentRealizationSpec(
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
                DeploymentImageRealization(
                    address="provision.node.custom",
                    service_name="custom",
                    source_name="aptl-custom",
                    source_version="aptl-custom@sha256:" + "b" * 64,
                    image_ref="aptl-custom:local",
                    mode="build",
                    policy_rule="project-build-provenance",
                    dockerfile_path="containers/custom/Dockerfile",
                    context_path=".",
                    provenance={"instructions": 1, "layers": 1},
                ),
            ),
        )
        (tmp_path / "docker-compose.yml").write_text("services: {}\n")
        real_write_text = Path.write_text

        def write_text_with_windows_default(
            path,
            data,
            encoding=None,
            errors=None,
            newline=None,
        ):
            if newline is None:
                newline = "\r\n"
            return real_write_text(
                path,
                data,
                encoding=encoding,
                errors=errors,
                newline=newline,
            )

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:3] == ["docker", "network", "ls"]:
                return MagicMock(returncode=0, stdout="test_aptl-internal\n", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with (
            patch.object(Path, "write_text", new=write_text_with_windows_default),
            patch("subprocess.run", side_effect=fake_run) as mock_run,
        ):
            result = backend.realize(spec, build=False)

        assert result.success is True
        commands = [call.args[0] for call in mock_run.call_args_list]
        assert ["docker", "pull", f"postgres@{digest}"] in commands
        assert [
            "docker",
            "build",
            "-t",
            "aptl-custom:local",
            "-f",
            "containers/custom/Dockerfile",
            ".",
        ] in commands
        compose_up = next(
            command for command in commands if command[-2:] == ["up", "-d"]
        )
        assert "-f" in compose_up
        override_paths = [
            compose_up[index + 1]
            for index, token in enumerate(compose_up)
            if token == "-f"
        ]
        assert str(tmp_path / "docker-compose.yml") in override_paths
        override_path = tmp_path / ".aptl" / "realization" / "compose-images.yml"
        assert str(override_path) in override_paths
        override = override_path.read_text()
        assert "db:" in override
        assert f"image: postgres@{digest}" in override
        assert "custom:" in override
        assert "image: aptl-custom:local" in override
        assert "build: null" in override
        assert b"\r\n" not in override_path.read_bytes()

    def test_stop_calls_compose_down(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = backend.stop(["wazuh"])

        assert result.success is True
        commands = [call.args[0] for call in mock_run.call_args_list]
        cmd = commands[0]
        assert cmd[2] == "-p"
        assert cmd[3] == "test"
        assert "down" in cmd
        assert "-v" not in cmd

    def test_stop_with_volumes(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = backend.stop(["wazuh"], remove_volumes=True)

        assert result.success is True
        cmd = mock_run.call_args_list[0][0][0]
        assert "-v" in cmd

    def test_stop_removes_leftover_project_networks(self, tmp_path):
        backend = self._make_backend(tmp_path)
        network_ls_command = None

        def fake_run(cmd, **kwargs):
            nonlocal network_ls_command
            del kwargs
            if cmd[:3] == ["docker", "network", "ls"]:
                network_ls_command = cmd
                return MagicMock(
                    returncode=0,
                    stdout="test_aptl-dmz\ntest_aptl-isolated\n",
                    stderr="",
                )
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run) as mock_run:
            result = backend.stop(["wazuh"])

        assert result.success is True
        assert network_ls_command is not None
        assert "label=org.aptl.realization.network=true" in network_ls_command
        commands = [call.args[0] for call in mock_run.call_args_list]
        assert ["docker", "network", "rm", "test_aptl-dmz"] in commands
        assert ["docker", "network", "rm", "test_aptl-isolated"] in commands

    def test_stop_returns_failure(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="network error"
            )
            result = backend.stop([])

        assert result.success is False

    def test_status_parses_json_array(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[{"Name":"aptl-victim","State":"running"}]',
                stderr="",
            )
            status = backend.status()

        assert status.running is True
        assert len(status.containers) == 1

    def test_status_uses_configured_project_name(self, tmp_path):
        backend = self._make_backend(tmp_path / "aptl-workshop-main.h9Jare")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[{"Name":"aptl-victim","State":"running"}]',
                stderr="",
            )
            status = backend.status()

        assert status.running is True
        cmd = mock_run.call_args[0][0]
        assert cmd[:4] == ["docker", "compose", "-p", "test"]
        assert cmd[-3:] == ["ps", "--format", "json"]
        assert mock_run.call_args[1]["cwd"] == tmp_path / "aptl-workshop-main.h9Jare"

    def test_status_parses_ndjson(self, tmp_path):
        backend = self._make_backend(tmp_path)
        ndjson = (
            '{"Name":"aptl-victim","State":"running"}\n'
            '{"Name":"aptl-kali","State":"running"}'
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=ndjson, stderr="")
            status = backend.status()

        assert status.running is True
        assert len(status.containers) == 2

    def test_status_handles_empty_output(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            status = backend.status()

        assert status.running is False
        assert status.containers == []

    def test_status_handles_compose_failure(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="docker not found"
            )
            status = backend.status()

        assert status.running is False
        assert "docker not found" in status.error

    def test_status_handles_invalid_json(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="not json", stderr=""
            )
            status = backend.status()

        assert status.running is False
        assert "parse" in status.error.lower()

    def test_kill_runs_compose_kill_then_down(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            success, error = backend.kill(["wazuh", "kali"])

        assert success is True
        assert error == ""
        assert mock_run.call_count >= 2

        first_cmd = mock_run.call_args_list[0][0][0]
        assert "kill" in first_cmd
        second_cmd = mock_run.call_args_list[1][0][0]
        assert "down" in second_cmd

    def test_kill_handles_timeout(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=30)
            success, error = backend.kill(["wazuh"])

        assert success is False

    def test_kill_handles_file_not_found(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("docker not found")
            success, error = backend.kill(["wazuh"])

        assert success is False
        assert "docker compose kill failed" in error

    def test_pull_images_success(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            warnings = backend.pull_images(["wazuh/wazuh-manager:4.12.0"])

        assert warnings == []
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "pull", "wazuh/wazuh-manager:4.12.0"]

    def test_pull_images_returns_warnings(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="not found"
            )
            warnings = backend.pull_images(["bad:image"])

        assert len(warnings) == 1
        assert "bad:image" in warnings[0]

    def test_pull_images_handles_oserror(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = OSError("docker binary not found")
            warnings = backend.pull_images(["some:image"])

        assert len(warnings) == 1

    def test_project_dir_property(self, tmp_path):
        backend = self._make_backend(tmp_path)
        assert backend.project_dir == tmp_path

    def test_project_name_property(self, tmp_path):
        backend = DockerComposeBackend(project_dir=tmp_path, project_name="mylab")
        assert backend.project_name == "mylab"


# ---------------------------------------------------------------------------
# DockerComposeBackend container interaction tests (CLI-004)
# ---------------------------------------------------------------------------


class TestDockerComposeBackendContainerInteraction:
    """Tests for the 6 container-interaction methods added under CLI-004."""

    def _make_backend(self, tmp_path: Path) -> DockerComposeBackend:
        return DockerComposeBackend(project_dir=tmp_path, project_name="test")

    # container_list -------------------------------------------------------

    def test_container_list_uses_compose_ps_with_all_flag(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.container_list()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "docker"
        assert cmd[1] == "compose"
        # `-p <project_name>` scopes the listing to the configured
        # compose project (CLI-004 codex finding).
        assert cmd[2] == "-p"
        assert cmd[3] == "test"
        assert "ps" in cmd
        assert "-a" in cmd
        assert "--format" in cmd
        assert "json" in cmd
        assert mock_run.call_args[1]["cwd"] == tmp_path

    def test_container_list_omits_all_when_requested(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.container_list(all_containers=False)
        cmd = mock_run.call_args[0][0]
        assert "-a" not in cmd

    def test_container_list_parses_ndjson(self, tmp_path):
        backend = self._make_backend(tmp_path)
        ndjson = (
            '{"Name":"aptl-victim","State":"running"}\n'
            '{"Name":"aptl-kali","State":"exited"}'
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=ndjson, stderr="")
            containers = backend.container_list()
        assert len(containers) == 2
        assert containers[0]["Name"] == "aptl-victim"
        assert containers[1]["State"] == "exited"

    def test_container_list_parses_json_array(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[{"Name":"aptl-victim","State":"running"}]',
                stderr="",
            )
            containers = backend.container_list()
        assert len(containers) == 1

    def test_container_list_empty_when_no_output(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            containers = backend.container_list()
        assert containers == []

    def test_container_list_empty_on_compose_failure(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="not running"
            )
            containers = backend.container_list()
        assert containers == []

    def test_container_list_empty_on_invalid_json(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="not-json", stderr=""
            )
            containers = backend.container_list()
        assert containers == []

    # container_logs (streaming) -------------------------------------------

    def test_container_logs_streams_without_capture(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            exit_code = backend.container_logs("aptl-victim")
        assert exit_code == 0
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "logs", "aptl-victim"]
        # Streaming: no capture_output kwarg
        assert "capture_output" not in mock_run.call_args[1]

    def test_container_logs_with_follow_and_tail(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            backend.container_logs("aptl-victim", follow=True, tail=100)
        cmd = mock_run.call_args[0][0]
        assert "-f" in cmd
        assert "--tail" in cmd
        tail_idx = cmd.index("--tail")
        assert cmd[tail_idx + 1] == "100"
        assert "aptl-victim" in cmd

    def test_container_logs_propagates_exit_code(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=2)
            exit_code = backend.container_logs("aptl-missing")
        assert exit_code == 2

    # container_logs_capture -----------------------------------------------

    def test_container_logs_capture_runs_docker_logs(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="line1\nline2\n", stderr=""
            )
            result = backend.container_logs_capture("aptl-victim")
        cmd = mock_run.call_args[0][0]
        assert cmd[:3] == ["docker", "logs", "aptl-victim"]
        assert mock_run.call_args[1].get("capture_output") is True
        assert "line1" in result.stdout

    def test_container_logs_capture_passes_since_and_until(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.container_logs_capture(
                "aptl-suricata",
                since="2026-05-03T00:00:00Z",
                until="2026-05-03T01:00:00Z",
            )
        cmd = mock_run.call_args[0][0]
        assert "--since" in cmd
        since_idx = cmd.index("--since")
        assert cmd[since_idx + 1] == "2026-05-03T00:00:00Z"
        assert "--until" in cmd
        until_idx = cmd.index("--until")
        assert cmd[until_idx + 1] == "2026-05-03T01:00:00Z"

    # container_shell ------------------------------------------------------

    def test_container_shell_uses_docker_exec_it(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            exit_code = backend.container_shell("aptl-kali", shell="/bin/bash")
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "exec", "-it", "aptl-kali", "/bin/bash"]
        assert exit_code == 0
        # Streaming: no capture_output
        assert "capture_output" not in mock_run.call_args[1]

    # The bash-vs-sh auto-detect is now driven by a non-interactive
    # probe (see TestDockerComposeBackendContainerInteraction.
    # test_container_shell_probe_*).

    # container_exec -------------------------------------------------------

    def test_container_exec_runs_docker_exec_captured(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="hello", stderr="")
            result = backend.container_exec("aptl-victim", ["echo", "hello"])
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "exec", "aptl-victim", "echo", "hello"]
        assert "-it" not in cmd
        assert mock_run.call_args[1].get("capture_output") is True
        assert result.stdout == "hello"

    def test_container_exec_passes_timeout(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.container_exec("aptl-victim", ["true"], timeout=5)
        assert mock_run.call_args[1]["timeout"] == 5

    # container_restart ----------------------------------------------------

    def test_container_restart_issues_docker_restart(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.container_restart("aptl-wazuh-manager")
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "restart", "aptl-wazuh-manager"]

    def test_container_restart_logs_warning_on_nonzero_exit(self, tmp_path, caplog):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="No such container: whatever"
            )
            caplog.set_level(logging.WARNING, logger="aptl")
            backend.container_restart("aptl-wazuh-manager")
        # Best-effort — no exception raised, but the failure is logged.
        assert any("docker restart" in rec.getMessage() for rec in caplog.records)

    # container_inspect ----------------------------------------------------

    def test_container_inspect_parses_first_element(self, tmp_path):
        backend = self._make_backend(tmp_path)
        payload = json.dumps(
            [
                {
                    "Id": "abc",
                    "NetworkSettings": {"Networks": {"net": {"IPAddress": "1.2.3.4"}}},
                },
            ]
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=payload, stderr="")
            data = backend.container_inspect("aptl-victim")
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "inspect", "aptl-victim"]
        assert data["Id"] == "abc"

    def test_container_inspect_returns_empty_dict_on_failure(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="No such object"
            )
            data = backend.container_inspect("aptl-missing")
        assert data == {}

    def test_container_inspect_returns_empty_dict_on_invalid_json(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="not-json", stderr=""
            )
            data = backend.container_inspect("aptl-victim")
        assert data == {}

    def test_container_inspect_returns_empty_dict_on_empty_array(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="[]", stderr="")
            data = backend.container_inspect("aptl-victim")
        assert data == {}

    # container_exists ----------------------------------------------------

    def test_container_exists_true_for_project_container(self, tmp_path):
        backend = self._make_backend(tmp_path)
        payload = json.dumps(
            [
                {
                    "Config": {"Labels": {"com.docker.compose.project": "test"}},
                }
            ]
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=payload, stderr="")
            assert backend.container_exists("aptl-victim") is True

    def test_container_exists_false_for_other_project(self, tmp_path):
        backend = self._make_backend(tmp_path)
        payload = json.dumps(
            [
                {
                    "Config": {
                        "Labels": {"com.docker.compose.project": "other-tenant"}
                    },
                }
            ]
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=payload, stderr="")
            assert backend.container_exists("aptl-evil") is False

    def test_container_exists_false_when_no_compose_label(self, tmp_path):
        backend = self._make_backend(tmp_path)
        payload = json.dumps([{"Config": {"Labels": {"unrelated": "value"}}}])
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=payload, stderr="")
            assert backend.container_exists("aptl-victim") is False

    def test_container_exists_false_on_inspect_failure(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="No such container"
            )
            assert backend.container_exists("aptl-missing") is False

    def test_container_exists_false_when_labels_missing(self, tmp_path):
        backend = self._make_backend(tmp_path)
        payload = json.dumps([{"Config": {}}])
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=payload, stderr="")
            assert backend.container_exists("aptl-victim") is False

    # Host inventory ------------------------------------------------------

    def test_host_versions_returns_docker_and_compose(self, tmp_path):
        backend = self._make_backend(tmp_path)

        def _fake(args, **kw):
            if "compose" in args:
                return MagicMock(returncode=0, stdout="2.23.0\n", stderr="")
            return MagicMock(returncode=0, stdout="24.0.7\n", stderr="")

        with patch("subprocess.run", side_effect=_fake):
            versions = backend.host_versions()
        assert versions == {"docker": "24.0.7", "compose": "2.23.0"}

    def test_host_versions_handles_failure(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="boom")
            versions = backend.host_versions()
        assert versions == {"docker": "", "compose": ""}

    def test_host_list_lab_containers_parses_tsv(self, tmp_path):
        backend = self._make_backend(tmp_path)
        line = (
            "aptl-victim\taptl/victim:latest\tabc\tUp 5m (healthy)\t"
            "service=victim\t0.0.0.0:2022->22/tcp"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=line, stderr="")
            rows = backend.host_list_lab_containers()
        cmd = mock_run.call_args[0][0]
        assert "docker" in cmd and "ps" in cmd and "-a" in cmd
        assert any("name=aptl-" in arg for arg in cmd)
        # Scoping by compose project label keeps shared-daemon snapshots
        # from leaking other tenants' aptl-* containers.
        assert any("label=com.docker.compose.project=test" in arg for arg in cmd)
        # Bounded execution: a stalled daemon must not hang snapshot capture.
        assert mock_run.call_args[1]["timeout"] == 15
        assert len(rows) == 1
        row = rows[0]
        assert row["name"] == "aptl-victim"
        assert row["image"] == "aptl/victim:latest"
        assert row["id"] == "abc"
        assert row["status"] == "Up 5m (healthy)"
        assert row["labels"] == {"service": "victim"}
        assert row["ports"] == ["0.0.0.0:2022->22/tcp"]

    def test_host_list_lab_containers_skips_short_lines(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="too\tfew", stderr=""
            )
            assert backend.host_list_lab_containers() == []

    def test_host_list_lab_containers_returns_empty_on_error(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="docker missing"
            )
            assert backend.host_list_lab_containers() == []

    def test_host_list_lab_networks_filters_by_prefix(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="aptl_security\naptl_internal\n", stderr=""
            )
            nets = backend.host_list_lab_networks("aptl")
        assert nets == ["aptl_security", "aptl_internal"]
        cmd = mock_run.call_args[0][0]
        assert any("name=aptl" in arg for arg in cmd)
        # Compose-project scoping prevents shared-daemon network leak.
        assert any("label=com.docker.compose.project=test" in arg for arg in cmd)
        assert mock_run.call_args[1]["timeout"] == 15

    def test_host_list_lab_networks_returns_empty_on_error(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
            assert backend.host_list_lab_networks("aptl") == []

    def test_host_list_networks_returns_all_visible_networks(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="bridge\naptl-workshop-main_default\n",
                stderr="",
            )
            nets = backend.host_list_networks()
        assert nets == ["bridge", "aptl-workshop-main_default"]
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "network", "ls", "--format", "{{.Name}}"]
        assert mock_run.call_args[1]["timeout"] == 15

    def test_host_list_networks_returns_empty_on_error(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
            assert backend.host_list_networks() == []

    def test_host_inspect_network_parses_subnet_and_containers(self, tmp_path):
        backend = self._make_backend(tmp_path)
        payload = json.dumps(
            [
                {
                    "IPAM": {
                        "Config": [{"Subnet": "172.20.0.0/16", "Gateway": "172.20.0.1"}]
                    },
                    "Containers": {
                        "abc": {"Name": "aptl-victim"},
                        "def": {"Name": "aptl-kali"},
                    },
                }
            ]
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=payload, stderr="")
            info = backend.host_inspect_network("aptl_security")
        assert info["name"] == "aptl_security"
        assert info["subnet"] == "172.20.0.0/16"
        assert info["gateway"] == "172.20.0.1"
        assert info["containers"] == ["aptl-kali", "aptl-victim"]

    def test_host_inspect_network_empty_on_failure(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="not found"
            )
            assert backend.host_inspect_network("missing") == {}

    def test_host_inspect_network_empty_on_invalid_json(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="not-json", stderr=""
            )
            assert backend.host_inspect_network("net") == {}

    def test_container_shell_probe_then_bash_when_available(self, tmp_path):
        """Auto-fallback probes bash non-interactively first."""
        backend = self._make_backend(tmp_path)
        # First call: probe (captured). Second call: streaming bash.
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),  # probe ok
                MagicMock(returncode=0),  # interactive
            ]
            rc = backend.container_shell("aptl-victim")
        assert rc == 0
        assert mock_run.call_count == 2
        probe_cmd = mock_run.call_args_list[0][0][0]
        assert "/bin/bash" in probe_cmd
        assert "-c" in probe_cmd
        assert "true" in probe_cmd
        # Probe is captured (returns CompletedProcess).
        assert mock_run.call_args_list[0][1].get("capture_output") is True
        # Interactive call streams (no capture_output).
        interactive_cmd = mock_run.call_args_list[1][0][0]
        assert interactive_cmd[:3] == ["docker", "exec", "-it"]
        assert interactive_cmd[-1] == "/bin/bash"
        assert "capture_output" not in mock_run.call_args_list[1][1]

    def test_container_shell_probe_falls_back_to_sh_on_127(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=127, stdout="", stderr=""),  # probe says no bash
                MagicMock(returncode=0),  # interactive sh
            ]
            rc = backend.container_shell("aptl-alpine")
        assert rc == 0
        sh_cmd = mock_run.call_args_list[1][0][0]
        assert sh_cmd[-1] == "/bin/sh"

    def test_container_shell_probe_failure_returns_probe_exit(self, tmp_path):
        """Non-bash-related probe failures (no such container, etc.)
        propagate the exit code rather than masking with sh."""
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="No such container"
            )
            rc = backend.container_shell("aptl-missing")
        assert rc == 1
        assert mock_run.call_count == 1  # no fallback to sh

    def test_container_shell_explicit_shell_skips_probe(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            backend.container_shell("aptl-kali", shell="/bin/zsh")
        # Only one call, the interactive one.
        assert mock_run.call_count == 1
        cmd = mock_run.call_args[0][0]
        assert cmd[-1] == "/bin/zsh"


# ---------------------------------------------------------------------------
# SSHComposeBackend tests
# ---------------------------------------------------------------------------


class TestSSHComposeBackend:
    """Tests for the SSH Remote Docker Compose backend."""

    def _make_backend(
        self,
        tmp_path: Path,
        host: str = "lab.example.com",
        user: str = "admin",
        **kwargs,
    ) -> SSHComposeBackend:
        return SSHComposeBackend(
            project_dir=tmp_path,
            host=host,
            user=user,
            **kwargs,
        )

    def test_docker_host_format(self, tmp_path):
        backend = self._make_backend(tmp_path)
        assert backend.docker_host == "ssh://admin@lab.example.com"

    def test_docker_host_with_custom_port(self, tmp_path):
        backend = self._make_backend(tmp_path, ssh_port=2222)
        assert backend.docker_host == "ssh://admin@lab.example.com:2222"

    def test_host_and_user_properties(self, tmp_path):
        backend = self._make_backend(tmp_path)
        assert backend.host == "lab.example.com"
        assert backend.user == "admin"

    def test_run_sets_docker_host_env(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.start(["wazuh"])

        call_kwargs = mock_run.call_args[1]
        env = call_kwargs["env"]
        assert env["DOCKER_HOST"] == "ssh://admin@lab.example.com"

    def test_run_sets_ssh_identity_when_key_provided(self, tmp_path):
        backend = self._make_backend(tmp_path, ssh_key=_ABS_SSH_KEY)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.start(["wazuh"])

        call_kwargs = mock_run.call_args[1]
        env = call_kwargs["env"]
        assert env["DOCKER_SSH_IDENTITY"] == _ABS_SSH_KEY

    def test_inherits_start_behavior(self, tmp_path):
        """SSH backend start should produce same command structure."""
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = backend.start(["wazuh", "kali"])

        assert result.success is True
        cmd = mock_run.call_args[0][0]
        assert "docker" in cmd
        assert "compose" in cmd
        assert "up" in cmd

    def test_inherits_stop_behavior(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = backend.stop(["wazuh"], remove_volumes=True)

        assert result.success is True
        cmd = mock_run.call_args_list[0][0][0]
        assert "down" in cmd
        assert "-v" in cmd

    def test_validate_connection_success(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="24.0.7\n", stderr=""
            )
            ok, err = backend.validate_connection()

        assert ok is True
        assert err == ""

    def test_validate_connection_failure(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="Connection refused"
            )
            ok, err = backend.validate_connection()

        assert ok is False
        assert "Connection refused" in err

    def test_validate_connection_timeout(self, tmp_path):
        backend = self._make_backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=30)
            ok, err = backend.validate_connection()

        assert ok is False
        assert "timed out" in err

    # CLI-004: streaming methods inject DOCKER_HOST too --------------------

    def test_container_shell_injects_docker_host(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            backend.container_shell("aptl-kali", shell="/bin/bash")
        env = mock_run.call_args[1]["env"]
        assert env["DOCKER_HOST"] == "ssh://admin@lab.example.com"

    def test_container_logs_injects_docker_host(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            backend.container_logs("aptl-victim", follow=True)
        env = mock_run.call_args[1]["env"]
        assert env["DOCKER_HOST"] == "ssh://admin@lab.example.com"

    def test_container_logs_streaming_injects_ssh_identity(self, tmp_path):
        backend = self._make_backend(tmp_path, ssh_key=_ABS_SSH_KEY)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            backend.container_logs("aptl-victim")
        env = mock_run.call_args[1]["env"]
        assert env["DOCKER_SSH_IDENTITY"] == _ABS_SSH_KEY

    def test_container_exec_uses_ssh_path(self, tmp_path):
        """container_exec is captured; verify it inherits the _run override."""
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.container_exec("aptl-victim", ["true"])
        env = mock_run.call_args[1]["env"]
        assert env["DOCKER_HOST"] == "ssh://admin@lab.example.com"

    def test_container_list_uses_ssh_path(self, tmp_path):
        backend = self._make_backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.container_list()
        env = mock_run.call_args[1]["env"]
        assert env["DOCKER_HOST"] == "ssh://admin@lab.example.com"


# ---------------------------------------------------------------------------
# Factory function tests
# ---------------------------------------------------------------------------


class TestGetBackend:
    """Tests for the get_backend factory function."""

    def test_returns_docker_compose_by_default(self, tmp_path):
        config = AptlConfig(lab={"name": "test"})
        backend = get_backend(config, tmp_path)
        assert isinstance(backend, DockerComposeBackend)

    def test_returns_docker_compose_explicitly(self, tmp_path):
        config = AptlConfig(
            lab={"name": "test"},
            deployment={"provider": "docker-compose"},
        )
        backend = get_backend(config, tmp_path)
        assert isinstance(backend, DockerComposeBackend)

    def test_returns_ssh_compose(self, tmp_path):
        config = AptlConfig(
            lab={"name": "test"},
            deployment={
                "provider": "ssh-compose",
                "ssh_host": "server.example.com",
                "ssh_user": "deploy",
            },
        )
        backend = get_backend(config, tmp_path)
        assert isinstance(backend, SSHComposeBackend)
        assert backend.host == "server.example.com"
        assert backend.user == "deploy"

    def test_ssh_compose_requires_host(self, tmp_path):
        config = AptlConfig(
            lab={"name": "test"},
            deployment={
                "provider": "ssh-compose",
                "ssh_user": "deploy",
            },
        )
        with pytest.raises(ValueError, match="ssh_host is required"):
            get_backend(config, tmp_path)

    def test_ssh_compose_requires_user(self, tmp_path):
        config = AptlConfig(
            lab={"name": "test"},
            deployment={
                "provider": "ssh-compose",
                "ssh_host": "server",
            },
        )
        with pytest.raises(ValueError, match="ssh_user is required"):
            get_backend(config, tmp_path)

    def test_passes_project_name(self, tmp_path):
        config = AptlConfig(
            lab={"name": "test"},
            deployment={"provider": "docker-compose", "project_name": "mylab"},
        )
        backend = get_backend(config, tmp_path)
        assert isinstance(backend, DockerComposeBackend)
        assert backend.project_name == "mylab"

    def test_passes_ssh_options(self, tmp_path):
        config = AptlConfig(
            lab={"name": "test"},
            deployment={
                "provider": "ssh-compose",
                "ssh_host": "server",
                "ssh_user": "admin",
                "ssh_key": _ABS_SSH_KEY,
                "ssh_port": 2222,
                "remote_dir": "/opt/aptl",
            },
        )
        backend = get_backend(config, tmp_path)
        assert isinstance(backend, SSHComposeBackend)
        assert backend.docker_host == "ssh://admin@server:2222"


# ---------------------------------------------------------------------------
# Backward-compatibility: lab.py wrapper functions
# ---------------------------------------------------------------------------


class TestLabBackwardCompat:
    """Verify that lab.py wrapper functions still work without backend arg."""

    def test_start_lab_without_backend(self, mock_subprocess):
        from aptl.core.lab import start_lab

        config = AptlConfig(
            lab={"name": "test"},
            containers={"wazuh": True, "victim": True, "kali": False, "reverse": False},
        )
        mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = start_lab(config)

        assert result.success is True

    def test_stop_lab_without_backend(self, mock_subprocess, tmp_path):
        from aptl.core.lab import stop_lab

        mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = stop_lab(project_dir=tmp_path)

        assert result.success is True

    def test_lab_status_without_backend(self, mock_subprocess):
        from aptl.core.lab import lab_status

        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout='[{"Name":"aptl-victim","State":"running"}]',
            stderr="",
        )

        status = lab_status()

        assert status.running is True

    def test_start_lab_with_explicit_backend(self, tmp_path):
        """start_lab accepts an explicit backend."""
        from aptl.core.lab import start_lab

        config = AptlConfig(
            lab={"name": "test"},
            containers={"wazuh": True, "kali": False, "reverse": False},
        )

        mock_backend = MagicMock()
        mock_backend.start.return_value = LabResult(success=True, message="ok")

        result = start_lab(config, backend=mock_backend)

        assert result.success is True
        mock_backend.start.assert_called_once()


class TestKillBackwardCompat:
    """Verify kill_lab_containers still works without backend arg."""

    @patch("aptl.core.kill.subprocess.run")
    def test_kill_without_backend(self, mock_run):
        from aptl.core.kill import kill_lab_containers

        mock_run.return_value = MagicMock(returncode=0, stderr="")

        success, error = kill_lab_containers(project_dir=Path("/tmp/aptl"))

        assert success is True

    def test_kill_with_backend(self):
        from aptl.core.kill import kill_lab_containers

        mock_backend = MagicMock()
        mock_backend.kill.return_value = (True, "")

        success, error = kill_lab_containers(backend=mock_backend)

        assert success is True
        mock_backend.kill.assert_called_once()


# ---------------------------------------------------------------------------
# SSH parameter validation tests
# ---------------------------------------------------------------------------


class TestSSHComposeBackendValidation:
    """Validate that SSHComposeBackend rejects dangerous parameter values."""

    def test_rejects_host_with_at_sign(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid SSH host"):
            SSHComposeBackend(tmp_path, host="user@evil", user="deploy")

    def test_rejects_host_with_semicolon(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid SSH host"):
            SSHComposeBackend(tmp_path, host="host;rm -rf /", user="deploy")

    def test_rejects_host_with_spaces(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid SSH host"):
            SSHComposeBackend(tmp_path, host="host name", user="deploy")

    def test_rejects_user_with_spaces(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid SSH user"):
            SSHComposeBackend(tmp_path, host="example.com", user="admin root")

    def test_rejects_user_with_at_sign(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid SSH user"):
            SSHComposeBackend(tmp_path, host="example.com", user="user@host")

    def test_rejects_port_zero(self, tmp_path):
        with pytest.raises(ValueError, match="ssh_port must be int in 1-65535"):
            SSHComposeBackend(tmp_path, host="example.com", user="deploy", ssh_port=0)

    def test_rejects_port_negative(self, tmp_path):
        with pytest.raises(ValueError, match="ssh_port must be int in 1-65535"):
            SSHComposeBackend(tmp_path, host="example.com", user="deploy", ssh_port=-1)

    def test_rejects_port_over_65535(self, tmp_path):
        with pytest.raises(ValueError, match="ssh_port must be int in 1-65535"):
            SSHComposeBackend(
                tmp_path, host="example.com", user="deploy", ssh_port=70000
            )

    def test_rejects_relative_ssh_key(self, tmp_path):
        with pytest.raises(ValueError, match="absolute path"):
            SSHComposeBackend(
                tmp_path,
                host="example.com",
                user="deploy",
                ssh_key="relative/path/key",
            )

    def test_rejects_ssh_key_with_traversal(self, tmp_path):
        with pytest.raises(ValueError, match="must not contain"):
            SSHComposeBackend(
                tmp_path,
                host="example.com",
                user="deploy",
                ssh_key=_ABS_SSH_KEY_TRAVERSAL,
            )

    def test_accepts_valid_ipv6_host(self, tmp_path):
        backend = SSHComposeBackend(tmp_path, host="[::1]", user="deploy")
        assert backend.docker_host == "ssh://deploy@[::1]"

    def test_accepts_valid_hostname(self, tmp_path):
        backend = SSHComposeBackend(tmp_path, host="lab.example.com", user="deploy")
        assert backend.docker_host == "ssh://deploy@lab.example.com"

    def test_accepts_valid_absolute_key(self, tmp_path):
        backend = SSHComposeBackend(
            tmp_path,
            host="example.com",
            user="deploy",
            ssh_key=_ABS_SSH_KEY,
        )
        assert backend.docker_host == "ssh://deploy@example.com"

    def test_accepts_non_default_port(self, tmp_path):
        backend = SSHComposeBackend(
            tmp_path,
            host="example.com",
            user="deploy",
            ssh_port=2222,
        )
        assert backend.docker_host == "ssh://deploy@example.com:2222"


class TestSeedNamedVolumes:
    """ADR-043 named-volume seeding via short-lived root containers."""

    def _backend(self, tmp_path):
        return DockerComposeBackend(project_dir=tmp_path, project_name="test")

    def _config_seed(self):
        from aptl.core.seed_spec import NamedVolumeSeed, SeedFile

        return NamedVolumeSeed(
            volume_suffix="suricata_config_seed",
            source_dir=Path("/proj/config/suricata"),
            files=(
                SeedFile("suricata.yaml", "suricata.yaml"),
                SeedFile("rules/local.rules", "rules/local.rules"),
            ),
        )

    def _misp_seed_with_legacy(self):
        from aptl.core.seed_spec import NamedVolumeSeed, SeedFile

        return NamedVolumeSeed(
            volume_suffix="suricata_misp_rules",
            source_dir=Path("/proj/config/suricata/rules/misp"),
            files=(SeedFile("misp-iocs.rules", "misp-iocs.rules"),),
            legacy_retire_path=Path("/proj/.aptl/suricata/rules/misp"),
        )

    def test_seed_runs_root_copy_into_project_scoped_volume(self, tmp_path):
        backend = self._backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.seed_named_volumes([self._config_seed()], seeder_image="img:1")
        cmd = mock_run.call_args[0][0]
        assert cmd[:7] == [
            "docker",
            "run",
            "--rm",
            "--user",
            "0:0",
            "--entrypoint",
            "/bin/sh",
        ]
        # Source is read-only (checked-in files can never be chowned),
        # dest is the Compose project-scoped volume name. The host source is
        # rendered with the platform separator (str(Path(...))): a real Windows
        # run gets a real Windows source path, which Docker Desktop accepts.
        assert f"{Path('/proj/config/suricata')}:/src:ro" in cmd
        assert "test_suricata_config_seed:/dest" in cmd
        assert cmd[-3] == "img:1"
        assert cmd[-2] == "-c"
        script = cmd[-1]
        assert "cp -a /src/suricata.yaml /dest/suricata.yaml" in script
        assert "mkdir -p /dest/rules" in script
        assert "cp -a /src/rules/local.rules /dest/rules/local.rules" in script

    def test_legacy_path_retired_before_seed_as_root(self, tmp_path):
        # The legacy .aptl tree may be UID-991-owned from a prior run, so the
        # host operator cannot delete it; a root container mounts the
        # host-owned parent and removes the one canonical child.
        backend = self._backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.seed_named_volumes(
                [self._misp_seed_with_legacy()], seeder_image="img:1"
            )
        calls = [c[0][0] for c in mock_run.call_args_list]
        assert len(calls) == 2
        retire, seed = calls
        assert retire[:5] == ["docker", "run", "--rm", "--user", "0:0"]
        assert retire[5:7] == ["--entrypoint", "rm"]
        assert f"{Path('/proj/.aptl/suricata/rules')}:/legacy" in retire
        assert retire[-2:] == ["-rf", "/legacy/misp"]
        # Seed runs after the retire.
        assert "test_suricata_misp_rules:/dest" in seed

    def test_no_legacy_retire_when_path_absent(self, tmp_path):
        backend = self._backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.seed_named_volumes([self._config_seed()], seeder_image="img:1")
        # Exactly one container: the seed copy, no retire.
        assert mock_run.call_count == 1

    def test_seed_is_idempotent_across_runs(self, tmp_path):
        # Root `cp -a` overwrites prior content, so the backend issues the
        # same command on every start regardless of the volume's state —
        # repeated `aptl lab start` is idempotent.
        backend = self._backend(tmp_path)
        seed = self._config_seed()
        commands = []
        for _ in range(2):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                backend.seed_named_volumes([seed], seeder_image="img:1")
                commands.append(mock_run.call_args[0][0])
        assert commands[0] == commands[1]

    def test_nonzero_exit_raises_without_leaking_stderr(self, tmp_path):
        from aptl.core.deployment.errors import BackendSeedError

        backend = self._backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="secret docker stderr"
            )
            with pytest.raises(BackendSeedError) as exc_info:
                backend.seed_named_volumes([self._config_seed()], seeder_image="img:1")
        assert "suricata_config_seed" in str(exc_info.value)
        assert "secret docker stderr" not in str(exc_info.value)

    def test_nonzero_exit_logs_stderr_hint(self, tmp_path, caplog):
        # Issue #716: a seed failure must be diagnosable from the log alone.
        # The real docker error text reaches the operator-facing log line
        # while the raised message stays artifact-name-only.
        from aptl.core.deployment.errors import BackendSeedError

        stderr = (
            "Unable to find image 'jasonish/suricata:7.0' locally\n"
            "docker: Error response from daemon: pull access denied"
        )
        backend = self._backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr=stderr)
            caplog.set_level(logging.ERROR, logger="aptl")
            with pytest.raises(BackendSeedError) as exc_info:
                backend.seed_named_volumes([self._config_seed()], seeder_image="img:1")
        message = "\n".join(rec.getMessage() for rec in caplog.records)
        assert "Error response from daemon: pull access denied" in message
        assert "suricata_config_seed" in message
        # The exception itself still leaks nothing beyond the artifact name.
        assert "Error response from daemon" not in str(exc_info.value)

    def test_stderr_hint_is_redacted(self, tmp_path, caplog):
        # A credential-shaped token in docker stderr must be scrubbed before
        # it reaches the log; the shared redactor owns the masking.
        from aptl.core.deployment.errors import BackendSeedError

        stderr = (
            "docker: Error response from daemon: failed to auth: "
            "Authorization: Bearer sk-supersecrettoken123"
        )
        backend = self._backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr=stderr)
            caplog.set_level(logging.ERROR, logger="aptl")
            with pytest.raises(BackendSeedError):
                backend.seed_named_volumes([self._config_seed()], seeder_image="img:1")
        message = "\n".join(rec.getMessage() for rec in caplog.records)
        assert "sk-supersecrettoken123" not in message
        assert "[REDACTED]" in message

    def test_empty_stderr_adds_no_hint_fragment(self, tmp_path, caplog):
        # No stderr means no dangling " — stderr:" suffix on the log line.
        from aptl.core.deployment.errors import BackendSeedError

        backend = self._backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="   ")
            caplog.set_level(logging.ERROR, logger="aptl")
            with pytest.raises(BackendSeedError):
                backend.seed_named_volumes([self._config_seed()], seeder_image="img:1")
        message = "\n".join(rec.getMessage() for rec in caplog.records)
        assert "stderr:" not in message
        assert "suricata_config_seed" in message

    def test_long_stderr_hint_is_tail_truncated(self, tmp_path, caplog):
        # A verbose stderr collapses to a bounded tail; the daemon error at
        # the end (the useful part) survives, the leading progress noise does
        # not, and an ellipsis marks the cut.
        from aptl.core.deployment.errors import BackendSeedError

        stderr = "HEAD_NOISE " + ("x" * 2000) + " TAIL_DAEMON_ERROR"
        backend = self._backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr=stderr)
            caplog.set_level(logging.ERROR, logger="aptl")
            with pytest.raises(BackendSeedError):
                backend.seed_named_volumes([self._config_seed()], seeder_image="img:1")
        message = "\n".join(rec.getMessage() for rec in caplog.records)
        assert "TAIL_DAEMON_ERROR" in message
        assert "HEAD_NOISE" not in message
        assert "…" in message

    def test_retire_failure_logs_stderr_hint(self, tmp_path, caplog):
        # The legacy-retire error path shares the same redacted-hint contract
        # as the seed path. Retire runs first, so a nonzero exit fails there.
        from aptl.core.deployment.errors import BackendSeedError

        stderr = "docker: Error response from daemon: permission denied on /legacy"
        backend = self._backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr=stderr)
            caplog.set_level(logging.ERROR, logger="aptl")
            with pytest.raises(BackendSeedError) as exc_info:
                backend.seed_named_volumes(
                    [self._misp_seed_with_legacy()], seeder_image="img:1"
                )
        message = "\n".join(rec.getMessage() for rec in caplog.records)
        assert "Retire of legacy seed path" in message
        assert "permission denied on /legacy" in message
        assert "permission denied" not in str(exc_info.value)

    def test_unsafe_relpath_rejected_before_any_container(self, tmp_path):
        from aptl.core.deployment.errors import BackendSeedError
        from aptl.core.seed_spec import NamedVolumeSeed, SeedFile

        backend = self._backend(tmp_path)
        evil = NamedVolumeSeed(
            volume_suffix="x",
            source_dir=Path("/proj/src"),
            files=(SeedFile("../../etc/passwd", "ok"),),
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            with pytest.raises(BackendSeedError):
                backend.seed_named_volumes([evil], seeder_image="img:1")
        mock_run.assert_not_called()


class TestRealizeContent:
    """Issue #689: typed content-placement realization via the ADR-043 seed seam.

    ``realize_content`` mirrors ``seed_named_volumes`` (same root one-off
    container, argv-list command, redacted failure) but takes typed
    ``DeploymentContentRealization`` records instead of pre-built
    ``NamedVolumeSeed``\\ s, so these tests focus on the extra translation
    step (inline-text rendering, project-source resolution) rather than
    re-testing the seed mechanics ``TestSeedNamedVolumes`` already covers.
    """

    def _backend(self, tmp_path):
        return DockerComposeBackend(project_dir=tmp_path, project_name="test")

    def _inline_text_item(self, **overrides):
        from aptl.core.deployment.realization import DeploymentContentRealization

        fields = {
            "address": "provision.content-placement.notice",
            "target_address": "provision.node.fileshare",
            "content_name": "notice",
            "volume_suffix": "fileshare_data",
            "dest_relpath": "public/notice.txt",
            "source_kind": "inline-text",
            "inline_text": "Welcome to TechVault.",
        }
        fields.update(overrides)
        return DeploymentContentRealization(**fields)

    def test_inline_text_renders_and_seeds_into_project_scoped_volume(self, tmp_path):
        backend = self._backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.realize_content([self._inline_text_item()], seeder_image="img:1")

        cmd = mock_run.call_args[0][0]
        assert cmd[:7] == [
            "docker",
            "run",
            "--rm",
            "--user",
            "0:0",
            "--entrypoint",
            "/bin/sh",
        ]
        rendered_dir = (
            tmp_path / ".aptl" / "content" / "provision.content-placement.notice"
        )
        assert f"{rendered_dir}:/src:ro" in cmd
        assert "test_fileshare_data:/dest" in cmd
        assert cmd[-3] == "img:1"
        script = cmd[-1]
        assert "mkdir -p /dest/public" in script
        assert "cp -a /src/notice.txt /dest/public/notice.txt" in script

        rendered_file = rendered_dir / "notice.txt"
        assert rendered_file.read_text(encoding="utf-8") == "Welcome to TechVault."

    def test_project_file_source_binds_resolved_parent_directory(self, tmp_path):
        from aptl.core.deployment.realization import DeploymentContentRealization

        source_dir = tmp_path / "scenarios" / "fixtures" / "techvault-content"
        source_dir.mkdir(parents=True)
        (source_dir / "onboarding.md").write_text("hello", encoding="utf-8")
        item = DeploymentContentRealization(
            address="provision.content-placement.onboarding",
            target_address="provision.node.fileshare",
            content_name="onboarding",
            volume_suffix="fileshare_data",
            dest_relpath="onboarding/onboarding.md",
            source_kind="project-file",
            source_relpath="scenarios/fixtures/techvault-content/onboarding.md",
        )
        backend = self._backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            backend.realize_content([item], seeder_image="img:1")

        cmd = mock_run.call_args[0][0]
        assert f"{source_dir}:/src:ro" in cmd
        assert "test_fileshare_data:/dest" in cmd
        script = cmd[-1]
        assert "mkdir -p /dest/onboarding" in script
        assert "cp -a /src/onboarding.md /dest/onboarding/onboarding.md" in script

    def test_project_source_escaping_project_root_raises(self, tmp_path):
        from aptl.core.credentials import PathContainmentError
        from aptl.core.deployment.realization import DeploymentContentRealization

        item = DeploymentContentRealization(
            address="provision.content-placement.evil",
            target_address="provision.node.fileshare",
            content_name="evil",
            volume_suffix="fileshare_data",
            dest_relpath="public/evil.txt",
            source_kind="project-file",
            source_relpath="../../etc/passwd",
        )
        backend = self._backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            with pytest.raises(PathContainmentError):
                backend.realize_content([item], seeder_image="img:1")
        mock_run.assert_not_called()

    def test_realize_content_is_idempotent_across_runs(self, tmp_path):
        backend = self._backend(tmp_path)
        item = self._inline_text_item()
        commands = []
        for _ in range(2):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                backend.realize_content([item], seeder_image="img:1")
                commands.append(mock_run.call_args[0][0])
        assert commands[0] == commands[1]

    def test_empty_content_list_runs_no_container(self, tmp_path):
        backend = self._backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            backend.realize_content([], seeder_image="img:1")
        mock_run.assert_not_called()

    def test_nonzero_exit_raises_without_leaking_stderr(self, tmp_path):
        from aptl.core.deployment.errors import BackendSeedError

        backend = self._backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="secret docker stderr"
            )
            with pytest.raises(BackendSeedError) as exc_info:
                backend.realize_content(
                    [self._inline_text_item()], seeder_image="img:1"
                )
        assert "fileshare_data" in str(exc_info.value)
        assert "secret docker stderr" not in str(exc_info.value)


class TestComposeRealizeContentStep:
    """Issue #689: content realization wired into ``ComposeRealizationMixin.realize``."""

    def _backend(self, tmp_path):
        return DockerComposeBackend(project_dir=tmp_path, project_name="test")

    def test_realize_content_failure_is_fail_closed_lab_result(self, tmp_path):
        from aptl.core.deployment.errors import BackendSeedError
        from aptl.core.deployment.realization import DeploymentContentRealization

        backend = self._backend(tmp_path)
        item = DeploymentContentRealization(
            address="provision.content-placement.notice",
            target_address="provision.node.fileshare",
            content_name="notice",
            volume_suffix="fileshare_data",
            dest_relpath="public/notice.txt",
            source_kind="inline-text",
            inline_text="hi",
        )
        spec = DeploymentRealizationSpec(
            profiles=(), nodes=(), networks=(), content=(item,)
        )
        # BackendSeedError itself only ever carries the artifact name, never
        # raw Docker stderr (see TestRealizeContent's own leak test); this
        # test proves the wrapping step fails closed rather than raising.
        with patch.object(
            backend,
            "realize_content",
            side_effect=BackendSeedError(
                "Seeding named volume 'fileshare_data' failed"
            ),
        ):
            result = backend._realize_content(spec)
        assert result is not None
        assert result.success is False
        assert "fileshare_data" in (result.error or "")

    def test_no_content_is_a_no_op(self, tmp_path):
        backend = self._backend(tmp_path)
        spec = DeploymentRealizationSpec(profiles=(), nodes=(), networks=(), content=())
        assert backend._realize_content(spec) is None


class _FakeAd:
    """A minimal stateful Samba AD, driven through ``container_exec``.

    Records every command in order so tests can assert sequencing (groups
    before members, existence-check before create, verify after mutation) and
    convergent-upsert behavior. It does not model passwords — that a secret is
    never disclosed is proven structurally: an already-existing user is never
    re-created, so its provisioner-owned password is untouched.
    """

    def __init__(self, *, ready=True, provisioned=True, users=None, groups=None):
        self.ready = ready
        self.provisioned = provisioned
        self.users = {
            u: {"mail": "", "disabled": False, "spns": set(), "groups": set()}
            for u in (users or [])
        }
        self.groups = set(groups or [])
        self.calls: list[list[str]] = []

    def __call__(self, name, cmd, *, timeout=None):
        self.calls.append(list(cmd))
        return self._dispatch(cmd)

    def cmds(self, *prefix):
        """Return recorded calls whose leading tokens match ``prefix``."""
        n = len(prefix)
        return [c for c in self.calls if c[:n] == list(prefix)]

    def _ok(self, cmd, stdout=""):
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=stdout, stderr=""
        )

    def _fail(self, cmd, stderr="samba-tool: internal detail leak"):
        return subprocess.CompletedProcess(
            args=cmd, returncode=1, stdout="", stderr=stderr
        )

    def _dispatch(self, cmd):
        if cmd[0] == "test" and cmd[1] == "-f":
            return self._ok(cmd) if self.provisioned else self._fail(cmd)
        if cmd[1:] == ["domain", "info", "127.0.0.1"]:
            return self._ok(cmd) if self.ready else self._fail(cmd)
        if cmd[1] == "group":
            return self._dispatch_group(cmd)
        if cmd[1] in ("user", "spn"):
            return self._dispatch_user(cmd)
        return self._fail(cmd)

    def _dispatch_group(self, cmd):
        action = cmd[2]
        if action == "show":
            return self._ok(cmd) if cmd[3] in self.groups else self._fail(cmd)
        if action == "add":
            self.groups.add(cmd[3])
            return self._ok(cmd)
        if action == "addmembers":
            if cmd[4] not in self.users:
                return self._fail(cmd)
            self.users[cmd[4]]["groups"].add(cmd[3])
            return self._ok(cmd)
        if action == "listmembers":
            members = "\n".join(
                u for u, s in self.users.items() if cmd[3] in s["groups"]
            )
            return self._ok(cmd, stdout=members)
        return self._fail(cmd)

    def _dispatch_user(self, cmd):
        verb = tuple(cmd[1:3])
        if verb == ("user", "show"):
            if cmd[3] not in self.users:
                return self._fail(cmd)
            u = self.users[cmd[3]]
            uac = 514 if u["disabled"] else 512
            return self._ok(
                cmd, stdout=f"mail: {u['mail']}\nuserAccountControl: {uac}\n"
            )
        if verb == ("user", "create"):
            mail = next(
                (a.split("=", 1)[1] for a in cmd if a.startswith("--mail-address=")), ""
            )
            self.users[cmd[3]] = self._blank(mail=mail)
            return self._ok(cmd)
        if verb == ("user", "rename"):
            if cmd[3] not in self.users:
                return self._fail(cmd)
            for arg in cmd:
                if arg.startswith("--mail-address="):
                    self.users[cmd[3]]["mail"] = arg.split("=", 1)[1]
            return self._ok(cmd)
        if verb in (("user", "disable"), ("user", "enable")):
            if cmd[3] not in self.users:
                return self._fail(cmd)
            self.users[cmd[3]]["disabled"] = cmd[2] == "disable"
            return self._ok(cmd)
        if verb == ("spn", "add"):
            if cmd[4] not in self.users:
                return self._fail(cmd)
            self.users[cmd[4]]["spns"].add(cmd[3])
            return self._ok(cmd)
        if verb == ("spn", "list"):
            spns = sorted(self.users.get(cmd[3], self._blank())["spns"])
            return self._ok(cmd, stdout="\n".join(spns))
        return self._fail(cmd)

    @staticmethod
    def _blank(mail=""):
        return {"mail": mail, "disabled": False, "spns": set(), "groups": set()}


def _ad_node(
    address="scenario.node.ad", *, service_name="ad", container_name="aptl-ad"
):
    return DeploymentNodeRealization(
        address=address,
        name="scenario.ad",
        service_name=service_name,
        container_name=container_name,
        networks=(),
        network_attachments=(),
    )


def _acct(
    username,
    *,
    address=None,
    target="scenario.node.ad",
    groups=(),
    spn="",
    mail="",
    disabled=None,
):
    from aptl.core.deployment.realization import DeploymentAccountRealization

    return DeploymentAccountRealization(
        address=address or f"provision.account-placement.{username}",
        target_address=target,
        username=username,
        groups=tuple(groups),
        spn=spn,
        mail=mail,
        disabled=disabled,
    )


def _index(calls, predicate):
    return next(i for i, c in enumerate(calls) if predicate(c))


class TestRealizeAccounts:
    """Issue #577: backend-driven account/group realization on the AD provider."""

    def _backend(self, tmp_path):
        return DockerComposeBackend(project_dir=tmp_path, project_name="test")

    def test_empty_accounts_is_a_no_op(self, tmp_path):
        backend = self._backend(tmp_path)
        ad = _FakeAd()
        with patch.object(backend, "container_exec", ad):
            assert backend.realize_accounts((), ()) is None
        assert ad.calls == []

    def test_creates_new_user_with_groups_and_verifies(self, tmp_path):
        backend = self._backend(tmp_path)
        ad = _FakeAd()
        account = _acct(
            "jessica.williams",
            groups=("Sales", "VPN-Users"),
            mail="jessica.williams@techvault.local",
        )
        with patch.object(backend, "container_exec", ad):
            result = backend.realize_accounts((account,), (_ad_node(),))
        assert result is None
        # User created via --random-password, mail set atomically, no secret argv.
        create = ad.cmds("samba-tool", "user", "create")[0]
        assert "--random-password" in create
        assert "--mail-address=jessica.williams@techvault.local" in create
        assert all("password123" not in tok for tok in create)
        # Groups are ensured before membership is reconciled.
        first_addmember = _index(ad.calls, lambda c: c[1:3] == ["group", "addmembers"])
        last_group_add = max(
            _index(ad.calls[::-1], lambda c: c[1:3] == ["group", "add"] and c[3] == g)
            for g in ("Sales", "VPN-Users")
        )
        last_group_add = len(ad.calls) - 1 - last_group_add
        assert last_group_add < first_addmember
        # Read-after-write verification actually ran.
        assert ad.cmds("samba-tool", "user", "show")
        assert ad.cmds("samba-tool", "group", "listmembers")

    def test_existing_user_is_not_recreated_preserving_password(self, tmp_path):
        backend = self._backend(tmp_path)
        ad = _FakeAd(users=["jessica.williams"], groups=["Sales"])
        account = _acct("jessica.williams", groups=("Sales",))
        with patch.object(backend, "container_exec", ad):
            result = backend.realize_accounts((account,), (_ad_node(),))
        assert result is None
        # Convergent upsert: an existing account is never re-created, so the
        # provisioner-script-owned weak password is left untouched.
        assert ad.cmds("samba-tool", "user", "create") == []
        # Membership is still reconciled and verified.
        assert [
            "samba-tool",
            "group",
            "addmembers",
            "Sales",
            "jessica.williams",
        ] in ad.calls

    def test_authored_disabled_true_disables_and_verifies(self, tmp_path):
        backend = self._backend(tmp_path)
        ad = _FakeAd()
        account = _acct("former.employee", disabled=True)
        with patch.object(backend, "container_exec", ad):
            assert backend.realize_accounts((account,), (_ad_node(),)) is None
        assert ["samba-tool", "user", "disable", "former.employee"] in ad.calls

    def test_authored_disabled_false_enables_and_verifies(self, tmp_path):
        # An existing suspended account, explicitly declared enabled, converges.
        backend = self._backend(tmp_path)
        ad = _FakeAd(users=["contractor.temp"])
        ad.users["contractor.temp"]["disabled"] = True
        account = _acct("contractor.temp", disabled=False)
        with patch.object(backend, "container_exec", ad):
            assert backend.realize_accounts((account,), (_ad_node(),)) is None
        assert ["samba-tool", "user", "enable", "contractor.temp"] in ad.calls
        assert ad.users["contractor.temp"]["disabled"] is False

    def test_omitted_disabled_never_touches_account_state(self, tmp_path):
        # Security (#577 codex review): an omitted `disabled` must NOT be
        # reconstructed as False and applied — that would re-enable a suspended
        # account on an otherwise-benign placement, restoring attacker access.
        backend = self._backend(tmp_path)
        ad = _FakeAd(users=["former.employee"])
        ad.users["former.employee"]["disabled"] = True
        account = _acct("former.employee", disabled=None)
        with patch.object(backend, "container_exec", ad):
            assert backend.realize_accounts((account,), (_ad_node(),)) is None
        assert ad.cmds("samba-tool", "user", "enable") == []
        assert ad.cmds("samba-tool", "user", "disable") == []
        assert ad.users["former.employee"]["disabled"] is True  # left suspended

    def test_disabled_verify_fails_when_provider_state_wrong(self, tmp_path):
        # Read-after-write: a disable that did not take must fail closed, not
        # report success on a zero exit code.
        backend = self._backend(tmp_path)

        class _IgnoresDisable(_FakeAd):
            def _dispatch_user(self, cmd):
                if cmd[1:3] == ["user", "disable"]:
                    return self._ok(cmd)  # pretend success but never persist
                return super()._dispatch_user(cmd)

        ad = _IgnoresDisable()
        account = _acct("former.employee", disabled=True)
        with patch.object(backend, "container_exec", ad):
            result = backend.realize_accounts((account,), (_ad_node(),))
        assert result is not None and result.success is False
        assert "provision.account-placement.former.employee" in (result.error or "")

    def test_mail_converged_on_existing_user_and_verified(self, tmp_path):
        # An existing account whose stored mail drifts from the declaration is
        # converged (samba-tool user rename --mail-address), not left stale, and
        # the create path is never taken (password preserved).
        backend = self._backend(tmp_path)
        ad = _FakeAd(users=["jessica.williams"])
        ad.users["jessica.williams"]["mail"] = "stale@old.local"
        account = _acct("jessica.williams", mail="jessica.williams@techvault.local")
        with patch.object(backend, "container_exec", ad):
            assert backend.realize_accounts((account,), (_ad_node(),)) is None
        assert ad.cmds("samba-tool", "user", "create") == []
        assert [
            "samba-tool",
            "user",
            "rename",
            "jessica.williams",
            "--mail-address=jessica.williams@techvault.local",
        ] in ad.calls
        assert (
            ad.users["jessica.williams"]["mail"] == "jessica.williams@techvault.local"
        )

    def test_omitted_mail_is_not_materialized_or_verified(self, tmp_path):
        backend = self._backend(tmp_path)
        ad = _FakeAd(users=["svc-sql"])
        account = _acct("svc-sql", spn="MSSQLSvc/db:1433")  # no mail declared
        with patch.object(backend, "container_exec", ad):
            assert backend.realize_accounts((account,), (_ad_node(),)) is None
        assert ad.cmds("samba-tool", "user", "rename") == []

    def test_spn_verification_is_exact_not_substring(self, tmp_path):
        # A declared SPN ending :1433 must NOT be certified by an existing SPN
        # ending :14330 (Kerberos treats a superstring as a different principal).
        backend = self._backend(tmp_path)

        class _PrefixSpnAd(_FakeAd):
            def _dispatch_user(self, cmd):
                if cmd[1:3] == ["spn", "add"]:
                    return self._ok(cmd)  # pretend success, never persist exact spn
                return super()._dispatch_user(cmd)

        ad = _PrefixSpnAd(users=["svc-sql"])
        ad.users["svc-sql"]["spns"].add("MSSQLSvc/db.techvault.local:14330")
        account = _acct("svc-sql", spn="MSSQLSvc/db.techvault.local:1433")
        with patch.object(backend, "container_exec", ad):
            result = backend.realize_accounts((account,), (_ad_node(),))
        assert result is not None and result.success is False
        assert "svc-sql" in (result.error or "")

    def test_mail_verification_is_exact_not_substring(self, tmp_path):
        # A superstring stored mail must not certify the declared value.
        backend = self._backend(tmp_path)

        class _IgnoreRenameAd(_FakeAd):
            def _dispatch_user(self, cmd):
                if cmd[1:3] == ["user", "rename"]:
                    return self._ok(cmd)  # pretend success, never update mail
                return super()._dispatch_user(cmd)

        ad = _IgnoreRenameAd(users=["jessica.williams"])
        ad.users["jessica.williams"]["mail"] = "xjessica.williams@techvault.local"
        account = _acct("jessica.williams", mail="jessica.williams@techvault.local")
        with patch.object(backend, "container_exec", ad):
            result = backend.realize_accounts((account,), (_ad_node(),))
        assert result is not None and result.success is False

    def test_membership_verification_is_exact_not_whitespace_token(self, tmp_path):
        # A requested user 'Admin' must not be certified by a member 'Alice Admin'.
        backend = self._backend(tmp_path)

        class _SpaceMemberAd(_FakeAd):
            def _dispatch_group(self, cmd):
                if cmd[2] == "listmembers":
                    return self._ok(cmd, stdout="Alice Admin\nBob\n")
                if cmd[2] == "addmembers":
                    return self._ok(cmd)  # pretend success, never record membership
                return super()._dispatch_group(cmd)

        ad = _SpaceMemberAd(users=["Admin"], groups=["Engineering"])
        account = _acct("Admin", groups=("Engineering",))
        with patch.object(backend, "container_exec", ad):
            result = backend.realize_accounts((account,), (_ad_node(),))
        assert result is not None and result.success is False

    def test_failed_create_stops_before_membership_mutation(self, tmp_path):
        # If the user could not be created, no membership/attribute mutation may
        # run against the raw identifier — it must fail closed first.
        backend = self._backend(tmp_path)

        class _AmnesiacAd(_FakeAd):
            def _dispatch_user(self, cmd):
                if cmd[1:3] == ["user", "create"]:
                    return self._ok(cmd)  # pretend success but never persist
                return super()._dispatch_user(cmd)

        ad = _AmnesiacAd()
        account = _acct("ghost", groups=("Engineering",))
        with patch.object(backend, "container_exec", ad):
            result = backend.realize_accounts((account,), (_ad_node(),))
        assert result is not None and result.success is False
        assert ad.cmds("samba-tool", "group", "addmembers") == []

    def test_batch_with_one_invalid_account_mutates_nothing(self, tmp_path):
        # Batch-atomic at the realize boundary: a single invalid placement blocks
        # the whole batch, so no valid sibling is partially mutated first.
        backend = self._backend(tmp_path)
        ad = _FakeAd()
        accounts = (
            _acct("jessica.williams", groups=("Sales",)),
            _acct("emily.chen", address="provision.account-placement.emily"),
            _acct("weak,Administrator", address="provision.account-placement.evil"),
        )
        with patch.object(backend, "container_exec", ad):
            result = backend.realize_accounts(accounts, (_ad_node(),))
        assert result is not None and result.success is False
        assert "invalid-username" in (result.error or "")
        assert ad.calls == []

    def test_membership_verification_is_case_insensitive(self, tmp_path):
        # AD account names are case-insensitive: a member returned in a different
        # case must still verify (the exact-line parse must not over-tighten into
        # a false negative).
        backend = self._backend(tmp_path)

        class _CaseMemberAd(_FakeAd):
            def _dispatch_group(self, cmd):
                if cmd[2] == "listmembers":
                    return self._ok(cmd, stdout="JESSICA.WILLIAMS\n")
                return super()._dispatch_group(cmd)

        ad = _CaseMemberAd(users=["jessica.williams"], groups=["Sales"])
        account = _acct("jessica.williams", groups=("Sales",))
        with patch.object(backend, "container_exec", ad):
            assert backend.realize_accounts((account,), (_ad_node(),)) is None

    def test_verification_read_requires_success_return_code(self, tmp_path):
        # A nonzero verification read with misleading stdout must not certify.
        backend = self._backend(tmp_path)

        class _BadListAd(_FakeAd):
            def _dispatch_group(self, cmd):
                if cmd[2] == "listmembers":
                    return self._fail(cmd, stderr="jessica.williams")  # rc!=0 w/ stdout
                return super()._dispatch_group(cmd)

        ad = _BadListAd(users=["jessica.williams"], groups=["Sales"])
        account = _acct("jessica.williams", groups=("Sales",))
        with patch.object(backend, "container_exec", ad):
            result = backend.realize_accounts((account,), (_ad_node(),))
        assert result is not None and result.success is False

    def test_spn_is_added_and_verified(self, tmp_path):
        backend = self._backend(tmp_path)
        ad = _FakeAd()
        account = _acct("svc-sql", spn="MSSQLSvc/db.techvault.local:1433")
        with patch.object(backend, "container_exec", ad):
            assert backend.realize_accounts((account,), (_ad_node(),)) is None
        assert [
            "samba-tool",
            "spn",
            "add",
            "MSSQLSvc/db.techvault.local:1433",
            "svc-sql",
        ] in ad.calls
        assert ad.cmds("samba-tool", "spn", "list")

    def test_unknown_provider_fails_closed_before_mutation(self, tmp_path):
        backend = self._backend(tmp_path)
        ad = _FakeAd()
        node = _ad_node("scenario.node.db", service_name="db", container_name="aptl-db")
        account = _acct("x", target="scenario.node.db")
        with patch.object(backend, "container_exec", ad):
            result = backend.realize_accounts((account,), (node,))
        assert result is not None and result.success is False
        assert "provision.account-placement.x" in (result.error or "")
        assert "no-account-provider-for-service" in (result.error or "")
        assert ad.calls == []  # no mutation happened

    def test_invalid_username_fails_closed_before_mutation(self, tmp_path):
        backend = self._backend(tmp_path)
        ad = _FakeAd()
        account = _acct("bad\x00name")
        with patch.object(backend, "container_exec", ad):
            result = backend.realize_accounts((account,), (_ad_node(),))
        assert result is not None and result.success is False
        assert "invalid-username" in (result.error or "")
        assert ad.calls == []

    def test_readiness_timeout_fails_closed(self, tmp_path, monkeypatch):
        from aptl.core.deployment import _compose_account_realization as car

        monkeypatch.setattr(car, "_READINESS_TIMEOUT", 0)
        backend = self._backend(tmp_path)
        ad = _FakeAd(ready=False)
        account = _acct("jessica.williams", groups=("Sales",))
        with patch.object(backend, "container_exec", ad):
            result = backend.realize_accounts((account,), (_ad_node(),))
        assert result is not None and result.success is False
        assert "aptl-ad" in (result.error or "")
        # Readiness never passed, so no group/user mutation ran.
        assert ad.cmds("samba-tool", "group", "add") == []
        assert ad.cmds("samba-tool", "user", "create") == []

    def test_readiness_requires_provisioner_complete_marker(
        self, tmp_path, monkeypatch
    ):
        # The directory can answer `domain info` before the service-owned baseline
        # provisioner has finished. Gating only on that would let the backend
        # create an account the provisioner is about to create, losing the
        # fixture credential. Realization must also wait for the explicit
        # provisioning-complete marker, so "absent" is authoritative.
        from aptl.core.deployment import _compose_account_realization as car

        monkeypatch.setattr(car, "_READINESS_TIMEOUT", 0)
        backend = self._backend(tmp_path)
        ad = _FakeAd(provisioned=False)  # service up, baseline not yet complete
        account = _acct("jessica.williams", groups=("Sales",))
        with patch.object(backend, "container_exec", ad):
            result = backend.realize_accounts((account,), (_ad_node(),))
        assert result is not None and result.success is False
        assert ad.cmds("samba-tool", "user", "create") == []
        assert ad.cmds("samba-tool", "group", "add") == []

    def test_verify_failure_fails_closed_without_raw_stderr(self, tmp_path):
        backend = self._backend(tmp_path)

        # AD that silently forgets a created user, so read-after-write fails.
        class _AmnesiacAd(_FakeAd):
            def _dispatch(self, cmd):
                if cmd[1:3] == ["user", "create"]:
                    return self._ok(cmd)  # pretend success but never persist
                return super()._dispatch(cmd)

        ad = _AmnesiacAd()
        account = _acct("ghost")
        with patch.object(backend, "container_exec", ad):
            result = backend.realize_accounts((account,), (_ad_node(),))
        assert result is not None and result.success is False
        assert "provision.account-placement.ghost" in (result.error or "")
        assert "internal detail leak" not in (result.error or "")


class TestAccountProvisionerOrderingContract:
    """Issue #577: the AD readiness gate depends on setup-ad.sh's ordering.

    ``_account_provider_ready`` waits for ``/var/lib/samba/private/.provisioned``
    as the provisioner-complete signal. That is only correct if the AD entrypoint
    writes that marker AFTER running its baseline account provisioner. Lock that
    container contract here so a future entrypoint change that reorders them (and
    would reopen the clean-start create race) fails a fast unit test rather than
    only a full lab boot.
    """

    def test_setup_ad_writes_provisioned_marker_after_provision_users(self):
        repo_root = Path(__file__).resolve().parents[1]
        setup = (repo_root / "containers/ad/setup-ad.sh").read_text(encoding="utf-8")
        marker_write = setup.index('touch "$PROVISIONED_MARKER"')
        provision_call = setup.index("/opt/provision-users.sh")
        assert provision_call < marker_write
        # And the marker the backend probes matches the one the script writes.
        assert 'PROVISIONED_MARKER="/var/lib/samba/private/.provisioned"' in setup


class TestComposeRealizeAccountsStep:
    """Issue #577: account realization wired into ``ComposeRealizationMixin.realize``."""

    def _backend(self, tmp_path):
        return DockerComposeBackend(project_dir=tmp_path, project_name="test")

    def test_no_accounts_is_a_no_op(self, tmp_path):
        backend = self._backend(tmp_path)
        spec = DeploymentRealizationSpec(
            profiles=(), nodes=(), networks=(), accounts=()
        )
        assert backend._realize_accounts_step(spec) is None

    def test_step_surfaces_account_failure(self, tmp_path):
        backend = self._backend(tmp_path)
        spec = DeploymentRealizationSpec(
            profiles=(),
            nodes=(_ad_node(),),
            networks=(),
            accounts=(_acct("x", target="scenario.node.missing"),),
        )
        result = backend._realize_accounts_step(spec)
        assert result is not None and result.success is False
        assert "unresolved-target-node" in (result.error or "")

    def test_step_converts_backend_timeout_to_bounded_result(self, tmp_path):
        backend = self._backend(tmp_path)
        spec = DeploymentRealizationSpec(
            profiles=(), nodes=(_ad_node(),), networks=(), accounts=(_acct("x"),)
        )
        with patch.object(
            backend, "realize_accounts", side_effect=BackendTimeoutError("boom")
        ):
            result = backend._realize_accounts_step(spec)
        assert result is not None and result.success is False
        assert "timed out" in (result.error or "").lower()
