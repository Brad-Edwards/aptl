"""Unit tests for range snapshot capture."""

import json
import subprocess
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch, MagicMock

from aptl.core.snapshot import (
    SoftwareVersions,
    ContainerSnapshot,
    WazuhRulesSnapshot,
    NetworkSnapshot,
    RangeSnapshot,
    ServiceEndpoint,
    SSHEndpoint,
    capture_snapshot,
    _hash_config_files,
    _run_cmd,
    _get_software_versions,
    _get_container_snapshots,
    _get_wazuh_rules_snapshot,
    _get_network_snapshots,
)


def _backend_with_exec(exec_responses: dict[tuple, MagicMock]) -> MagicMock:
    """Build a fake backend whose ``container_exec`` returns the response
    keyed by (container, tuple(cmd)). Falls back to returncode=1 if the
    call doesn't match a mapped key.
    """
    backend = MagicMock()

    def _exec(container, cmd, *, timeout=None):
        key = (container, tuple(cmd))
        for k, v in exec_responses.items():
            if k[0] == container and "".join(k[1]) in "".join(cmd):
                return v
        if key in exec_responses:
            return exec_responses[key]
        return MagicMock(returncode=1, stdout="", stderr="")

    backend.container_exec.side_effect = _exec
    backend.container_inspect.return_value = {}
    return backend


class TestDataclasses:
    """Tests for snapshot dataclass creation and serialization."""

    def test_software_versions_defaults(self):
        sv = SoftwareVersions()
        assert sv.python_version == ""
        assert sv.docker_version == ""
        assert sv.aptl_version == ""

    def test_software_versions_values(self):
        sv = SoftwareVersions(
            python_version="3.11.5",
            docker_version="24.0.7",
            compose_version="2.23.0",
            wazuh_manager_version="4.7.0",
            wazuh_indexer_version="4.7.0",
            aptl_version="0.1.0",
        )
        d = asdict(sv)
        assert d["python_version"] == "3.11.5"
        assert d["docker_version"] == "24.0.7"
        assert d["aptl_version"] == "0.1.0"

    def test_container_snapshot(self):
        cs = ContainerSnapshot(
            name="aptl-victim",
            image="aptl/victim:latest",
            image_id="sha256:abc123",
            status="Up 5 minutes (healthy)",
            health="healthy",
            labels={"com.docker.compose.service": "victim"},
            networks={"aptl_aptl-internal": "172.20.2.20"},
            ports=["0.0.0.0:2022->22/tcp"],
        )
        d = asdict(cs)
        assert d["name"] == "aptl-victim"
        assert d["health"] == "healthy"
        assert d["labels"]["com.docker.compose.service"] == "victim"
        assert d["networks"]["aptl_aptl-internal"] == "172.20.2.20"
        assert len(d["ports"]) == 1

    def test_container_snapshot_defaults(self):
        cs = ContainerSnapshot()
        assert cs.labels == {}
        assert cs.networks == {}
        assert cs.ports == []
        assert cs.name == ""

    def test_wazuh_rules_snapshot(self):
        wr = WazuhRulesSnapshot(
            total_rules=3500,
            custom_rules=15,
            custom_rule_files=["local_rules.xml", "ssh_rules.xml"],
            total_decoders=800,
            custom_decoders=3,
        )
        d = asdict(wr)
        assert d["total_rules"] == 3500
        assert d["custom_rules"] == 15
        assert len(d["custom_rule_files"]) == 2

    def test_network_snapshot(self):
        ns = NetworkSnapshot(
            name="aptl_default",
            subnet="172.20.0.0/16",
            gateway="172.20.0.1",
            containers=["aptl-victim", "aptl-wazuh-manager"],
        )
        d = asdict(ns)
        assert d["subnet"] == "172.20.0.0/16"
        assert len(d["containers"]) == 2

    def test_range_snapshot_to_dict(self):
        snap = RangeSnapshot(
            timestamp="2026-03-07T12:00:00+00:00",
            software=SoftwareVersions(python_version="3.11.5"),
            containers=[
                ContainerSnapshot(name="aptl-victim", image="aptl/victim:latest"),
            ],
            wazuh_rules=WazuhRulesSnapshot(total_rules=100),
            networks=[
                NetworkSnapshot(name="aptl_default", subnet="172.20.0.0/16"),
            ],
            config_hashes={"aptl.json": "abc123def456"},
        )
        d = snap.to_dict()
        assert d["timestamp"] == "2026-03-07T12:00:00+00:00"
        assert d["software"]["python_version"] == "3.11.5"
        assert len(d["containers"]) == 1
        assert d["containers"][0]["name"] == "aptl-victim"
        assert d["wazuh_rules"]["total_rules"] == 100
        assert d["networks"][0]["subnet"] == "172.20.0.0/16"
        assert d["config_hashes"]["aptl.json"] == "abc123def456"

    def test_range_snapshot_json_roundtrip(self):
        snap = RangeSnapshot(
            timestamp="2026-03-07T12:00:00+00:00",
            software=SoftwareVersions(python_version="3.11"),
            containers=[ContainerSnapshot(name="test")],
            wazuh_rules=WazuhRulesSnapshot(),
            networks=[],
            config_hashes={"f.json": "deadbeef"},
        )
        serialized = json.dumps(snap.to_dict())
        loaded = json.loads(serialized)
        assert loaded["timestamp"] == "2026-03-07T12:00:00+00:00"
        assert loaded["containers"][0]["name"] == "test"
        assert loaded["config_hashes"]["f.json"] == "deadbeef"


class TestRunCmd:
    """Tests for the _run_cmd helper."""

    def test_returns_stdout_on_success(self, mocker):
        mocker.patch(
            "aptl.core.snapshot.subprocess.run",
            return_value=MagicMock(returncode=0, stdout="hello\n"),
        )
        assert _run_cmd(["echo", "hello"]) == "hello"

    def test_returns_empty_on_nonzero_exit(self, mocker):
        mocker.patch(
            "aptl.core.snapshot.subprocess.run",
            return_value=MagicMock(returncode=1, stdout="error"),
        )
        assert _run_cmd(["false"]) == ""

    def test_returns_empty_on_timeout(self, mocker):
        import subprocess
        mocker.patch(
            "aptl.core.snapshot.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="cmd", timeout=15),
        )
        assert _run_cmd(["slow"]) == ""

    def test_returns_empty_on_file_not_found(self, mocker):
        mocker.patch(
            "aptl.core.snapshot.subprocess.run",
            side_effect=FileNotFoundError("not found"),
        )
        assert _run_cmd(["nonexistent"]) == ""


class TestGetSoftwareVersions:
    """Tests for _get_software_versions with mocked subprocess + backend."""

    def test_collects_all_versions(self, mocker):
        # Host-level: docker version + docker compose version
        def fake_run_cmd(args, timeout=15):
            cmd_str = " ".join(args)
            if "docker version" in cmd_str:
                return "24.0.7"
            if "compose version" in cmd_str:
                return "2.23.0"
            return ""

        mocker.patch("aptl.core.snapshot._run_cmd", side_effect=fake_run_cmd)

        backend = MagicMock()
        def _exec(container, cmd, *, timeout=None):
            cmd_str = " ".join(cmd)
            if "wazuh-control" in cmd_str:
                return MagicMock(returncode=0, stdout="v4.12.0\n", stderr="")
            if "opensearch" in cmd_str:
                return MagicMock(
                    returncode=0,
                    stdout="/usr/share/wazuh-indexer/lib/opensearch-2.19.1.jar\n",
                    stderr="",
                )
            return MagicMock(returncode=1, stdout="", stderr="")

        backend.container_exec.side_effect = _exec
        sv = _get_software_versions(backend)
        assert sv.docker_version == "24.0.7"
        assert sv.compose_version == "2.23.0"
        assert sv.wazuh_manager_version == "4.12.0"
        assert sv.wazuh_indexer_version == "2.19.1"
        assert sv.python_version  # always set from sys.version

    def test_handles_empty_docker_output(self, mocker):
        mocker.patch("aptl.core.snapshot._run_cmd", return_value="")
        backend = MagicMock()
        backend.container_exec.return_value = MagicMock(
            returncode=1, stdout="", stderr=""
        )
        sv = _get_software_versions(backend)
        assert sv.docker_version == ""
        assert sv.compose_version == ""
        assert sv.wazuh_manager_version == ""
        assert sv.python_version  # still set


class TestGetContainerSnapshots:
    """Tests for _get_container_snapshots with mocked subprocess + backend."""

    DOCKER_PS_LINE = (
        "aptl-victim\taptl/victim:latest\tabc123\tUp 5 minutes (healthy)\t"
        "com.docker.compose.service=victim\t0.0.0.0:2022->22/tcp"
    )

    INSPECT_DICT = {
        "NetworkSettings": {
            "Networks": {"aptl_aptl-internal": {"IPAddress": "172.20.2.20"}}
        }
    }

    def _backend_with_inspect(self, inspect=None):
        backend = MagicMock()
        backend.container_inspect.return_value = (
            inspect if inspect is not None else self.INSPECT_DICT
        )
        return backend

    def test_parses_container_output(self, mocker):
        mocker.patch(
            "aptl.core.snapshot._run_cmd",
            side_effect=lambda a, **kw: self.DOCKER_PS_LINE if "ps" in a else "",
        )
        backend = self._backend_with_inspect()
        containers = _get_container_snapshots(backend)
        assert len(containers) == 1
        c = containers[0]
        assert c.name == "aptl-victim"
        assert c.image == "aptl/victim:latest"
        assert c.health == "healthy"
        assert c.networks["aptl_aptl-internal"] == "172.20.2.20"
        assert "2022->22/tcp" in c.ports[0]
        assert c.labels["com.docker.compose.service"] == "victim"

    def test_parses_unhealthy_status(self, mocker):
        line = "aptl-foo\timg\tid\tUp 1 minute (unhealthy)\tlabel=val\t"
        mocker.patch("aptl.core.snapshot._run_cmd", side_effect=lambda a, **kw: line if "ps" in a else "")
        containers = _get_container_snapshots(self._backend_with_inspect({}))
        assert containers[0].health == "unhealthy"

    def test_parses_starting_status(self, mocker):
        line = "aptl-foo\timg\tid\tUp 5s (health: starting)\tlabel=val\t"
        mocker.patch("aptl.core.snapshot._run_cmd", side_effect=lambda a, **kw: line if "ps" in a else "")
        containers = _get_container_snapshots(self._backend_with_inspect({}))
        assert containers[0].health == "starting"

    def test_returns_empty_on_no_output(self, mocker):
        mocker.patch("aptl.core.snapshot._run_cmd", return_value="")
        assert _get_container_snapshots(self._backend_with_inspect({})) == []

    def test_handles_bad_inspect_response(self, mocker):
        mocker.patch(
            "aptl.core.snapshot._run_cmd",
            side_effect=lambda a, **kw: self.DOCKER_PS_LINE if "ps" in a else "",
        )
        # Empty dict simulates the "no such container / parse error" case
        # ``container_inspect`` returns on failure.
        containers = _get_container_snapshots(self._backend_with_inspect({}))
        assert len(containers) == 1
        assert containers[0].networks == {}

    def test_skips_short_lines(self, mocker):
        mocker.patch("aptl.core.snapshot._run_cmd", side_effect=lambda a, **kw: "too\tfew" if "ps" in a else "")
        assert _get_container_snapshots(self._backend_with_inspect({})) == []

    def test_multiple_containers(self, mocker):
        lines = (
            "aptl-victim\timg1\tid1\tUp 5m\tlabel=a\t2022->22/tcp\n"
            "aptl-kali\timg2\tid2\tUp 3m\tlabel=b\t2023->22/tcp"
        )
        mocker.patch("aptl.core.snapshot._run_cmd", side_effect=lambda a, **kw: lines if "ps" in a else "")
        containers = _get_container_snapshots(self._backend_with_inspect({}))
        assert len(containers) == 2
        names = {c.name for c in containers}
        assert names == {"aptl-victim", "aptl-kali"}


class TestGetWazuhRulesSnapshot:
    """Tests for _get_wazuh_rules_snapshot with mocked backend."""

    def _exec_responder(self, mapping):
        def _exec(container, cmd, *, timeout=None):
            cmd_str = " ".join(cmd)
            for key, value in mapping.items():
                if key in cmd_str:
                    return MagicMock(returncode=0, stdout=value + "\n", stderr="")
            return MagicMock(returncode=1, stdout="", stderr="")
        return _exec

    def test_parses_rule_counts(self):
        backend = MagicMock()
        backend.container_exec.side_effect = self._exec_responder({
            "ruleset/rules": "3500",
            "etc/rules" + " -name": "15",  # find -name on etc/rules
            "ls /var/ossec/etc/rules": "/var/ossec/etc/rules/local_rules.xml\n/var/ossec/etc/rules/ssh_rules.xml",
            "ruleset/decoders": "800",
            "etc/decoders": "3",
        })
        # The above naive substring matching can collide (etc/rules
        # appears in two of the wazuh shell commands). Use a more
        # robust mapping based on the exact command shape:

        def _exec(container, cmd, *, timeout=None):
            cmd_str = " ".join(cmd)
            if "ruleset/rules" in cmd_str:
                return MagicMock(returncode=0, stdout="3500\n", stderr="")
            if "etc/rules" in cmd_str and "grep -c" in cmd_str:
                return MagicMock(returncode=0, stdout="15\n", stderr="")
            if "etc/rules" in cmd_str and "ls /var/ossec/etc/rules" in cmd_str:
                return MagicMock(
                    returncode=0,
                    stdout="/var/ossec/etc/rules/local_rules.xml\n/var/ossec/etc/rules/ssh_rules.xml\n",
                    stderr="",
                )
            if "ruleset/decoders" in cmd_str:
                return MagicMock(returncode=0, stdout="800\n", stderr="")
            if "etc/decoders" in cmd_str:
                return MagicMock(returncode=0, stdout="3\n", stderr="")
            return MagicMock(returncode=1, stdout="", stderr="")

        backend.container_exec.side_effect = _exec
        snap = _get_wazuh_rules_snapshot(backend)
        assert snap.total_rules == 3500
        assert snap.custom_rules == 15
        assert snap.custom_rule_files == ["local_rules.xml", "ssh_rules.xml"]
        assert snap.total_decoders == 800
        assert snap.custom_decoders == 3

    def test_handles_non_numeric_output(self):
        backend = MagicMock()
        backend.container_exec.return_value = MagicMock(
            returncode=0, stdout="not-a-number\n", stderr=""
        )
        snap = _get_wazuh_rules_snapshot(backend)
        assert snap.total_rules == 0
        assert snap.custom_rules == 0

    def test_handles_empty_output(self):
        backend = MagicMock()
        backend.container_exec.return_value = MagicMock(
            returncode=0, stdout="", stderr=""
        )
        snap = _get_wazuh_rules_snapshot(backend)
        assert snap.total_rules == 0
        assert snap.custom_rule_files == []


class TestGetNetworkSnapshots:
    """Tests for _get_network_snapshots with mocked subprocess."""

    NETWORK_INSPECT = json.dumps([{
        "Name": "aptl_aptl-internal",
        "IPAM": {"Config": [{"Subnet": "172.20.2.0/24", "Gateway": "172.20.2.1"}]},
        "Containers": {
            "abc": {"Name": "aptl-victim"},
            "def": {"Name": "aptl-workstation"},
        },
    }])

    def test_parses_network_info(self, mocker):
        def fake_run_cmd(args, timeout=15):
            if "network" in args and "ls" in args:
                return "aptl_aptl-internal"
            if "network" in args and "inspect" in args:
                return self.NETWORK_INSPECT
            return ""

        mocker.patch("aptl.core.snapshot._run_cmd", side_effect=fake_run_cmd)
        nets = _get_network_snapshots()
        assert len(nets) == 1
        assert nets[0].name == "aptl_aptl-internal"
        assert nets[0].subnet == "172.20.2.0/24"
        assert nets[0].gateway == "172.20.2.1"
        assert "aptl-victim" in nets[0].containers

    def test_returns_empty_when_no_networks(self, mocker):
        mocker.patch("aptl.core.snapshot._run_cmd", return_value="")
        assert _get_network_snapshots() == []

    def test_handles_bad_inspect_json(self, mocker):
        def fake_run_cmd(args, timeout=15):
            if "ls" in args:
                return "aptl_aptl-internal"
            return "not-json"

        mocker.patch("aptl.core.snapshot._run_cmd", side_effect=fake_run_cmd)
        nets = _get_network_snapshots()
        assert len(nets) == 1
        assert nets[0].name == "aptl_aptl-internal"
        assert nets[0].subnet == ""

    def test_handles_missing_ipam_config(self, mocker):
        inspect = json.dumps([{"Name": "net", "IPAM": {"Config": []}, "Containers": {}}])

        def fake_run_cmd(args, timeout=15):
            if "ls" in args:
                return "aptl_aptl-internal"
            return inspect

        mocker.patch("aptl.core.snapshot._run_cmd", side_effect=fake_run_cmd)
        nets = _get_network_snapshots()
        assert nets[0].subnet == ""

    def test_multiple_networks(self, mocker):
        def fake_run_cmd(args, timeout=15):
            if "ls" in args:
                return "aptl_aptl-security\naptl_aptl-internal\naptl_aptl-dmz"
            return json.dumps([{"Name": "n", "IPAM": {"Config": []}, "Containers": {}}])

        mocker.patch("aptl.core.snapshot._run_cmd", side_effect=fake_run_cmd)
        nets = _get_network_snapshots()
        assert len(nets) == 3

    def test_fallback_on_empty_inspect(self, mocker):
        def fake_run_cmd(args, timeout=15):
            if "ls" in args:
                return "aptl_aptl-internal"
            return ""

        mocker.patch("aptl.core.snapshot._run_cmd", side_effect=fake_run_cmd)
        nets = _get_network_snapshots()
        assert len(nets) == 1
        assert nets[0].name == "aptl_aptl-internal"
        assert nets[0].subnet == ""


class TestHashConfigFiles:
    """Tests for config file hashing."""

    def test_hash_config_files(self, tmp_path):
        (tmp_path / "aptl.json").write_text('{"lab": {"name": "test"}}')
        (tmp_path / "docker-compose.yml").write_text("version: '3'\n")
        (tmp_path / "unrelated.txt").write_text("ignored")

        hashes = _hash_config_files(tmp_path)
        assert "aptl.json" in hashes
        assert "docker-compose.yml" in hashes
        assert "unrelated.txt" not in hashes
        assert len(hashes["aptl.json"]) == 64  # SHA-256 hex digest length

    def test_hash_config_empty_dir(self, tmp_path):
        hashes = _hash_config_files(tmp_path)
        assert hashes == {}


class TestCaptureSnapshot:
    """Tests for the capture_snapshot function."""

    @patch("aptl.core.snapshot._get_network_snapshots")
    @patch("aptl.core.snapshot._get_wazuh_rules_snapshot")
    @patch("aptl.core.snapshot._get_container_snapshots")
    @patch("aptl.core.snapshot._get_software_versions")
    def test_capture_snapshot_structure(
        self, mock_sw, mock_containers, mock_wazuh, mock_networks, tmp_path
    ):
        mock_sw.return_value = SoftwareVersions(python_version="3.11.5")
        mock_containers.return_value = [
            ContainerSnapshot(
                name="aptl-victim",
                image="aptl/victim:latest",
                status="Up 5 minutes",
            ),
        ]
        mock_wazuh.return_value = WazuhRulesSnapshot(total_rules=100)
        mock_networks.return_value = [
            NetworkSnapshot(name="aptl_aptl-internal", subnet="172.20.2.0/24"),
        ]

        (tmp_path / "aptl.json").write_text("{}")

        snap = capture_snapshot(config_dir=tmp_path)

        assert snap.timestamp  # non-empty
        assert snap.software.python_version == "3.11.5"
        assert len(snap.containers) == 1
        assert snap.containers[0].name == "aptl-victim"
        assert snap.wazuh_rules.total_rules == 100
        assert len(snap.networks) == 1
        assert "aptl.json" in snap.config_hashes
        # SSH endpoints derived from running containers
        assert len(snap.ssh) == 1
        assert snap.ssh[0].port == 2022

    @patch("aptl.core.snapshot._get_network_snapshots")
    @patch("aptl.core.snapshot._get_wazuh_rules_snapshot")
    @patch("aptl.core.snapshot._get_container_snapshots")
    @patch("aptl.core.snapshot._get_software_versions")
    def test_capture_snapshot_serializable(
        self, mock_sw, mock_containers, mock_wazuh, mock_networks, tmp_path
    ):
        mock_sw.return_value = SoftwareVersions()
        mock_containers.return_value = []
        mock_wazuh.return_value = WazuhRulesSnapshot()
        mock_networks.return_value = []

        snap = capture_snapshot(config_dir=tmp_path)
        serialized = json.dumps(snap.to_dict())
        loaded = json.loads(serialized)
        assert "timestamp" in loaded
        assert "software" in loaded
        assert "containers" in loaded
        assert "services" in loaded
        assert "ssh" in loaded
