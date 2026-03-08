"""Unit tests for range snapshot capture."""

import json
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

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
)


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
