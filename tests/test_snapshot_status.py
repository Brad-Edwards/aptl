"""Tests for range snapshot and lab status JSON output.

Replaces the old test_connections.py. Tests verify that snapshot
captures container IPs, port mappings, service endpoints, and SSH
endpoints from Docker runtime state.
"""

import json
import stat
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from aptl.core.snapshot import (
    ContainerSnapshot,
    NetworkSnapshot,
    RangeSnapshot,
    ServiceEndpoint,
    SSHEndpoint,
    SoftwareVersions,
    WazuhRulesSnapshot,
    _get_service_endpoints,
    _get_ssh_endpoints,
)


class TestContainerSnapshotNewFields:
    """Tests for per-container networks and ports fields."""

    def test_container_snapshot_has_networks(self):
        cs = ContainerSnapshot(
            name="aptl-victim",
            networks={"aptl_aptl-internal": "172.20.2.20"},
        )
        assert cs.networks["aptl_aptl-internal"] == "172.20.2.20"

    def test_container_snapshot_has_ports(self):
        cs = ContainerSnapshot(
            name="aptl-victim",
            ports=["0.0.0.0:2022->22/tcp"],
        )
        assert "2022->22/tcp" in cs.ports[0]

    def test_container_snapshot_defaults_empty(self):
        cs = ContainerSnapshot()
        assert cs.networks == {}
        assert cs.ports == []

    def test_container_snapshot_serializable(self):
        cs = ContainerSnapshot(
            name="aptl-kali",
            networks={
                "aptl_aptl-redteam": "172.20.4.30",
                "aptl_aptl-dmz": "172.20.1.30",
            },
            ports=["0.0.0.0:2023->22/tcp"],
        )
        d = asdict(cs)
        assert d["networks"]["aptl_aptl-redteam"] == "172.20.4.30"
        assert len(d["ports"]) == 1


class TestServiceEndpoints:
    """Tests for deriving service endpoints from containers."""

    def test_returns_dashboard_when_running(self):
        containers = [
            ContainerSnapshot(name="aptl-wazuh-dashboard", status="Up 5 minutes (healthy)"),
        ]
        endpoints = _get_service_endpoints(containers)
        assert len(endpoints) == 1
        assert endpoints[0].name == "Wazuh Dashboard"
        assert endpoints[0].port == 443
        assert "https" in endpoints[0].url

    def test_returns_all_wazuh_services(self):
        containers = [
            ContainerSnapshot(name="aptl-wazuh-dashboard", status="Up 5 minutes"),
            ContainerSnapshot(name="aptl-wazuh-indexer", status="Up 5 minutes"),
            ContainerSnapshot(name="aptl-wazuh-manager", status="Up 5 minutes"),
        ]
        endpoints = _get_service_endpoints(containers)
        names = {e.name for e in endpoints}
        assert "Wazuh Dashboard" in names
        assert "Wazuh Indexer" in names
        assert "Wazuh API" in names

    def test_skips_stopped_containers(self):
        containers = [
            ContainerSnapshot(name="aptl-wazuh-dashboard", status="Exited (0) 2 minutes ago"),
        ]
        endpoints = _get_service_endpoints(containers)
        assert len(endpoints) == 0

    def test_empty_containers(self):
        assert _get_service_endpoints([]) == []


class TestSSHEndpoints:
    """Tests for deriving SSH endpoints from containers."""

    def test_returns_victim_ssh(self):
        containers = [
            ContainerSnapshot(name="aptl-victim", status="Up 5 minutes"),
        ]
        endpoints = _get_ssh_endpoints(containers)
        assert len(endpoints) == 1
        assert endpoints[0].port == 2022
        assert endpoints[0].user == "labadmin"
        assert "2022" in endpoints[0].command

    def test_returns_all_ssh_containers(self):
        containers = [
            ContainerSnapshot(name="aptl-victim", status="Up 5 minutes"),
            ContainerSnapshot(name="aptl-kali", status="Up 5 minutes"),
            ContainerSnapshot(name="aptl-reverse", status="Up 5 minutes"),
        ]
        endpoints = _get_ssh_endpoints(containers)
        assert len(endpoints) == 3
        ports = {e.port for e in endpoints}
        assert ports == {2022, 2023, 2027}

    def test_skips_stopped_containers(self):
        containers = [
            ContainerSnapshot(name="aptl-kali", status="Exited (137) 1 minute ago"),
        ]
        endpoints = _get_ssh_endpoints(containers)
        assert len(endpoints) == 0

    def test_skips_non_ssh_containers(self):
        containers = [
            ContainerSnapshot(name="aptl-wazuh-manager", status="Up 5 minutes"),
            ContainerSnapshot(name="aptl-ad", status="Up 5 minutes"),
        ]
        endpoints = _get_ssh_endpoints(containers)
        assert len(endpoints) == 0


class TestRangeSnapshotNewFields:
    """Tests for services and ssh fields on RangeSnapshot."""

    def test_snapshot_includes_services_and_ssh(self):
        snap = RangeSnapshot(
            timestamp="2026-03-08T00:00:00+00:00",
            services=[
                ServiceEndpoint(name="Wazuh Dashboard", url="https://localhost:443", port=443),
            ],
            ssh=[
                SSHEndpoint(name="Victim", port=2022, user="labadmin"),
            ],
        )
        d = snap.to_dict()
        assert len(d["services"]) == 1
        assert d["services"][0]["port"] == 443
        assert len(d["ssh"]) == 1
        assert d["ssh"][0]["user"] == "labadmin"

    def test_snapshot_json_roundtrip_with_new_fields(self):
        snap = RangeSnapshot(
            timestamp="2026-03-08T00:00:00+00:00",
            containers=[
                ContainerSnapshot(
                    name="aptl-victim",
                    networks={"aptl_aptl-internal": "172.20.2.20"},
                    ports=["0.0.0.0:2022->22/tcp"],
                ),
            ],
            services=[ServiceEndpoint(name="Dashboard", port=443)],
            ssh=[SSHEndpoint(name="Victim", port=2022)],
        )
        serialized = json.dumps(snap.to_dict())
        loaded = json.loads(serialized)
        assert loaded["containers"][0]["networks"]["aptl_aptl-internal"] == "172.20.2.20"
        assert loaded["services"][0]["port"] == 443
        assert loaded["ssh"][0]["port"] == 2022


class TestStatusCLIJsonOutput:
    """Tests for aptl lab status --json and --output flags."""

    @patch("aptl.core.snapshot.capture_snapshot")
    def test_json_flag_outputs_json(self, mock_capture, capsys):
        from typer.testing import CliRunner
        from aptl.cli.lab import app

        mock_capture.return_value = RangeSnapshot(
            timestamp="2026-03-08T00:00:00+00:00",
            software=SoftwareVersions(python_version="3.11"),
            containers=[
                ContainerSnapshot(name="aptl-victim", status="Up"),
            ],
        )

        runner = CliRunner()
        result = runner.invoke(app, ["status", "--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["timestamp"] == "2026-03-08T00:00:00+00:00"
        assert data["containers"][0]["name"] == "aptl-victim"

    @patch("aptl.core.snapshot.capture_snapshot")
    def test_output_flag_writes_file(self, mock_capture, tmp_path):
        from typer.testing import CliRunner
        from aptl.cli.lab import app

        mock_capture.return_value = RangeSnapshot(
            timestamp="2026-03-08T00:00:00+00:00",
        )

        out_file = tmp_path / "status.json"
        runner = CliRunner()
        result = runner.invoke(app, ["status", "--output", str(out_file)])

        assert result.exit_code == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert data["timestamp"] == "2026-03-08T00:00:00+00:00"

    @patch("aptl.core.snapshot.capture_snapshot")
    def test_output_file_has_restricted_permissions(self, mock_capture, tmp_path):
        from typer.testing import CliRunner
        from aptl.cli.lab import app

        mock_capture.return_value = RangeSnapshot()

        out_file = tmp_path / "status.json"
        runner = CliRunner()
        runner.invoke(app, ["status", "--output", str(out_file)])

        mode = out_file.stat().st_mode & 0o777
        assert mode == 0o600
