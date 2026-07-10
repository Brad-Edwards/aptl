"""Tests for range snapshot and lab status JSON output.

Replaces the old test_connections.py. Tests verify that snapshot
captures container IPs, port mappings, service endpoints, and SSH
endpoints from Docker runtime state.
"""

import json
import os
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
    @pytest.mark.skipif(
        os.name != "posix",
        reason="0o600 chmod is a POSIX no-op on Windows (st_mode reads 0o666)",
    )
    def test_output_file_has_restricted_permissions(self, mock_capture, tmp_path):
        from typer.testing import CliRunner
        from aptl.cli.lab import app

        mock_capture.return_value = RangeSnapshot()

        out_file = tmp_path / "status.json"
        # Pre-create the file with permissive mode so the assertion
        # below proves the CLI *actively* chmod'd it to 0o600, rather
        # than the host's umask happening to clamp the new file's mode.
        out_file.write_text("{}")
        out_file.chmod(0o644)

        runner = CliRunner()
        result = runner.invoke(app, ["status", "--output", str(out_file)])

        assert result.exit_code == 0, result.output
        assert out_file.exists()
        mode = out_file.stat().st_mode & 0o777
        assert mode == 0o600
