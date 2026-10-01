"""Overlay-only desktop identity and Guacamole connection contract."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _desktop_module():
    path = ROOT / "appliance/guest/seat-desktop.py"
    spec = importlib.util.spec_from_file_location("seat_desktop", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _handoff_module():
    path = ROOT / "appliance/guest/desktop-handoff.py"
    spec = importlib.util.spec_from_file_location("seat_desktop_handoff", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_desktop_handoff_delivers_live_red_and_blue_mcp_inputs(tmp_path: Path) -> None:
    handoff = _handoff_module()
    project = tmp_path / "project"
    project.mkdir()
    (project / "aptl.json").write_text(
        json.dumps({"run_storage": {"local_path": "./runs"}})
    )
    (project / "runs" / "run-1" / "mcp-side").mkdir(parents=True)
    lifecycle = project / ".aptl" / "lifecycle" / "resource-receipts-v1"
    lifecycle.mkdir(parents=True)
    ownership = lifecycle.parent / "workspace-ownership-v1.json"
    ownership.write_text('{"schema":1,"workspace_id":"' + "a" * 32 + '"}\n')
    for directory in (project / ".aptl", lifecycle.parent, lifecycle):
        directory.chmod(0o700)
    ownership.chmod(0o600)
    (project / ".env").write_text("INDEXER_PASSWORD=guest-only\n")
    os.chmod(project / ".env", 0o600)
    servers = {}
    for names in handoff.ROLES.values():
        for name in names:
            package = project / "mcp" / name.replace("aptl-", "mcp-")
            (package / "build").mkdir(parents=True)
            (package / "build" / "index.js").write_text("// packaged\n")
            servers[name] = {
                "command": "node",
                "args": [f"./mcp/{package.name}/build/index.js"],
                "env": {"APTL_HP_TEST": "1234"},
            }
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    supervisor = tmp_path / "supervisor"
    (supervisor / ".ssh").mkdir(parents=True)
    (supervisor / ".ssh" / "aptl_lab_key").write_text("private-guest-key\n")
    home = tmp_path / "home"
    home.mkdir()
    (home / "red.mcp.json").write_text("stale\n")

    with patch.object(handoff, "_configure_browser_access"):
        handoff.handoff(project, home, supervisor, os.getuid(), os.getgid(), "run-1")

    red = json.loads((home / "red.mcp.json").read_text())["mcpServers"]
    blue = json.loads((home / "blue.mcp.json").read_text())["mcpServers"]
    assert set(red) == {"aptl-red"}
    assert set(blue) == set(handoff.ROLES["blue"])
    assert all(
        spec["env"]["APTL_MCP_ADMITTED_RUN_ID"] == "run-1"
        and spec["env"]["APTL_HP_TEST"] == "1234"
        and "HTTPS_PROXY" not in spec["env"]
        and "http_proxy" not in spec["env"]
        for spec in (*red.values(), *blue.values())
    )
    assert (home / ".ssh" / "aptl_lab_key").read_text() == "private-guest-key\n"
    assert stat.S_IMODE((home / ".ssh" / "aptl_lab_key").stat().st_mode) == 0o600
    assert stat.S_IMODE((project / ".env").stat().st_mode) == 0o640
    assert stat.S_IMODE(ownership.stat().st_mode) == 0o640
    assert stat.S_IMODE(lifecycle.stat().st_mode) == 0o750
    assert (home / ".config" / "aptl" / "run-ready").is_file()


def test_desktop_browser_hosts_are_live_and_idempotent(tmp_path: Path) -> None:
    handoff = _handoff_module()
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")

    handoff._browser_hosts(hosts, "172.20.0.16")
    handoff._browser_hosts(hosts, "172.20.0.17")

    assert hosts.read_text().count("misp.techvault.local") == 1
    assert "172.20.0.17 misp.techvault.local" in hosts.read_text()
    assert "127.0.0.1 wazuh.dashboard" in hosts.read_text()
    assert "172.20.0.16" not in hosts.read_text()


def test_desktop_browser_uses_misp_security_address(monkeypatch) -> None:
    handoff = _handoff_module()

    def run(argv, **_kwargs):
        if argv[:2] == ["docker", "ps"]:
            return SimpleNamespace(stdout="aptl-w123-misp\naptl-w123-misp-db\n")
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "aptl-w123_aptl-security": {"IPAddress": "172.20.0.16"},
                }
            )
        )

    monkeypatch.setattr(handoff.subprocess, "run", run)
    assert handoff._misp_security_ip() == "172.20.0.16"


def test_desktop_handoff_refuses_missing_mcp_before_ready(tmp_path: Path) -> None:
    handoff = _handoff_module()
    project = tmp_path / "project"
    project.mkdir()
    (project / "aptl.json").write_text('{"run_storage":{"local_path":"./runs"}}')
    (project / "runs").mkdir()
    (project / ".mcp.json").write_text('{"mcpServers":{}}')
    home = tmp_path / "home"
    home.mkdir()
    uid, gid = os.getuid(), os.getgid()
    with pytest.raises(ValueError, match="registration is incomplete"):
        handoff.handoff(project, home, tmp_path, uid, gid, "run-1")
    assert not (home / ".config" / "aptl" / "run-ready").exists()


def test_guacamole_connection_uses_overlay_password_without_web_login() -> None:
    desktop = _desktop_module()
    sql = desktop.connection_sql("a" * 64)

    assert "Seat Desktop" in sql
    assert "host.docker.internal" in sql
    assert "3389" in sql
    assert "participant" in sql
    assert "a" * 64 in sql
    assert "guacadmin" not in sql


def test_gateway_strips_client_identity_before_injecting_seat_identity() -> None:
    config = (ROOT / "appliance/guest/desktop-nginx.conf").read_text()

    assert "proxy_set_header REMOTE_USER participant" in config
    assert "proxy_pass http://guacamole:8080" in config
    compose = (ROOT / "appliance/guest/desktop-compose.yml").read_text()
    assert "HTTP_AUTH_ENABLED" in compose
    assert "127.0.0.1:8080:80" in compose


def test_desktop_uses_direct_network_without_an_outbound_proxy() -> None:
    session = (ROOT / "appliance/guest/desktop-session.sh").read_text()

    assert "gsettings set org.gnome.system.proxy mode none" in session
    assert "HTTP_PROXY" not in session
    assert "HTTPS_PROXY" not in session
    assert "10.0.2.100:3128" not in session


def test_desktop_prepare_creates_private_stable_overlay_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    desktop = _desktop_module()
    source = tmp_path / "source"
    source.mkdir()
    for name in ("guac-schema.sql", "desktop-compose.yml", "desktop-nginx.conf"):
        (source / name).write_text("input\n")
    monkeypatch.setattr(desktop, "SOURCE", source)
    monkeypatch.setattr(desktop, "RUNTIME", tmp_path / "overlay" / "desktop")

    with (
        patch.object(desktop.os, "chown"),
        patch.object(desktop.subprocess, "run") as run,
    ):
        first = desktop.prepare()
        second = desktop.prepare()

    assert first == second
    assert first["rdp"] in (desktop.RUNTIME / "initdb/002-seat.sql").read_text()
    assert first["rdp"] not in (source / "guac-schema.sql").read_text()
    assert json.loads((desktop.RUNTIME / "credentials.json").read_text()) == first
    assert stat.S_IMODE((desktop.RUNTIME / "credentials.json").stat().st_mode) == 0o600
    assert (
        stat.S_IMODE((desktop.RUNTIME / "initdb/002-seat.sql").stat().st_mode) == 0o600
    )
    assert all(call.args[0] == ["chpasswd"] for call in run.call_args_list)


def test_desktop_prepare_refuses_symlinked_credentials(
    tmp_path: Path, monkeypatch
) -> None:
    desktop = _desktop_module()
    runtime = tmp_path / "desktop"
    runtime.mkdir()
    target = tmp_path / "outside"
    target.write_text("untouched")
    (runtime / "credentials.json").symlink_to(target)
    monkeypatch.setattr(desktop, "RUNTIME", runtime)

    with pytest.raises(RuntimeError, match="credentials path"):
        desktop.prepare()
    assert target.read_text() == "untouched"
