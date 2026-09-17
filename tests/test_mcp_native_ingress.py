"""Native MCP ingress uses the captured Kali endpoint, never its inner sshd."""

import pytest

from aptl.core.mcp_ingress import native_kali_ingress


def test_native_client_sync_binds_run_without_changing_manual_entries(tmp_path):
    import json
    from types import SimpleNamespace

    from aptl.core.lab import _sync_native_mcp_ingress

    path = tmp_path / ".mcp.json"
    manual = {"command": "user-owned", "env": {"CUSTOM": "keep"}}
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "aptl-red": {"env": {}},
                    "aptl-indexer": {"env": {}},
                    "manual": manual,
                }
            }
        )
    )
    backend = SimpleNamespace(
        container_inspect=lambda _: {
            "Id": "a" * 64,
            "State": {"Running": True},
            "NetworkSettings": {"Networks": {"red": {"IPAddress": "172.20.1.30"}}},
        }
    )
    _sync_native_mcp_ingress(tmp_path, backend, "a" * 32)
    servers = json.loads(path.read_text())["mcpServers"]
    assert servers["manual"] == manual
    assert servers["aptl-red"]["env"]["APTL_MCP_KALI_HOST"] == "172.20.1.30"
    assert servers["aptl-indexer"]["env"]["APTL_MCP_ADMITTED_RUN_ID"] == "a" * 32
    assert servers["aptl-indexer"]["env"]["APTL_STATE_DIR"] == str(tmp_path / ".aptl")


def test_native_ingress_requires_running_exact_identity():
    inspected = {
        "Id": "a" * 64,
        "State": {"Running": True},
        "NetworkSettings": {"Networks": {"redteam": {"IPAddress": "172.20.10.10"}}},
    }
    assert native_kali_ingress(inspected, "a" * 64) == {
        "APTL_MCP_KALI_HOST": "172.20.10.10"
    }
    for row in (
        {**inspected, "Id": "b" * 64},
        {**inspected, "State": {"Running": False}},
        {**inspected, "NetworkSettings": {}},
    ):
        with pytest.raises(ValueError):
            native_kali_ingress(row, "a" * 64)
