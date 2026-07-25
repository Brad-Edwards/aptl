"""Guards for the generated participant MCP client configuration."""

from __future__ import annotations

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_PATH = REPO_ROOT / ".mcp.json.example"
EXPECTED_SERVERS = {
    "aptl-red": "mcp/mcp-red/build/index.js",
    "aptl-indexer": "mcp/mcp-indexer/build/index.js",
    "aptl-wazuh": "mcp/mcp-wazuh/build/index.js",
    "aptl-network": "mcp/mcp-network/build/index.js",
    "aptl-threatintel": "mcp/mcp-threatintel/build/index.js",
    "aptl-casemgmt": "mcp/mcp-casemgmt/build/index.js",
    "aptl-soar": "mcp/mcp-soar/build/index.js",
}


def _example() -> dict:
    return json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))


def test_mcp_example_uses_current_enabled_custom_servers() -> None:
    servers = _example()["mcpServers"]

    assert set(servers) == set(EXPECTED_SERVERS)
    assert "aptl-reverse" not in servers
    for name, entrypoint in EXPECTED_SERVERS.items():
        spec = servers[name]
        assert spec["command"] == "node"
        assert spec["args"] == [f"./{entrypoint}"]
        assert set(spec["env"]) == {"OTEL_EXPORTER_OTLP_ENDPOINT"}


def test_mcp_sync_creates_private_config_and_injects_seeded_keys(tmp_path) -> None:
    from aptl.core.lab import _sync_mcp_config_keys

    (tmp_path / ".mcp.json.example").write_text(
        EXAMPLE_PATH.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / ".env").write_text(
        "THEHIVE_API_KEY=thehive-test-key\n"
        "MISP_API_KEY=misp-test-key\n"
        "SHUFFLE_API_KEY=shuffle-test-key\n",
        encoding="utf-8",
    )

    _sync_mcp_config_keys(tmp_path)

    generated_path = tmp_path / ".mcp.json"
    generated = json.loads(generated_path.read_text(encoding="utf-8"))
    servers = generated["mcpServers"]
    assert generated_path.stat().st_mode & 0o777 == 0o600
    assert servers["aptl-casemgmt"]["env"]["THEHIVE_API_KEY"] == (
        "thehive-test-key"
    )
    assert servers["aptl-threatintel"]["env"]["MISP_API_KEY"] == (
        "misp-test-key"
    )
    assert servers["aptl-soar"]["env"]["SHUFFLE_API_KEY"] == (
        "shuffle-test-key"
    )


def test_mcp_sync_preserves_existing_client_entries(tmp_path) -> None:
    from aptl.core.lab import _sync_mcp_config_keys

    existing = {
        "mcpServers": {
            "operator-tool": {"command": "operator-mcp"},
            "aptl-casemgmt": {
                "command": "node",
                "args": ["./custom-casemgmt.js"],
                "env": {"THEHIVE_API_KEY": "stale"},
            },
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(existing), encoding="utf-8")
    (tmp_path / ".env").write_text(
        "THEHIVE_API_KEY=fresh\n", encoding="utf-8"
    )

    _sync_mcp_config_keys(tmp_path)

    updated = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert updated["mcpServers"]["operator-tool"] == {
        "command": "operator-mcp"
    }
    casemgmt = updated["mcpServers"]["aptl-casemgmt"]
    assert casemgmt["args"] == ["./custom-casemgmt.js"]
    assert casemgmt["env"]["THEHIVE_API_KEY"] == "fresh"
