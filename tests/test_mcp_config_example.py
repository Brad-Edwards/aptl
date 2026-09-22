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

    _sync_mcp_config_keys(tmp_path, [])

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

    _sync_mcp_config_keys(tmp_path, [])

    updated = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert updated["mcpServers"]["operator-tool"] == {
        "command": "operator-mcp"
    }
    casemgmt = updated["mcpServers"]["aptl-casemgmt"]
    assert casemgmt["args"] == ["./custom-casemgmt.js"]
    assert casemgmt["env"]["THEHIVE_API_KEY"] == "fresh"


def _resolved(env_var: str, default_port: int, resolved_port: int):
    from aptl.core.host_ports import ResolvedPort

    return ResolvedPort(
        service="svc",
        env_var=env_var,
        default_port=default_port,
        resolved_port=resolved_port,
        protos=("tcp",),
        host_ip="127.0.0.1",
        remapped=default_port != resolved_port,
    )


def test_mcp_sync_injects_resolved_host_ports(tmp_path) -> None:
    """A server's ${APTL_HP_*} port refs get the run's resolved values."""
    from aptl.core.lab import _sync_mcp_config_keys

    server_dir = tmp_path / "mcp" / "mcp-wazuh"
    server_dir.mkdir(parents=True)
    (server_dir / "docker-lab-config.json").write_text(
        json.dumps(
            {
                "api": {"baseUrl": "https://localhost:${APTL_HP_WAZUH_INDEXER_9200}"},
                "queries": {
                    "q": {"url": "https://localhost:${APTL_HP_WAZUH_MANAGER_55000}/x"}
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "aptl-wazuh": {
                        "command": "node",
                        "args": ["./mcp/mcp-wazuh/build/index.js"],
                        "env": {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://x"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text("INDEXER_USERNAME=admin\n", encoding="utf-8")

    _sync_mcp_config_keys(
        tmp_path,
        [
            _resolved("APTL_HP_WAZUH_INDEXER_9200", 9200, 20005),
            _resolved("APTL_HP_WAZUH_MANAGER_55000", 55000, 20008),
            # An unreferenced remap must NOT be injected into this server.
            _resolved("APTL_HP_MISP_443", 8443, 20001),
        ],
    )

    env = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))[
        "mcpServers"
    ]["aptl-wazuh"]["env"]
    assert env["APTL_HP_WAZUH_INDEXER_9200"] == "20005"
    assert env["APTL_HP_WAZUH_MANAGER_55000"] == "20008"
    assert "APTL_HP_MISP_443" not in env  # not referenced by this server's config
    assert env["OTEL_EXPORTER_OTLP_ENDPOINT"] == "http://x"  # preserved


def test_runtime_mcp_ports_use_only_owned_generated_service_binding(
    mocker, tmp_path
) -> None:
    """Env-pack MCP sync maps dotted source services to owned live bindings."""
    from aptl.core.lab import _runtime_mcp_host_ports

    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  wazuh.indexer:\n"
        "    ports:\n"
        "      - '127.0.0.1:${APTL_HP_WAZUH_INDEXER_9200:-9200}:9200'\n"
        "  foreign:\n"
        "    ports:\n"
        "      - '127.0.0.1:${APTL_HP_FOREIGN_8080:-8080}:8080'\n",
        encoding="utf-8",
    )
    backend = mocker.MagicMock()
    backend.container_list.return_value = [
        {"Service": "wazuh-indexer", "Name": "generated-wazuh-indexer"}
    ]
    backend.container_inspect.return_value = {
        "NetworkSettings": {
            "Ports": {
                "9200/tcp": [
                    {"HostIp": "127.0.0.1", "HostPort": "29200"}
                ]
            }
        }
    }

    ports = _runtime_mcp_host_ports(tmp_path, backend)

    assert [(port.env_var, port.resolved_port) for port in ports] == [
        ("APTL_HP_WAZUH_INDEXER_9200", 29200)
    ]


def test_shipped_mcp_configs_reference_resolved_host_ports() -> None:
    """Shipped MCP configs must not hardcode host ports (use ${APTL_HP_*})."""
    import re

    mcp_dir = REPO_ROOT / "mcp"
    literal = re.compile(r"localhost:\d+|\"ssh_port\"\s*:\s*\d+")
    offenders = [
        str(cfg.relative_to(REPO_ROOT))
        for cfg in sorted(mcp_dir.glob("*/docker-lab-config.json"))
        if literal.search(cfg.read_text(encoding="utf-8"))
    ]
    assert offenders == [], f"hardcoded host ports in: {offenders}"
