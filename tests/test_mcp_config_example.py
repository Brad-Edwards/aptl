"""Guard for the shipped .mcp.json.example template.

TheHive terminates HTTPS in-container on port 9000 (see the docker-compose
healthcheck ``curl -ksf https://localhost:9000/api/status``), so a client
pointed at ``http://localhost:9000`` gets a dead connection. The example MCP
config is copied verbatim by users, so its TheHive URL must use the same
scheme the service actually serves.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_mcp_example_is_valid_json() -> None:
    data = json.loads((REPO_ROOT / ".mcp.json.example").read_text(encoding="utf-8"))
    assert "mcpServers" in data


def test_thehive_example_url_matches_served_scheme() -> None:
    data = json.loads((REPO_ROOT / ".mcp.json.example").read_text(encoding="utf-8"))
    url = data["mcpServers"]["thehive"]["env"]["THEHIVE_URL"]
    assert url.startswith("https://"), (
        f"TheHive serves HTTPS on 9000, so .mcp.json.example THEHIVE_URL must be "
        f"https:// (got {url!r})"
    )

    # The compose healthcheck is the source of truth for the served scheme.
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert re.search(r"curl[^\n]*https://localhost:9000/api/status", compose), (
        "expected the docker-compose TheHive healthcheck to probe "
        "https://localhost:9000/api/status"
    )
