"""Tests for MCP server discovery and role tagging."""

import json

import pytest

pytest.importorskip("pydantic")

from aptl.console.models import Role  # noqa: E402
from aptl.console.registry import load_registry  # noqa: E402


def _write_mcp(tmp_path, servers):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))


class TestRoleTagging:
    def test_kali_is_red_wazuh_is_blue(self, tmp_path):
        _write_mcp(
            tmp_path,
            {
                "kali-ssh": {"command": "node", "args": ["x.js"]},
                "wazuh": {"command": "node", "args": ["y.js"]},
            },
        )
        reg = load_registry(tmp_path)
        assert reg.get("kali-ssh").role is Role.RED
        assert reg.get("wazuh").role is Role.BLUE

    def test_explicit_override_wins(self, tmp_path):
        _write_mcp(tmp_path, {"kali-ssh": {"command": "node", "aptlRole": "blue"}})
        reg = load_registry(tmp_path)
        assert reg.get("kali-ssh").role is Role.BLUE

    def test_invalid_override_falls_back_to_classification(self, tmp_path):
        _write_mcp(tmp_path, {"kali-ssh": {"command": "node", "aptlRole": "bogus"}})
        reg = load_registry(tmp_path)
        assert reg.get("kali-ssh").role is Role.RED

    def test_unknown_server_is_neutral(self, tmp_path):
        _write_mcp(tmp_path, {"weather": {"command": "node"}})
        reg = load_registry(tmp_path)
        assert reg.get("weather").role is Role.NEUTRAL


class TestDefaults:
    def test_red_session_defaults_to_red_plus_neutral(self, tmp_path):
        _write_mcp(
            tmp_path,
            {
                "kali-ssh": {"command": "node"},
                "wazuh": {"command": "node"},
                "network": {"command": "node"},
            },
        )
        reg = load_registry(tmp_path)
        defaults = reg.default_for_role(Role.RED)
        assert "kali-ssh" in defaults
        assert "network" in defaults
        assert "wazuh" not in defaults

    def test_purple_gets_everything(self, tmp_path):
        _write_mcp(
            tmp_path,
            {"kali-ssh": {"command": "node"}, "wazuh": {"command": "node"}},
        )
        reg = load_registry(tmp_path)
        assert set(reg.default_for_role(Role.PURPLE)) == {"kali-ssh", "wazuh"}


class TestAvailability:
    def test_missing_entrypoint_marked_unavailable(self, tmp_path):
        _write_mcp(tmp_path, {"x": {"command": "node", "args": ["./does/not/exist.js"]}})
        reg = load_registry(tmp_path)
        spec = reg.get("x")
        assert spec.available is False
        assert "entrypoint" in spec.unavailable_reason

    def test_existing_entrypoint_marked_available(self, tmp_path):
        (tmp_path / "server.js").write_text("// stub")
        _write_mcp(tmp_path, {"x": {"command": "node", "args": ["./server.js"]}})
        reg = load_registry(tmp_path)
        # 'node' may or may not be on PATH in CI; assert the entrypoint check
        # passed by checking the reason is not about the entrypoint.
        spec = reg.get("x")
        if not spec.available:
            assert "entrypoint" not in spec.unavailable_reason

    def test_no_config_yields_empty_registry(self, tmp_path):
        reg = load_registry(tmp_path)
        assert reg.servers == []


class TestEnvSecrecy:
    def test_env_captured_for_bridge_but_excluded_from_serialization(self, tmp_path):
        _write_mcp(
            tmp_path,
            {"wazuh": {"command": "node", "env": {"WAZUH_API_PASSWORD": "s3cret"}}},
        )
        reg = load_registry(tmp_path)
        spec = reg.get("wazuh")
        # The bridge can read it...
        assert spec.env["WAZUH_API_PASSWORD"] == "s3cret"
        # ...but it never serializes into the API/wire payload.
        assert "env" not in spec.model_dump()
        assert "s3cret" not in spec.model_dump_json()
