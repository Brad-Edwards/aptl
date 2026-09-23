"""Native client documents preserve user settings and pin seat transport."""

import json
import tomllib
from pathlib import Path

import pytest

from aptl.workbench.access_clients import client_entries, render_claude, render_codex
from tests.test_mcp_access import access_record, grant


def test_native_configs_keep_manual_servers_and_provider_settings(tmp_path):
    entries = client_entries(
        access_record(),
        grant(),
        ssh_executable=Path("/usr/bin/ssh"),
        identity_file=tmp_path / "identity",
        known_hosts=tmp_path / "known_hosts",
        username="aptl-mcp",
    )
    claude = json.loads(
        render_claude('{"mcpServers":{"manual":{"command":"mine"}}}', entries)
    )
    assert claude["mcpServers"]["manual"] == {"command": "mine"}
    codex = tomllib.loads(
        render_codex(
            'model = "user-model"\n[mcp_servers.manual]\ncommand = "mine"\n', entries
        )
    )
    assert codex["model"] == "user-model"
    assert codex["mcp_servers"]["manual"]["command"] == "mine"
    assert codex["mcp_servers"]["aptl-seat-1-red"] == {
        **claude["mcpServers"]["aptl-seat-1-red"],
        "startup_timeout_sec": 120,
        "tool_timeout_sec": 180,
    }
    args = entries["aptl-seat-1-red"]["args"]
    assert "-F" in args
    assert args[args.index("-F") + 1] == "/dev/null"
    assert "StrictHostKeyChecking=yes" in args
    assert "IdentityAgent=none" in args
    known_hosts_option = next(
        item for item in args if item.startswith("UserKnownHostsFile=")
    )
    assert known_hosts_option == f"UserKnownHostsFile={tmp_path / 'known_hosts'}"
    assert '"' not in known_hosts_option
    assert "30222" in args
    assert "2222" not in args
    assert args[-1] == "aptl-mcp-v1 instance-1 1 aptl-red"


@pytest.mark.parametrize(
    "render,existing",
    [
        (render_claude, '{"mcpServers":{"aptl-seat-1-red":{"command":"mine"}}}'),
        (render_codex, '[mcp_servers.aptl-seat-1-red]\ncommand="mine"\n'),
    ],
)
def test_manual_name_collision_is_never_overwritten(render, existing):
    with pytest.raises(ValueError, match="managed|manual|conflict"):
        render(existing, {"aptl-seat-1-red": {"command": "ssh", "args": []}})


def test_duplicate_json_keys_and_toml_keys_are_rejected():
    with pytest.raises(ValueError):
        render_claude('{"mcpServers":{},"mcpServers":{}}', {})
    with pytest.raises(ValueError):
        render_codex('model="a"\nmodel="b"\n', {})


def test_unchanged_owned_entries_update_but_manual_edits_conflict():
    old = {"aptl-seat-1-red": {"command": "ssh", "args": ["old"]}}
    new = {"aptl-seat-1-red": {"command": "ssh", "args": ["new"]}}
    original = render_claude("{}", old)
    assert json.loads(render_claude(original, new, previous=old))["mcpServers"] == new
    changed = original.replace("old", "manual-edit")
    with pytest.raises(ValueError, match="conflict"):
        render_claude(changed, new, previous=old)
    original_toml = render_codex('model="mine"\n', old)
    assert tomllib.loads(render_codex(original_toml, new, previous=old))[
        "mcp_servers"
    ] == {
        name: {**value, "startup_timeout_sec": 120, "tool_timeout_sec": 180}
        for name, value in new.items()
    }
    prepared_input_1 = original_toml.replace("old", "manual-edit")
    with pytest.raises(ValueError, match="conflict"):
        render_codex(prepared_input_1, new, previous=old)


def test_project_publication_preserves_manual_changes_and_rejects_stale_identity(
    tmp_path,
):
    from aptl.workbench.client_files import publish_client_config

    target = tmp_path / ".mcp.json"
    target.write_text('{"mcpServers":{"manual":{"command":"mine"}}}')
    record = access_record()
    entry = {"aptl-seat-1-red": {"command": "ssh", "args": ["first"]}}
    publish_client_config(tmp_path, "claude", record, entry)
    content = json.loads(target.read_text())
    content["mcpServers"]["manual"]["env"] = {"USER_SETTING": "keep"}
    target.write_text(json.dumps(content))
    newer = access_record(generation=2)
    entry["aptl-seat-1-red"]["args"] = ["second"]
    publish_client_config(tmp_path, "claude", newer, entry)
    assert (
        json.loads(target.read_text())["mcpServers"]["manual"]["env"]["USER_SETTING"]
        == "keep"
    )
    with pytest.raises(ValueError, match="stale|identity"):
        publish_client_config(tmp_path, "claude", record, entry)
    assert target.stat().st_mode & 0o777 == 0o600


def test_project_publication_refuses_symlinked_client_file(tmp_path):
    from aptl.workbench.client_files import publish_client_config

    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_text("{}")
    (tmp_path / ".mcp.json").symlink_to(elsewhere)
    prepared_input_2 = access_record()
    with pytest.raises(ValueError):
        publish_client_config(tmp_path, "claude", prepared_input_2, {})
    assert elsewhere.read_text() == "{}"


@pytest.mark.parametrize("client", ["claude", "codex"])
def test_replacement_instance_refreshes_owned_client_only_in_newer_generation(
    tmp_path, client,
):
    from aptl.workbench.client_files import publish_client_config

    first = access_record()
    entries = {"aptl-seat-1-red": {"command": "ssh", "args": ["first"]}}
    target = publish_client_config(tmp_path, client, first, entries)
    replacement = access_record(instance_id="replacement", generation=2)
    entries["aptl-seat-1-red"]["args"] = ["replacement"]
    publish_client_config(tmp_path, client, replacement, entries)
    state = json.loads((tmp_path / f".aptl/{client}-mcp-owned.json").read_text())
    assert state["identity"]["instance_id"] == "replacement"
    assert state["identity"]["generation"] == 2
    content = target.read_bytes()
    for rejected in (
        first,
        access_record(instance_id="other", generation=2),
        access_record(owner_id="other-owner", generation=3),
        access_record(seat_id="other-seat", generation=3),
    ):
        with pytest.raises(ValueError, match="identity|generation"):
            publish_client_config(tmp_path, client, rejected, entries)
        assert target.read_bytes() == content


def test_empty_owned_toml_block_can_be_refreshed_without_losing_manual_settings():
    entries = {"aptl-seat-1-red": {"command": "ssh", "args": ["first"]}}
    populated = render_codex('model="mine"\n', entries)
    empty = render_codex(populated, {}, previous=entries)
    refreshed = render_codex(empty, entries, previous={})
    parsed = tomllib.loads(refreshed)
    assert parsed["model"] == "mine"
    assert parsed["mcp_servers"]["aptl-seat-1-red"]["args"] == ["first"]


def test_same_generation_cannot_silently_move_endpoint_or_workload(tmp_path):
    from aptl.workbench.client_files import publish_client_config

    record = access_record()
    publish_client_config(tmp_path, "codex", record, {})
    target = tmp_path / ".codex/config.toml"
    original = target.read_bytes()
    for changes in (
        {"outer_endpoint": {"address": "127.0.0.1", "port": 32000}},
        {"container_ids": {"kali": "c" * 64}},
        {"guest_daemon_id": "other"},
    ):
        changed = access_record(**changes)
        with pytest.raises(ValueError, match="generation"):
            publish_client_config(tmp_path, "codex", changed, {})
        assert target.read_bytes() == original


def test_interrupted_publication_recovers_ownership_without_losing_manual_data(
    tmp_path, monkeypatch
):
    from aptl.workbench import client_files

    original_write = client_files._atomic_write

    def fail_state(path, *args, **kwargs):
        if path.name == "claude-mcp-owned.json":
            raise OSError("simulated interruption after client write")
        original_write(path, *args, **kwargs)

    target = tmp_path / ".mcp.json"
    target.write_text('{"mcpServers":{"manual":{"command":"mine"}}}')
    record = access_record()
    entry = {"aptl-seat-1-red": {"command": "ssh", "args": ["first"]}}
    monkeypatch.setattr(client_files, "_atomic_write", fail_state)
    with pytest.raises(OSError):
        client_files.publish_client_config(tmp_path, "claude", record, entry)
    monkeypatch.setattr(client_files, "_atomic_write", original_write)
    client_files.publish_client_config(tmp_path, "claude", record, entry)
    assert json.loads(target.read_text())["mcpServers"]["manual"] == {"command": "mine"}
    assert not (tmp_path / ".aptl/claude-mcp-pending.json").exists()
