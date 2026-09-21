#!/usr/bin/env python3
"""Exercise one generated native MCP entry, then prove stale access is rejected."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tomllib
from pathlib import Path

import rfc8785

from aptl.validation.mcp_protocol import McpProtocolError, call_mcp_tool
from aptl.workbench.profiles import profile_for


def _entry(path: Path, client: str) -> tuple[str, dict[str, object]]:
    if client == "claude":
        document = json.loads(path.read_text(encoding="utf-8"))
        servers = document.get("mcpServers")
    else:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        servers = document.get("mcp_servers")
    if not isinstance(servers, dict):
        raise ValueError("native MCP server map is unavailable")
    selected = [
        (name, value)
        for name, value in servers.items()
        if isinstance(name, str) and name.endswith("-red") and isinstance(value, dict)
    ]
    if len(selected) != 1:
        raise ValueError("native red MCP entry is ambiguous")
    return selected[0]


def _transport_call(config: Path, client: str) -> tuple[str, dict[str, object]]:
    name, entry = _entry(config, client)
    command = entry.get("command")
    args = entry.get("args")
    if (
        not isinstance(command, str)
        or not isinstance(args, list)
        or not all(isinstance(item, str) for item in args)
    ):
        raise ValueError("native MCP command is invalid")
    server = profile_for("red").servers[0]
    result = call_mcp_tool(
        [command, *args],
        "kali_info",
        {},
        cwd=config.parent,
        timeout_seconds=180,
        expected_tool_names=server.tool_names,
    )
    return name, result


def _walk(value):
    """Yield every nested JSON object from bounded client event output."""

    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _parse_client_events(
    payload: str, *, client: str, server_name: str, tool_name: str
) -> object | None:
    """Return the real native client's successful MCP result, if present."""

    documents = []
    for line in payload.splitlines():
        if not line.strip():
            continue
        try:
            documents.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    objects = [item for document in documents for item in _walk(document)]
    if client == "claude":
        tool_ids = {
            item.get("id")
            for item in objects
            if item.get("type") == "tool_use"
            and item.get("name") == f"mcp__{server_name}__{tool_name}"
            and isinstance(item.get("id"), str)
        }
        for item in objects:
            if (
                item.get("type") == "tool_result"
                and item.get("tool_use_id") in tool_ids
                and item.get("is_error") is not True
            ):
                return item.get("content")
        return None
    for item in objects:
        if item.get("type") not in {"mcp_tool_call", "mcp_tool"}:
            continue
        server = item.get("server") or item.get("server_name")
        tool = item.get("tool") or item.get("tool_name") or item.get("name")
        if (
            server == server_name
            and tool == tool_name
            and item.get("error") in (None, False)
            and item.get("status") not in {"failed", "error"}
        ):
            return item.get("result") or item.get("content") or item
    return None


def _native_call(
    config: Path, client: str, *, require_success: bool
) -> tuple[str, str, object | None]:
    """Invoke the installed Claude/Codex binary using its managed config."""

    server_name, _entry_value = _entry(config, client)
    executable = shutil.which(client)
    if executable is None:
        raise ValueError(f"{client} CLI is unavailable")
    version = subprocess.run(
        [executable, "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    prompt = (
        f"Call exactly the MCP tool mcp__{server_name}__kali_info once with an "
        "empty object. Do not use any other tool. Report whether that call succeeded."
    )
    if client == "claude":
        command = [
            executable,
            "--print",
            "--output-format",
            "stream-json",
            "--verbose",
            "--mcp-config",
            str(config),
            "--strict-mcp-config",
            "--allowedTools",
            f"mcp__{server_name}__kali_info",
            "--permission-mode",
            "dontAsk",
            "--max-turns",
            "3",
            prompt,
        ]
    else:
        command = [
            executable,
            "exec",
            "--json",
            "--ephemeral",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--cd",
            str(config.parent),
            "--ignore-user-config",
            "--ignore-rules",
            "--config",
            'approval_policy="never"',
            prompt,
        ]
    completed = subprocess.run(
        command,
        cwd=config.parent,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=300,
    )
    output = (completed.stdout + "\n" + completed.stderr)[-(8 * 1024 * 1024) :]
    result = _parse_client_events(
        completed.stdout,
        client=client,
        server_name=server_name,
        tool_name="kali_info",
    )
    if completed.returncode != 0 or require_success != (result is not None):
        raise RuntimeError(f"{client} native MCP qualification failed")
    if not require_success and not any(
        marker in output for marker in (server_name, "kali_info", "MCP", "mcp")
    ):
        raise RuntimeError(f"{client} did not observe the revoked MCP surface")
    return server_name, version, result


def _write_once(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("active", "revoked"), required=True)
    parser.add_argument("--client", choices=("claude", "codex"), required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--candidate-manifest-digest", required=True)
    parser.add_argument("--golden-image-digest", required=True)
    parser.add_argument("--seat-id", required=True)
    parser.add_argument("--generation", type=int, required=True)
    args = parser.parse_args()

    if args.mode == "active":
        server_name, client_version, result = _native_call(
            args.config, args.client, require_success=True
        )
        digest = "sha256:" + hashlib.sha256(rfc8785.dumps(result)).hexdigest()
        _write_once(
            args.state,
            rfc8785.dumps(
                {
                    "schema_version": "aptl.native-client-active/v1",
                    "server_name": server_name,
                    "tool_name": "kali_info",
                    "client_version": client_version,
                    "active_response_digest": digest,
                }
            ),
        )
        return

    if args.receipt is None:
        raise ValueError("revoked mode requires --receipt")
    active = json.loads(args.state.read_bytes())
    try:
        _native_call(args.config, args.client, require_success=False)
        _transport_call(args.config, args.client)
    except (McpProtocolError, OSError, ValueError):
        pass
    else:
        raise RuntimeError("revoked native MCP access remained usable")
    receipt = {
        "schema_version": "aptl.native-client-probe/v1",
        "candidate_id": args.candidate_id,
        "candidate_manifest_digest": args.candidate_manifest_digest,
        "golden_image_digest": args.golden_image_digest,
        "seat_id": args.seat_id,
        "generation": args.generation,
        "client": args.client,
        "server_name": active["server_name"],
        "tool_name": active["tool_name"],
        "client_version": active["client_version"],
        "active_response_digest": active["active_response_digest"],
        "live_call_passed": True,
        "stale_call_rejected": True,
    }
    _write_once(args.receipt, rfc8785.dumps(receipt))


if __name__ == "__main__":
    main()
