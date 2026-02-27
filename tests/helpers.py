"""Shared test helpers for APTL live-lab tests."""

import json
import os
import selectors
import subprocess
import time

import pytest

# ---------------------------------------------------------------------------
# Live-lab shared constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INDEXER_URL = os.getenv("APTL_INDEXER_URL", "https://localhost:9200")
INDEXER_USER = os.getenv("INDEXER_USERNAME", "admin")
INDEXER_PASS = os.getenv("INDEXER_PASSWORD", "SecretPassword")
API_USER = os.getenv("API_USERNAME", "wazuh-wui")
API_PASS = os.getenv("API_PASSWORD", "WazuhPass123!")
SSH_KEY = os.path.expanduser(os.getenv("APTL_SSH_KEY", "~/.ssh/aptl_lab_key"))

MISP_URL = os.getenv("MISP_URL", "https://localhost:8443")
MISP_API_KEY = os.getenv(
    "MISP_API_KEY", "JHxBbGPnAtyut0FTwkeuhVFnbMksGRCRwsE0V9Xw",
)
THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000")


def _provision_thehive_key() -> str:
    """Auto-provision a TheHive API key via login + key renewal."""
    script = os.path.join(PROJECT_ROOT, "scripts", "thehive-apikey.sh")
    if os.path.isfile(script):
        try:
            result = subprocess.run(
                [script], capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, OSError):
            pass
    return ""


THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "") or _provision_thehive_key()
SHUFFLE_URL = os.getenv("SHUFFLE_URL", "http://localhost:5001")
SHUFFLE_API_KEY = os.getenv(
    "SHUFFLE_API_KEY", "31a211c4-ea5c-4a49-b022-5e2434e758a7",
)

# Kali's DMZ network IP (the one that appears in Wazuh alerts from webapp attacks)
KALI_DMZ_IP = "172.20.1.30"

# Enterprise container IPs and ports
WS_IP = "172.20.2.40"
WS_SSH_PORT = 2028
FILESHARE_IP = "172.20.2.12"
WEBAPP_IP_DMZ = "172.20.1.20"
WEBAPP_PORT = 8080
AD_IP = "172.20.2.10"
DB_IP = "172.20.2.11"
VICTIM_IP = "172.20.2.20"

LIVE_LAB = pytest.mark.skipif(
    os.getenv("APTL_SMOKE", "0") != "1",
    reason="Set APTL_SMOKE=1 to run live smoke tests",
)

# ---------------------------------------------------------------------------
# MCP server configurations
# ---------------------------------------------------------------------------


def _find_node() -> str:
    """Find a Node.js binary, preferring NVM if available."""
    nvm_dir = os.environ.get("NVM_DIR", os.path.expanduser("~/.nvm"))
    nvm_bin = os.path.join(nvm_dir, "versions", "node")
    if os.path.isdir(nvm_bin):
        versions = sorted(os.listdir(nvm_bin), reverse=True)
        for v in versions:
            candidate = os.path.join(nvm_bin, v, "bin", "node")
            if os.path.isfile(candidate):
                return candidate
    return "node"


# Custom Node.js MCP servers (built from source in mcp/)
CUSTOM_MCP_SERVERS = ["mcp-red", "mcp-reverse", "mcp-soar", "mcp-indexer"]

# Published MCP server binaries/scripts (downloaded to tools/)
PUBLISHED_MCP_PATHS = {
    "wazuh": os.path.join(PROJECT_ROOT, "tools", "bin", "mcp-server-wazuh"),
    "thehive": os.path.join(PROJECT_ROOT, "tools", "bin", "thehivemcp"),
    "misp": os.path.join(
        PROJECT_ROOT, "tools", "misp-mcp-server", "misp_server.py",
    ),
}


def mcp_server_cmd(name: str) -> tuple[list[str], dict]:
    """Return (command, env) to spawn an MCP server by its .mcp.json name.

    Returns the command list and extra environment variables needed.
    """
    node_bin = _find_node()

    configs = {
        "kali-ssh": {
            "cmd": [
                node_bin,
                os.path.join(
                    PROJECT_ROOT, "mcp", "mcp-red",
                    "build", "index.js",
                ),
            ],
            "env": {},
        },
        "reverse-sandbox-ssh": {
            "cmd": [
                node_bin,
                os.path.join(
                    PROJECT_ROOT, "mcp", "mcp-reverse",
                    "build", "index.js",
                ),
            ],
            "env": {},
        },
        "shuffle": {
            "cmd": [
                node_bin,
                os.path.join(
                    PROJECT_ROOT, "mcp", "mcp-soar",
                    "build", "index.js",
                ),
            ],
            "env": {"SHUFFLE_API_KEY": SHUFFLE_API_KEY},
        },
        "indexer": {
            "cmd": [
                node_bin,
                os.path.join(
                    PROJECT_ROOT, "mcp", "mcp-indexer",
                    "build", "index.js",
                ),
            ],
            "env": {
                "INDEXER_USERNAME": INDEXER_USER,
                "INDEXER_PASSWORD": INDEXER_PASS,
                "API_USERNAME": API_USER,
                "API_PASSWORD": API_PASS,
            },
        },
        "wazuh": {
            "cmd": [PUBLISHED_MCP_PATHS["wazuh"]],
            "env": {
                "WAZUH_API_HOST": "localhost",
                "WAZUH_API_PORT": "55000",
                "WAZUH_API_USERNAME": API_USER,
                "WAZUH_API_PASSWORD": API_PASS,
                "WAZUH_INDEXER_HOST": "localhost",
                "WAZUH_INDEXER_PORT": "9200",
                "WAZUH_INDEXER_USERNAME": INDEXER_USER,
                "WAZUH_INDEXER_PASSWORD": INDEXER_PASS,
                "WAZUH_VERIFY_SSL": "false",
                "RUST_LOG": "warn",
            },
        },
        "misp": {
            "cmd": [
                os.path.join(PROJECT_ROOT, "tools", "misp-mcp-server", ".venv", "bin", "python"),
                PUBLISHED_MCP_PATHS["misp"],
            ],
            "env": {
                "MISP_URL": MISP_URL,
                "MISP_API_KEY": MISP_API_KEY,
                "MISP_VERIFY_SSL": "False",
            },
        },
        "thehive": {
            "cmd": [PUBLISHED_MCP_PATHS["thehive"], "--transport", "stdio"],
            "env": {
                "THEHIVE_URL": THEHIVE_URL,
                "THEHIVE_API_KEY": THEHIVE_API_KEY,
                "THEHIVE_ORGANISATION": "admin",
            },
        },
    }

    if name not in configs:
        raise ValueError(f"Unknown MCP server: {name}")

    cfg = configs[name]
    return cfg["cmd"], cfg["env"]


def _read_jsonrpc_response(
    stdout, deadline: float,
) -> dict | None:
    """Read one JSON-RPC response line with timeout."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    sel = selectors.DefaultSelector()
    sel.register(stdout, selectors.EVENT_READ)
    ready = sel.select(timeout=remaining)
    sel.close()
    if not ready:
        return None
    line = stdout.readline().strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def mcp_jsonrpc(
    server_name: str,
    messages: list[dict],
    timeout: int = 15,
) -> list[dict]:
    """Spawn an MCP server and exchange JSON-RPC messages.

    Uses Popen with sequential writes so servers that process
    one message at a time (e.g. Rust binaries) work correctly.
    """
    cmd, extra_env = mcp_server_cmd(server_name)
    env = {**os.environ, **extra_env}

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )

    deadline = time.monotonic() + timeout
    responses = []

    try:
        for msg in messages:
            if time.monotonic() > deadline:
                break
            proc.stdin.write(json.dumps(msg) + "\n")
            proc.stdin.flush()

            # Notifications (no id) don't get responses
            if "id" not in msg:
                time.sleep(0.2)
                continue

            resp = _read_jsonrpc_response(
                proc.stdout, deadline,
            )
            if resp is not None:
                responses.append(resp)
    except BrokenPipeError:
        pass
    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    if not responses:
        pytest.fail(
            f"MCP server '{server_name}' produced no "
            f"responses within {timeout}s"
        )

    return responses


_INIT_MSG = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {
            "name": "aptl-test",
            "version": "1.0.0",
        },
    },
}

_INITIALIZED_MSG = {
    "jsonrpc": "2.0",
    "method": "notifications/initialized",
}


def mcp_tools_list(server_name: str, timeout: int = 15) -> list[str]:
    """Spawn an MCP server and return the list of tool names it advertises."""
    messages = [
        _INIT_MSG,
        _INITIALIZED_MSG,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        },
    ]

    responses = mcp_jsonrpc(server_name, messages, timeout=timeout)

    tool_names = []
    for resp in responses:
        for tool in resp.get("result", {}).get("tools", []):
            name = tool.get("name", "")
            if name:
                tool_names.append(name)

    return tool_names


def mcp_call_tool(
    server_name: str,
    tool_name: str,
    arguments: dict,
    timeout: int = 30,
) -> dict:
    """Spawn an MCP server, initialize, and call a single tool.

    Returns the JSON-RPC result from the tools/call response.
    """
    messages = [
        _INIT_MSG,
        _INITIALIZED_MSG,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        },
    ]

    responses = mcp_jsonrpc(server_name, messages, timeout=timeout)

    for resp in responses:
        if resp.get("id") == 2:
            if "error" in resp:
                pytest.fail(
                    f"MCP {server_name}/{tool_name} returned error: {resp['error']}"
                )
            return resp.get("result", {})

    cmd, _ = mcp_server_cmd(server_name)
    pytest.fail(
        f"No tools/call response from {server_name}/{tool_name}. "
        f"Sent to: {' '.join(cmd)}"
    )


def mcp_tool_text(result: dict) -> str:
    """Extract text from an MCP tools/call result."""
    parts = []
    for item in result.get("content", []):
        if item.get("type") == "text":
            parts.append(item["text"])
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Live-lab shared helper functions
# ---------------------------------------------------------------------------


def run_cmd(cmd: list[str], timeout: int = 15) -> subprocess.CompletedProcess:
    """Run a subprocess command with capture and timeout."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def docker_exec(
    container: str, cmd: str | list[str], timeout: int = 30,
) -> subprocess.CompletedProcess:
    """Run a command inside a Docker container."""
    if isinstance(cmd, str):
        parts = ["docker", "exec", container, "bash", "-c", cmd]
    else:
        parts = ["docker", "exec", container] + cmd
    return run_cmd(parts, timeout=timeout)


def kali_exec(cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a command inside the Kali container."""
    return docker_exec("aptl-kali", cmd, timeout=timeout)


def workstation_exec(
    cmd: str, timeout: int = 30,
) -> subprocess.CompletedProcess:
    """Run a command inside the workstation container."""
    return docker_exec("aptl-workstation", cmd, timeout=timeout)


def container_running(name: str) -> bool:
    """Check if a Docker container is running."""
    result = run_cmd(["docker", "inspect", "-f", "{{.State.Status}}", name])
    return result.returncode == 0 and result.stdout.strip() == "running"


def curl_indexer(path: str = "", body: dict | None = None) -> dict:
    """Query the Wazuh Indexer API via curl."""
    url = f"{INDEXER_URL}/{path}" if path else INDEXER_URL
    cmd = [
        "curl", "-ks", "-f", url,
        "-u", f"{INDEXER_USER}:{INDEXER_PASS}",
    ]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    result = run_cmd(cmd, timeout=20)
    assert result.returncode == 0, f"curl failed: {result.stderr}"
    return json.loads(result.stdout)


def curl_json(
    url: str,
    *,
    auth_header: str = "",
    method: str = "GET",
    body: dict | None = None,
    timeout: int = 20,
    insecure: bool = False,
) -> dict:
    """Make an HTTP request via curl and return parsed JSON."""
    cmd = ["curl", "-sf", url]
    if insecure:
        cmd.insert(1, "-k")
    if method != "GET":
        cmd += ["-X", method]
    if auth_header:
        cmd += ["-H", f"Authorization: {auth_header}"]
    cmd += ["-H", "Content-Type: application/json"]
    if body is not None:
        cmd += ["-d", json.dumps(body)]
    result = run_cmd(cmd, timeout=timeout)
    assert result.returncode == 0, f"curl {url} failed: {result.stderr}"
    return json.loads(result.stdout)


def ssh_cmd(
    port: int, user: str, cmd: str = "echo OK",
) -> subprocess.CompletedProcess:
    """Run a command via SSH to a lab container."""
    return run_cmd([
        "ssh",
        "-i", SSH_KEY,
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-p", str(port),
        f"{user}@localhost",
        cmd,
    ])


def wait_for_alert(
    query: dict, timeout: int = 90, poll_interval: int = 10,
) -> dict:
    """Poll the Wazuh Indexer for a matching alert.

    Returns the first matching hit's _source, or calls pytest.fail.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            data = curl_indexer(
                "wazuh-alerts-4.x-*/_search",
                body={"query": query, "size": 1},
            )
            hits = data.get("hits", {}).get("hits", [])
            if hits:
                return hits[0].get("_source", hits[0])
        except (AssertionError, json.JSONDecodeError):
            pass
        time.sleep(poll_interval)

    pytest.fail(f"Alert not found within {timeout}s: {json.dumps(query, indent=2)}")
