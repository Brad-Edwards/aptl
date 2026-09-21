"""Shared test helpers for APTL live-lab tests."""

import json
import os
import re
import subprocess
import time
from pathlib import Path

import pytest

from aptl.core.env import load_dotenv
from aptl.validation.mcp_protocol import exchange_jsonrpc

# ---------------------------------------------------------------------------
# Live-lab shared constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    PROJECT_ENV = load_dotenv(Path(PROJECT_ROOT) / ".env")
except (OSError, ValueError):
    PROJECT_ENV = {}


def _credential(name: str, fallback: str = "") -> str:
    """Prefer the process environment, then the generated project .env."""
    return os.getenv(name, PROJECT_ENV.get(name, fallback))

INDEXER_URL = os.getenv("APTL_INDEXER_URL", "https://localhost:9200")
INDEXER_USER = _credential("INDEXER_USERNAME", "admin")
INDEXER_PASS = _credential("INDEXER_PASSWORD", "SecretPassword")
API_USER = _credential("API_USERNAME", "wazuh-wui")
API_PASS = _credential("API_PASSWORD", "WazuhPass123!")
SSH_KEY = os.path.expanduser(os.getenv("APTL_SSH_KEY", "~/.ssh/aptl_lab_key"))

MISP_URL = os.getenv("MISP_URL", "https://localhost:8443")
MISP_API_KEY = _credential(
    "MISP_API_KEY", "JHxBbGPnAtyut0FTwkeuhVFnbMksGRCRwsE0V9Xw",
)
# SEC-006 / ADR-034: TheHive and Shuffle's host-facing surfaces moved
# to HTTPS with lab-CA-signed certs. Tests default to the verified
# endpoints and to the lab CA bundle materialized by `aptl lab start`.
THEHIVE_URL = os.getenv("THEHIVE_URL", "https://localhost:9000")
LAB_CA_PATH = os.getenv(
    "APTL_LAB_CA_PATH",
    os.path.join(PROJECT_ROOT, "config", "soc_certs", "lab-ca.pem"),
)


def _provision_thehive_key() -> str:
    """Auto-provision a TheHive API key via login + key renewal."""
    script = os.path.join(PROJECT_ROOT, "scripts", "thehive-apikey.sh")
    if os.path.isfile(script):
        try:
            result = subprocess.run(
                [script], capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, OSError):
            pass
    return ""


THEHIVE_API_KEY = _credential("THEHIVE_API_KEY") or _provision_thehive_key()
SHUFFLE_URL = os.getenv("SHUFFLE_URL", "https://localhost:3443")
SHUFFLE_API_KEY = _credential(
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
    import shutil
    return shutil.which("node") or "node"


# Custom Node.js MCP servers built by `aptl lab start`.
CUSTOM_MCP_SERVERS = [
    "mcp-red",
    "mcp-reverse",
    "mcp-indexer",
    "mcp-wazuh",
    "mcp-network",
    "mcp-threatintel",
    "mcp-casemgmt",
    "mcp-soar",
]


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
            "cmd": [
                node_bin,
                os.path.join(
                    PROJECT_ROOT, "mcp", "mcp-wazuh", "build", "index.js"
                ),
            ],
            "env": {
                "INDEXER_USERNAME": INDEXER_USER,
                "INDEXER_PASSWORD": INDEXER_PASS,
            },
        },
        "network": {
            "cmd": [
                node_bin,
                os.path.join(
                    PROJECT_ROOT, "mcp", "mcp-network", "build", "index.js"
                ),
            ],
            "env": {
                "INDEXER_USERNAME": INDEXER_USER,
                "INDEXER_PASSWORD": INDEXER_PASS,
            },
        },
        "misp": {
            "cmd": [
                node_bin,
                os.path.join(
                    PROJECT_ROOT,
                    "mcp",
                    "mcp-threatintel",
                    "build",
                    "index.js",
                ),
            ],
            "env": {"MISP_API_KEY": MISP_API_KEY},
        },
        "thehive": {
            "cmd": [
                node_bin,
                os.path.join(
                    PROJECT_ROOT,
                    "mcp",
                    "mcp-casemgmt",
                    "build",
                    "index.js",
                ),
            ],
            "env": {"THEHIVE_API_KEY": THEHIVE_API_KEY},
        },
    }

    if name not in configs:
        raise ValueError(f"Unknown MCP server: {name}")

    cfg = configs[name]
    return cfg["cmd"], cfg["env"]


def mcp_jsonrpc(
    server_name: str,
    messages: list[dict],
    timeout: int = 30,
) -> list[dict]:
    """Spawn an MCP server and exchange JSON-RPC messages.

    Uses Popen with sequential writes so servers that process
    one message at a time (e.g. Rust binaries) work correctly.
    """
    cmd, extra_env = mcp_server_cmd(server_name)
    env = {**os.environ, **extra_env}

    return exchange_jsonrpc(
        cmd,
        messages,
        cwd=Path(PROJECT_ROOT),
        env=env,
        timeout_seconds=timeout,
    )


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


def mcp_tools_list(server_name: str, timeout: int = 30) -> list[str]:
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
    timeout: int = 60,
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


def run_cmd(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a subprocess command with capture and timeout."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def docker_exec(
    container: str, cmd: str | list[str], timeout: int = 60,
    user: str | None = None,
) -> subprocess.CompletedProcess:
    """Run a command inside a Docker container, optionally as ``user``."""
    base = ["docker", "exec"]
    if user is not None:
        base += ["--user", user]
    base.append(container)
    if isinstance(cmd, str):
        parts = base + ["bash", "-c", cmd]
    else:
        parts = base + cmd
    return run_cmd(parts, timeout=timeout)


def kali_exec(cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a command inside the Kali container."""
    return docker_exec("aptl-kali", cmd, timeout=timeout)


def kali_capture_exec(cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a command inside the Kali capture sidecar (ADR-041).

    The sidecar owns the kali_captures volume read-write; the Kali workload
    does not mount it, so capture-evidence assertions must run here.
    """
    return docker_exec("aptl-kali-capture", cmd, timeout=timeout)


def workstation_exec(
    cmd: str, timeout: int = 60,
) -> subprocess.CompletedProcess:
    """Run a command inside the workstation container."""
    return docker_exec("aptl-workstation", cmd, timeout=timeout)


def container_running(name: str) -> bool:
    """Check if a Docker container is running."""
    try:
        result = run_cmd(["docker", "inspect", "-f", "{{.State.Status}}", name])
    except FileNotFoundError:
        return False
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
    result = run_cmd(cmd, timeout=40)
    assert result.returncode == 0, f"curl failed: {result.stderr}"
    return json.loads(result.stdout)


def curl_json(
    url: str,
    *,
    auth_header: str = "",
    method: str = "GET",
    body: dict | None = None,
    timeout: int = 120,
    insecure: bool = False,
    ca_cert_path: str | None = None,
) -> dict:
    """Make an HTTP request via curl and return parsed JSON.

    SEC-006 / ADR-034: SOC stack callers should pass
    ``ca_cert_path=LAB_CA_PATH`` to verify against the lab-managed CA.
    ``insecure=True`` remains for Wazuh inter-component traffic
    (SEC-004 territory) and for fallback when the lab CA bundle is
    unavailable. Mutually exclusive — ``insecure`` wins when both set.
    """
    lab_ca_urls = (MISP_URL, THEHIVE_URL, SHUFFLE_URL)
    if (
        not insecure
        and ca_cert_path is None
        and any(url == base or url.startswith(f"{base}/") for base in lab_ca_urls)
        and os.path.isfile(LAB_CA_PATH)
    ):
        ca_cert_path = LAB_CA_PATH

    cmd = ["curl", "-sf", url]
    if insecure:
        cmd.insert(1, "-k")
    elif ca_cert_path:
        cmd[1:1] = ["--cacert", ca_cert_path]
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
    port: int, user: str, cmd: str = "echo OK", host: str = "localhost",
) -> subprocess.CompletedProcess:
    """Run a command via SSH to a lab container.

    ``host`` defaults to ``localhost`` for services published to the host
    (e.g. the kali SSH proxy on 2023). Internal-only targets such as victim
    and workstation publish NO host port by design (issue #293) — they attach
    only to an internal Docker network and are reached by container IP over the
    bridge with the same lab key. For those, pass ``host=VICTIM_IP`` /
    ``host=WS_IP`` with ``port=22``.
    """
    return run_cmd([
        "ssh",
        "-i", SSH_KEY,
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-p", str(port),
        f"{user}@{host}",
        cmd,
    ])


def wait_for_alert(
    query: dict, timeout: int = 180, poll_interval: int = 10,
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


# --------------------------------------------------------------------------- #
# Default TechVault scenario (issue #875): the in-tree techvault-operational.sdl
# was retired in favour of the bundled env-pack. Tests that parse/plan/realize
# "the default TechVault scenario" resolve its staged SDL through this helper.
# --------------------------------------------------------------------------- #
def techvault_scenario_bundle(staging_root: Path):
    """Stage + return the default TechVault env-pack bundle under ``staging_root``."""
    from aptl.core.scenario_bundle import env_pack_bundle

    return env_pack_bundle(Path(staging_root) / ".aptl" / "staged-packs", "techvault")


def techvault_scenario_path(staging_root: Path) -> Path:
    """Staged SDL path of the default TechVault env-pack scenario (#875)."""
    return techvault_scenario_bundle(staging_root).sdl_path


def docker_ps_inventory_row(
    name: str,
    image: str = "victim:latest",
    container_id: str = "abc",
    status: str = "Up 1 minute",
    state: str = "running",
    labels: str = "com.docker.compose.project=test",
    ports: str = "",
) -> str:
    """Render one `docker ps --format '{{json .}}'` row.

    The project inventory reads JSON rather than tab-delimited columns because
    image labels are arbitrary text: Ubuntu 26.04 ships an
    `org.opencontainers.image.description` containing newlines, which split one
    container across several "rows" and made the inventory unparseable (issue
    #1006).
    """
    return json.dumps(
        {
            "Names": name,
            "Image": image,
            "ID": container_id,
            "Status": status,
            "State": state,
            "Labels": labels,
            "Ports": ports,
        }
    )


def dockerfile_copies(dockerfile: Path) -> list[tuple[str, str]]:
    """Return the (source, destination) pairs a Dockerfile actually COPYs.

    Tests that assert on Dockerfile content must look at instructions, not at
    text: a comment mentioning a destination, or a source and destination that
    appear in different instructions, satisfied the old independent-substring
    checks while the real COPY was wrong (issue #1006). Comments are ignored,
    line continuations are joined, and `--flag=value` options are skipped. A
    multi-source COPY yields one pair per source.
    """
    logical: list[str] = []
    pending = ""
    for raw in dockerfile.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not pending and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        logical.append(pending + line)
        pending = ""
    pairs: list[tuple[str, str]] = []
    for instruction in logical:
        words = instruction.split()
        if not words or words[0].upper() != "COPY":
            continue
        operands = [word for word in words[1:] if not word.startswith("--")]
        if len(operands) < 2:
            continue
        *sources, destination = operands
        pairs.extend((source, destination) for source in sources)
    return pairs


# ---------------------------------------------------------------------------
# Workspace-scoped backend resources (#1054)
# ---------------------------------------------------------------------------


def realized_container_name(backend, semantic_name: str) -> str:
    """Return the external name this backend's workspace gives a container.

    Backend resources carry workspace-scoped external names recorded in
    ownership receipts, so concurrent labs cannot collide. ``container_exec``
    and friends resolve a semantic name through those receipts themselves; a
    test that shells out to ``docker`` has to ask what the container is really
    called instead of assuming the name the scenario declared.
    """

    return backend._ensure_resource_ownership().container_name(semantic_name)


def realized_project_name(backend) -> str:
    """Return the workspace-scoped Compose project name a backend realizes under.

    Networks are named ``<project>_<network>``, and the project itself carries
    the workspace suffix, so a test that names a network directly has to build
    it from this rather than from the project name it passed in.
    """

    return backend._ensure_resource_ownership().project_name


def run_owned_container(backend, semantic_name: str, image_args: list[str]) -> str:
    """Start a container this backend owns and return its native id.

    A backend resolves a selector only through its own ownership receipts, so a
    container started behind its back is invisible to it — correctly, because a
    backend must not reach resources outside its workspace. A test that needs
    the backend to observe a container it did not realize therefore has to give
    it a real one: workspace-scoped name, workspace labels, recorded receipt.

    ``image_args`` is everything from the image reference onward.
    """

    from aptl.core.deployment._compose_resource_ownership import ResourceReceipt

    ownership = backend._ensure_resource_ownership()
    attempt_id = backend._resource_attempt_id
    external = ownership.container_name(semantic_name)
    labels: list[str] = []
    for label, value in ownership.labels(attempt_id=attempt_id).items():
        labels.extend(("--label", f"{label}={value}"))
    created = subprocess.run(
        ["docker", "run", "-d", "--name", external, *labels, *image_args],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    native_id = created.stdout.strip()
    ownership.record(
        ResourceReceipt(
            kind="container",
            native_id=native_id,
            external_name=external,
            semantic_name=semantic_name,
            node_address=f"test.{semantic_name}",
            workspace_id=ownership.workspace_id,
            project_name=ownership.project_name,
            daemon_id=backend._ownership_daemon_id(),
            attempt_id=attempt_id,
            managed_by="direct",
        )
    )
    return native_id


_EPHEMERAL_NAME = re.compile(r"^aptl-[a-z0-9]+(?:-[a-z0-9]+)*-[0-9a-f]{12}$")


def without_helper_identity(argv: list[str]) -> list[str]:
    """Return a helper's argv without its per-invocation name and role label.

    ``EphemeralContainer`` names every helper randomly so concurrent helpers
    never collide on the daemon. A test that pins the rest of the argv — the
    order of its security options, its mounts — strips exactly that identity
    here rather than loosening every other assertion. Only the generated name
    shape and the ephemeral role label are removed; a node's own ``--name`` is
    left alone.
    """

    from aptl.core.ephemeral_containers import EPHEMERAL_ROLE_LABEL

    stripped: list[str] = []
    skip_next = False
    for index, item in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        following = str(argv[index + 1]) if index + 1 < len(argv) else ""
        if (item == "--name" and _EPHEMERAL_NAME.fullmatch(following)) or (
            item == "--label" and following.startswith(f"{EPHEMERAL_ROLE_LABEL}=")
        ):
            skip_next = True
            continue
        stripped.append(item)
    return stripped
