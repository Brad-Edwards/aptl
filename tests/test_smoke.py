"""Live range smoke tests.

Run these against a running APTL lab to validate end-to-end functionality.
Requires: lab running (`aptl lab start`), Docker socket access, SSH keys.

    APTL_SMOKE=1 pytest tests/test_smoke.py -v

Skip individual sections via standard pytest markers:
    APTL_SMOKE=1 pytest tests/test_smoke.py -v -k "not mcp"
"""

import os
import time

import pytest

from tests.helpers import (
    CUSTOM_MCP_SERVERS,
    LIVE_LAB,
    PROJECT_ROOT,
    PUBLISHED_MCP_PATHS,
    container_running,
    curl_indexer,
    docker_exec,
    run_cmd,
    ssh_cmd,
)


# -------------------------------------------------------------------
# Section 1: Container health
# -------------------------------------------------------------------


@LIVE_LAB
class TestContainerHealth:
    """Core containers are running and healthy."""

    @pytest.mark.parametrize("name", [
        "aptl-wazuh.manager-1",
        "aptl-wazuh.indexer-1",
        "aptl-wazuh.dashboard-1",
    ], ids=["wazuh-manager", "wazuh-indexer", "wazuh-dashboard"])
    def test_wazuh_stack_running(self, name):
        assert container_running(name), f"{name} is not running"

    def test_victim_running(self):
        assert container_running("aptl-victim")

    def test_kali_running(self):
        assert container_running("aptl-kali")


# -------------------------------------------------------------------
# Section 2: SSH access
# -------------------------------------------------------------------


@LIVE_LAB
class TestSSHAccess:
    """SSH key auth works for all SSH-accessible containers."""

    def test_victim_ssh(self):
        result = ssh_cmd(2022, "labadmin")
        assert result.returncode == 0, f"SSH failed: {result.stderr}"
        assert "OK" in result.stdout

    def test_kali_ssh(self):
        result = ssh_cmd(2023, "kali")
        assert result.returncode == 0, f"SSH failed: {result.stderr}"
        assert "OK" in result.stdout


# -------------------------------------------------------------------
# Section 3: Wazuh pipeline
# -------------------------------------------------------------------


@LIVE_LAB
class TestWazuhPipeline:
    """Logs flow from containers through Wazuh Manager to Indexer."""

    def test_indexer_responds(self):
        data = curl_indexer()
        assert "cluster_name" in data

    def test_manager_api_responds(self):
        result = run_cmd([
            "docker", "exec", "aptl-wazuh.manager-1",
            "curl", "-ks", "https://localhost:55000",
        ])
        assert result.returncode == 0
        assert (
            "Unauthorized" in result.stdout
            or "title" in result.stdout
        )

    def test_log_ingestion(self):
        """Generate a log on victim, verify it reaches archives."""
        tag = f"APTL_SMOKE_{int(time.time())}"
        run_cmd([
            "docker", "exec", "aptl-victim",
            "logger", "-t", "smoketest", tag,
        ])

        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            time.sleep(5)
            result = docker_exec(
                "aptl-wazuh.manager-1",
                [
                    "grep", "-c", tag,
                    "/var/ossec/logs/archives/archives.log",
                ],
            )
            if (
                result.returncode == 0
                and result.stdout.strip() != "0"
            ):
                return

        pytest.fail(f"Log '{tag}' not in archives within 60s")


# -------------------------------------------------------------------
# Section 4: Web interfaces
# -------------------------------------------------------------------


@LIVE_LAB
class TestWebInterfaces:
    """Web UIs and API endpoints are reachable."""

    def test_wazuh_dashboard(self):
        result = run_cmd([
            "curl", "-ks",
            "-o", "/dev/null",
            "-w", "%{http_code}",
            "https://localhost:443",
        ])
        assert result.returncode == 0
        code = result.stdout.strip()
        assert code in ("200", "302"), (
            f"Dashboard returned {code}"
        )

    def test_indexer_api(self):
        data = curl_indexer()
        assert "cluster_name" in data


# -------------------------------------------------------------------
# Section 5: Network connectivity
# -------------------------------------------------------------------


@LIVE_LAB
class TestNetworkConnectivity:
    """Kali can reach targets across network segments."""

    def test_kali_to_victim(self):
        result = run_cmd([
            "docker", "exec", "aptl-kali",
            "ping", "-c", "1", "-W", "3", "172.20.2.20",
        ])
        assert result.returncode == 0, (
            f"Ping failed: {result.stderr}"
        )


# -------------------------------------------------------------------
# Section 6: MCP server artifacts
# -------------------------------------------------------------------


@LIVE_LAB
class TestMCPServers:
    """MCP server builds and published binaries exist."""

    @pytest.mark.parametrize("server", CUSTOM_MCP_SERVERS)
    def test_custom_build_exists(self, server):
        """Custom Node.js MCP server has a compiled build."""
        entry = os.path.join(
            PROJECT_ROOT, "mcp", server, "build", "index.js",
        )
        assert os.path.isfile(entry), (
            f"{entry} not found -- "
            "run ./mcp/build-all-mcps.sh"
        )

    @pytest.mark.parametrize(
        "name,path",
        list(PUBLISHED_MCP_PATHS.items()),
        ids=list(PUBLISHED_MCP_PATHS.keys()),
    )
    def test_published_binary_exists(self, name, path):
        """Published MCP server binary or script is installed."""
        assert os.path.isfile(path), (
            f"Published MCP '{name}' not found at {path} -- "
            "see tools/.gitignore for install instructions"
        )
