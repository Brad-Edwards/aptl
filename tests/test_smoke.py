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
    WS_SSH_PORT,
    container_running,
    curl_indexer,
    docker_exec,
    run_cmd,
    ssh_cmd,
    workstation_exec,
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

    @pytest.mark.parametrize("name", [
        "aptl-workstation",
        "aptl-fileshare",
        "aptl-webapp",
        "aptl-ad",
        "aptl-db",
    ], ids=["workstation", "fileshare", "webapp", "ad", "db"])
    def test_enterprise_container_running(self, name):
        assert container_running(name), f"{name} is not running"

    @pytest.mark.parametrize("name", [
        "aptl-misp",
        "aptl-thehive",
        "aptl-shuffle-backend",
        "aptl-suricata",
    ], ids=["misp", "thehive", "shuffle", "suricata"])
    def test_soc_container_running(self, name):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if container_running(name):
                return
            time.sleep(10)
        assert container_running(name), f"{name} is not running"


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

    def test_workstation_ssh(self):
        result = ssh_cmd(WS_SSH_PORT, "labadmin")
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

        time.sleep(20)  # Let rsyslog establish connection
        deadline = time.monotonic() + 240
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

        pytest.fail(f"Log '{tag}' not in archives within 240s")


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


# -------------------------------------------------------------------
# Section 7: Workstation credential artifacts
# -------------------------------------------------------------------


@LIVE_LAB
class TestWorkstationArtifacts:
    """Workstation has all planted credential artifacts (WS-01..WS-05)."""

    @pytest.mark.parametrize("path", [
        "/home/dev-user/.bash_history",
        "/home/dev-user/.pgpass",
        "/home/dev-user/.ssh/id_rsa",
        "/home/dev-user/.ssh/id_rsa.pub",
        "/home/dev-user/.ssh/known_hosts",
        "/home/dev-user/.config/credentials.json",
        "/home/dev-user/projects/techvault-portal/.env",
        "/home/dev-user/projects/techvault-portal/deploy.sh",
        "/home/dev-user/Documents/onboarding-notes.txt",
    ], ids=[
        "bash_history", "pgpass", "ssh_privkey", "ssh_pubkey",
        "known_hosts", "credentials_json", "dotenv", "deploy_sh",
        "onboarding_notes",
    ])
    def test_artifact_exists(self, path):
        result = workstation_exec(f"test -f {path} && echo EXISTS")
        assert result.returncode == 0 and "EXISTS" in result.stdout, (
            f"Artifact missing: {path}"
        )

    def test_pgpass_has_db_creds(self):
        result = workstation_exec("cat /home/dev-user/.pgpass")
        assert "techvault_db_pass" in result.stdout

    def test_credentials_json_has_creds(self):
        result = workstation_exec(
            "cat /home/dev-user/.config/credentials.json",
        )
        assert "admin123" in result.stdout
        assert "techvault_db_pass" in result.stdout

    def test_dotenv_has_secrets(self):
        result = workstation_exec(
            "cat /home/dev-user/projects/techvault-portal/.env",
        )
        assert "DB_PASSWORD" in result.stdout
        assert "JWT_SECRET" in result.stdout

    def test_bash_history_has_commands(self):
        result = workstation_exec("cat /home/dev-user/.bash_history")
        assert "sshpass" in result.stdout or "ssh" in result.stdout


# -------------------------------------------------------------------
# Section 8: Fileshare SMB
# -------------------------------------------------------------------


@LIVE_LAB
class TestFileshareShares:
    """Fileshare container is serving SMB shares with planted data."""

    def test_fileshare_smb_listening(self):
        result = docker_exec(
            "aptl-fileshare",
            "smbstatus --brief 2>/dev/null; echo RC=$?",
        )
        assert result.returncode == 0, "smbstatus failed to run"

    def test_public_share_has_welcome(self):
        result = docker_exec(
            "aptl-fileshare",
            "cat /srv/shares/public/welcome.txt",
        )
        assert "TechVault" in result.stdout

    def test_engineering_share_has_deploy_script(self):
        result = docker_exec(
            "aptl-fileshare",
            "cat /srv/shares/engineering/deployments/deploy.sh",
        )
        assert "DB_PASS" in result.stdout or "AWS_SECRET_KEY" in result.stdout

    def test_shared_drive_has_wifi_passwords(self):
        result = docker_exec(
            "aptl-fileshare",
            "cat /srv/shares/shared/wifi-passwords.txt",
        )
        assert "TechVault-Corp" in result.stdout

    def test_hr_share_has_employee_data(self):
        result = docker_exec(
            "aptl-fileshare",
            "cat /srv/shares/hr/employees/directory.csv",
        )
        assert "SSN_Last4" in result.stdout
        assert "Sarah" in result.stdout
