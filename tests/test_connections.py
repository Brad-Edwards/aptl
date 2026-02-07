"""Tests for connection info generation.

Tests are written FIRST (TDD). Uses real AptlConfig and EnvVars objects.
"""

from pathlib import Path

import pytest


def _make_config(wazuh=True, victim=True, kali=True, reverse=False):
    """Helper to create an AptlConfig with specific container settings."""
    from aptl.core.config import AptlConfig

    return AptlConfig(
        lab={"name": "test-lab"},
        containers={
            "wazuh": wazuh,
            "victim": victim,
            "kali": kali,
            "reverse": reverse,
        },
    )


def _make_env():
    """Helper to create an EnvVars instance."""
    from aptl.core.env import EnvVars

    return EnvVars(
        indexer_username="admin",
        indexer_password="SecretPassword",
        api_username="wazuh-wui",
        api_password="ApiSecret123",
        dashboard_username="kibanaserver",
        dashboard_password="kibanapass",
        wazuh_cluster_key="clusterkey",
    )


class TestGenerateConnectionInfo:
    """Tests for generating connection info text."""

    def test_includes_dashboard_url_for_enabled_wazuh(self):
        """Output should include dashboard URL when wazuh is enabled."""
        from aptl.core.connections import generate_connection_info

        config = _make_config(wazuh=True)
        env = _make_env()

        info = generate_connection_info(config, env)

        assert "https://localhost:443" in info

    def test_includes_ssh_commands_for_enabled_containers(self):
        """Output should include SSH commands for each enabled container."""
        from aptl.core.connections import generate_connection_info

        config = _make_config(victim=True, kali=True, reverse=False)
        env = _make_env()

        info = generate_connection_info(config, env)

        assert "ssh" in info.lower()
        assert "2022" in info  # victim port
        assert "2023" in info  # kali port
        assert "labadmin@localhost" in info
        assert "kali@localhost" in info

    def test_omits_ssh_for_disabled_containers(self):
        """Output should not include SSH for disabled containers."""
        from aptl.core.connections import generate_connection_info

        config = _make_config(victim=False, kali=False, reverse=False)
        env = _make_env()

        info = generate_connection_info(config, env)

        assert "2022" not in info
        assert "2023" not in info

    def test_includes_credentials_from_env(self):
        """Output should include credentials from EnvVars."""
        from aptl.core.connections import generate_connection_info

        config = _make_config()
        env = _make_env()

        info = generate_connection_info(config, env)

        assert "admin" in info
        assert "SecretPassword" in info
        assert "wazuh-wui" in info
        assert "ApiSecret123" in info

    def test_includes_container_ips_for_enabled_containers(self):
        """Output should include container IPs for enabled containers."""
        from aptl.core.connections import generate_connection_info

        config = _make_config(wazuh=True, victim=True, kali=True)
        env = _make_env()

        info = generate_connection_info(config, env)

        assert "172.20.0.10" in info  # wazuh manager
        assert "172.20.0.20" in info  # victim
        assert "172.20.0.30" in info  # kali

    def test_omits_sections_for_disabled_containers(self):
        """Output should omit IPs for disabled containers."""
        from aptl.core.connections import generate_connection_info

        config = _make_config(wazuh=False, victim=False, kali=False, reverse=False)
        env = _make_env()

        info = generate_connection_info(config, env)

        assert "172.20.0.10" not in info
        assert "172.20.0.20" not in info
        assert "172.20.0.30" not in info

    def test_includes_reverse_when_enabled(self):
        """Output should include reverse container info when enabled."""
        from aptl.core.connections import generate_connection_info

        config = _make_config(reverse=True)
        env = _make_env()

        info = generate_connection_info(config, env)

        assert "2027" in info  # reverse SSH port
        assert "172.20.0.27" in info  # reverse IP

    def test_includes_management_commands(self):
        """Output should include common management commands."""
        from aptl.core.connections import generate_connection_info

        config = _make_config()
        env = _make_env()

        info = generate_connection_info(config, env)

        assert "docker compose" in info
        assert "logs" in info
        assert "down" in info

    def test_omits_dashboard_url_when_wazuh_disabled(self):
        """Output should not include dashboard info when wazuh is disabled."""
        from aptl.core.connections import generate_connection_info

        config = _make_config(wazuh=False)
        env = _make_env()

        info = generate_connection_info(config, env)

        # Should not have wazuh-specific URLs
        assert "https://localhost:443" not in info
        assert "https://localhost:9200" not in info


class TestWriteConnectionFile:
    """Tests for writing connection info to a file."""

    def test_creates_file_with_correct_content(self, tmp_path):
        """Should write the info text to the specified file."""
        from aptl.core.connections import write_connection_file

        output_path = tmp_path / "lab_connections.txt"
        info = "Test connection info\nLine 2\n"

        write_connection_file(info, output_path)

        assert output_path.exists()
        assert output_path.read_text() == info

    def test_overwrites_existing_file(self, tmp_path):
        """Should overwrite existing file contents."""
        from aptl.core.connections import write_connection_file

        output_path = tmp_path / "lab_connections.txt"
        output_path.write_text("old content")

        write_connection_file("new content", output_path)

        assert output_path.read_text() == "new content"

    def test_creates_parent_directories(self, tmp_path):
        """Should create parent directories if they don't exist."""
        from aptl.core.connections import write_connection_file

        output_path = tmp_path / "subdir" / "lab_connections.txt"

        write_connection_file("info text", output_path)

        assert output_path.exists()
        assert output_path.read_text() == "info text"

    def test_file_has_restricted_permissions(self, tmp_path):
        """Should set 0o600 permissions on the connection file (C4)."""
        import stat
        from aptl.core.connections import write_connection_file

        output_path = tmp_path / "lab_connections.txt"

        write_connection_file("credentials here", output_path)

        mode = output_path.stat().st_mode & 0o777
        assert mode == 0o600
