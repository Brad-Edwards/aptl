"""Tests for config file credential syncing.

Tests are written FIRST (TDD). Uses tmp_path for real file operations.
"""

import pytest


class TestSyncDashboardConfig:
    """Tests for dashboard (wazuh.yml) password replacement."""

    def test_replaces_password_in_wazuh_yml(self, tmp_path):
        """Should replace the password value in wazuh.yml."""
        from aptl.core.credentials import sync_dashboard_config

        config_file = tmp_path / "wazuh.yml"
        config_file.write_text(
            'hosts:\n'
            '  - default:\n'
            '      url: "https://wazuh.manager"\n'
            '      port: 55000\n'
            '      username: "wazuh-wui"\n'
            '      password: "placeholder"\n'
            '      run_as: false\n'
        )

        sync_dashboard_config(config_file, "MyS3cretPa$$word")

        content = config_file.read_text()
        assert 'password: "MyS3cretPa$$word"' in content
        assert 'placeholder' not in content

    def test_preserves_surrounding_content(self, tmp_path):
        """Should not corrupt other lines in the config."""
        from aptl.core.credentials import sync_dashboard_config

        config_file = tmp_path / "wazuh.yml"
        original = (
            'hosts:\n'
            '  - default:\n'
            '      url: "https://wazuh.manager"\n'
            '      port: 55000\n'
            '      username: "wazuh-wui"\n'
            '      password: "old_password"\n'
            '      run_as: false\n'
        )
        config_file.write_text(original)

        sync_dashboard_config(config_file, "new_password")

        content = config_file.read_text()
        assert 'url: "https://wazuh.manager"' in content
        assert 'port: 55000' in content
        assert 'username: "wazuh-wui"' in content
        assert 'run_as: false' in content

    def test_raises_file_not_found(self, tmp_path):
        """Should raise FileNotFoundError for missing config file."""
        from aptl.core.credentials import sync_dashboard_config

        missing = tmp_path / "nonexistent.yml"

        with pytest.raises(FileNotFoundError):
            sync_dashboard_config(missing, "password")

    def test_handles_no_password_pattern(self, tmp_path):
        """Should not crash when the config doesn't contain password pattern."""
        from aptl.core.credentials import sync_dashboard_config

        config_file = tmp_path / "wazuh.yml"
        config_file.write_text("some_other_setting: value\nno_password_here: true\n")

        # Should not raise; file should remain unchanged
        sync_dashboard_config(config_file, "new_password")

        content = config_file.read_text()
        assert "some_other_setting: value" in content
        assert "no_password_here: true" in content

    def test_replaces_only_password_field(self, tmp_path):
        """Should only replace password: "..." not other quoted strings."""
        from aptl.core.credentials import sync_dashboard_config

        config_file = tmp_path / "wazuh.yml"
        config_file.write_text(
            '      username: "admin"\n'
            '      password: "old"\n'
            '      description: "This has quotes"\n'
        )

        sync_dashboard_config(config_file, "new_pass")

        content = config_file.read_text()
        assert 'username: "admin"' in content
        assert 'password: "new_pass"' in content
        assert 'description: "This has quotes"' in content


class TestSyncManagerConfig:
    """Tests for manager (wazuh_manager.conf) cluster key replacement."""

    def test_replaces_cluster_key(self, tmp_path):
        """Should replace the cluster key in wazuh_manager.conf."""
        from aptl.core.credentials import sync_manager_config

        config_file = tmp_path / "wazuh_manager.conf"
        config_file.write_text(
            '<cluster>\n'
            '  <name>wazuh</name>\n'
            '  <key>placeholder_key</key>\n'
            '  <node_name>master</node_name>\n'
            '</cluster>\n'
        )

        sync_manager_config(config_file, "my-real-cluster-key")

        content = config_file.read_text()
        assert '<key>my-real-cluster-key</key>' in content
        assert 'placeholder_key' not in content

    def test_preserves_surrounding_xml_content(self, tmp_path):
        """Should not corrupt other XML elements."""
        from aptl.core.credentials import sync_manager_config

        config_file = tmp_path / "wazuh_manager.conf"
        config_file.write_text(
            '<cluster>\n'
            '  <name>wazuh</name>\n'
            '  <key>old_key</key>\n'
            '  <node_name>master</node_name>\n'
            '  <node_type>master</node_type>\n'
            '</cluster>\n'
        )

        sync_manager_config(config_file, "new_key")

        content = config_file.read_text()
        assert '<name>wazuh</name>' in content
        assert '<node_name>master</node_name>' in content
        assert '<node_type>master</node_type>' in content

    def test_raises_file_not_found(self, tmp_path):
        """Should raise FileNotFoundError for missing config file."""
        from aptl.core.credentials import sync_manager_config

        missing = tmp_path / "nonexistent.conf"

        with pytest.raises(FileNotFoundError):
            sync_manager_config(missing, "key")

    def test_handles_no_key_pattern(self, tmp_path):
        """Should not crash when the config doesn't contain key pattern."""
        from aptl.core.credentials import sync_manager_config

        config_file = tmp_path / "wazuh_manager.conf"
        config_file.write_text("<ossec_config>\n  <other>value</other>\n</ossec_config>\n")

        # Should not raise; file should remain unchanged
        sync_manager_config(config_file, "new_key")

        content = config_file.read_text()
        assert "<other>value</other>" in content

    def test_replaces_multiple_key_elements(self, tmp_path):
        """If there are multiple <key> elements, all should be replaced."""
        from aptl.core.credentials import sync_manager_config

        config_file = tmp_path / "wazuh_manager.conf"
        config_file.write_text(
            '<cluster>\n'
            '  <key>first_key</key>\n'
            '  <key>second_key</key>\n'
            '</cluster>\n'
        )

        sync_manager_config(config_file, "unified_key")

        content = config_file.read_text()
        assert content.count('<key>unified_key</key>') == 2
        assert 'first_key' not in content
        assert 'second_key' not in content

    def test_empty_cluster_key_allowed(self, tmp_path):
        """Should allow setting an empty cluster key."""
        from aptl.core.credentials import sync_manager_config

        config_file = tmp_path / "wazuh_manager.conf"
        config_file.write_text('<cluster>\n  <key>old_key</key>\n</cluster>\n')

        sync_manager_config(config_file, "")

        content = config_file.read_text()
        assert '<key></key>' in content


class TestRegexSpecialCharacters:
    """Tests for passwords/keys containing regex special characters (C1)."""

    def test_password_with_backslash_one(self, tmp_path):
        r"""Password containing \1 should not be treated as backreference."""
        from aptl.core.credentials import sync_dashboard_config

        config_file = tmp_path / "wazuh.yml"
        config_file.write_text('      password: "old"\n')

        sync_dashboard_config(config_file, r"pass\1word")

        content = config_file.read_text()
        assert r'password: "pass\1word"' in content

    def test_password_with_dollar_sign(self, tmp_path):
        """Password containing $ should be literal."""
        from aptl.core.credentials import sync_dashboard_config

        config_file = tmp_path / "wazuh.yml"
        config_file.write_text('      password: "old"\n')

        sync_dashboard_config(config_file, "pa$$word$1")

        content = config_file.read_text()
        assert 'password: "pa$$word$1"' in content

    def test_password_with_backslashes(self, tmp_path):
        r"""Password containing backslashes should be preserved literally."""
        from aptl.core.credentials import sync_dashboard_config

        config_file = tmp_path / "wazuh.yml"
        config_file.write_text('      password: "old"\n')

        sync_dashboard_config(config_file, r"C:\Users\admin")

        content = config_file.read_text()
        assert r'password: "C:\Users\admin"' in content

    def test_password_with_newline_escape(self, tmp_path):
        r"""Password containing \n should not insert a newline."""
        from aptl.core.credentials import sync_dashboard_config

        config_file = tmp_path / "wazuh.yml"
        config_file.write_text('      password: "old"\n')

        sync_dashboard_config(config_file, r"pass\nword")

        content = config_file.read_text()
        assert r'password: "pass\nword"' in content

    def test_cluster_key_with_backslash_one(self, tmp_path):
        r"""Cluster key containing \1 should not be treated as backreference."""
        from aptl.core.credentials import sync_manager_config

        config_file = tmp_path / "wazuh_manager.conf"
        config_file.write_text('<cluster>\n  <key>old</key>\n</cluster>\n')

        sync_manager_config(config_file, r"key\1value")

        content = config_file.read_text()
        assert r'<key>key\1value</key>' in content

    def test_cluster_key_with_dollar_sign(self, tmp_path):
        """Cluster key containing $ should be literal."""
        from aptl.core.credentials import sync_manager_config

        config_file = tmp_path / "wazuh_manager.conf"
        config_file.write_text('<cluster>\n  <key>old</key>\n</cluster>\n')

        sync_manager_config(config_file, "key$1$2")

        content = config_file.read_text()
        assert '<key>key$1$2</key>' in content

    def test_password_with_quotes(self, tmp_path):
        """Password containing single quotes should be handled."""
        from aptl.core.credentials import sync_dashboard_config

        config_file = tmp_path / "wazuh.yml"
        config_file.write_text('      password: "old"\n')

        sync_dashboard_config(config_file, "it's-a-password")

        content = config_file.read_text()
        assert """password: "it's-a-password\"""" in content
