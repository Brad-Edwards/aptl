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

    def test_replaces_cluster_key_only(self, tmp_path):
        """Only <key> elements inside <cluster> blocks should be replaced."""
        from aptl.core.credentials import sync_manager_config

        config_file = tmp_path / "wazuh_manager.conf"
        config_file.write_text(
            '<cluster>\n'
            '  <key>first_key</key>\n'
            '</cluster>\n'
        )

        sync_manager_config(config_file, "unified_key")

        content = config_file.read_text()
        assert '<key>unified_key</key>' in content
        assert 'first_key' not in content

    def test_preserves_ssl_key_element(self, tmp_path):
        """<key> inside <indexer><ssl> must NOT be touched (#183)."""
        from aptl.core.credentials import sync_manager_config

        config_file = tmp_path / "wazuh_manager.conf"
        config_file.write_text(
            '<ossec_config>\n'
            '  <indexer>\n'
            '    <ssl>\n'
            '      <key>/etc/filebeat/certs/filebeat-key.pem</key>\n'
            '    </ssl>\n'
            '  </indexer>\n'
            '  <cluster>\n'
            '    <key>old_cluster_key</key>\n'
            '  </cluster>\n'
            '</ossec_config>\n'
        )

        sync_manager_config(config_file, "new_cluster_key")

        content = config_file.read_text()
        # SSL key path must be untouched
        assert '<key>/etc/filebeat/certs/filebeat-key.pem</key>' in content
        # Cluster key must be replaced
        assert '<key>new_cluster_key</key>' in content
        assert 'old_cluster_key' not in content

    def test_real_config_structure(self, tmp_path):
        """Mirror actual wazuh_manager.conf structure with both key elements."""
        from aptl.core.credentials import sync_manager_config

        config_file = tmp_path / "wazuh_manager.conf"
        config_file.write_text(
            '<ossec_config>\n'
            '  <indexer>\n'
            '    <enabled>yes</enabled>\n'
            '    <hosts>\n'
            '      <host>https://wazuh.indexer:9200</host>\n'
            '    </hosts>\n'
            '    <ssl>\n'
            '      <certificate_authorities>\n'
            '        <ca>/etc/filebeat/certs/root-ca.pem</ca>\n'
            '      </certificate_authorities>\n'
            '      <certificate>/etc/filebeat/certs/filebeat.pem</certificate>\n'
            '      <key>/etc/filebeat/certs/filebeat-key.pem</key>\n'
            '    </ssl>\n'
            '  </indexer>\n'
            '\n'
            '  <cluster>\n'
            '    <name>wazuh</name>\n'
            '    <node_name>master</node_name>\n'
            '    <node_type>master</node_type>\n'
            '    <key>placeholder_cluster_key</key>\n'
            '    <port>1516</port>\n'
            '    <bind_addr>0.0.0.0</bind_addr>\n'
            '    <nodes>\n'
            '      <node>NODE_IP</node>\n'
            '    </nodes>\n'
            '    <hidden>no</hidden>\n'
            '    <disabled>yes</disabled>\n'
            '  </cluster>\n'
            '</ossec_config>\n'
        )

        sync_manager_config(config_file, "real_secret_key_123")

        content = config_file.read_text()
        # SSL key path preserved
        assert '<key>/etc/filebeat/certs/filebeat-key.pem</key>' in content
        # Cluster key replaced
        assert '<key>real_secret_key_123</key>' in content
        assert 'placeholder_cluster_key' not in content
        # Other cluster elements preserved
        assert '<name>wazuh</name>' in content
        assert '<port>1516</port>' in content

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
        # Backslash is escaped for YAML double-quoted string safety.
        assert r'password: "pass\\1word"' in content

    def test_password_with_dollar_sign(self, tmp_path):
        """Password containing $ should be literal."""
        from aptl.core.credentials import sync_dashboard_config

        config_file = tmp_path / "wazuh.yml"
        config_file.write_text('      password: "old"\n')

        sync_dashboard_config(config_file, "pa$$word$1")

        content = config_file.read_text()
        assert 'password: "pa$$word$1"' in content

    def test_password_with_backslashes(self, tmp_path):
        r"""Password containing backslashes should be escaped for YAML."""
        from aptl.core.credentials import sync_dashboard_config

        config_file = tmp_path / "wazuh.yml"
        config_file.write_text('      password: "old"\n')

        sync_dashboard_config(config_file, r"C:\Users\admin")

        content = config_file.read_text()
        # YAML double-quoted strings interpret \U as escape; must be \\U.
        assert r'password: "C:\\Users\\admin"' in content

    def test_password_with_newline_escape(self, tmp_path):
        r"""Password containing \n should be escaped, not insert a newline."""
        from aptl.core.credentials import sync_dashboard_config

        config_file = tmp_path / "wazuh.yml"
        config_file.write_text('      password: "old"\n')

        sync_dashboard_config(config_file, r"pass\nword")

        content = config_file.read_text()
        # YAML double-quoted \n means newline; must be \\n for literal.
        assert r'password: "pass\\nword"' in content

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

    def test_password_with_double_quotes(self, tmp_path):
        """Password containing double quotes should be escaped."""
        from aptl.core.credentials import sync_dashboard_config

        config_file = tmp_path / "wazuh.yml"
        config_file.write_text('      password: "old"\n')

        sync_dashboard_config(config_file, 'pass"word')

        content = config_file.read_text()
        assert 'password: "pass\\"word"' in content

    def test_cluster_key_with_xml_special_chars(self, tmp_path):
        """Cluster key with <, >, & should be XML-escaped."""
        from aptl.core.credentials import sync_manager_config

        config_file = tmp_path / "wazuh_manager.conf"
        config_file.write_text("<cluster>\n  <key>old</key>\n</cluster>\n")

        sync_manager_config(config_file, "key<>&value")

        content = config_file.read_text()
        assert "<key>key&lt;&gt;&amp;value</key>" in content
