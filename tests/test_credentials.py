"""Tests for config file credential syncing.

Tests are written FIRST (TDD). Uses tmp_path for real file operations.

Both sync functions now take ``project_dir`` and build the canonical
project-relative target internally (issue #266 / ADR-007 path-containment
guardrail). Tests create the file at the canonical relative location
under tmp_path and pass tmp_path as the project root.
"""

from pathlib import Path

import pytest


_DASHBOARD_RELPATH = Path("config/wazuh_dashboard/wazuh.yml")
_MANAGER_RELPATH = Path("config/wazuh_cluster/wazuh_manager.conf")


def _layout_dashboard(project_dir: Path, content: str) -> Path:
    target = project_dir / _DASHBOARD_RELPATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return target


def _layout_manager(project_dir: Path, content: str) -> Path:
    target = project_dir / _MANAGER_RELPATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return target


class TestSyncDashboardConfig:
    """Tests for dashboard (wazuh.yml) password replacement."""

    def test_replaces_password_in_wazuh_yml(self, tmp_path):
        from aptl.core.credentials import sync_dashboard_config

        config_file = _layout_dashboard(
            tmp_path,
            'hosts:\n'
            '  - default:\n'
            '      url: "https://wazuh.manager"\n'
            '      port: 55000\n'
            '      username: "wazuh-wui"\n'
            '      password: "placeholder"\n'
            '      run_as: false\n',
        )

        sync_dashboard_config(tmp_path, "MyS3cretPa$$word")

        content = config_file.read_text()
        assert 'password: "MyS3cretPa$$word"' in content
        assert 'placeholder' not in content

    def test_preserves_surrounding_content(self, tmp_path):
        from aptl.core.credentials import sync_dashboard_config

        config_file = _layout_dashboard(
            tmp_path,
            'hosts:\n'
            '  - default:\n'
            '      url: "https://wazuh.manager"\n'
            '      port: 55000\n'
            '      username: "wazuh-wui"\n'
            '      password: "old_password"\n'
            '      run_as: false\n',
        )

        sync_dashboard_config(tmp_path, "new_password")

        content = config_file.read_text()
        assert 'url: "https://wazuh.manager"' in content
        assert 'port: 55000' in content
        assert 'username: "wazuh-wui"' in content
        assert 'run_as: false' in content

    def test_raises_file_not_found(self, tmp_path):
        """No file at the canonical relative location → FileNotFoundError."""
        from aptl.core.credentials import sync_dashboard_config

        # tmp_path is empty; no config/wazuh_dashboard/wazuh.yml exists.
        with pytest.raises(FileNotFoundError):
            sync_dashboard_config(tmp_path, "password")

    def test_handles_no_password_pattern(self, tmp_path):
        from aptl.core.credentials import sync_dashboard_config

        config_file = _layout_dashboard(
            tmp_path, "some_other_setting: value\nno_password_here: true\n",
        )

        # Should not raise; file should remain unchanged.
        sync_dashboard_config(tmp_path, "new_password")

        content = config_file.read_text()
        assert "some_other_setting: value" in content
        assert "no_password_here: true" in content

    def test_replaces_only_password_field(self, tmp_path):
        from aptl.core.credentials import sync_dashboard_config

        config_file = _layout_dashboard(
            tmp_path,
            '      username: "admin"\n'
            '      password: "old"\n'
            '      description: "This has quotes"\n',
        )

        sync_dashboard_config(tmp_path, "new_pass")

        content = config_file.read_text()
        assert 'username: "admin"' in content
        assert 'password: "new_pass"' in content
        assert 'description: "This has quotes"' in content


class TestSyncManagerConfig:
    """Tests for manager (wazuh_manager.conf) cluster key replacement."""

    def test_replaces_cluster_key(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        config_file = _layout_manager(
            tmp_path,
            '<cluster>\n'
            '  <name>wazuh</name>\n'
            '  <key>placeholder_key</key>\n'
            '  <node_name>master</node_name>\n'
            '</cluster>\n',
        )

        sync_manager_config(tmp_path, "my-real-cluster-key")

        content = config_file.read_text()
        assert '<key>my-real-cluster-key</key>' in content
        assert 'placeholder_key' not in content

    def test_preserves_surrounding_xml_content(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        config_file = _layout_manager(
            tmp_path,
            '<cluster>\n'
            '  <name>wazuh</name>\n'
            '  <key>old_key</key>\n'
            '  <node_name>master</node_name>\n'
            '  <node_type>master</node_type>\n'
            '</cluster>\n',
        )

        sync_manager_config(tmp_path, "new_key")

        content = config_file.read_text()
        assert '<name>wazuh</name>' in content
        assert '<node_name>master</node_name>' in content
        assert '<node_type>master</node_type>' in content

    def test_raises_file_not_found(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        with pytest.raises(FileNotFoundError):
            sync_manager_config(tmp_path, "key")

    def test_handles_no_key_pattern(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        config_file = _layout_manager(
            tmp_path,
            "<ossec_config>\n  <other>value</other>\n</ossec_config>\n",
        )

        sync_manager_config(tmp_path, "new_key")

        content = config_file.read_text()
        assert "<other>value</other>" in content

    def test_replaces_cluster_key_only(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        config_file = _layout_manager(
            tmp_path,
            '<cluster>\n'
            '  <key>first_key</key>\n'
            '</cluster>\n',
        )

        sync_manager_config(tmp_path, "unified_key")

        content = config_file.read_text()
        assert '<key>unified_key</key>' in content
        assert 'first_key' not in content

    def test_preserves_ssl_key_element(self, tmp_path):
        """<key> inside <indexer><ssl> must NOT be touched (#183)."""
        from aptl.core.credentials import sync_manager_config

        config_file = _layout_manager(
            tmp_path,
            '<ossec_config>\n'
            '  <indexer>\n'
            '    <ssl>\n'
            '      <key>/etc/filebeat/certs/filebeat-key.pem</key>\n'
            '    </ssl>\n'
            '  </indexer>\n'
            '  <cluster>\n'
            '    <key>old_cluster_key</key>\n'
            '  </cluster>\n'
            '</ossec_config>\n',
        )

        sync_manager_config(tmp_path, "new_cluster_key")

        content = config_file.read_text()
        assert '<key>/etc/filebeat/certs/filebeat-key.pem</key>' in content
        assert '<key>new_cluster_key</key>' in content
        assert 'old_cluster_key' not in content

    def test_real_config_structure(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        config_file = _layout_manager(
            tmp_path,
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
            '</ossec_config>\n',
        )

        sync_manager_config(tmp_path, "real_secret_key_123")

        content = config_file.read_text()
        assert '<key>/etc/filebeat/certs/filebeat-key.pem</key>' in content
        assert '<key>real_secret_key_123</key>' in content
        assert 'placeholder_cluster_key' not in content
        assert '<name>wazuh</name>' in content
        assert '<port>1516</port>' in content

    def test_empty_cluster_key_allowed(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        config_file = _layout_manager(
            tmp_path,
            '<cluster>\n  <key>old_key</key>\n</cluster>\n',
        )

        sync_manager_config(tmp_path, "")

        content = config_file.read_text()
        assert '<key></key>' in content


class TestRegexSpecialCharacters:
    """Tests for passwords/keys containing regex special characters (C1)."""

    def test_password_with_backslash_one(self, tmp_path):
        r"""Password containing \1 should not be treated as backreference."""
        from aptl.core.credentials import sync_dashboard_config

        config_file = _layout_dashboard(
            tmp_path, '      password: "old"\n',
        )

        sync_dashboard_config(tmp_path, r"pass\1word")

        content = config_file.read_text()
        # Backslash is escaped for YAML double-quoted string safety.
        assert r'password: "pass\\1word"' in content

    def test_password_with_dollar_sign(self, tmp_path):
        from aptl.core.credentials import sync_dashboard_config

        config_file = _layout_dashboard(
            tmp_path, '      password: "old"\n',
        )

        sync_dashboard_config(tmp_path, "pa$$word$1")

        content = config_file.read_text()
        assert 'password: "pa$$word$1"' in content

    def test_password_with_backslashes(self, tmp_path):
        r"""Password containing backslashes should be escaped for YAML."""
        from aptl.core.credentials import sync_dashboard_config

        config_file = _layout_dashboard(
            tmp_path, '      password: "old"\n',
        )

        sync_dashboard_config(tmp_path, r"C:\Users\admin")

        content = config_file.read_text()
        assert r'password: "C:\\Users\\admin"' in content

    def test_password_with_newline_escape(self, tmp_path):
        r"""Password containing \n should be escaped, not insert a newline."""
        from aptl.core.credentials import sync_dashboard_config

        config_file = _layout_dashboard(
            tmp_path, '      password: "old"\n',
        )

        sync_dashboard_config(tmp_path, r"pass\nword")

        content = config_file.read_text()
        assert r'password: "pass\\nword"' in content

    def test_cluster_key_with_backslash_one(self, tmp_path):
        r"""Cluster key containing \1 should not be treated as backreference."""
        from aptl.core.credentials import sync_manager_config

        config_file = _layout_manager(
            tmp_path, '<cluster>\n  <key>old</key>\n</cluster>\n',
        )

        sync_manager_config(tmp_path, r"key\1value")

        content = config_file.read_text()
        assert r'<key>key\1value</key>' in content

    def test_cluster_key_with_dollar_sign(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        config_file = _layout_manager(
            tmp_path, '<cluster>\n  <key>old</key>\n</cluster>\n',
        )

        sync_manager_config(tmp_path, "key$1$2")

        content = config_file.read_text()
        assert '<key>key$1$2</key>' in content

    def test_password_with_quotes(self, tmp_path):
        from aptl.core.credentials import sync_dashboard_config

        config_file = _layout_dashboard(
            tmp_path, '      password: "old"\n',
        )

        sync_dashboard_config(tmp_path, "it's-a-password")

        content = config_file.read_text()
        assert """password: "it's-a-password\"""" in content

    def test_password_with_double_quotes(self, tmp_path):
        from aptl.core.credentials import sync_dashboard_config

        config_file = _layout_dashboard(
            tmp_path, '      password: "old"\n',
        )

        sync_dashboard_config(tmp_path, 'pass"word')

        content = config_file.read_text()
        assert 'password: "pass\\"word"' in content

    def test_cluster_key_with_xml_special_chars(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        config_file = _layout_manager(
            tmp_path, "<cluster>\n  <key>old</key>\n</cluster>\n",
        )

        sync_manager_config(tmp_path, "key<>&value")

        content = config_file.read_text()
        assert "<key>key&lt;&gt;&amp;value</key>" in content


class TestPathContainment:
    """Issue #266: refuse to read or write outside the resolved project root."""

    def test_dashboard_rejects_symlink_escape(self, tmp_path):
        """Symlink at canonical location pointing outside project_dir is rejected."""
        from aptl.core.credentials import sync_dashboard_config

        outside = tmp_path / "escape.yml"
        outside.write_text('password: "untouched"\n')

        project_dir = tmp_path / "project"
        canonical_parent = project_dir / "config" / "wazuh_dashboard"
        canonical_parent.mkdir(parents=True)
        (canonical_parent / "wazuh.yml").symlink_to(outside)

        with pytest.raises(ValueError, match="escapes project root"):
            sync_dashboard_config(project_dir, "new_password")

        # Outside file untouched.
        assert outside.read_text() == 'password: "untouched"\n'

    def test_manager_rejects_symlink_escape(self, tmp_path):
        """Symlink at canonical location pointing outside project_dir is rejected."""
        from aptl.core.credentials import sync_manager_config

        outside = tmp_path / "escape.conf"
        outside.write_text("<cluster>\n  <key>untouched</key>\n</cluster>\n")

        project_dir = tmp_path / "project"
        canonical_parent = project_dir / "config" / "wazuh_cluster"
        canonical_parent.mkdir(parents=True)
        (canonical_parent / "wazuh_manager.conf").symlink_to(outside)

        with pytest.raises(ValueError, match="escapes project root"):
            sync_manager_config(project_dir, "new_key")

        assert "untouched" in outside.read_text()

    def test_dashboard_writes_to_canonical_location_only(self, tmp_path):
        """Sanity: writes go to <project_dir>/config/wazuh_dashboard/wazuh.yml,
        not a sibling location, even if such a file exists."""
        from aptl.core.credentials import sync_dashboard_config

        # File at the canonical location.
        canonical = _layout_dashboard(tmp_path, '      password: "old"\n')

        # Decoy file elsewhere — function must not touch this.
        decoy = tmp_path / "wazuh.yml"
        decoy.write_text('      password: "decoy_untouched"\n')

        sync_dashboard_config(tmp_path, "new_password")

        assert 'password: "new_password"' in canonical.read_text()
        assert 'decoy_untouched' in decoy.read_text()

    def test_manager_writes_to_canonical_location_only(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        canonical = _layout_manager(
            tmp_path, "<cluster>\n  <key>old</key>\n</cluster>\n",
        )

        decoy = tmp_path / "wazuh_manager.conf"
        decoy.write_text("<cluster>\n  <key>decoy_untouched</key>\n</cluster>\n")

        sync_manager_config(tmp_path, "new_key")

        assert "<key>new_key</key>" in canonical.read_text()
        assert "decoy_untouched" in decoy.read_text()
