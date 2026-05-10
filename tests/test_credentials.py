"""Tests for config file credential rendering.

The credentialized config is rendered from a checked-in ``config/``
template into the project's ignored ``.aptl/config/`` state tree
(ADR-028). The checked-in template is never written. Tests lay out the
template at the canonical source location under ``tmp_path``, run the
render function, and assert on (a) the rendered output under
``.aptl/config/...`` and (b) the source template being byte-for-byte
unchanged.
"""

import os
import re
import sys
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[1]

_DASHBOARD_SOURCE_RELPATH = Path("config/wazuh_dashboard/wazuh.yml")
_MANAGER_SOURCE_RELPATH = Path("config/wazuh_cluster/wazuh_manager.conf")
_DASHBOARD_RENDERED_RELPATH = Path(".aptl/config/wazuh_dashboard/wazuh.yml")
_MANAGER_RENDERED_RELPATH = Path(".aptl/config/wazuh_cluster/wazuh_manager.conf")

_POSIX_MODES = os.name == "posix"
_skip_no_posix_modes = pytest.mark.skipif(
    not _POSIX_MODES, reason="POSIX file modes not honoured on this platform"
)


def _layout_dashboard(project_dir: Path, content: str) -> Path:
    target = project_dir / _DASHBOARD_SOURCE_RELPATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return target


def _layout_manager(project_dir: Path, content: str) -> Path:
    target = project_dir / _MANAGER_SOURCE_RELPATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return target


def _rendered_dashboard(project_dir: Path) -> Path:
    return project_dir / _DASHBOARD_RENDERED_RELPATH


def _rendered_manager(project_dir: Path) -> Path:
    return project_dir / _MANAGER_RENDERED_RELPATH


class TestSyncDashboardConfig:
    """Tests for dashboard (wazuh.yml) password rendering."""

    def test_replaces_password_in_wazuh_yml(self, tmp_path):
        from aptl.core.credentials import sync_dashboard_config

        _layout_dashboard(
            tmp_path,
            'hosts:\n'
            '  - default:\n'
            '      url: "https://wazuh.manager"\n'
            '      port: 55000\n'
            '      username: "wazuh-wui"\n'
            '      password: "placeholder"\n'
            '      run_as: false\n',
        )

        out = sync_dashboard_config(tmp_path, "MyS3cretPa$$word")

        assert out == _rendered_dashboard(tmp_path).resolve()
        content = _rendered_dashboard(tmp_path).read_text()
        assert 'password: "MyS3cretPa$$word"' in content
        assert 'placeholder' not in content

    def test_source_template_unmodified(self, tmp_path):
        from aptl.core.credentials import sync_dashboard_config

        original = (
            'hosts:\n'
            '  - default:\n'
            '      url: "https://wazuh.manager"\n'
            '      password: "placeholder"\n'
        )
        source = _layout_dashboard(tmp_path, original)
        before = source.read_bytes()

        sync_dashboard_config(tmp_path, "a-real-secret")

        assert source.read_bytes() == before
        # And the secret only appears in the rendered copy.
        assert "a-real-secret" not in source.read_text()
        assert 'password: "a-real-secret"' in _rendered_dashboard(tmp_path).read_text()

    def test_preserves_surrounding_content(self, tmp_path):
        from aptl.core.credentials import sync_dashboard_config

        _layout_dashboard(
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

        content = _rendered_dashboard(tmp_path).read_text()
        assert 'url: "https://wazuh.manager"' in content
        assert 'port: 55000' in content
        assert 'username: "wazuh-wui"' in content
        assert 'run_as: false' in content

    def test_raises_file_not_found(self, tmp_path):
        """No template at the canonical source location → FileNotFoundError."""
        from aptl.core.credentials import sync_dashboard_config

        with pytest.raises(FileNotFoundError):
            sync_dashboard_config(tmp_path, "password")

    def test_no_password_pattern_aborts_render(self, tmp_path):
        """A template that no longer matches ``password: "..."`` is an
        error — the rendered file is a mandatory mount source, so a
        verbatim (placeholder/stale) copy must not be emitted."""
        from aptl.core.credentials import CredentialRenderError, sync_dashboard_config

        source = _layout_dashboard(
            tmp_path, "some_other_setting: value\nno_password_here: true\n",
        )
        before = source.read_bytes()

        with pytest.raises(CredentialRenderError):
            sync_dashboard_config(tmp_path, "new_password")

        # Nothing rendered; source untouched.
        assert not _rendered_dashboard(tmp_path).exists()
        assert source.read_bytes() == before

    def test_replaces_only_password_field(self, tmp_path):
        from aptl.core.credentials import sync_dashboard_config

        _layout_dashboard(
            tmp_path,
            '      username: "admin"\n'
            '      password: "old"\n'
            '      description: "This has quotes"\n',
        )

        sync_dashboard_config(tmp_path, "new_pass")

        content = _rendered_dashboard(tmp_path).read_text()
        assert 'username: "admin"' in content
        assert 'password: "new_pass"' in content
        assert 'description: "This has quotes"' in content

    def test_render_is_idempotent(self, tmp_path):
        from aptl.core.credentials import sync_dashboard_config

        source = _layout_dashboard(tmp_path, '      password: "old"\n')
        before_source = source.read_bytes()

        sync_dashboard_config(tmp_path, "secret-1")
        first = _rendered_dashboard(tmp_path).read_bytes()
        sync_dashboard_config(tmp_path, "secret-1")
        second = _rendered_dashboard(tmp_path).read_bytes()

        assert first == second
        assert source.read_bytes() == before_source
        # No temp file left behind.
        rendered_dir = _rendered_dashboard(tmp_path).parent
        assert not list(rendered_dir.glob("*.tmp"))


class TestSyncManagerConfig:
    """Tests for manager (wazuh_manager.conf) cluster key rendering."""

    def test_replaces_cluster_key(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        _layout_manager(
            tmp_path,
            '<cluster>\n'
            '  <name>wazuh</name>\n'
            '  <key>placeholder_key</key>\n'
            '  <node_name>master</node_name>\n'
            '</cluster>\n',
        )

        out = sync_manager_config(tmp_path, "my-real-cluster-key")

        assert out == _rendered_manager(tmp_path).resolve()
        content = _rendered_manager(tmp_path).read_text()
        assert '<key>my-real-cluster-key</key>' in content
        assert 'placeholder_key' not in content

    def test_source_template_unmodified(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        original = (
            '<ossec_config>\n'
            '  <cluster>\n'
            '    <key>placeholder_cluster_key</key>\n'
            '  </cluster>\n'
            '</ossec_config>\n'
        )
        source = _layout_manager(tmp_path, original)
        before = source.read_bytes()

        sync_manager_config(tmp_path, "real-cluster-secret")

        assert source.read_bytes() == before
        assert "real-cluster-secret" not in source.read_text()
        assert '<key>real-cluster-secret</key>' in _rendered_manager(tmp_path).read_text()

    def test_preserves_surrounding_xml_content(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        _layout_manager(
            tmp_path,
            '<cluster>\n'
            '  <name>wazuh</name>\n'
            '  <key>old_key</key>\n'
            '  <node_name>master</node_name>\n'
            '  <node_type>master</node_type>\n'
            '</cluster>\n',
        )

        sync_manager_config(tmp_path, "new_key")

        content = _rendered_manager(tmp_path).read_text()
        assert '<name>wazuh</name>' in content
        assert '<node_name>master</node_name>' in content
        assert '<node_type>master</node_type>' in content

    def test_raises_file_not_found(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        with pytest.raises(FileNotFoundError):
            sync_manager_config(tmp_path, "key")

    def test_no_cluster_key_pattern_aborts_render(self, tmp_path):
        """No ``<cluster><key>`` element → render error, not a verbatim copy."""
        from aptl.core.credentials import CredentialRenderError, sync_manager_config

        source = _layout_manager(
            tmp_path,
            "<ossec_config>\n  <other>value</other>\n</ossec_config>\n",
        )
        before = source.read_bytes()

        with pytest.raises(CredentialRenderError):
            sync_manager_config(tmp_path, "new_key")

        assert not _rendered_manager(tmp_path).exists()
        assert source.read_bytes() == before

    def test_replaces_cluster_key_only(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        _layout_manager(
            tmp_path,
            '<cluster>\n'
            '  <key>first_key</key>\n'
            '</cluster>\n',
        )

        sync_manager_config(tmp_path, "unified_key")

        content = _rendered_manager(tmp_path).read_text()
        assert '<key>unified_key</key>' in content
        assert 'first_key' not in content

    def test_preserves_ssl_key_element(self, tmp_path):
        """<key> inside <indexer><ssl> must NOT be touched (#183)."""
        from aptl.core.credentials import sync_manager_config

        _layout_manager(
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

        content = _rendered_manager(tmp_path).read_text()
        assert '<key>/etc/filebeat/certs/filebeat-key.pem</key>' in content
        assert '<key>new_cluster_key</key>' in content
        assert 'old_cluster_key' not in content

    def test_real_config_structure(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        _layout_manager(
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

        content = _rendered_manager(tmp_path).read_text()
        assert '<key>/etc/filebeat/certs/filebeat-key.pem</key>' in content
        assert '<key>real_secret_key_123</key>' in content
        assert 'placeholder_cluster_key' not in content
        assert '<name>wazuh</name>' in content
        assert '<port>1516</port>' in content

    def test_empty_cluster_key_allowed(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        _layout_manager(
            tmp_path,
            '<cluster>\n  <key>old_key</key>\n</cluster>\n',
        )

        sync_manager_config(tmp_path, "")

        content = _rendered_manager(tmp_path).read_text()
        assert '<key></key>' in content


class TestRegexSpecialCharacters:
    """Tests for passwords/keys containing regex special characters (C1)."""

    def test_password_with_backslash_one(self, tmp_path):
        r"""Password containing \1 should not be treated as backreference."""
        from aptl.core.credentials import sync_dashboard_config

        _layout_dashboard(tmp_path, '      password: "old"\n')

        sync_dashboard_config(tmp_path, r"pass\1word")

        content = _rendered_dashboard(tmp_path).read_text()
        # Backslash is escaped for YAML double-quoted string safety.
        assert r'password: "pass\\1word"' in content

    def test_password_with_dollar_sign(self, tmp_path):
        from aptl.core.credentials import sync_dashboard_config

        _layout_dashboard(tmp_path, '      password: "old"\n')

        sync_dashboard_config(tmp_path, "pa$$word$1")

        content = _rendered_dashboard(tmp_path).read_text()
        assert 'password: "pa$$word$1"' in content

    def test_password_with_backslashes(self, tmp_path):
        r"""Password containing backslashes should be escaped for YAML."""
        from aptl.core.credentials import sync_dashboard_config

        _layout_dashboard(tmp_path, '      password: "old"\n')

        sync_dashboard_config(tmp_path, r"C:\Users\admin")

        content = _rendered_dashboard(tmp_path).read_text()
        assert r'password: "C:\\Users\\admin"' in content

    def test_password_with_newline_escape(self, tmp_path):
        r"""Password containing \n should be escaped, not insert a newline."""
        from aptl.core.credentials import sync_dashboard_config

        _layout_dashboard(tmp_path, '      password: "old"\n')

        sync_dashboard_config(tmp_path, r"pass\nword")

        content = _rendered_dashboard(tmp_path).read_text()
        assert r'password: "pass\\nword"' in content

    def test_cluster_key_with_backslash_one(self, tmp_path):
        r"""Cluster key containing \1 should not be treated as backreference."""
        from aptl.core.credentials import sync_manager_config

        _layout_manager(tmp_path, '<cluster>\n  <key>old</key>\n</cluster>\n')

        sync_manager_config(tmp_path, r"key\1value")

        content = _rendered_manager(tmp_path).read_text()
        assert r'<key>key\1value</key>' in content

    def test_cluster_key_with_dollar_sign(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        _layout_manager(tmp_path, '<cluster>\n  <key>old</key>\n</cluster>\n')

        sync_manager_config(tmp_path, "key$1$2")

        content = _rendered_manager(tmp_path).read_text()
        assert '<key>key$1$2</key>' in content

    def test_password_with_quotes(self, tmp_path):
        from aptl.core.credentials import sync_dashboard_config

        _layout_dashboard(tmp_path, '      password: "old"\n')

        sync_dashboard_config(tmp_path, "it's-a-password")

        content = _rendered_dashboard(tmp_path).read_text()
        assert """password: "it's-a-password\"""" in content

    def test_password_with_double_quotes(self, tmp_path):
        from aptl.core.credentials import sync_dashboard_config

        _layout_dashboard(tmp_path, '      password: "old"\n')

        sync_dashboard_config(tmp_path, 'pass"word')

        content = _rendered_dashboard(tmp_path).read_text()
        assert 'password: "pass\\"word"' in content

    def test_cluster_key_with_xml_special_chars(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        _layout_manager(tmp_path, "<cluster>\n  <key>old</key>\n</cluster>\n")

        sync_manager_config(tmp_path, "key<>&value")

        content = _rendered_manager(tmp_path).read_text()
        assert "<key>key&lt;&gt;&amp;value</key>" in content


class TestRenderedArtifactProtection:
    """ADR-028: the rendered copy lives under the ignored ``.aptl/`` tree
    behind an owner-only directory; the checked-in template is never
    written. The file itself is ``0o644`` so a container process can read
    it across its bind mount — the ``0o700`` parent dir is the host-side
    access control."""

    def test_rendered_path_is_under_aptl_state_tree(self, tmp_path):
        from aptl.core.credentials import (
            RENDERED_DASHBOARD_RELPATH,
            RENDERED_MANAGER_RELPATH,
            sync_dashboard_config,
            sync_manager_config,
        )

        # The module's declared rendered relpaths must live under .aptl/
        # (which .gitignore already excludes) so they are never committed.
        assert RENDERED_DASHBOARD_RELPATH.parts[0] == ".aptl"
        assert RENDERED_MANAGER_RELPATH.parts[0] == ".aptl"

        _layout_dashboard(tmp_path, '      password: "old"\n')
        _layout_manager(tmp_path, "<cluster>\n  <key>old</key>\n</cluster>\n")

        d_out = sync_dashboard_config(tmp_path, "p")
        m_out = sync_manager_config(tmp_path, "k")

        assert d_out.is_relative_to((tmp_path / ".aptl").resolve())
        assert m_out.is_relative_to((tmp_path / ".aptl").resolve())

    @_skip_no_posix_modes
    def test_rendered_file_is_container_readable(self, tmp_path):
        """The rendered file is ``0o644`` — readable by a container process
        whose UID may not match the host UID — not owner-only ``0o600``,
        which would break the Wazuh Dashboard's non-root bind mount."""
        from aptl.core.credentials import sync_dashboard_config

        _layout_dashboard(tmp_path, '      password: "old"\n')

        out = sync_dashboard_config(tmp_path, "secret")

        mode = out.stat().st_mode & 0o777
        assert mode == 0o644, oct(mode)

    @_skip_no_posix_modes
    def test_rendered_dir_is_owner_only(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        _layout_manager(tmp_path, "<cluster>\n  <key>old</key>\n</cluster>\n")

        out = sync_manager_config(tmp_path, "k")

        # The file's parent dir and the .aptl/config root are both 0700 —
        # this is what keeps other local users away from the credentials,
        # despite the 0o644 file mode.
        parent_mode = out.parent.stat().st_mode & 0o777
        root_mode = (tmp_path / ".aptl" / "config").stat().st_mode & 0o777
        assert parent_mode == 0o700, oct(parent_mode)
        assert root_mode == 0o700, oct(root_mode)


class TestPathContainment:
    """Issue #266 / ADR-028: refuse to read or write outside the resolved
    project root — on both the source template and the rendered output."""

    def test_dashboard_rejects_source_symlink_escape(self, tmp_path):
        """Symlink at the canonical source location pointing outside the
        project root is rejected (and the outside file is untouched)."""
        from aptl.core.credentials import sync_dashboard_config

        outside = tmp_path / "escape.yml"
        outside.write_text('password: "untouched"\n')

        project_dir = tmp_path / "project"
        canonical_parent = project_dir / "config" / "wazuh_dashboard"
        canonical_parent.mkdir(parents=True)
        (canonical_parent / "wazuh.yml").symlink_to(outside)

        with pytest.raises(ValueError, match="escapes project root"):
            sync_dashboard_config(project_dir, "new_password")

        assert outside.read_text() == 'password: "untouched"\n'

    def test_manager_rejects_source_symlink_escape(self, tmp_path):
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

    @pytest.mark.skipif(sys.platform == "win32", reason="requires POSIX symlinks")
    def test_dashboard_rejects_output_symlink_escape(self, tmp_path):
        """A symlink among the rendered-output path components that points
        outside the project root is rejected before any write."""
        from aptl.core.credentials import sync_dashboard_config

        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        sentinel = outside_dir / "wazuh.yml"
        sentinel.write_text("ORIGINAL")

        project_dir = tmp_path / "project"
        _layout_dashboard(project_dir, '      password: "old"\n')
        # Pre-create .aptl/config/wazuh_dashboard as a symlink escaping
        # the project root.
        rendered_parent = project_dir / ".aptl" / "config"
        rendered_parent.mkdir(parents=True)
        (rendered_parent / "wazuh_dashboard").symlink_to(outside_dir)

        with pytest.raises(ValueError, match="symlinked path component"):
            sync_dashboard_config(project_dir, "leaked")

        # Nothing written through the symlink.
        assert sentinel.read_text() == "ORIGINAL"

    @pytest.mark.skipif(sys.platform == "win32", reason="requires POSIX symlinks")
    def test_rejects_output_symlink_back_into_tracked_config(self, tmp_path):
        """A symlink among the rendered-output components pointing at a
        *tracked* in-project file (e.g. ``.aptl/config`` → ``config``) is
        rejected — otherwise the renderer would write the live credential
        straight back into a checked-in file, the exposure ADR-028 removes."""
        from aptl.core.credentials import sync_dashboard_config

        project_dir = tmp_path
        template = _layout_dashboard(project_dir, '      password: "old"\n')
        template_before = template.read_bytes()
        # `.aptl/config` -> `config`, so `.aptl/config/wazuh_dashboard/wazuh.yml`
        # resolves to the tracked template.
        aptl_dir = project_dir / ".aptl"
        aptl_dir.mkdir()
        (aptl_dir / "config").symlink_to(project_dir / "config")

        with pytest.raises(ValueError, match="symlinked path component"):
            sync_dashboard_config(project_dir, "would-be-written-into-tracked")

        # The checked-in template is byte-for-byte untouched.
        assert template.read_bytes() == template_before

    def test_failed_replace_leaves_no_temp_file(self, tmp_path, mocker):
        """If the atomic rename fails after the temp file is written, the
        secret-bearing temp file must not be left behind."""
        from aptl.core.credentials import sync_dashboard_config

        _layout_dashboard(tmp_path, '      password: "old"\n')
        mocker.patch(
            "aptl.core.credentials.os.replace",
            side_effect=OSError("simulated rename failure"),
        )

        with pytest.raises(OSError, match="simulated rename failure"):
            sync_dashboard_config(tmp_path, "secret")

        rendered_dir = _rendered_dashboard(tmp_path).parent
        assert rendered_dir.is_dir()
        assert not [p for p in rendered_dir.iterdir() if p.name.endswith(".tmp")]

    @pytest.mark.skipif(sys.platform == "win32", reason="requires POSIX symlinks")
    def test_pre_planted_temp_symlink_does_not_leak_or_capture_target(self, tmp_path):
        """A symlink pre-planted at the predictable ``<name>.tmp`` path must
        not redirect the rendered secret outside the project, nor end up
        renamed into the output path. The renderer creates its temp file
        with an unpredictable name (``mkstemp``: ``O_EXCL | O_NOFOLLOW``),
        so the planted symlink is simply ignored."""
        from aptl.core.credentials import sync_dashboard_config

        outside = tmp_path / "outside-leak-target.yml"
        outside.write_text("ORIGINAL")

        _layout_dashboard(tmp_path, '      password: "old"\n')
        rendered = _rendered_dashboard(tmp_path)
        rendered.parent.mkdir(parents=True)
        # Plant the legacy predictable temp name as a symlink escaping the
        # project root.
        (rendered.parent / (rendered.name + ".tmp")).symlink_to(outside)

        sync_dashboard_config(tmp_path, "would-be-leaked")

        # Secret never written through the planted symlink.
        assert outside.read_text() == "ORIGINAL"
        # Output is a real regular file with the rendered content (not a symlink).
        assert rendered.is_file() and not rendered.is_symlink()
        assert 'password: "would-be-leaked"' in rendered.read_text()

    def test_dashboard_renders_from_canonical_source_only(self, tmp_path):
        """Sanity: the render reads <project_dir>/config/wazuh_dashboard/
        wazuh.yml, not a sibling decoy, and never writes the decoy."""
        from aptl.core.credentials import sync_dashboard_config

        _layout_dashboard(tmp_path, '      password: "old"\n')

        decoy = tmp_path / "wazuh.yml"
        decoy.write_text('      password: "decoy_untouched"\n')

        sync_dashboard_config(tmp_path, "new_password")

        assert 'password: "new_password"' in _rendered_dashboard(tmp_path).read_text()
        assert 'decoy_untouched' in decoy.read_text()

    def test_manager_renders_from_canonical_source_only(self, tmp_path):
        from aptl.core.credentials import sync_manager_config

        _layout_manager(tmp_path, "<cluster>\n  <key>old</key>\n</cluster>\n")

        decoy = tmp_path / "wazuh_manager.conf"
        decoy.write_text("<cluster>\n  <key>decoy_untouched</key>\n</cluster>\n")

        sync_manager_config(tmp_path, "new_key")

        assert "<key>new_key</key>" in _rendered_manager(tmp_path).read_text()
        assert "decoy_untouched" in decoy.read_text()


class TestCheckedInTemplates:
    """Guards that the checked-in ``config/`` templates the render functions
    read are well-formed and have not been credential-corrupted.

    The repo previously shipped ``config/wazuh_cluster/wazuh_manager.conf``
    with the ``<indexer><ssl><key>`` element rewritten to the literal cluster
    key value — fallout from the old blanket ``<key>`` replacement being
    dirtied into the working tree and committed. ADR-028 stops startup from
    mutating these files; this test stops the corrupted shape from creeping
    back in.
    """

    _HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")

    def test_manager_template_indexer_ssl_key_is_a_path(self):
        conf = (_REPO_ROOT / _MANAGER_SOURCE_RELPATH).read_text()
        # The filebeat client key path matches the docker-compose mount
        # `wazuh.manager-key.pem:/etc/ssl/filebeat.key` and the sibling
        # `<certificate>/etc/ssl/filebeat.pem</certificate>`.
        assert "<key>/etc/ssl/filebeat.key</key>" in conf

    def test_manager_template_has_no_credential_shaped_key_outside_cluster(self):
        conf = (_REPO_ROOT / _MANAGER_SOURCE_RELPATH).read_text()
        # Strip the <cluster>...</cluster> block(s) (where a hex key is the
        # legitimate placeholder cluster key) and assert no remaining <key>
        # element looks like a raw 32-hex-char secret.
        outside_cluster = re.sub(
            r"<cluster>.*?</cluster>", "", conf, flags=re.DOTALL
        )
        stray = [
            m.group(1)
            for m in re.finditer(r"<key>([^<]*)</key>", outside_cluster)
            if self._HEX32.match(m.group(1).strip())
        ]
        assert not stray, (
            "non-cluster <key> element(s) hold a credential-shaped value "
            f"(template was likely dirtied by an old startup run): {stray}"
        )
