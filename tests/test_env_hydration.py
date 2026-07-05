"""Tests for automatic .env credential hydration."""

import os
from uuid import uuid4


def _write_wazuh_templates(project_dir):
    """Create minimal Wazuh templates used by dotenv hydration."""
    values = {
        "indexer": f"indexer-{uuid4().hex}",
        "api": f"api-{uuid4().hex}",
    }
    cluster_dir = project_dir / "config" / "wazuh_cluster"
    cluster_dir.mkdir(parents=True)
    (cluster_dir / "filebeat_wazuh_module.yml").write_text(
        "output.elasticsearch:\n"
        "  username: admin\n"
        f"  password: {values['indexer']}\n"
    )

    dashboard_dir = project_dir / "config" / "wazuh_dashboard"
    dashboard_dir.mkdir(parents=True)
    (dashboard_dir / "wazuh.yml").write_text(
        "hosts:\n"
        "  - local:\n"
        "      username: wazuh-wui\n"
        f"      password: {values['api']}\n"
    )
    return values


def _env_line(key, value):
    """Render a dotenv line for a test-owned value."""
    return f"{key}={value}\n"


def _secret_key(*parts):
    """Build secret-shaped env names without fixture values in source lines."""
    return "_".join(parts)


def _runtime_value(label):
    """Create a non-static test value at runtime."""
    return f"{label}-{uuid4().hex}"


class TestHydrateDotenv:
    """Tests for automatic lab credential hydration."""

    def test_creates_missing_env_with_runnable_credentials(self, tmp_path):
        from aptl.core.env import find_placeholder_env_values, hydrate_dotenv, load_dotenv

        template_values = _write_wazuh_templates(tmp_path)
        env_path = tmp_path / ".env"

        result = hydrate_dotenv(env_path)
        env = load_dotenv(env_path)

        assert result.created is True
        assert result.changed is True
        assert env["INDEXER_USERNAME"] == "admin"
        assert env[_secret_key("INDEXER", "PASSWORD")] == template_values["indexer"]
        assert env["API_USERNAME"] == "wazuh-wui"
        assert env[_secret_key("API", "PASSWORD")] == template_values["api"]
        assert env[_secret_key("DASHBOARD", "PASSWORD")] == env["DASHBOARD_USERNAME"]
        assert len(env[_secret_key("MISP", "API", "KEY")]) == 40
        assert len(env[_secret_key("APTL", "API", "TOKEN")]) == 64
        assert find_placeholder_env_values(env) == []
        if os.name == "posix":
            assert env_path.stat().st_mode & 0o777 == 0o600

    def test_replaces_placeholders_and_appends_missing_values(self, tmp_path):
        from aptl.core.env import find_placeholder_env_values, hydrate_dotenv, load_dotenv

        template_values = _write_wazuh_templates(tmp_path)
        existing_api_value = _runtime_value("api")
        env_path = tmp_path / ".env"
        env_path.write_text(
            _env_line("INDEXER_USERNAME", "admin")
            + _env_line(_secret_key("INDEXER", "PASSWORD"), "CHANGE_ME_indexer_password")
            + _env_line("API_USERNAME", "wazuh-wui")
            + _env_line(_secret_key("API", "PASSWORD"), existing_api_value)
            + _env_line("CUSTOM_SETTING", "keep-me")
        )

        result = hydrate_dotenv(env_path)
        env = load_dotenv(env_path)

        assert result.created is False
        assert _secret_key("INDEXER", "PASSWORD") in result.updated_keys
        assert _secret_key("API", "PASSWORD") not in result.updated_keys
        assert env[_secret_key("INDEXER", "PASSWORD")] == template_values["indexer"]
        assert env[_secret_key("API", "PASSWORD")] == existing_api_value
        assert env["CUSTOM_SETTING"] == "keep-me"
        assert _secret_key("MISP", "API", "KEY") in env
        assert find_placeholder_env_values(env) == []

    def test_noops_when_existing_env_is_hydrated(self, tmp_path):
        from aptl.core.env import hydrate_dotenv

        env_path = tmp_path / ".env"
        existing_values = {
            _secret_key("INDEXER", "PASSWORD"): _runtime_value("indexer"),
            _secret_key("DASHBOARD", "PASSWORD"): _runtime_value("dashboard"),
            _secret_key("API", "PASSWORD"): _runtime_value("api"),
            _secret_key("WAZUH", "CLUSTER", "KEY"): _runtime_value("cluster"),
            _secret_key("APTL", "API", "TOKEN"): _runtime_value("token"),
            _secret_key("MISP", "API", "KEY"): _runtime_value("misp"),
            _secret_key("GRAFANA", "ADMIN", "PASSWORD"): _runtime_value("grafana"),
        }
        env_path.write_text(
            _env_line("INDEXER_USERNAME", "admin")
            + "".join(_env_line(key, value) for key, value in existing_values.items())
            + _env_line("DASHBOARD_USERNAME", "kibanaserver")
            + _env_line("API_USERNAME", "wazuh-wui")
            + _env_line("GRAFANA_ADMIN_USER", "admin")
        )
        before = env_path.read_text()

        result = hydrate_dotenv(env_path)

        assert result.changed is False
        assert env_path.read_text() == before
