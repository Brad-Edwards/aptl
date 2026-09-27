"""Tests for automatic .env credential hydration."""

import os
from uuid import uuid4


def _patch_windows_default_fdopen(mocker, module_path):
    """Make text writes default to CRLF unless the caller pins newlines."""
    real_fdopen = os.fdopen

    def fdopen_with_windows_default(fd, mode="r", *args, **kwargs):
        if "b" not in mode and "newline" not in kwargs:
            kwargs["newline"] = "\r\n"
        return real_fdopen(fd, mode, *args, **kwargs)

    return mocker.patch(
        f"{module_path}.os.fdopen", side_effect=fdopen_with_windows_default
    )


def _scenario_fixtures():
    """Return test-owned pack fixture values without checked-in copies."""

    return {
        "INDEXER_USERNAME": _runtime_value("indexer-user"),
        "INDEXER_PASSWORD": _runtime_value("indexer-password"),
        "DASHBOARD_USERNAME": _runtime_value("dashboard-user"),
        "DASHBOARD_PASSWORD": _runtime_value("dashboard-password"),
        "API_USERNAME": _runtime_value("api-user"),
        "API_PASSWORD": _runtime_value("api-password"),
    }


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
        from aptl.core.env import (
            find_placeholder_env_values,
            hydrate_dotenv,
            load_dotenv,
        )

        fixtures = _scenario_fixtures()
        env_path = tmp_path / ".env"

        result = hydrate_dotenv(env_path, authoritative_values=fixtures)
        env = load_dotenv(env_path)

        assert result.created is True
        assert result.changed is True
        assert all(env[key] == value for key, value in fixtures.items())
        assert len(env[_secret_key("MISP", "API", "KEY")]) == 40
        assert len(env[_secret_key("APTL", "API", "TOKEN")]) == 64
        assert find_placeholder_env_values(env) == []
        if os.name == "posix":
            assert env_path.stat().st_mode & 0o777 == 0o600

    def test_created_env_uses_lf_when_host_default_is_crlf(self, tmp_path, mocker):
        from aptl.core.env import hydrate_dotenv

        fixtures = _scenario_fixtures()
        env_path = tmp_path / ".env"
        _patch_windows_default_fdopen(mocker, "aptl.core.env")

        hydrate_dotenv(env_path, authoritative_values=fixtures)

        raw = env_path.read_bytes()
        assert b"\r\n" not in raw
        assert raw.endswith(b"\n")

    def test_replaces_placeholders_and_appends_missing_values(self, tmp_path):
        from aptl.core.env import (
            find_placeholder_env_values,
            hydrate_dotenv,
            load_dotenv,
        )

        fixtures = _scenario_fixtures()
        existing_api_value = _runtime_value("api")
        env_path = tmp_path / ".env"
        env_path.write_text(
            _env_line("INDEXER_USERNAME", "admin")
            + _env_line(
                _secret_key("INDEXER", "PASSWORD"), "CHANGE_ME_indexer_password"
            )
            + _env_line("API_USERNAME", "wazuh-wui")
            + _env_line(_secret_key("API", "PASSWORD"), existing_api_value)
            + _env_line("CUSTOM_SETTING", "keep-me")
        )

        result = hydrate_dotenv(env_path, authoritative_values=fixtures)
        env = load_dotenv(env_path)

        assert result.created is False
        assert _secret_key("INDEXER", "PASSWORD") in result.updated_keys
        assert _secret_key("API", "PASSWORD") in result.updated_keys
        assert _secret_key("API", "PASSWORD") in result.overridden_keys
        assert env[_secret_key("INDEXER", "PASSWORD")] == fixtures["INDEXER_PASSWORD"]
        assert env[_secret_key("API", "PASSWORD")] == fixtures["API_PASSWORD"]
        assert env["CUSTOM_SETTING"] == "keep-me"
        assert _secret_key("MISP", "API", "KEY") in env
        assert find_placeholder_env_values(env) == []

    def test_noops_when_existing_env_is_hydrated(self, tmp_path):
        from aptl.core.env import hydrate_dotenv

        fixtures = _scenario_fixtures()
        env_path = tmp_path / ".env"
        # Every scenario-owned fixture must already hold its declared value for
        # a true no-op. Generic APTL-owned secrets keep existing values.
        existing_values = {
            _secret_key("WAZUH", "CLUSTER", "KEY"): _runtime_value("cluster"),
            _secret_key("APTL", "API", "TOKEN"): _runtime_value("token"),
            _secret_key("MISP", "API", "KEY"): _runtime_value("misp"),
            _secret_key("GRAFANA", "ADMIN", "PASSWORD"): _runtime_value("grafana"),
        }
        env_path.write_text(
            "".join(_env_line(key, value) for key, value in fixtures.items())
            + "".join(_env_line(key, value) for key, value in existing_values.items())
            + _env_line("GRAFANA_ADMIN_USER", "admin")
        )
        before = env_path.read_text()

        result = hydrate_dotenv(env_path, authoritative_values=fixtures)

        assert result.changed is False
        assert result.overridden_keys == ()
        assert env_path.read_text() == before

    def test_reconciles_divergent_indexer_password_fixture(self, tmp_path):
        from aptl.core.env import hydrate_dotenv, load_dotenv

        fixtures = _scenario_fixtures()
        divergent = _runtime_value("my-own-indexer-pw")
        env_path = tmp_path / ".env"
        env_path.write_text(
            _env_line("INDEXER_USERNAME", "admin")
            + _env_line(_secret_key("INDEXER", "PASSWORD"), divergent)
        )

        result = hydrate_dotenv(env_path, authoritative_values=fixtures)
        env = load_dotenv(env_path)

        # A user-supplied value that cannot match the indexer's baked hash is
        # reconciled to the fixture, not preserved.
        assert _secret_key("INDEXER", "PASSWORD") in result.overridden_keys
        assert _secret_key("INDEXER", "PASSWORD") in result.updated_keys
        assert result.changed is True
        assert env[_secret_key("INDEXER", "PASSWORD")] == fixtures["INDEXER_PASSWORD"]
        assert env[_secret_key("INDEXER", "PASSWORD")] != divergent

    def test_reconciles_divergent_dashboard_password_fixture(self, tmp_path):
        from aptl.core.env import hydrate_dotenv, load_dotenv

        fixtures = _scenario_fixtures()
        divergent = _runtime_value("my-own-dashboard-pw")
        env_path = tmp_path / ".env"
        env_path.write_text(
            _env_line("DASHBOARD_USERNAME", "kibanaserver")
            + _env_line(_secret_key("DASHBOARD", "PASSWORD"), divergent)
        )

        result = hydrate_dotenv(env_path, authoritative_values=fixtures)
        env = load_dotenv(env_path)

        assert _secret_key("DASHBOARD", "PASSWORD") in result.overridden_keys
        assert (
            env[_secret_key("DASHBOARD", "PASSWORD")] == fixtures["DASHBOARD_PASSWORD"]
        )
        assert env[_secret_key("DASHBOARD", "PASSWORD")] != divergent

    def test_reconciles_divergent_pack_fixed_api_secret(self, tmp_path):
        from aptl.core.env import hydrate_dotenv, load_dotenv

        fixtures = _scenario_fixtures()
        chosen_api = _runtime_value("api")
        env_path = tmp_path / ".env"
        env_path.write_text(
            _env_line("API_USERNAME", "wazuh-wui")
            + _env_line(_secret_key("API", "PASSWORD"), chosen_api)
        )

        result = hydrate_dotenv(env_path, authoritative_values=fixtures)
        env = load_dotenv(env_path)

        assert _secret_key("API", "PASSWORD") in result.overridden_keys
        assert env[_secret_key("API", "PASSWORD")] == fixtures["API_PASSWORD"]
        assert env[_secret_key("API", "PASSWORD")] != chosen_api
