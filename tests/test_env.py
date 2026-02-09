"""Tests for .env file loading and validation.

Tests are written FIRST (TDD). Each test exercises parsing, validation,
default handling, and error paths for environment variable loading.
"""

import pytest
from pathlib import Path


class TestLoadDotenv:
    """Tests for parsing .env files."""

    def test_parse_valid_env_with_all_vars(self, tmp_path):
        """Should parse KEY=VALUE lines from a well-formed .env file."""
        from aptl.core.env import load_dotenv

        env_file = tmp_path / ".env"
        env_file.write_text(
            "INDEXER_USERNAME=admin\n"
            "INDEXER_PASSWORD=SecretPassword\n"
            "API_USERNAME=wazuh-wui\n"
            "API_PASSWORD=MyS3cr3t\n"
        )
        result = load_dotenv(env_file)
        assert result["INDEXER_USERNAME"] == "admin"
        assert result["INDEXER_PASSWORD"] == "SecretPassword"
        assert result["API_USERNAME"] == "wazuh-wui"
        assert result["API_PASSWORD"] == "MyS3cr3t"

    def test_skip_comment_lines(self, tmp_path):
        """Lines starting with # should be ignored."""
        from aptl.core.env import load_dotenv

        env_file = tmp_path / ".env"
        env_file.write_text(
            "# This is a comment\n"
            "INDEXER_USERNAME=admin\n"
            "  # Another comment with leading spaces\n"
            "API_USERNAME=wazuh\n"
        )
        result = load_dotenv(env_file)
        assert len(result) == 2
        assert result["INDEXER_USERNAME"] == "admin"
        assert result["API_USERNAME"] == "wazuh"

    def test_skip_blank_lines(self, tmp_path):
        """Blank lines should be ignored."""
        from aptl.core.env import load_dotenv

        env_file = tmp_path / ".env"
        env_file.write_text(
            "INDEXER_USERNAME=admin\n"
            "\n"
            "   \n"
            "API_USERNAME=wazuh\n"
        )
        result = load_dotenv(env_file)
        assert len(result) == 2

    def test_strip_double_quotes_from_values(self, tmp_path):
        """Values wrapped in double quotes should have quotes stripped."""
        from aptl.core.env import load_dotenv

        env_file = tmp_path / ".env"
        env_file.write_text('INDEXER_PASSWORD="SecretPassword"\n')
        result = load_dotenv(env_file)
        assert result["INDEXER_PASSWORD"] == "SecretPassword"

    def test_strip_single_quotes_from_values(self, tmp_path):
        """Values wrapped in single quotes should have quotes stripped."""
        from aptl.core.env import load_dotenv

        env_file = tmp_path / ".env"
        env_file.write_text("INDEXER_PASSWORD='SecretPassword'\n")
        result = load_dotenv(env_file)
        assert result["INDEXER_PASSWORD"] == "SecretPassword"

    def test_handle_values_with_equals_signs(self, tmp_path):
        """Values containing = signs (e.g., base64 passwords) should be preserved."""
        from aptl.core.env import load_dotenv

        env_file = tmp_path / ".env"
        env_file.write_text("API_PASSWORD=MyS3cr3t==\n")
        result = load_dotenv(env_file)
        assert result["API_PASSWORD"] == "MyS3cr3t=="

    def test_handle_empty_values(self, tmp_path):
        """KEY= with no value should result in an empty string."""
        from aptl.core.env import load_dotenv

        env_file = tmp_path / ".env"
        env_file.write_text("WAZUH_CLUSTER_KEY=\n")
        result = load_dotenv(env_file)
        assert result["WAZUH_CLUSTER_KEY"] == ""

    def test_raises_file_not_found(self, tmp_path):
        """Loading a nonexistent .env file should raise FileNotFoundError."""
        from aptl.core.env import load_dotenv

        with pytest.raises(FileNotFoundError):
            load_dotenv(tmp_path / "nonexistent.env")

    def test_strip_whitespace_around_key_and_value(self, tmp_path):
        """Whitespace around keys and values should be stripped."""
        from aptl.core.env import load_dotenv

        env_file = tmp_path / ".env"
        env_file.write_text("  INDEXER_USERNAME = admin  \n")
        result = load_dotenv(env_file)
        assert result["INDEXER_USERNAME"] == "admin"

    def test_lines_without_equals_are_skipped(self, tmp_path):
        """Lines without = should be silently skipped."""
        from aptl.core.env import load_dotenv

        env_file = tmp_path / ".env"
        env_file.write_text(
            "INDEXER_USERNAME=admin\n"
            "no_equals_here\n"
            "API_USERNAME=wazuh\n"
        )
        result = load_dotenv(env_file)
        assert len(result) == 2

    def test_export_prefix_is_stripped(self, tmp_path):
        """Lines like 'export KEY=VALUE' should strip the export prefix."""
        from aptl.core.env import load_dotenv

        env_file = tmp_path / ".env"
        env_file.write_text("export INDEXER_USERNAME=admin\n")
        result = load_dotenv(env_file)
        assert result["INDEXER_USERNAME"] == "admin"


class TestValidateRequiredEnv:
    """Tests for required environment variable validation."""

    def test_returns_empty_when_all_present(self):
        """Should return empty list when all required vars are present and non-empty."""
        from aptl.core.env import validate_required_env

        env = {
            "INDEXER_USERNAME": "admin",
            "INDEXER_PASSWORD": "secret",
            "API_USERNAME": "wazuh",
            "API_PASSWORD": "mysecret",
        }
        required = ["INDEXER_USERNAME", "INDEXER_PASSWORD", "API_USERNAME", "API_PASSWORD"]
        missing = validate_required_env(env, required)
        assert missing == []

    def test_returns_missing_var_names(self):
        """Should return names of variables that are missing from env dict."""
        from aptl.core.env import validate_required_env

        env = {"INDEXER_USERNAME": "admin"}
        required = ["INDEXER_USERNAME", "INDEXER_PASSWORD", "API_USERNAME"]
        missing = validate_required_env(env, required)
        assert "INDEXER_PASSWORD" in missing
        assert "API_USERNAME" in missing
        assert "INDEXER_USERNAME" not in missing

    def test_catches_empty_string_values(self):
        """Variables set to empty string should be reported as missing."""
        from aptl.core.env import validate_required_env

        env = {
            "INDEXER_USERNAME": "admin",
            "INDEXER_PASSWORD": "",
        }
        required = ["INDEXER_USERNAME", "INDEXER_PASSWORD"]
        missing = validate_required_env(env, required)
        assert "INDEXER_PASSWORD" in missing

    def test_empty_required_list(self):
        """An empty required list should always return empty."""
        from aptl.core.env import validate_required_env

        missing = validate_required_env({}, [])
        assert missing == []


class TestEnvVarsFromDict:
    """Tests for building typed EnvVars from raw dict."""

    def test_builds_correct_envvars(self):
        """Should create EnvVars with correct field values."""
        from aptl.core.env import env_vars_from_dict

        env = {
            "INDEXER_USERNAME": "admin",
            "INDEXER_PASSWORD": "secret",
            "API_USERNAME": "wazuh-wui",
            "API_PASSWORD": "mysecret",
            "DASHBOARD_USERNAME": "kibana",
            "DASHBOARD_PASSWORD": "dashpass",
            "WAZUH_CLUSTER_KEY": "clusterkey123",
        }
        result = env_vars_from_dict(env)
        assert result.indexer_username == "admin"
        assert result.indexer_password == "secret"
        assert result.api_username == "wazuh-wui"
        assert result.api_password == "mysecret"
        assert result.dashboard_username == "kibana"
        assert result.dashboard_password == "dashpass"
        assert result.wazuh_cluster_key == "clusterkey123"

    def test_uses_defaults_for_optional_fields(self):
        """Optional fields should use defaults when not in env dict."""
        from aptl.core.env import env_vars_from_dict

        env = {
            "INDEXER_USERNAME": "admin",
            "INDEXER_PASSWORD": "secret",
            "API_USERNAME": "wazuh-wui",
            "API_PASSWORD": "mysecret",
        }
        result = env_vars_from_dict(env)
        assert result.dashboard_username == "kibanaserver"
        assert result.dashboard_password == ""
        assert result.wazuh_cluster_key == ""

    def test_raises_when_required_vars_missing(self):
        """Should raise ValueError when required env vars are missing."""
        from aptl.core.env import env_vars_from_dict

        env = {"INDEXER_USERNAME": "admin"}  # Missing others
        with pytest.raises(ValueError, match="INDEXER_PASSWORD"):
            env_vars_from_dict(env)

    def test_raises_when_required_var_is_empty(self):
        """Should raise ValueError when a required var has empty value."""
        from aptl.core.env import env_vars_from_dict

        env = {
            "INDEXER_USERNAME": "admin",
            "INDEXER_PASSWORD": "",
            "API_USERNAME": "wazuh",
            "API_PASSWORD": "secret",
        }
        with pytest.raises(ValueError, match="INDEXER_PASSWORD"):
            env_vars_from_dict(env)
