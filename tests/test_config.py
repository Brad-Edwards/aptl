"""Tests for APTL configuration loading and validation.

Tests are written FIRST (TDD). Each test exercises our validation logic,
default handling, error paths, and config loading from files.
"""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError


class TestLabSettings:
    """Tests for the LabSettings Pydantic model."""

    def test_valid_minimal_config(self):
        """A lab config with just a name should work, using defaults."""
        from aptl.core.config import LabSettings

        settings = LabSettings(name="my-lab")
        assert settings.name == "my-lab"
        assert settings.network_subnet == "172.20.0.0/16"

    def test_custom_network_subnet(self):
        """User can override the default subnet."""
        from aptl.core.config import LabSettings

        settings = LabSettings(name="custom", network_subnet="10.0.0.0/24")
        assert settings.network_subnet == "10.0.0.0/24"

    def test_rejects_empty_name(self):
        """Lab name cannot be empty string."""
        from aptl.core.config import LabSettings

        with pytest.raises(ValidationError, match="name"):
            LabSettings(name="")

    def test_rejects_name_with_spaces(self):
        """Lab name must be a valid identifier-like string (no spaces)."""
        from aptl.core.config import LabSettings

        with pytest.raises(ValidationError, match="name"):
            LabSettings(name="my lab with spaces")

    def test_rejects_missing_name(self):
        """Lab name is required."""
        from aptl.core.config import LabSettings

        with pytest.raises(ValidationError):
            LabSettings()


class TestContainerSettings:
    """Tests for the ContainerSettings Pydantic model."""

    def test_defaults_all_containers_enabled(self):
        """By default, wazuh/victim/kali are enabled, reverse is disabled."""
        from aptl.core.config import ContainerSettings

        settings = ContainerSettings()
        assert settings.wazuh is True
        assert settings.victim is True
        assert settings.kali is True
        assert settings.reverse is False

    def test_can_disable_containers(self):
        """User can selectively disable containers."""
        from aptl.core.config import ContainerSettings

        settings = ContainerSettings(wazuh=False, kali=False)
        assert settings.wazuh is False
        assert settings.kali is False
        assert settings.victim is True

    def test_enabled_profiles_returns_only_enabled(self):
        """enabled_profiles() should return docker compose profile names for enabled containers."""
        from aptl.core.config import ContainerSettings

        settings = ContainerSettings(wazuh=True, victim=False, kali=True, reverse=False)
        profiles = settings.enabled_profiles()
        assert "wazuh" in profiles
        assert "kali" in profiles
        assert "victim" not in profiles
        assert "reverse" not in profiles


class TestAptlConfig:
    """Tests for the top-level AptlConfig model."""

    def test_valid_full_config(self, valid_config_dict):
        """A complete config dict should parse successfully."""
        from aptl.core.config import AptlConfig

        config = AptlConfig(**valid_config_dict)
        assert config.lab.name == "test-lab"
        assert config.containers.wazuh is True
        assert config.containers.reverse is False

    def test_missing_lab_section_uses_default(self):
        """Config without a lab section should use default lab settings."""
        from aptl.core.config import AptlConfig

        config = AptlConfig(containers={"wazuh": True})
        assert config.lab.name == "aptl"

    def test_containers_default_when_omitted(self):
        """If containers section is omitted, defaults apply."""
        from aptl.core.config import AptlConfig

        config = AptlConfig(lab={"name": "test"})
        assert config.containers.wazuh is True
        assert config.containers.reverse is False

    def test_extra_fields_are_ignored(self):
        """Unknown top-level keys should be silently ignored."""
        from aptl.core.config import AptlConfig

        config = AptlConfig(
            lab={"name": "test"},
            unknown_section={"foo": "bar"},
        )
        assert config.lab.name == "test"


class TestConfigLoading:
    """Tests for loading config from filesystem."""

    def test_load_from_json_file(self, valid_config_file):
        """Should load and parse a JSON config file."""
        from aptl.core.config import load_config

        config = load_config(valid_config_file)
        assert config.lab.name == "test-lab"

    def test_load_from_nonexistent_file_raises(self, tmp_config_dir):
        """Loading a missing file should raise FileNotFoundError."""
        from aptl.core.config import load_config

        with pytest.raises(FileNotFoundError):
            load_config(tmp_config_dir / "missing.json")

    def test_load_from_invalid_json_raises(self, tmp_config_dir):
        """Malformed JSON should raise a clear error."""
        from aptl.core.config import load_config

        bad_file = tmp_config_dir / "bad.json"
        bad_file.write_text("{not valid json!!!")
        with pytest.raises(ValueError, match="[Ii]nvalid JSON"):
            load_config(bad_file)

    def test_load_from_empty_file_raises(self, tmp_config_dir):
        """An empty file should raise a clear error."""
        from aptl.core.config import load_config

        empty = tmp_config_dir / "empty.json"
        empty.write_text("")
        with pytest.raises(ValueError):
            load_config(empty)

    def test_find_config_searches_cwd(self, tmp_config_dir, valid_config_dict):
        """find_config() should locate aptl.json in the given directory."""
        from aptl.core.config import find_config

        config_path = tmp_config_dir / "aptl.json"
        config_path.write_text(json.dumps(valid_config_dict))
        found = find_config(tmp_config_dir)
        assert found == config_path

    def test_find_config_returns_none_when_missing(self, tmp_config_dir):
        """find_config() returns None when no config file exists."""
        from aptl.core.config import find_config

        result = find_config(tmp_config_dir)
        assert result is None
