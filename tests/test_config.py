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


# Canonical expected defaults for ContainerSettings. Any new field
# added to ContainerSettings MUST be added here as well, or the
# ``test_defaults_*`` tests below will fail. That coupling is the
# point: a new container type accidentally defaulting to ``True`` must
# not slip past the test suite (it would otherwise enable that
# container in every lab start).
_EXPECTED_CONTAINER_DEFAULTS = {
    "wazuh": True,
    "victim": True,
    "kali": True,
    "reverse": False,
    "enterprise": True,
    "soc": True,
    "mail": False,
    "fileshare": True,
    "dns": True,
}


class TestContainerSettings:
    """Tests for the ContainerSettings Pydantic model."""

    def test_defaults_match_canonical_set(self):
        """Every ContainerSettings field defaults to its canonical value.

        Compares the full ``model_dump()`` against
        ``_EXPECTED_CONTAINER_DEFAULTS`` so adding a new field to
        ``ContainerSettings`` without updating the expected set fails
        this test loudly — preventing an accidental new-container
        default-True from shipping silently.
        """
        from aptl.core.config import ContainerSettings

        assert ContainerSettings().model_dump() == _EXPECTED_CONTAINER_DEFAULTS

    def test_can_disable_containers(self):
        """User can selectively disable containers."""
        from aptl.core.config import ContainerSettings

        settings = ContainerSettings(wazuh=False, kali=False)
        assert settings.wazuh is False
        assert settings.kali is False
        assert settings.victim is True

    def test_enabled_profiles_returns_only_enabled(self):
        """enabled_profiles() returns exactly the set of enabled container names.

        Asserts an exact set equality, not a few `in`/`not in` checks,
        so a new field accidentally defaulting to ``True`` would show
        up in the profile list and trip this assertion.
        """
        from aptl.core.config import ContainerSettings

        # Set every field explicitly so this exercises enabled_profiles() itself
        # rather than the model defaults.
        settings = ContainerSettings(
            wazuh=True,
            victim=False,
            kali=True,
            reverse=False,
            enterprise=False,
            soc=False,
            mail=False,
            fileshare=False,
            dns=False,
        )
        assert set(settings.enabled_profiles()) == {"wazuh", "kali"}


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
        """If containers section is omitted, the canonical defaults apply.

        Asserts the full ``model_dump()`` against
        ``_EXPECTED_CONTAINER_DEFAULTS`` so a new container field added
        to ``ContainerSettings`` without updating the expected set
        fails this top-level path too — preventing an accidental new
        container from being enabled by default.
        """
        from aptl.core.config import AptlConfig

        config = AptlConfig(lab={"name": "test"})
        assert config.containers.model_dump() == _EXPECTED_CONTAINER_DEFAULTS

    def test_extra_fields_are_rejected(self):
        """Unknown top-level keys are validation errors per ADR-025."""
        from aptl.core.config import AptlConfig

        with pytest.raises(ValidationError, match="unknown_section"):
            AptlConfig(
                lab={"name": "test"},
                unknown_section={"foo": "bar"},
            )

    @pytest.mark.parametrize("dead_key", ["edr_agents", "agent_configs"])
    def test_dead_top_level_keys_are_rejected(self, dead_key):
        """The legacy `edr_agents` and `agent_configs` blocks have no
        runtime consumer; they must fail validation rather than be
        silently accepted (regression for issue #190)."""
        from aptl.core.config import AptlConfig

        with pytest.raises(ValidationError, match=dead_key):
            AptlConfig(
                lab={"name": "test"},
                **{dead_key: {"victim": ["wazuh"]}},
            )


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

    @pytest.mark.parametrize(
        "body,top_type",
        [
            ("0", "int"),
            ("3.14", "float"),
            ('"hello"', "str"),
            ("true", "bool"),
            ("null", "NoneType"),
            ("[1, 2, 3]", "list"),
        ],
    )
    def test_load_from_non_mapping_json_raises_valueerror(
        self, tmp_config_dir, body, top_type,
    ):
        """A JSON top-level that isn't an object must raise ``ValueError``.

        Pre-fix, ``AptlConfig(**data)`` would raise ``TypeError`` for any
        non-mapping ``data``, leaking past the documented public-exception
        contract (``FileNotFoundError`` / ``ValueError``). Caught by
        ``tests/test_config_fuzz.py::test_load_config_arbitrary_text_bounded_outcomes``
        with falsifying example ``body='0'``.
        """
        from aptl.core.config import load_config

        path = tmp_config_dir / "aptl.json"
        path.write_text(body)
        with pytest.raises(ValueError, match="JSON object"):
            load_config(path)

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

    def test_load_rejects_unknown_top_level_key(self, tmp_config_dir):
        """load_config() must surface unknown top-level keys as a
        ValidationError, not silently accept them (issue #190)."""
        from aptl.core.config import load_config

        path = tmp_config_dir / "aptl.json"
        path.write_text(
            json.dumps(
                {
                    "lab": {"name": "test"},
                    "edr_agents": {"victim": ["wazuh"]},
                }
            )
        )
        with pytest.raises(ValidationError, match="edr_agents"):
            load_config(path)

    def test_checked_in_aptl_json_loads_cleanly(self):
        """The repo's checked-in aptl.json must remain compatible with
        the schema (ADR-025: checked-in top-level sections must have
        both a Pydantic field and a runtime owner)."""
        from aptl.core.config import AptlConfig, load_config

        repo_root = Path(__file__).resolve().parent.parent
        config = load_config(repo_root / "aptl.json")
        assert isinstance(config, AptlConfig)
        # The lab profile in the checked-in config must remain the
        # default name; if it ever changes, ADR-025's "checked-in
        # config is the canonical example" contract is at risk.
        assert config.lab.name == "aptl"
