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


class TestExperimentSettings:
    """The sole code-owned apparatus binding target stays strict and bounded."""

    def test_default_participant_action_timeout(self):
        from aptl.core.config import ExperimentSettings

        assert ExperimentSettings().participant_action_timeout_seconds == 120

    @pytest.mark.parametrize("value", [0, 3601, "90", True])
    def test_rejects_out_of_range_or_non_integer_timeout(self, value):
        from aptl.core.config import ExperimentSettings

        with pytest.raises(ValidationError):
            ExperimentSettings(participant_action_timeout_seconds=value)

    def test_installed_participant_models_are_explicit_and_provider_closed(self):
        from aptl.core.config import ExperimentSettings

        settings = ExperimentSettings(
            participant_models={
                "claude": "claude-sonnet-4-5-20250929",
                "codex": "gpt-5-nano-2025-08-07",
            }
        )

        assert settings.participant_models.model_for("claude") == (
            "claude-sonnet-4-5-20250929"
        )
        assert settings.participant_models.model_for("codex") == "gpt-5-nano-2025-08-07"
        default_models = ExperimentSettings().participant_models
        with pytest.raises(ValueError, match="not configured"):
            default_models.model_for("codex")
        with pytest.raises(ValueError, match="unknown installed participant provider"):
            settings.participant_models.model_for("other")

    @pytest.mark.parametrize(
        "value",
        [
            "",
            " ",
            "latest",
            "default",
            "auto",
            "sonnet",
            "claude-sonnet-4-5",
            "gpt-4o",
            "gpt-5.2-codex",
            "bad model",
            "bad\nmodel",
            "x" * 129,
            7,
            True,
        ],
    )
    def test_rejects_ambiguous_or_malformed_participant_model(self, value):
        from aptl.core.config import ExperimentSettings

        with pytest.raises(ValidationError):
            ExperimentSettings(participant_models={"codex": value})

    def test_rejects_unknown_participant_model_provider_or_option(self):
        from aptl.core.config import ExperimentSettings

        with pytest.raises(ValidationError):
            ExperimentSettings(participant_models={"other": "gpt-5-nano-2025-08-07"})
        with pytest.raises(ValidationError):
            ExperimentSettings(
                participant_models={
                    "codex": "gpt-5-nano-2025-08-07",
                    "codex_options": {"fallback": "o1"},
                }
            )

    @pytest.mark.parametrize(
        ("provider", "model"),
        [
            ("claude", "gpt-5-nano-2025-08-07"),
            ("codex", "claude-sonnet-4-5-20250929"),
        ],
    )
    def test_rejects_model_identity_from_another_provider(self, provider, model):
        from aptl.core.config import ExperimentSettings

        with pytest.raises(ValidationError):
            ExperimentSettings(participant_models={provider: model})

    def test_participant_credential_sources_are_explicit_and_provider_closed(self):
        from aptl.core.config import ExperimentSettings

        settings = ExperimentSettings(
            participant_credential_sources={
                "claude": {
                    "kind": "process-environment",
                    "variable": "APTL_PARTICIPANT_CLAUDE_CREDENTIAL",
                },
                "codex": {
                    "kind": "process-environment",
                    "variable": "APTL_PARTICIPANT_CODEX_CREDENTIAL",
                },
            }
        )

        claude = settings.participant_credential_sources.source_for("claude")
        assert claude.kind == "process-environment"
        assert claude.variable == "APTL_PARTICIPANT_CLAUDE_CREDENTIAL"
        assert claude.descriptor_digest().startswith("sha256:")
        default_sources = ExperimentSettings().participant_credential_sources
        with pytest.raises(ValueError, match="not configured"):
            default_sources.source_for("codex")
        with pytest.raises(ValueError, match="unknown installed participant provider"):
            settings.participant_credential_sources.source_for("other")

    @pytest.mark.parametrize(
        "source",
        [
            {"kind": "unknown", "variable": "APTL_PARTICIPANT_CREDENTIAL"},
            {"kind": "process-environment"},
            {"kind": "process-environment", "variable": ""},
            {"kind": "process-environment", "variable": "lowercase"},
            {"kind": "process-environment", "variable": "1INVALID"},
            {"kind": "process-environment", "variable": "BAD-NAME"},
            {"kind": "process-environment", "variable": "A" * 129},
            {
                "kind": "process-environment",
                "variable": "APTL_PARTICIPANT_CREDENTIAL",
                "fallback": "ANTHROPIC_API_KEY",
            },
            {
                "kind": "process-environment",
                "variable": "APTL_PARTICIPANT_CREDENTIAL",
                "value": "must-never-be-configured-here",
            },
            "APTL_PARTICIPANT_CREDENTIAL",
        ],
    )
    def test_rejects_invalid_participant_credential_source(self, source):
        from aptl.core.config import ExperimentSettings

        with pytest.raises(ValidationError):
            ExperimentSettings(participant_credential_sources={"claude": source})

    def test_rejects_unknown_participant_credential_provider(self):
        from aptl.core.config import ExperimentSettings

        with pytest.raises(ValidationError):
            ExperimentSettings(
                participant_credential_sources={
                    "other": {
                        "kind": "process-environment",
                        "variable": "APTL_PARTICIPANT_OTHER_CREDENTIAL",
                    }
                }
            )


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
        self,
        tmp_config_dir,
        body,
        top_type,
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
