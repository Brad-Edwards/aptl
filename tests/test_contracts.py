"""Tests for the pure-predicate module used by lab-orchestration contracts.

These predicates are the inputs to `icontract.require` decorators on the
`_step_*` functions in `aptl.core.lab`. The contract is that each
predicate is a pure read over already-built dataclasses — no Docker,
filesystem, network, env-parsing, or secret-reading side effects (ADR-031).
"""

from pathlib import Path

from aptl.core.config import AptlConfig, ContainerSettings
from aptl.core.contracts import (
    backend_is_initialized,
    config_is_loaded,
    env_is_loaded,
    required_profiles_enabled,
    ssh_key_is_ready,
)
from aptl.core.env import EnvVars


def _make_env() -> EnvVars:
    return EnvVars(
        indexer_username="u",
        indexer_password="p",
        api_username="u",
        api_password="p",
    )


def _make_config(**container_overrides) -> AptlConfig:
    containers = ContainerSettings(**container_overrides)
    return AptlConfig(containers=containers)


class TestEnvIsLoaded:
    def test_none_is_false(self) -> None:
        assert env_is_loaded(None) is False

    def test_envvars_instance_is_true(self) -> None:
        assert env_is_loaded(_make_env()) is True


class TestConfigIsLoaded:
    def test_none_is_false(self) -> None:
        assert config_is_loaded(None) is False

    def test_aptlconfig_instance_is_true(self) -> None:
        assert config_is_loaded(_make_config()) is True


class TestBackendIsInitialized:
    def test_none_is_false(self) -> None:
        assert backend_is_initialized(None) is False

    def test_any_object_is_true(self) -> None:
        # The predicate is a presence check, not a type check; the typed
        # DeploymentBackend protocol is enforced at construction sites.
        assert backend_is_initialized(object()) is True


class TestSshKeyIsReady:
    def test_none_is_false(self) -> None:
        assert ssh_key_is_ready(None) is False

    def test_path_instance_is_true(self, tmp_path: Path) -> None:
        # The predicate checks the field is populated, not that the file
        # exists on disk — orchestration owns the actual generation step.
        assert ssh_key_is_ready(tmp_path / "aptl_lab_key") is True


class TestRequiredProfilesEnabled:
    def test_empty_required_is_trivially_true(self) -> None:
        config = _make_config()
        assert required_profiles_enabled(config, frozenset()) is True

    def test_all_required_enabled_is_true(self) -> None:
        config = _make_config(wazuh=True, victim=True, kali=True)
        assert (
            required_profiles_enabled(config, frozenset({"wazuh", "victim"}))
            is True
        )

    def test_one_required_missing_is_false(self) -> None:
        config = _make_config(wazuh=True, victim=True, kali=False)
        assert (
            required_profiles_enabled(config, frozenset({"wazuh", "kali"}))
            is False
        )

    def test_subset_of_enabled_is_true(self) -> None:
        config = _make_config(wazuh=True, victim=True, kali=True, soc=True)
        assert (
            required_profiles_enabled(config, frozenset({"soc"})) is True
        )

    def test_superset_of_enabled_is_false(self) -> None:
        config = _make_config(wazuh=True, victim=False, kali=False)
        assert (
            required_profiles_enabled(config, frozenset({"wazuh", "victim"}))
            is False
        )

    def test_prime_set_requires_soc_true(self) -> None:
        # Named regression on the issue's exact prime profile requirement.
        # Defaults have soc=False, so the prime set must be False here.
        config = _make_config(
            wazuh=True,
            enterprise=False,
            victim=True,
            kali=True,
            fileshare=False,
            soc=False,
        )
        prime_required = frozenset(
            {"wazuh", "enterprise", "victim", "kali", "fileshare", "soc"}
        )
        assert required_profiles_enabled(config, prime_required) is False

    def test_prime_set_full_enabled_is_true(self) -> None:
        config = _make_config(
            wazuh=True,
            enterprise=True,
            victim=True,
            kali=True,
            fileshare=True,
            soc=True,
        )
        prime_required = frozenset(
            {"wazuh", "enterprise", "victim", "kali", "fileshare", "soc"}
        )
        assert required_profiles_enabled(config, prime_required) is True
