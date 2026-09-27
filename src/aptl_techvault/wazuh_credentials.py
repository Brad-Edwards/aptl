"""Exact-release Wazuh fixture projection for the TechVault startup adapter."""

from __future__ import annotations

from collections.abc import Mapping

import yaml

from aptl.backends.scenario_startup import (
    ScenarioEnvironmentFixture,
    ScenarioStartupProviderError,
)
from aptl.core.scenario_bundle import ScenarioBundle

# OpenRAE/env-packs#392: the current pack carries the bcrypt hashes but not the
# corresponding indexer plaintexts. Keep this temporary compatibility knowledge
# release-local and adapter-owned; core never copies or classifies these values.
_INDEXER_COMPATIBILITY = {
    "INDEXER_USERNAME": "admin",
    "INDEXER_PASSWORD": "SecretPassword",  # NOSONAR S2068 -- exact lab fixture
    "DASHBOARD_USERNAME": "kibanaserver",
    "DASHBOARD_PASSWORD": "kibanaserver",  # NOSONAR S2068 -- exact lab fixture
}


def techvault_wazuh_environment(
    bundle: ScenarioBundle,
) -> tuple[ScenarioEnvironmentFixture, ...]:
    """Return Wazuh aliases from validated pack content plus narrow fallbacks."""

    try:
        document = yaml.safe_load(bundle.sdl_path.read_text(encoding="utf-8"))
        content = document["content"]["wazuh-dashboard-app-config"]
        if (
            content.get("target") != "wazuh-dashboard"
            or content.get("path")
            != "/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
        ):
            raise KeyError("unexpected dashboard credential content")
        dashboard = yaml.safe_load(content["text"])
        host = next(iter(dashboard["hosts"][0].values()))
        api_username = host["username"]
        api_password = host["password"]
    except (OSError, TypeError, KeyError, IndexError, StopIteration, yaml.YAMLError):
        raise ScenarioStartupProviderError("provider-result-invalid") from None
    if not all(
        isinstance(value, str) and value and "\n" not in value and "\r" not in value
        for value in (api_username, api_password)
    ):
        raise ScenarioStartupProviderError("provider-result-invalid")
    values: Mapping[str, str] = {
        **_INDEXER_COMPATIBILITY,
        "API_USERNAME": api_username,
        "API_PASSWORD": api_password,
    }
    return tuple(
        ScenarioEnvironmentFixture(name=name, value=value)
        for name, value in sorted(values.items())
    )


__all__ = ("techvault_wazuh_environment",)
