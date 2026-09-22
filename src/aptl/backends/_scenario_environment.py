"""Environment contracts shared by scenario startup adapter validation."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass, field

from aptl.core.deployment.realization import valid_environment_variable_name


class ScenarioStartupProviderError(RuntimeError):
    """Stable fail-closed diagnostic for the scenario-startup adapter seam."""


@dataclass(frozen=True, order=True)
class EnvironmentAlias:
    """Copy one existing operator credential to a runtime variable name."""

    target: str
    source: str


@dataclass(frozen=True, order=True)
class ScenarioEnvironmentFixture:
    """One pack-fixed value projected into the local environment cache."""

    name: str
    value: str = field(repr=False, compare=False)


def validated_aliases(value: object) -> tuple[EnvironmentAlias, ...]:
    """Validate unique, well-formed operator environment aliases."""

    if not isinstance(value, tuple):
        raise ScenarioStartupProviderError("provider-result-invalid")
    if any(not isinstance(item, EnvironmentAlias) for item in value):
        raise ScenarioStartupProviderError("provider-result-invalid")
    valid_names = all(
        valid_environment_variable_name(item.target)
        and valid_environment_variable_name(item.source)
        for item in value
    )
    unique_targets = len({item.target for item in value}) == len(value)
    if not valid_names or not unique_targets:
        raise ScenarioStartupProviderError("provider-result-invalid")
    return value


def validated_environment_fixtures(
    value: object, forbidden_names: Collection[str]
) -> tuple[ScenarioEnvironmentFixture, ...]:
    """Validate fixed values without copying their bytes into diagnostics."""

    if not isinstance(value, tuple):
        raise ScenarioStartupProviderError("provider-result-invalid")
    if any(not isinstance(item, ScenarioEnvironmentFixture) for item in value):
        raise ScenarioStartupProviderError("provider-result-invalid")
    names = [item.name for item in value]
    valid_names = all(
        valid_environment_variable_name(name) and name not in forbidden_names
        for name in names
    )
    valid_values = all(
        item.value and "\n" not in item.value and "\r" not in item.value
        for item in value
    )
    if len(names) != len(set(names)) or not valid_names or not valid_values:
        raise ScenarioStartupProviderError("provider-result-invalid")
    return value


__all__ = [
    "EnvironmentAlias",
    "ScenarioEnvironmentFixture",
    "ScenarioStartupProviderError",
    "validated_aliases",
    "validated_environment_fixtures",
]
