"""Lazy, content-identified startup adapters for scenario-specific enrichment.

The generic lab lifecycle owns sequencing, subprocess containment, diagnostics,
and deployment-backend access.  A scenario adapter may identify the optional
post-readiness seed script, the operator-environment aliases its admitted
runtime requires, and semantic containers whose realized identities the script
needs.  No scenario name or topology is embedded in core lifecycle code.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
from pathlib import Path, PurePosixPath

from raes_processor.semantics.realization import (
    CONCERN_PAYLOAD_PATH,
    project_realization_concern,
)

from aptl.core.deployment.realization import valid_environment_variable_name
from aptl.core.scenario_bundle import PackIdentity, ScenarioBundle
from aptl.utils.logging import get_logger

log = get_logger("scenario-startup")

ENTRY_POINT_GROUP = "aptl.scenario_startup"
EXTENSION_API_VERSION = "1"


class ScenarioStartupProviderError(RuntimeError):
    """Stable fail-closed diagnostic for the scenario-startup adapter seam."""


@dataclass(frozen=True, order=True)
class EnvironmentAlias:
    """Copy one existing operator credential to a runtime variable name."""

    target: str
    source: str


@dataclass(frozen=True, order=True)
class ContainerEnvironmentBinding:
    """Expose one receipt-resolved semantic container to a seed subprocess."""

    variable: str
    semantic_name: str


@dataclass(frozen=True)
class ScenarioStartupPlan:
    """Validated scenario-specific work executed by the generic lifecycle."""

    seed_script: str
    required_profiles: tuple[str, ...]
    activation_profiles: tuple[str, ...]
    environment_aliases: tuple[EnvironmentAlias, ...] = ()
    container_environment: tuple[ContainerEnvironmentBinding, ...] = ()


def _entry_points() -> list[metadata.EntryPoint]:
    return list(metadata.entry_points(group=ENTRY_POINT_GROUP))


def _load(entry_point: metadata.EntryPoint) -> object:
    try:
        provider = entry_point.load()
        if isinstance(provider, type):
            provider = provider()
    except Exception as exc:
        log.warning(
            "scenario startup provider load failed: selector=%s exception=%s",
            entry_point.name,
            type(exc).__name__,
        )
        raise ScenarioStartupProviderError("provider-load-failed") from None
    return provider


def _string_tuple(provider: object, name: str) -> tuple[str, ...]:
    value = getattr(provider, name, None)
    if not isinstance(value, tuple) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ScenarioStartupProviderError("provider-malformed")
    return value


def _compatible_identity(provider: object, identity: PackIdentity) -> bool:
    if (
        getattr(provider, "extension_api_version", None) != EXTENSION_API_VERSION
        or getattr(provider, "supported_pack_id", None) != identity.pack_id
        or not callable(getattr(provider, "resolve", None))
    ):
        raise ScenarioStartupProviderError("provider-malformed")
    return identity.pack_version in _string_tuple(
        provider, "supported_pack_versions"
    ) and identity.set_digest in _string_tuple(provider, "supported_pack_set_digests")


def _compatible(provider: object, bundle: ScenarioBundle) -> bool:
    identity = bundle.pack_identity
    return identity is not None and _compatible_identity(provider, identity)


def _safe_relative_script(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ScenarioStartupProviderError("provider-result-invalid")
    path = PurePosixPath(value)
    if path.is_absolute():
        raise ScenarioStartupProviderError("provider-result-invalid")
    return str(path)


def _validated_aliases(value: object) -> tuple[EnvironmentAlias, ...]:
    if not isinstance(value, tuple) or any(
        not isinstance(item, EnvironmentAlias) for item in value
    ):
        raise ScenarioStartupProviderError("provider-result-invalid")
    if any(
        not valid_environment_variable_name(item.target)
        or not valid_environment_variable_name(item.source)
        for item in value
    ):
        raise ScenarioStartupProviderError("provider-result-invalid")
    if len({item.target for item in value}) != len(value):
        raise ScenarioStartupProviderError("provider-result-invalid")
    return tuple(value)


def _validated_container_environment(
    value: object,
) -> tuple[ContainerEnvironmentBinding, ...]:
    if not isinstance(value, tuple) or any(
        not isinstance(item, ContainerEnvironmentBinding) for item in value
    ):
        raise ScenarioStartupProviderError("provider-result-invalid")
    if any(
        not valid_environment_variable_name(item.variable)
        or not item.semantic_name
        or len(item.semantic_name) > 255
        or any(char.isspace() for char in item.semantic_name)
        for item in value
    ):
        raise ScenarioStartupProviderError("provider-result-invalid")
    if len({item.variable for item in value}) != len(value):
        raise ScenarioStartupProviderError("provider-result-invalid")
    return tuple(value)


def _validated_plan(value: object) -> ScenarioStartupPlan:
    if not isinstance(value, ScenarioStartupPlan):
        raise ScenarioStartupProviderError("provider-result-invalid")
    profiles = value.required_profiles
    activation = value.activation_profiles
    if any(
        not isinstance(group, tuple)
        or not group
        or any(not isinstance(item, str) or not item for item in group)
        or len(set(group)) != len(group)
        for group in (profiles, activation)
    ) or not set(activation).issubset(profiles):
        raise ScenarioStartupProviderError("provider-result-invalid")
    return ScenarioStartupPlan(
        seed_script=_safe_relative_script(value.seed_script),
        required_profiles=tuple(profiles),
        activation_profiles=tuple(activation),
        environment_aliases=_validated_aliases(value.environment_aliases),
        container_environment=_validated_container_environment(
            value.container_environment
        ),
    )


def resolve_scenario_startup(bundle: ScenarioBundle) -> ScenarioStartupPlan | None:
    """Resolve one exact adapter without importing scenario code in core."""

    identity = bundle.pack_identity
    if identity is None:
        return None
    candidates = [
        entry_point
        for entry_point in _entry_points()
        if entry_point.name == identity.pack_id
    ]
    compatible: list[object] = []
    for entry_point in candidates:
        provider = _load(entry_point)
        if _compatible(provider, bundle):
            compatible.append(provider)
    if len(compatible) > 1:
        raise ScenarioStartupProviderError("provider-ambiguous")
    if not compatible:
        return None
    try:
        return _validated_plan(compatible[0].resolve(bundle))
    except ScenarioStartupProviderError:
        raise
    except Exception as exc:
        log.warning(
            "scenario startup provider resolve failed: selector=%s exception=%s",
            identity.pack_id,
            type(exc).__name__,
        )
        raise ScenarioStartupProviderError("provider-resolve-failed") from None


def _runtime_provider(identity: PackIdentity | None) -> object | None:
    """Select at most one installed adapter for an exact pack release."""

    if identity is None:
        return None
    compatible: list[object] = []
    for entry in _entry_points():
        if entry.name != identity.pack_id:
            continue
        provider = _load(entry)
        if _compatible_identity(provider, identity):
            compatible.append(provider)
    if len(compatible) > 1:
        raise ScenarioStartupProviderError("provider-ambiguous")
    return compatible[0] if compatible else None


def run_scenario_runtime(
    identity: PackIdentity | None,
    backend: object,
    nodes: tuple[object, ...],
) -> list[str]:
    """Run installed, content-qualified post-start work for one scenario.

    The generic lifecycle selects an adapter by immutable pack identity. The
    adapter owns product-specific service configuration; core neither imports
    it nor interprets scenario names. Any adapter failure is a bounded,
    fail-closed startup failure, never a skipped materialization concern.
    """

    try:
        provider = _runtime_provider(identity)
    except ScenarioStartupProviderError:
        return ["scenario runtime provider selection failed"]
    if provider is None:
        return []
    runner = getattr(provider, "realize_runtime", None)
    if runner is None:
        return []
    if not callable(runner):
        return ["scenario runtime provider is malformed"]
    try:
        failures = runner(backend, nodes)
    except Exception as exc:
        log.warning(
            "scenario runtime provider failed: selector=%s exception=%s",
            identity.pack_id,
            type(exc).__name__,
        )
        return ["scenario runtime provider failed"]
    if not isinstance(failures, list) or any(
        not isinstance(item, str) or not item for item in failures
    ):
        return ["scenario runtime provider returned an invalid result"]
    return failures


def observe_scenario_runtime_concerns(
    identity: PackIdentity | None,
    backend: object,
    node: object,
) -> dict[tuple[str, ...], object]:
    """Ask the exact installed adapter for corroborated, projected concerns.

    An absent, ambiguous, malformed, or failed observer discloses nothing;
    RAES then rejects any exact SDL declaration for that concern. In
    particular, core never guesses a product's authorization semantics.
    """

    try:
        provider = _runtime_provider(identity)
        observer = getattr(provider, "observe_runtime", None) if provider else None
        if observer is None:
            return {}
        if not callable(observer):
            raise ScenarioStartupProviderError("provider-malformed")
        observed = observer(backend, node)
    except Exception as exc:
        log.warning(
            "scenario runtime observation failed: selector=%s exception=%s",
            getattr(identity, "pack_id", ""),
            type(exc).__name__,
        )
        return {}
    kinds_by_path = {path: kind for kind, path in CONCERN_PAYLOAD_PATH.items()}
    if not isinstance(observed, dict) or any(
        not isinstance(path, tuple) or path not in kinds_by_path or value is None
        for path, value in observed.items()
    ):
        return {}
    try:
        for path, value in observed.items():
            project_realization_concern(kinds_by_path[path], value, observed=True)
    except (TypeError, ValueError):
        return {}
    return observed


def seed_script_path(project_dir: Path, plan: ScenarioStartupPlan) -> Path:
    """Resolve a validated plan script beneath the materialized project root."""

    root = project_dir.resolve()
    candidate = root.joinpath(*PurePosixPath(plan.seed_script).parts).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ScenarioStartupProviderError("provider-result-invalid") from exc
    return candidate


__all__ = [
    "ENTRY_POINT_GROUP",
    "EXTENSION_API_VERSION",
    "ContainerEnvironmentBinding",
    "EnvironmentAlias",
    "ScenarioStartupPlan",
    "ScenarioStartupProviderError",
    "resolve_scenario_startup",
    "run_scenario_runtime",
    "observe_scenario_runtime_concerns",
    "seed_script_path",
]
