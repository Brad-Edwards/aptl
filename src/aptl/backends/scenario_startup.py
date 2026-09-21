"""Lazy, content-identified startup adapters for scenario-specific enrichment.

The generic lab lifecycle owns sequencing, subprocess containment, diagnostics,
and deployment-backend access.  A scenario adapter may identify the optional
post-readiness seed script, the operator-environment aliases its admitted
runtime requires, and semantic containers whose realized identities the script
needs.  No scenario name or topology is embedded in core lifecycle code.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from importlib import metadata
from pathlib import Path, PurePosixPath
import re

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
DOCKER_TRANSPORT_KEYS = frozenset(
    {"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_SSH_IDENTITY"}
)


class ScenarioStartupProviderError(RuntimeError):
    """Stable fail-closed diagnostic for the scenario-startup adapter seam."""


class StartupCapability(str, Enum):
    """Fixed optional lab mechanics an exact scenario adapter may request."""

    SSH = "ssh"
    HOST_TOOLS = "host_tools"
    MCP = "mcp"
    NATIVE_EVIDENCE = "native_evidence"


class StartupHook(str, Enum):
    """Fixed lifecycle hook slots an admitted adapter may implement."""

    STACK_ENVIRONMENT = "stack_environment"
    BEFORE_BACKEND_RETRY = "before_backend_retry"
    RESET = "reset"


class StartupPreparationPhase(str, Enum):
    """Core-owned ordered preparation slots available to an adapter."""

    ENVIRONMENT = "environment"
    PRE_START_CONFIGURATION = "pre_start_configuration"
    PRE_START_STORAGE = "pre_start_storage"
    PRE_START_TRUST = "pre_start_trust"
    PRE_START_SERVICE_TRUST = "pre_start_service_trust"
    PRE_START_ARTIFACTS = "pre_start_artifacts"
    POST_START_READINESS = "post_start_readiness"
    POST_START_CONFIGURATION = "post_start_configuration"


@dataclass(frozen=True)
class StartupHookContext:
    """Narrow runtime authority passed to a selected startup hook."""

    backend: object | None
    preparation_phase: StartupPreparationPhase | None = None
    operation: Callable[[], object] | None = field(
        default=None, repr=False, compare=False
    )

    def run_operation(self) -> object:
        """Run the single core operation delegated for this fixed phase."""

        if self.operation is None:
            raise ScenarioStartupProviderError("provider-hook-operation-unavailable")
        return self.operation()


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
class McpServerCredentials:
    """One client server's explicitly authorized dynamic environment keys."""

    server_id: str
    environment_keys: tuple[str, ...]


@dataclass(frozen=True)
class ScenarioStartupPlan:
    """Validated scenario-specific work executed by the generic lifecycle."""

    seed_script: str
    required_profiles: tuple[str, ...]
    activation_profiles: tuple[str, ...]
    environment_aliases: tuple[EnvironmentAlias, ...] = ()
    container_environment: tuple[ContainerEnvironmentBinding, ...] = ()
    lifecycle_capabilities: frozenset[StartupCapability] = frozenset()
    startup_hooks: frozenset[StartupHook] = frozenset()
    seed_environment_keys: tuple[str, ...] = ()
    mcp_build_script: str | None = None
    mcp_server_keys: tuple[McpServerCredentials, ...] = ()
    native_mcp_ingress: bool = False


@dataclass(frozen=True)
class ScenarioStartupSelection:
    """The exact provider and validated plan selected for one admission."""

    identity: PackIdentity | None
    provider: object | None = field(repr=False, compare=False)
    plan: ScenarioStartupPlan | None
    provenance: StartupProviderProvenance | None = None


@dataclass(frozen=True)
class StartupProviderProvenance:
    """Installed distribution identity used to rediscover a reset hook."""

    distribution: str
    distribution_version: str
    entry_point: str


def _entry_points() -> list[metadata.EntryPoint]:
    """Find installed startup providers without importing them eagerly."""

    return list(metadata.entry_points(group=ENTRY_POINT_GROUP))


def _load(entry_point: metadata.EntryPoint) -> object:
    """Load one provider and redact implementation failures."""

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


def _provenance(entry_point: metadata.EntryPoint) -> StartupProviderProvenance:
    dist = getattr(entry_point, "dist", None)
    return StartupProviderProvenance(
        distribution=str(getattr(dist, "name", "") or ""),
        distribution_version=str(getattr(dist, "version", "") or ""),
        entry_point=entry_point.name,
    )


def _string_tuple(provider: object, name: str) -> tuple[str, ...]:
    """Require a provider identity field to be a nonempty-string tuple."""

    value = getattr(provider, name, None)
    if not isinstance(value, tuple) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ScenarioStartupProviderError("provider-malformed")
    return value


def _compatible_identity(provider: object, identity: PackIdentity) -> bool:
    """Check the extension contract and immutable pack identity."""

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
    """Match an adapter only when the bundle carries a qualified pack."""

    identity = bundle.pack_identity
    return identity is not None and _compatible_identity(provider, identity)


def _safe_relative_script(value: object) -> str:
    """Reject absolute or escaping seed script paths from an adapter."""

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
    """Validate unique, well-formed operator environment aliases."""

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
    """Validate semantic container bindings before exposing them to seed."""

    if not isinstance(value, tuple) or any(
        not isinstance(item, ContainerEnvironmentBinding) for item in value
    ):
        raise ScenarioStartupProviderError("provider-result-invalid")
    if any(
        not valid_environment_variable_name(item.variable)
        or item.variable in DOCKER_TRANSPORT_KEYS
        or not item.semantic_name
        or len(item.semantic_name) > 255
        or any(char.isspace() for char in item.semantic_name)
        for item in value
    ):
        raise ScenarioStartupProviderError("provider-result-invalid")
    if len({item.variable for item in value}) != len(value):
        raise ScenarioStartupProviderError("provider-result-invalid")
    return tuple(value)


def _validated_profile_groups(
    profiles: object, activation: object
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Validate required and activated Compose profiles as one contract."""

    if any(
        not isinstance(group, tuple)
        or not group
        or any(not isinstance(item, str) or not item for item in group)
        or len(set(group)) != len(group)
        for group in (profiles, activation)
    ) or not set(activation).issubset(profiles):
        raise ScenarioStartupProviderError("provider-result-invalid")
    return profiles, activation


def _validated_seed_keys(value: object) -> tuple[str, ...]:
    """Allow declared seed values without Docker transport overrides."""

    if (
        not isinstance(value, tuple)
        or any(
            not isinstance(key, str)
            or not valid_environment_variable_name(key)
            or key in DOCKER_TRANSPORT_KEYS
            for key in value
        )
        or len(set(value)) != len(value)
    ):
        raise ScenarioStartupProviderError("provider-result-invalid")
    return value


def _valid_mcp_credential(item: object) -> bool:
    """Check one bounded MCP client's declared credential names."""

    return (
        isinstance(item, McpServerCredentials)
        and bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", item.server_id))
        and isinstance(item.environment_keys, tuple)
        and bool(item.environment_keys)
        and all(
            isinstance(key, str) and valid_environment_variable_name(key)
            for key in item.environment_keys
        )
        and len(set(item.environment_keys)) == len(item.environment_keys)
    )


def _validated_mcp_keys(value: object) -> tuple[McpServerCredentials, ...]:
    """Require unique, well-formed client credential declarations."""

    if (
        not isinstance(value, tuple)
        or any(not _valid_mcp_credential(item) for item in value)
        or len({item.server_id for item in value}) != len(value)
    ):
        raise ScenarioStartupProviderError("provider-result-invalid")
    return value


def _validated_plan(value: object) -> ScenarioStartupPlan:
    """Normalize one adapter plan and reject malformed profile sets."""

    if not isinstance(value, ScenarioStartupPlan):
        raise ScenarioStartupProviderError("provider-result-invalid")
    profiles, activation = _validated_profile_groups(
        value.required_profiles, value.activation_profiles
    )
    if not isinstance(value.lifecycle_capabilities, frozenset) or any(
        not isinstance(item, StartupCapability) for item in value.lifecycle_capabilities
    ):
        raise ScenarioStartupProviderError("provider-result-invalid")
    if not isinstance(value.startup_hooks, frozenset) or any(
        not isinstance(item, StartupHook) for item in value.startup_hooks
    ):
        raise ScenarioStartupProviderError("provider-result-invalid")
    seed_keys = _validated_seed_keys(value.seed_environment_keys)
    mcp_keys = _validated_mcp_keys(value.mcp_server_keys)
    if not isinstance(value.native_mcp_ingress, bool) or (
        value.mcp_build_script is not None
        and not isinstance(value.mcp_build_script, str)
    ):
        raise ScenarioStartupProviderError("provider-result-invalid")
    return ScenarioStartupPlan(
        seed_script=_safe_relative_script(value.seed_script),
        required_profiles=tuple(profiles),
        activation_profiles=tuple(activation),
        environment_aliases=_validated_aliases(value.environment_aliases),
        container_environment=_validated_container_environment(
            value.container_environment
        ),
        lifecycle_capabilities=frozenset(value.lifecycle_capabilities),
        startup_hooks=frozenset(value.startup_hooks),
        seed_environment_keys=seed_keys,
        mcp_build_script=(
            _safe_relative_script(value.mcp_build_script)
            if value.mcp_build_script is not None
            else None
        ),
        mcp_server_keys=tuple(mcp_keys),
        native_mcp_ingress=value.native_mcp_ingress,
    )


def select_scenario_startup(bundle: ScenarioBundle) -> ScenarioStartupSelection:
    """Select one exact adapter once for all stages of an admitted start."""

    identity = bundle.pack_identity
    if identity is None:
        return ScenarioStartupSelection(identity, None, None)
    candidates = [
        entry_point
        for entry_point in _entry_points()
        if entry_point.name == identity.pack_id
    ]
    compatible: list[tuple[metadata.EntryPoint, object]] = []
    for entry_point in candidates:
        provider = _load(entry_point)
        if _compatible(provider, bundle):
            compatible.append((entry_point, provider))
    if len(compatible) > 1:
        raise ScenarioStartupProviderError("provider-ambiguous")
    if not compatible:
        return ScenarioStartupSelection(identity, None, None)
    try:
        entry_point, provider = compatible[0]
        plan = _validated_plan(provider.resolve(bundle))
        _validate_hook_methods(provider, plan)
        return ScenarioStartupSelection(
            identity,
            provider,
            plan,
            _provenance(entry_point),
        )
    except ScenarioStartupProviderError:
        raise
    except Exception as exc:
        log.warning(
            "scenario startup provider resolve failed: selector=%s exception=%s",
            identity.pack_id,
            type(exc).__name__,
        )
        raise ScenarioStartupProviderError("provider-resolve-failed") from None


def _validate_hook_methods(provider: object, plan: ScenarioStartupPlan) -> None:
    """Require a callable implementation for every declared hook slot."""

    methods = {
        StartupHook.STACK_ENVIRONMENT: "prepare_stack_environment",
        StartupHook.BEFORE_BACKEND_RETRY: "before_backend_retry",
        StartupHook.RESET: "reset",
    }
    if any(
        hook in plan.startup_hooks and not callable(getattr(provider, method, None))
        for hook, method in methods.items()
    ):
        raise ScenarioStartupProviderError("provider-malformed")


def run_startup_hook(
    selection: ScenarioStartupSelection | None,
    hook: StartupHook,
    context: StartupHookContext,
) -> object | None:
    """Invoke one admitted fixed hook, normalizing adapter failures."""

    if (
        selection is None
        or selection.plan is None
        or hook not in selection.plan.startup_hooks
    ):
        return None
    method = {
        StartupHook.STACK_ENVIRONMENT: "prepare_stack_environment",
        StartupHook.BEFORE_BACKEND_RETRY: "before_backend_retry",
        StartupHook.RESET: "reset",
    }.get(hook)
    if method is None:
        return None
    try:
        return getattr(selection.provider, method)(context)
    except Exception as exc:
        log.warning(
            "scenario startup hook failed: hook=%s exception=%s",
            hook.value,
            type(exc).__name__,
        )
        raise ScenarioStartupProviderError("provider-hook-failed") from None


def resolve_scenario_startup(bundle: ScenarioBundle) -> ScenarioStartupPlan | None:
    """Resolve a plan for independent callers outside a lab admission."""

    return select_scenario_startup(bundle).plan


def selected_runtime_provider(
    identity: PackIdentity | None,
    selection: ScenarioStartupSelection | None,
) -> object | None:
    """Use the admitted provider, including an admitted absence, when supplied."""

    if selection is None:
        return _runtime_provider(identity)
    if selection.identity != identity:
        raise ScenarioStartupProviderError("provider-identity-mismatch")
    return selection.provider


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


def run_persisted_startup_reset(
    identity: PackIdentity,
    provenance: StartupProviderProvenance,
    context: StartupHookContext,
) -> None:
    """Invoke the exact installed reset provider recorded by a prior start."""

    compatible: list[object] = []
    for entry in _entry_points():
        if entry.name != provenance.entry_point or _provenance(entry) != provenance:
            continue
        provider = _load(entry)
        if _compatible_identity(provider, identity):
            compatible.append(provider)
    if len(compatible) != 1 or not callable(getattr(compatible[0], "reset", None)):
        raise ScenarioStartupProviderError("provider-reset-authority-unavailable")
    try:
        compatible[0].reset(context)
    except Exception as exc:
        log.warning(
            "persisted scenario startup reset failed: selector=%s exception=%s",
            provenance.entry_point,
            type(exc).__name__,
        )
        raise ScenarioStartupProviderError("provider-hook-failed") from None


def run_scenario_runtime(
    identity: PackIdentity | None,
    backend: object,
    nodes: tuple[object, ...],
    *,
    selection: ScenarioStartupSelection | None = None,
) -> list[str]:
    """Run installed, content-qualified post-start work for one scenario.

    The generic lifecycle selects an adapter by immutable pack identity. The
    adapter owns product-specific service configuration; core neither imports
    it nor interprets scenario names. Any adapter failure is a bounded,
    fail-closed startup failure, never a skipped materialization concern.
    """

    try:
        provider = selected_runtime_provider(identity, selection)
    except ScenarioStartupProviderError:
        return ["scenario runtime provider selection failed"]
    if provider is None:
        return []
    from aptl.backends.scenario_runtime_hooks import invoke_runtime_provider

    return invoke_runtime_provider(provider, identity, backend, nodes)


def observe_scenario_runtime_concerns(
    identity: PackIdentity | None,
    backend: object,
    node: object,
    *,
    selection: ScenarioStartupSelection | None = None,
) -> dict[tuple[str, ...], object]:
    """Ask the exact installed adapter for corroborated, projected concerns.

    An absent, ambiguous, malformed, or failed observer discloses nothing;
    RAES then rejects any exact SDL declaration for that concern. In
    particular, core never guesses a product's authorization semantics.
    """

    from aptl.backends.scenario_runtime_hooks import invoke_runtime_observer

    try:
        provider = selected_runtime_provider(identity, selection)
    except ScenarioStartupProviderError:
        provider = None
    observed = invoke_runtime_observer(provider, identity, backend, node)
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
    "McpServerCredentials",
    "ScenarioStartupPlan",
    "ScenarioStartupSelection",
    "StartupProviderProvenance",
    "ScenarioStartupProviderError",
    "StartupCapability",
    "StartupHook",
    "StartupHookContext",
    "StartupPreparationPhase",
    "resolve_scenario_startup",
    "select_scenario_startup",
    "run_scenario_runtime",
    "run_persisted_startup_reset",
    "observe_scenario_runtime_concerns",
    "run_startup_hook",
    "seed_script_path",
]
