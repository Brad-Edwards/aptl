"""Bounded Compose startup readiness supplied by a content-qualified adapter.

The SDL owns the service graph. An adapter may add a health probe to an
existing image service and require an already-declared dependency to be
healthy before startup; it cannot introduce services or dependency edges.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from aptl.backends.scenario_startup import (
    ScenarioStartupProviderError,
    _runtime_provider,
)
from aptl.core.deployment._compose_node_topology import service_dependencies
from aptl.core.deployment._compose_service_health import runtime_expects_completion
from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.utils.logging import get_logger

log = get_logger("scenario-startup-policy")

_OVERRIDE_RELPATH = Path(".aptl/realization/compose.startup.yml")
_POLICY_INVALID = "provider-compose-result-invalid"


@dataclass(frozen=True)
class StartupHealthProbe:
    """One in-container, shell-free health test for an emitted service."""

    service: str
    test: tuple[str, ...]
    interval_seconds: int = 30
    timeout_seconds: int = 10
    retries: int = 15
    start_period_seconds: int = 300


@dataclass(frozen=True)
class StartupHealthDependency:
    """Require an already-declared dependency to pass its adapter health test."""

    service: str
    dependency: str


@dataclass(frozen=True)
class ScenarioComposeStartupPolicy:
    """Bounded health additions selected by one exact pack identity."""

    probes: tuple[StartupHealthProbe, ...] = ()
    dependencies: tuple[StartupHealthDependency, ...] = ()


def _valid_test(test: object) -> bool:
    """Permit only bounded exec-form Compose health commands."""

    return bool(
        isinstance(test, tuple)
        and 2 <= len(test) <= 8
        and test[0] == "CMD"
        and all(isinstance(part, str) and 0 < len(part) <= 255 for part in test)
    )


def _valid_budget(value: object) -> bool:
    """Restrict each health timing field to a positive bounded integer."""

    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 900


def _probe_healthcheck(probe: object) -> dict[str, object]:
    """Validate one bounded exec-form test before rendering Compose fields."""

    if not isinstance(probe, StartupHealthProbe) or not _valid_test(probe.test):
        raise ScenarioStartupProviderError(_POLICY_INVALID)
    budgets = (
        probe.interval_seconds,
        probe.timeout_seconds,
        probe.retries,
        probe.start_period_seconds,
    )
    if not all(_valid_budget(value) for value in budgets):
        raise ScenarioStartupProviderError(_POLICY_INVALID)
    return {
        "test": list(probe.test),
        "interval": f"{probe.interval_seconds}s",
        "timeout": f"{probe.timeout_seconds}s",
        "retries": probe.retries,
        "start_period": f"{probe.start_period_seconds}s",
    }


def _apply_probes(
    probes: tuple[StartupHealthProbe, ...],
    nodes: dict[str, DeploymentNodeRealization],
    services: dict[str, dict[str, object]],
) -> set[str]:
    """Attach healthchecks only to emitted services, without duplicates."""

    probed: set[str] = set()
    for probe in probes:
        healthcheck = _probe_healthcheck(probe)
        if probe.service not in nodes or probe.service in probed:
            raise ScenarioStartupProviderError(_POLICY_INVALID)
        probed.add(probe.service)
        services.setdefault(probe.service, {})["healthcheck"] = healthcheck
    return probed


def _condition_map(
    declared: list[str] | dict[str, dict[str, str]],
) -> dict[str, dict[str, str]]:
    """Preserve declared Compose dependency conditions as a mutable map."""

    if isinstance(declared, dict):
        return {name: dict(value) for name, value in declared.items()}
    return {name: {"condition": "service_started"} for name in declared}


def _apply_dependencies(
    edges: tuple[StartupHealthDependency, ...],
    nodes: dict[str, DeploymentNodeRealization],
    probed: set[str],
    services: dict[str, dict[str, object]],
) -> None:
    """Strengthen existing graph edges only when the dependency is probed."""

    names = set(nodes)
    completion = {
        name for name, node in nodes.items() if runtime_expects_completion(node.runtime)
    }
    seen: set[tuple[str, str]] = set()
    for edge in edges:
        if not isinstance(edge, StartupHealthDependency):
            raise ScenarioStartupProviderError(_POLICY_INVALID)
        pair = (edge.service, edge.dependency)
        if edge.service not in nodes or edge.dependency not in probed or pair in seen:
            raise ScenarioStartupProviderError(_POLICY_INVALID)
        declared = service_dependencies(nodes[edge.service], names, completion)
        if edge.dependency not in declared:
            raise ScenarioStartupProviderError(_POLICY_INVALID)
        seen.add(pair)
        conditions = _condition_map(declared)
        existing = services.setdefault(edge.service, {}).get("depends_on")
        if isinstance(existing, dict):
            conditions.update(existing)
        conditions[edge.dependency] = {"condition": "service_healthy"}
        services[edge.service]["depends_on"] = conditions


def _validated_policy(
    policy: object, spec: DeploymentRealizationSpec
) -> dict[str, dict[str, object]]:
    """Return only health and existing-dependency fields for emitted services."""

    if not isinstance(policy, ScenarioComposeStartupPolicy):
        raise ScenarioStartupProviderError(_POLICY_INVALID)
    emitted = {image.address for image in spec.images}
    nodes = {
        node.service_name: node
        for node in spec.nodes
        if node.service_name and node.address in emitted
    }
    services: dict[str, dict[str, object]] = {}
    probed = _apply_probes(policy.probes, nodes, services)
    _apply_dependencies(policy.dependencies, nodes, probed, services)
    return services


def _resolved_services(spec: DeploymentRealizationSpec) -> dict[str, dict[str, object]]:
    """Resolve an exact-pack policy into bounded Compose service fields."""

    provider = _runtime_provider(spec.pack_identity)
    resolver = getattr(provider, "compose_startup_policy", None) if provider else None
    if resolver is None:
        return {}
    if not callable(resolver):
        raise ScenarioStartupProviderError(_POLICY_INVALID)
    try:
        return _validated_policy(resolver(), spec)
    except ScenarioStartupProviderError:
        raise
    except Exception as exc:
        log.warning("scenario startup policy failed: exception=%s", type(exc).__name__)
        raise ScenarioStartupProviderError("provider-compose-failed") from None


def write_scenario_startup_override(
    spec: DeploymentRealizationSpec, realization_root: Path
) -> Path | None:
    """Write an optional, pack-qualified readiness overlay under the engine root."""

    services = _resolved_services(spec)
    if not services:
        return None
    path = realization_root / _OVERRIDE_RELPATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump({"services": services}, sort_keys=True),
        encoding="utf-8",
        newline="\n",
    )
    return path
