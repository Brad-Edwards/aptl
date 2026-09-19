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
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.utils.logging import get_logger

log = get_logger("scenario-startup-policy")

_OVERRIDE_RELPATH = Path(".aptl/realization/compose.startup.yml")


@dataclass(frozen=True)
class StartupHealthProbe:
    service: str
    test: tuple[str, ...]
    interval_seconds: int = 30
    timeout_seconds: int = 10
    retries: int = 15
    start_period_seconds: int = 300


@dataclass(frozen=True)
class StartupHealthDependency:
    service: str
    dependency: str


@dataclass(frozen=True)
class ScenarioComposeStartupPolicy:
    probes: tuple[StartupHealthProbe, ...] = ()
    dependencies: tuple[StartupHealthDependency, ...] = ()


def _validated_policy(
    policy: object, spec: DeploymentRealizationSpec
) -> dict[str, dict[str, object]]:
    """Return only health and existing-dependency fields for emitted services."""

    if not isinstance(policy, ScenarioComposeStartupPolicy):
        raise ScenarioStartupProviderError("provider-compose-result-invalid")
    emitted = {image.address for image in spec.images}
    nodes = {
        node.service_name: node
        for node in spec.nodes
        if node.service_name and node.address in emitted
    }
    names = set(nodes)
    completion = {
        name for name, node in nodes.items() if runtime_expects_completion(node.runtime)
    }
    services: dict[str, dict[str, object]] = {}
    probed: set[str] = set()
    for probe in policy.probes:
        if (
            not isinstance(probe, StartupHealthProbe)
            or probe.service not in nodes
            or probe.service in probed
            or not isinstance(probe.test, tuple)
            or not 2 <= len(probe.test) <= 8
            or probe.test[0] != "CMD"
            or any(
                not isinstance(part, str) or not part or len(part) > 255
                for part in probe.test
            )
            or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 1 <= value <= 900
                for value in (
                    probe.interval_seconds,
                    probe.timeout_seconds,
                    probe.retries,
                    probe.start_period_seconds,
                )
            )
        ):
            raise ScenarioStartupProviderError("provider-compose-result-invalid")
        probed.add(probe.service)
        services.setdefault(probe.service, {})["healthcheck"] = {
            "test": list(probe.test),
            "interval": f"{probe.interval_seconds}s",
            "timeout": f"{probe.timeout_seconds}s",
            "retries": probe.retries,
            "start_period": f"{probe.start_period_seconds}s",
        }

    seen: set[tuple[str, str]] = set()
    for edge in policy.dependencies:
        if not isinstance(edge, StartupHealthDependency):
            raise ScenarioStartupProviderError("provider-compose-result-invalid")
        pair = (edge.service, edge.dependency)
        if edge.service not in nodes or edge.dependency not in probed or pair in seen:
            raise ScenarioStartupProviderError("provider-compose-result-invalid")
        declared = service_dependencies(nodes[edge.service], names, completion)
        if edge.dependency not in declared:
            raise ScenarioStartupProviderError("provider-compose-result-invalid")
        seen.add(pair)
        conditions = (
            {name: dict(value) for name, value in declared.items()}
            if isinstance(declared, dict)
            else {name: {"condition": "service_started"} for name in declared}
        )
        existing = services.setdefault(edge.service, {}).get("depends_on")
        if isinstance(existing, dict):
            conditions.update(existing)
        conditions[edge.dependency] = {"condition": "service_healthy"}
        services[edge.service]["depends_on"] = conditions
    return services


def write_scenario_startup_override(
    spec: DeploymentRealizationSpec, realization_root: Path
) -> Path | None:
    """Write an optional, pack-qualified readiness overlay under the engine root."""

    provider = _runtime_provider(spec.pack_identity)
    if provider is None:
        return None
    resolver = getattr(provider, "compose_startup_policy", None)
    if resolver is None:
        return None
    if not callable(resolver):
        raise ScenarioStartupProviderError("provider-compose-result-invalid")
    try:
        services = _validated_policy(resolver(), spec)
    except ScenarioStartupProviderError:
        raise
    except Exception as exc:
        log.warning("scenario startup policy failed: exception=%s", type(exc).__name__)
        raise ScenarioStartupProviderError("provider-compose-failed") from None
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
