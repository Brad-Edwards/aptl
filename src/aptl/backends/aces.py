"""APTL ACES runtime target.

This module is the handoff layer between the external ACES SDL/runtime
packages and APTL's existing deployment primitives.  It intentionally keeps
Docker/SSH details behind ``DeploymentBackend``; the ACES provisioner only
translates a provisioning plan into the compose profiles APTL can already
start.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
import re
from typing import TYPE_CHECKING, Any

import yaml

from aces_contracts.diagnostics import Diagnostic, Severity
from aces_contracts.planning import ChangeAction, ProvisioningPlan, RuntimeDomain
from aces_contracts.runtime_state import ApplyResult, RuntimeSnapshot, SnapshotEntry
from aces_runtime.manager import RuntimeManager
from aces_runtime.registry import RuntimeTarget
from aces_sdl import SDLError, parse_sdl_file

from aptl.core.config import AptlConfig
from aptl.core.lab_types import LabResult
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

log = get_logger("aces-backend")

APTL_ACES_TARGET_NAME = "aptl"
DEFAULT_ACES_SCENARIO = Path("scenarios") / "techvault.sdl.yaml"

_SUPPORTED_RESOURCE_TYPES = frozenset(
    {
        "network",
        "node",
        "feature-binding",
        "content-placement",
        "account-placement",
    }
)
_CORE_PROFILES = frozenset({"otel"})
_IDENTIFIER_SEPARATORS = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class _AptlProvisionerCapabilities:
    """Minimal capability shape consumed by the ACES planner."""

    name: str = "aptl-docker-compose-provisioner"
    supported_node_types: frozenset[str] = frozenset({"switch", "vm"})
    supported_os_families: frozenset[str] = frozenset(
        {"freebsd", "linux", "macos", "other", "windows"}
    )
    supported_content_types: frozenset[str] = frozenset(
        {"dataset", "directory", "file"}
    )
    supported_account_features: frozenset[str] = frozenset(
        {
            "auth_method",
            "disabled",
            "groups",
            "home",
            "mail",
            "other:password_strength",
            "shell",
            "spn",
        }
    )
    max_total_nodes: int | None = None
    supports_acls: bool = True
    supports_accounts: bool = True
    constraints: Mapping[str, str] | None = None


@dataclass(frozen=True)
class _AptlBackendManifest:
    """Runtime-target manifest shape used by ``RuntimeManager``.

    The installed ACES package validates full manifests against the ACES
    contract corpus.  APTL's direct-reference dependency does not vendor that
    corpus into ``.venv/contracts``, so the runtime target uses the attributes
    consumed by ``aces_processor.planner`` and ``aces_runtime.registry`` while
    leaving full manifest conformance to the ACES package distribution.
    """

    name: str = APTL_ACES_TARGET_NAME
    version: str = "0.1.0"
    provisioner: _AptlProvisionerCapabilities = (
        _AptlProvisionerCapabilities()
    )
    orchestrator: None = None
    evaluator: None = None
    participant_runtime: None = None

    @property
    def has_orchestrator(self) -> bool:
        return False

    @property
    def has_evaluator(self) -> bool:
        return False

    @property
    def has_participant_runtime(self) -> bool:
        return False

    @property
    def evaluator_supported_sections(self) -> frozenset[str]:
        return frozenset()

    @property
    def supports_scoring(self) -> bool:
        return False

    @property
    def supports_objectives(self) -> bool:
        return False


@dataclass(frozen=True)
class _ComposeProfileIndex:
    """Compose service aliases indexed to profile names."""

    alias_to_profiles: dict[str, frozenset[str]]

    def profiles_for_aliases(self, aliases: set[str]) -> frozenset[str]:
        profiles: set[str] = set()
        for alias in aliases:
            profiles.update(self.alias_to_profiles.get(alias, frozenset()))
        return frozenset(profiles)


def create_aptl_manifest() -> _AptlBackendManifest:
    """Return the APTL provisioning-only runtime manifest."""

    return _AptlBackendManifest()


def create_aptl_runtime_target(
    *,
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
) -> RuntimeTarget:
    """Build the ACES runtime target for APTL."""

    provisioner = AptlProvisioner(
        project_dir=project_dir,
        config=config,
        deployment_backend=backend,
    )
    return RuntimeTarget(
        name=APTL_ACES_TARGET_NAME,
        manifest=create_aptl_manifest(),  # type: ignore[arg-type]
        provisioner=provisioner,  # type: ignore[arg-type]
    )


def start_aces_scenario(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None = None,
) -> LabResult:
    """Start an APTL lab by compiling and applying an ACES SDL scenario."""

    resolved_scenario = scenario_path or DEFAULT_ACES_SCENARIO
    if not resolved_scenario.is_absolute():
        resolved_scenario = project_dir / resolved_scenario
    try:
        scenario = parse_sdl_file(resolved_scenario)
        target = create_aptl_runtime_target(
            project_dir=project_dir,
            config=config,
            backend=backend,
        )
        manager = RuntimeManager(target)
        execution_plan = manager.plan(scenario)
        result = manager.apply(execution_plan)
    except (FileNotFoundError, SDLError, TypeError, ValueError) as exc:
        return LabResult(
            success=False,
            error=redact(f"ACES runtime handoff failed: {exc}"),
        )

    if result.success:
        return LabResult(
            success=True,
            message=(
                "Lab started through ACES runtime target "
                f"'{APTL_ACES_TARGET_NAME}'"
            ),
        )
    return LabResult(
        success=False,
        error=_render_aces_diagnostics(result.diagnostics),
    )


@dataclass
class AptlProvisioner:
    """Provisioning-only ACES backend adapter for APTL."""

    project_dir: Path
    config: AptlConfig
    deployment_backend: "DeploymentBackend"

    def validate(self, plan: object) -> list[Diagnostic]:
        """Validate that the ACES provisioning plan is APTL-realizable."""

        if not isinstance(plan, ProvisioningPlan):
            return [
                _diagnostic(
                    "aptl.provisioner.invalid-plan",
                    "runtime.apply.provisioning",
                    "APTL provisioner expected an ACES ProvisioningPlan.",
                )
            ]

        diagnostics: list[Diagnostic] = []
        diagnostics.extend(_unsupported_resource_diagnostics(plan))

        profiles, profile_diagnostics = self._profiles_from_plan(plan)
        diagnostics.extend(profile_diagnostics)
        configured = _configured_profiles(self.config)
        if configured and not (set(configured) & set(profiles)):
            diagnostics.append(
                _diagnostic(
                    "aptl.provisioner.no-configured-profile-matches",
                    "runtime.apply.provisioning",
                    (
                        "ACES provisioning plan did not declare any node "
                        "that maps to an enabled APTL compose profile."
                    ),
                )
            )

        return diagnostics

    def apply(self, plan: object, snapshot: object) -> ApplyResult:
        """Apply an ACES provisioning plan via APTL's deployment backend."""

        working_snapshot = (
            snapshot if isinstance(snapshot, RuntimeSnapshot) else RuntimeSnapshot()
        )
        diagnostics = self.validate(plan)
        if not isinstance(plan, ProvisioningPlan):
            return ApplyResult(
                success=False,
                snapshot=working_snapshot,
                diagnostics=diagnostics,
            )
        if _has_error(diagnostics):
            return ApplyResult(
                success=False,
                snapshot=working_snapshot,
                diagnostics=diagnostics,
            )

        profiles, profile_diagnostics = self._profiles_from_plan(plan)
        diagnostics.extend(profile_diagnostics)
        if _has_error(diagnostics):
            return ApplyResult(
                success=False,
                snapshot=working_snapshot,
                diagnostics=diagnostics,
            )

        selected_profiles = _select_backend_profiles(self.config, profiles)
        start_result = self.deployment_backend.start(selected_profiles)
        if not start_result.success:
            diagnostics.append(
                _diagnostic(
                    "aptl.provisioner.backend-start-failed",
                    "runtime.apply.provisioning",
                    start_result.error or "APTL deployment backend failed.",
                )
            )
            return ApplyResult(
                success=False,
                snapshot=working_snapshot,
                diagnostics=diagnostics,
                details={"profiles": selected_profiles},
            )

        next_snapshot = _snapshot_after_apply(plan, working_snapshot)
        changed_addresses = [
            op.address
            for op in plan.operations
            if op.action != ChangeAction.UNCHANGED
        ]
        return ApplyResult(
            success=True,
            snapshot=next_snapshot,
            diagnostics=diagnostics,
            changed_addresses=changed_addresses,
            details={"profiles": selected_profiles},
        )

    def _profiles_from_plan(
        self,
        plan: ProvisioningPlan,
    ) -> tuple[frozenset[str], list[Diagnostic]]:
        diagnostics: list[Diagnostic] = []
        try:
            profile_index = _load_compose_profile_index(self.project_dir)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            return (
                frozenset(),
                [
                    _diagnostic(
                        "aptl.provisioner.compose-profile-index-failed",
                        "runtime.apply.provisioning",
                        redact(str(exc)),
                    )
                ],
            )

        profiles: set[str] = set()
        for resource in plan.resources.values():
            if resource.resource_type != "node":
                continue
            payload = resource.payload
            profiles.update(_explicit_compose_profile_hints(payload))
            profiles.update(
                profile_index.profiles_for_aliases(
                    _node_aliases(resource.address, payload)
                )
            )

        if not profiles:
            diagnostics.append(
                _diagnostic(
                    "aptl.provisioner.profile-resolution-failed",
                    "runtime.apply.provisioning",
                    (
                        "ACES provisioning plan contained no node resources "
                        "that map to APTL compose profiles."
                    ),
                )
            )
        return frozenset(profiles), diagnostics


def _load_compose_profile_index(project_dir: Path) -> _ComposeProfileIndex:
    compose_path = project_dir / "docker-compose.yml"
    if not compose_path.exists():
        raise ValueError(f"docker-compose.yml not found under {project_dir}")
    data = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, Mapping):
        raise ValueError(f"{compose_path} must contain a YAML mapping")
    services = data.get("services") or {}
    if not isinstance(services, Mapping):
        raise ValueError(f"{compose_path} services section must be a mapping")

    alias_to_profiles: dict[str, set[str]] = {}
    for service_name, service_def in services.items():
        if not isinstance(service_def, Mapping):
            continue
        profiles = {
            str(profile)
            for profile in (service_def.get("profiles") or [])
            if str(profile).strip()
        }
        if not profiles:
            continue
        aliases = {str(service_name)}
        for alias_key in ("container_name", "hostname"):
            alias = service_def.get(alias_key)
            if isinstance(alias, str) and alias.strip():
                aliases.add(alias)
        for alias in aliases:
            for normalized in _normalized_identifier_aliases(alias):
                alias_to_profiles.setdefault(normalized, set()).update(profiles)

    return _ComposeProfileIndex(
        {
            alias: frozenset(profiles)
            for alias, profiles in alias_to_profiles.items()
        }
    )


def _normalized_identifier_aliases(raw: str) -> set[str]:
    normalized = _normalize_identifier(raw)
    if not normalized:
        return set()
    aliases = {normalized}
    if normalized.startswith("aptl-"):
        aliases.add(normalized.removeprefix("aptl-"))
    return {alias for alias in aliases if alias}


def _normalize_identifier(raw: str) -> str:
    lowered = raw.strip().lower()
    normalized = _IDENTIFIER_SEPARATORS.sub("-", lowered).strip("-")
    return normalized


def _node_aliases(address: str, payload: Mapping[str, Any]) -> set[str]:
    raw_values: set[str] = {address}
    for key in ("name", "node_name", "target_node"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            raw_values.add(value)

    spec = payload.get("spec")
    if isinstance(spec, Mapping):
        node_spec = spec.get("node")
        if isinstance(node_spec, Mapping):
            for key in ("name", "node_id", "hostname"):
                value = node_spec.get(key)
                if isinstance(value, str) and value.strip():
                    raw_values.add(value)

    aliases: set[str] = set()
    for value in raw_values:
        aliases.update(_normalized_identifier_aliases(value))
        if "." in value:
            aliases.update(_normalized_identifier_aliases(value.rsplit(".", 1)[-1]))
    return aliases


def _explicit_compose_profile_hints(payload: Mapping[str, Any]) -> frozenset[str]:
    hints: set[str] = set()
    for parent_key in ("runtime", "aptl"):
        parent = payload.get(parent_key)
        if isinstance(parent, Mapping):
            hints.update(_profile_values(parent.get("compose_profiles")))
            hints.update(_profile_values(parent.get("compose_profile")))

    spec = payload.get("spec")
    if isinstance(spec, Mapping):
        for parent_key in ("runtime", "aptl"):
            parent = spec.get(parent_key)
            if isinstance(parent, Mapping):
                hints.update(_profile_values(parent.get("compose_profiles")))
                hints.update(_profile_values(parent.get("compose_profile")))
    return frozenset(hints)


def _profile_values(raw: object) -> set[str]:
    if isinstance(raw, str):
        return {raw} if raw.strip() else set()
    if isinstance(raw, list | tuple | set | frozenset):
        return {str(value) for value in raw if str(value).strip()}
    return set()


def _configured_profiles(config: AptlConfig) -> list[str]:
    return list(config.containers.enabled_profiles())


def _select_backend_profiles(
    config: AptlConfig,
    plan_profiles: frozenset[str],
) -> list[str]:
    selected = [
        profile
        for profile in _configured_profiles(config)
        if profile in plan_profiles
    ]
    for profile in _CORE_PROFILES:
        if profile not in selected:
            selected.append(profile)
    return selected


def _unsupported_resource_diagnostics(
    plan: ProvisioningPlan,
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    seen: set[tuple[str, str]] = set()
    for resource in list(plan.resources.values()) + list(plan.operations):
        resource_type = resource.resource_type
        if resource_type in _SUPPORTED_RESOURCE_TYPES:
            continue
        key = (resource.address, resource_type)
        if key in seen:
            continue
        seen.add(key)
        diagnostics.append(
            _diagnostic(
                "aptl.provisioner.unsupported-resource-type",
                resource.address,
                (
                    "APTL provisioning target does not support ACES "
                    f"resource type '{resource_type}'."
                ),
            )
        )
    return diagnostics


def _snapshot_after_apply(
    plan: ProvisioningPlan,
    snapshot: RuntimeSnapshot,
) -> RuntimeSnapshot:
    entries = dict(snapshot.entries)
    for op in plan.operations:
        if op.action == ChangeAction.DELETE:
            entries.pop(op.address, None)
    for address, resource in plan.resources.items():
        entries[address] = SnapshotEntry(
            address=address,
            domain=RuntimeDomain.PROVISIONING,
            resource_type=resource.resource_type,
            payload=resource.payload,
            ordering_dependencies=resource.ordering_dependencies,
            refresh_dependencies=resource.refresh_dependencies,
            status="ready",
        )
    return snapshot.with_entries(entries)


def _diagnostic(code: str, address: str, message: str) -> Diagnostic:
    return Diagnostic(
        code=code,
        domain=RuntimeDomain.PROVISIONING.value,
        address=address,
        message=redact(message),
        severity=Severity.ERROR,
    )


def _has_error(diagnostics: list[Diagnostic]) -> bool:
    return any(diagnostic.is_error for diagnostic in diagnostics)


def _render_aces_diagnostics(diagnostics: list[Diagnostic]) -> str:
    if not diagnostics:
        return "ACES runtime handoff failed."
    rendered = [
        f"{diag.code} at {diag.address}: {diag.message}"
        for diag in diagnostics
        if diag.is_error
    ]
    if not rendered:
        rendered = [
            f"{diag.code} at {diag.address}: {diag.message}"
            for diag in diagnostics
        ]
    return redact("ACES runtime handoff failed: " + "; ".join(rendered[:5]))
