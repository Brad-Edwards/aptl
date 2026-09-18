"""Select backend-owned implementations for semantically described nodes.

An env-pack may deliberately leave realization open while still describing the
in-world product and version precisely.  This module maps those portable facts
to an APTL Docker implementation.  It never selects through a closed scope and
never writes a runtime value unless the plan carries OPEN authority for that
exact concern.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from raes.runtime_configuration import RuntimeConfiguration
from raes_contracts.planning import (
    PlannedResource,
    ProvisioningPlan,
    RealizationAuthorityMode,
)

from aptl.backends._raes_backend_implementation_profiles import (
    matching_backend_implementation_profile,
    selected_backend_base,
)
from aptl.backends._raes_backend_implementation_types import (
    BackendBaseSelection,
    BackendImplementationProfile,
)
from aptl.backends.raes_diagnostics import diagnostic
from aptl.core.deployment._cortex_service_credentials import (
    CORTEX_SERVICE_CREDENTIALS_PROFILE,
)
from aptl.core.deployment._misp_server_tls import (
    MISP_SERVER_TLS_CERTIFICATE_OUTPUT,
    MISP_SERVER_TLS_MOUNT_DESTINATION,
    MISP_SERVER_TLS_PRIVATE_KEY_OUTPUT,
    MISP_SERVER_TLS_PROFILE,
)
from aptl.core.deployment._misp_cache_credential import (
    MISP_CACHE_CONFIG_MOUNT_DESTINATION,
    MISP_CACHE_CONFIG_OUTPUT,
    MISP_CACHE_CONFIG_RELPATH,
    MISP_CACHE_CREDENTIAL_PROFILE,
    MISP_CACHE_PASSWORD_OUTPUT,
)
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactEnvironmentConsumer,
    DeploymentGeneratedArtifactOutput,
    DeploymentGeneratedArtifactRealization,
    DeploymentImageRealization,
    DeploymentStatefulConsumer,
)

if TYPE_CHECKING:
    from raes_contracts.diagnostics import Diagnostic


@dataclass(frozen=True)
class BackendNodeImplementation:
    """The implementation values APTL selected under open authority."""

    image: DeploymentImageRealization | None
    base_image_ref: str | None
    base_use_image_command: bool
    base_run_capabilities: tuple[str, ...]
    provider_kind: str
    provider_parameters: tuple[tuple[str, str], ...]
    runtime: RuntimeConfiguration
    selected_concerns: tuple[str, ...]
    generated_artifacts: tuple[DeploymentGeneratedArtifactRealization, ...] = ()


def select_backend_node_implementation(
    *,
    plan: ProvisioningPlan,
    resource: PlannedResource,
    runtime: RuntimeConfiguration | None,
    service_name: str | None,
    services: tuple[object, ...] = (),
    diagnostics: list[Diagnostic],
    component_root: Path = Path("."),
) -> BackendNodeImplementation | None:
    """Return an admitted semantic implementation, or no selection.

    A matching profile with insufficient authority is an admission error rather
    than a cue to fall back to the generic base materializer.  That fallback
    would itself choose a substrate outside the closed boundary.
    """

    profile = matching_backend_implementation_profile(runtime)
    base = selected_backend_base(runtime, services)
    selected = None
    if profile is not None or base is not None:
        selected = _admit_backend_implementation(
            plan=plan,
            resource=resource,
            runtime=runtime,
            service_name=service_name,
            match=(profile, base),
            diagnostics=diagnostics,
            component_root=component_root,
        )
    return selected


def _admit_backend_implementation(
    *,
    plan: ProvisioningPlan,
    resource: PlannedResource,
    runtime: RuntimeConfiguration | None,
    service_name: str | None,
    match: tuple[BackendImplementationProfile | None, BackendBaseSelection | None],
    diagnostics: list[Diagnostic],
    component_root: Path,
) -> BackendNodeImplementation | None:
    """Admit one matching profile/base only through its exact open concerns."""

    profile, base = match
    selected = None
    if service_name is None or not _compute_substrate_is_open(plan, resource.address):
        diagnostics.append(_implementation_not_authorized(resource.address))
    else:
        original = runtime or RuntimeConfiguration()
        payload = original.model_dump(mode="python", by_alias=True)
        additions = _runtime_additions(profile, payload)
        if not _runtime_additions_authorized(plan, resource.address, additions):
            diagnostics.append(_implementation_not_authorized(resource.address))
        else:
            additions = _resolved_authored_settings(additions, original)
            selected_runtime = _selected_runtime(payload, additions)
            if selected_runtime is None:
                diagnostics.append(_implementation_invalid(resource.address))
            else:
                selected = _implementation_result(
                    resource=resource,
                    service_name=service_name,
                    profile=profile,
                    base=base,
                    selected_runtime=selected_runtime,
                    additions=additions,
                    component_root=component_root,
                )
    return selected


def _runtime_additions(
    profile: BackendImplementationProfile | None, payload: dict[str, object]
) -> dict[str, object]:
    """Return only absent runtime values supplied by the matching profile."""

    selections = getattr(profile, "runtime_selections", {})
    return {
        concern: value
        for concern, value in selections.items()
        if _selection_is_absent(payload, concern)
    }


def _runtime_additions_authorized(
    plan: ProvisioningPlan, address: str, additions: dict[str, object]
) -> bool:
    """Return whether every backend addition has explicit OPEN authority."""

    return all(
        _runtime_concern_is_open(plan, address, concern) for concern in additions
    )


#: An environment value may name an authored application setting instead of
#: carrying a literal. The scenario then owns the value while the backend still
#: owns the binding: MISP's participant-visible URL is authored as
#: ``misp-canonical-url`` and must not be re-decided here as ``localhost``.
_SETTING_REFERENCE = "platform_application_setting"


def _resolved_authored_settings(
    additions: dict[str, object], runtime: RuntimeConfiguration
) -> dict[str, object]:
    """Replace setting-referencing environment values with their authored value.

    A reference that resolves to no authored setting is left as it is, so the
    runtime model rejects the unresolved reference rather than a silently
    invented default reaching a container.
    """

    environment = additions.get("runtime-environment")
    if not isinstance(environment, list):
        return additions
    settings = _authored_settings(runtime)
    resolved = []
    for variable in environment:
        reference = (
            variable.get("value_from", {}).get(_SETTING_REFERENCE)
            if isinstance(variable, dict)
            else None
        )
        if reference is None or reference not in settings:
            resolved.append(variable)
            continue
        replacement = {
            key: value for key, value in variable.items() if key != "value_from"
        }
        replacement["value"] = settings[reference]
        resolved.append(replacement)
    return {**additions, "runtime-environment": resolved}


def _authored_settings(runtime: RuntimeConfiguration) -> dict[str, str]:
    """Return every authored platform-application setting that carries a value."""

    return {
        str(setting.setting_id): str(setting.value)
        for application in getattr(runtime, "platform_applications", ())
        for setting in getattr(application, "settings", ())
        if str(getattr(setting, "setting_id", "")) and str(getattr(setting, "value", ""))
    }


def _selected_runtime(
    payload: dict[str, object], additions: dict[str, object]
) -> RuntimeConfiguration | None:
    """Apply selected additions and validate the resulting runtime model."""

    for concern, value in additions.items():
        _set_runtime_selection(payload, concern, value)
    try:
        return RuntimeConfiguration.model_validate(payload)
    except (TypeError, ValueError):
        return None


def _implementation_result(
    *,
    resource: PlannedResource,
    service_name: str,
    profile: BackendImplementationProfile | None,
    base: BackendBaseSelection | None,
    selected_runtime: RuntimeConfiguration,
    additions: dict[str, object],
    component_root: Path,
) -> BackendNodeImplementation:
    """Build the admitted implementation report from selected profile values."""

    return BackendNodeImplementation(
        image=_selected_image(profile, resource, service_name, component_root),
        base_image_ref=getattr(base, "image_ref", None),
        base_use_image_command=bool(getattr(base, "use_image_command", False)),
        base_run_capabilities=tuple(getattr(base, "run_capabilities", ())),
        provider_kind=str(getattr(base, "provider_kind", "")),
        provider_parameters=tuple(getattr(base, "provider_parameters", ())),
        runtime=selected_runtime,
        selected_concerns=("compute-substrate", *sorted(additions)),
        generated_artifacts=_selected_generated_artifacts(
            profile_id=str(getattr(profile, "profile_id", "")),
            resource=resource,
            service_name=service_name,
            additions=additions,
            runtime=selected_runtime,
        ),
    )


def _selected_image(
    profile: BackendImplementationProfile | None,
    resource: PlannedResource,
    service_name: str,
    component_root: Path,
) -> DeploymentImageRealization | None:
    """Build the image realization for a selected semantic profile."""

    if profile is None:
        return None
    dockerfile = profile.dockerfile_relpath
    context = profile.context_relpath
    return DeploymentImageRealization(
        address=resource.address,
        service_name=service_name,
        source_name=profile.source_name,
        source_version=profile.source_version,
        image_ref=profile.image_ref,
        mode=profile.image_mode,
        policy_rule="backend-open-profile",
        dockerfile_path=str(component_root / dockerfile) if dockerfile else None,
        context_path=str(component_root / context) if context else None,
        provenance={"backend_profile": 1},
    )


def _selected_generated_artifacts(
    *,
    profile_id: str,
    resource: PlannedResource,
    service_name: str,
    additions: dict[str, object],
    runtime: RuntimeConfiguration,
) -> tuple[DeploymentGeneratedArtifactRealization, ...]:
    """Return prerequisites introduced by an admitted backend selection.

    The TheHive profile introduces a generated-value reference only when APTL
    selects the otherwise-absent runtime environment.  Its backing credential
    artifact is therefore part of that same OPEN-authority choice.  It must not
    be inferred from the product identity alone: an authored/closed environment
    never reaches this function with ``runtime-environment`` in ``additions``.

    The MISP profile introduces its cache credential on the same condition, and
    resolves the peer that must receive the server side of it from the node's
    own authored ``upstream_bindings`` rather than from a node name.  A pack
    that binds MISP to a differently named cache therefore still works, and a
    MISP that declares no cache binding introduces no artifact at all.
    """

    artifacts: list[DeploymentGeneratedArtifactRealization] = []
    if profile_id == "thehive-5.4" and "runtime-environment" in additions:
        artifacts.append(
            DeploymentGeneratedArtifactRealization(
                address="backend.generated-artifact.cortex-service-credentials",
                name="cortex-service-credentials",
                generator="rendered_config",
                lifecycle="reuse_valid",
                provenance=CORTEX_SERVICE_CREDENTIALS_PROFILE,
                outputs=(
                    DeploymentGeneratedArtifactOutput(
                        name="initializer-api-key",
                        path="cortex/initializer-api-key",
                        sensitivity="secret",
                        disposition="producer_private",
                    ),
                    DeploymentGeneratedArtifactOutput(
                        name="connector-api-key",
                        path="cortex/connector-api-key",
                        sensitivity="secret",
                    ),
                ),
                consumers=(),
                environment_consumers=(
                    DeploymentGeneratedArtifactEnvironmentConsumer(
                        target_address=resource.address,
                        node_name=resource.address.rsplit(".", 1)[-1],
                        service_name=service_name,
                        output_name="connector-api-key",
                        environment_variable="TH_CORTEX_KEYS",
                    ),
                ),
            )
        )
    if profile_id == "misp-2.5.44" and "runtime-environment" in additions:
        artifacts.extend(
            _misp_cache_credential_artifacts(
                resource=resource, service_name=service_name, runtime=runtime
            )
        )
        artifacts.append(
            _misp_server_tls_artifact(
                resource=resource, service_name=service_name
            )
        )
    return tuple(artifacts)


#: The pack-authored certificate bundle produces the material; this delivery is
#: ordered after it so a run can never stage a stale or absent leaf.
_SOC_CERTIFICATE_ARTIFACT = "generated_artifacts.techvault-soc-certificates"


def _misp_server_tls_artifact(
    *,
    resource: PlannedResource,
    service_name: str,
) -> DeploymentGeneratedArtifactRealization:
    """Deliver the authored MISP leaf where the selected image reads it."""

    return DeploymentGeneratedArtifactRealization(
        address="backend.generated-artifact.misp-server-tls",
        name="misp-server-tls",
        generator="rendered_config",
        lifecycle="reuse_valid",
        provenance=MISP_SERVER_TLS_PROFILE,
        outputs=(
            DeploymentGeneratedArtifactOutput(
                name=MISP_SERVER_TLS_CERTIFICATE_OUTPUT,
                path="cert.pem",
                sensitivity="public",
            ),
            DeploymentGeneratedArtifactOutput(
                name=MISP_SERVER_TLS_PRIVATE_KEY_OUTPUT,
                path="key.pem",
                sensitivity="secret",
            ),
        ),
        consumers=(
            DeploymentStatefulConsumer(
                target_address=resource.address,
                node_name=resource.address.rsplit(".", 1)[-1],
                service_name=service_name,
                mount_destination=MISP_SERVER_TLS_MOUNT_DESTINATION,
                access_mode="read_only",
                selected_outputs=(
                    MISP_SERVER_TLS_CERTIFICATE_OUTPUT,
                    MISP_SERVER_TLS_PRIVATE_KEY_OUTPUT,
                ),
            ),
        ),
        ordering_dependencies=(_SOC_CERTIFICATE_ARTIFACT,),
    )


_MISP_CACHE_BINDING_ROLE = "data_source"


def _misp_cache_credential_artifacts(
    *,
    resource: PlannedResource,
    service_name: str,
    runtime: RuntimeConfiguration,
) -> list[DeploymentGeneratedArtifactRealization]:
    """Build the cache credential for MISP's one authored cache binding."""

    cache_node = _bound_cache_node(runtime)
    if cache_node is None:
        return []
    return [
        DeploymentGeneratedArtifactRealization(
            address="backend.generated-artifact.misp-cache-credential",
            name="misp-cache-credential",
            generator="rendered_config",
            lifecycle="reuse_valid",
            provenance=MISP_CACHE_CREDENTIAL_PROFILE,
            outputs=(
                # The credential reaches MISP only through environment
                # delivery, which reads the output file directly. Marking it
                # producer-private means no consumer can ever bind it into a
                # container, so the only in-container copy is the server's own
                # configuration file.
                DeploymentGeneratedArtifactOutput(
                    name=MISP_CACHE_PASSWORD_OUTPUT,
                    path="cache-password",
                    sensitivity="secret",
                    disposition="producer_private",
                ),
                DeploymentGeneratedArtifactOutput(
                    name=MISP_CACHE_CONFIG_OUTPUT,
                    path=MISP_CACHE_CONFIG_RELPATH,
                    sensitivity="secret",
                ),
            ),
            consumers=(
                DeploymentStatefulConsumer(
                    target_address=f"provision.node.{cache_node}",
                    node_name=cache_node,
                    service_name=cache_node,
                    mount_destination=MISP_CACHE_CONFIG_MOUNT_DESTINATION,
                    access_mode="read_only",
                    selected_outputs=(MISP_CACHE_CONFIG_OUTPUT,),
                ),
            ),
            environment_consumers=(
                DeploymentGeneratedArtifactEnvironmentConsumer(
                    target_address=resource.address,
                    node_name=resource.address.rsplit(".", 1)[-1],
                    service_name=service_name,
                    output_name=MISP_CACHE_PASSWORD_OUTPUT,
                    environment_variable="REDIS_PASSWORD",
                ),
            ),
        )
    ]


def _bound_cache_node(runtime: RuntimeConfiguration) -> str | None:
    """Return the single cache node MISP's authored bindings point at."""

    targets = {
        str(binding.target_node_ref)
        for application in getattr(runtime, "platform_applications", ())
        for binding in getattr(application, "upstream_bindings", ())
        if str(getattr(binding.role, "value", binding.role)) == _MISP_CACHE_BINDING_ROLE
        and str(getattr(binding, "target_service_ref", "")) == "redis"
        and str(getattr(binding, "target_node_ref", ""))
    }
    return targets.pop() if len(targets) == 1 else None


def _compute_substrate_is_open(plan: ProvisioningPlan, address: str) -> bool:
    """Return whether the node's compute substrate is explicitly open."""

    return any(
        constraint.address == address
        and constraint.concern == "compute-substrate"
        and constraint.posture == "open"
        for constraint in plan.realization_constraints
    )


def _runtime_concern_is_open(
    plan: ProvisioningPlan, address: str, concern: str
) -> bool:
    """Return whether one runtime concern grants backend selection authority."""

    return any(
        authority.address == address
        and authority.requirement_kind == concern
        and authority.mode is RealizationAuthorityMode.OPEN
        for authority in plan.realization_authority
    )


def _selection_is_absent(payload: dict[str, object], concern: str) -> bool:
    """Return whether the profile may fill the selected runtime concern."""

    value = _runtime_selection(payload, concern)
    if concern == "runtime-restart-policy":
        return value in (None, "", "unknown")
    return value in (None, "", [], {})


def _runtime_selection(payload: dict[str, object], concern: str) -> object:
    """Read one supported selection concern from a runtime payload."""

    paths = {
        "runtime-environment": ("environment",),
        "published-ports": ("network", "published_ports"),
        "linux-capabilities": ("linux_capabilities",),
        "runtime-container-entrypoint": ("container", "entrypoint"),
        "runtime-container-command": ("container", "command"),
        "runtime-restart-policy": ("operational_policy", "restart"),
        "runtime-node-memory-limit": (
            "operational_policy",
            "resource_limits",
            "memory",
        ),
    }
    try:
        return _nested(payload, *paths[concern])
    except KeyError as exc:
        raise ValueError(
            f"Unsupported backend runtime selection concern: {concern}"
        ) from exc


def _nested(payload: dict[str, object], *path: str) -> object:
    """Read a nested mapping value, returning None through absent structure."""

    current: object = payload
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _set_runtime_selection(
    payload: dict[str, object], concern: str, value: object
) -> None:
    """Set one supported profile concern in the copied runtime payload."""

    selected = deepcopy(value)
    paths = {
        "runtime-environment": ("environment",),
        "published-ports": ("network", "published_ports"),
        "linux-capabilities": ("linux_capabilities",),
        "runtime-container-entrypoint": ("container", "entrypoint"),
        "runtime-container-command": ("container", "command"),
        "runtime-restart-policy": ("operational_policy", "restart"),
        "runtime-node-memory-limit": (
            "operational_policy",
            "resource_limits",
            "memory",
        ),
    }
    try:
        _set_nested(payload, paths[concern], selected)
    except KeyError as exc:
        raise ValueError(
            f"Unsupported backend runtime selection concern: {concern}"
        ) from exc


def _set_nested(
    payload: dict[str, object], path: tuple[str, ...], value: object
) -> None:
    """Create intermediate mappings and assign one copied runtime value."""

    current = payload
    for key in path[:-1]:
        child = current.get(key)
        if not isinstance(child, dict):
            child = {}
            current[key] = child
        current = child
    current[path[-1]] = value


def _implementation_not_authorized(address: str) -> Diagnostic:
    """Build the bounded diagnostic for a selection outside open authority."""

    return diagnostic(
        "aptl.provisioner.backend-implementation-not-authorized",
        address,
        "The matching backend implementation requires a realization choice that is not open.",
    )


def _implementation_invalid(address: str) -> Diagnostic:
    """Build the bounded diagnostic for an invalid selected runtime."""

    return diagnostic(
        "aptl.provisioner.backend-implementation-invalid",
        address,
        "The selected backend implementation does not form a valid runtime configuration.",
    )


__all__ = (
    "BackendNodeImplementation",
    "select_backend_node_implementation",
)
