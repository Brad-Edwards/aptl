"""Qualify authored runtime fields before any deployment mutation."""

from __future__ import annotations

from aptl.core.deployment._runtime_materialization_types import (
    RuntimeMaterializationIssue,
    RuntimeMaterializationProfile,
    materialization_issue,
)
from aptl.core.deployment.realization import DeploymentRealizationSpec
_COMPOSE_FIELDS = frozenset(
    {
        "entrypoint",
        "command",
        "log_driver",
        "log_options",
        "namespaces",
        "privileged",
        "read_only_rootfs",
        "autoremove",
        "shm_size",
        "cgroup_parent",
        "runtime_name",
        "devices",
        "device_cgroup_rules",
        "seccomp_profile",
        "security_opt",
        "extra_hosts",
        "dns",
        "dns_options",
        "dns_search",
        "group_add",
        "init_process",
    }
)
_COMPOSE_UNSUPPORTED_FIELDS = frozenset(
    {"masked_paths", "read_only_paths", "publish_all_ports"}
)
def _present(value: object) -> bool:
    """Whether a runtime value selects material state rather than omission."""

    if value is None:
        result = False
    elif isinstance(value, str):
        result = bool(value.strip())
    elif isinstance(value, bool):
        result = value
    else:
        normalized = (
            value.model_dump(exclude_defaults=True)
            if hasattr(value, "model_dump")
            else value
        )
        try:
            result = bool(normalized)
        except TypeError:
            result = True
    return result


def _container_fields(runtime: object) -> dict[str, object]:
    """Return explicitly material container selections."""

    container = getattr(runtime, "container", None)
    if container is None:
        return {}
    return {
        name: getattr(container, name, None)
        for name in container.__class__.model_fields
        if name != "description" and _present(getattr(container, name, None))
    }


def _capabilities_selected(capabilities: object | None) -> bool:
    """Whether any capability dimension is materially selected."""

    return bool(
        capabilities is not None
        and any(
            getattr(capabilities, name, ())
            for name in (
                "add",
                "drop",
                "required",
                "effective",
                "process_overrides",
            )
        )
    )


def _generic_container_issue(
    address: str,
    fields: dict[str, object],
    capabilities: object | None,
    image_backed: bool,
    profile: RuntimeMaterializationProfile,
) -> RuntimeMaterializationIssue | None:
    """Reject image-only settings on the generic substrate."""

    if image_backed or (not fields and not _capabilities_selected(capabilities)):
        return None
    selected = next(iter(fields), "linux_capabilities")
    field = (
        "runtime.linux_capabilities"
        if selected == "linux_capabilities"
        else f"runtime.container.{selected}"
    )
    return materialization_issue(
        address,
        field,
        profile,
        "generic substrate does not faithfully lower this field",
    )


def _capability_issue(
    address: str,
    capabilities: object | None,
    profile: RuntimeMaterializationProfile,
) -> RuntimeMaterializationIssue | None:
    """Reject capability dimensions Compose cannot faithfully lower."""

    unsupported = next(
        (
            name
            for name in ("required", "effective", "process_overrides")
            if capabilities is not None and _present(getattr(capabilities, name, None))
        ),
        None,
    )
    if unsupported is None:
        return None
    return materialization_issue(
        address,
        f"runtime.linux_capabilities.{unsupported}",
        profile,
        "selected backend has no faithful lowering for this capability dimension",
    )


def _namespace_issue(
    address: str,
    runtime: object,
    profile: RuntimeMaterializationProfile,
) -> RuntimeMaterializationIssue | None:
    """Reject namespace joins the backend cannot independently read back."""

    namespaces = getattr(getattr(runtime, "container", None), "namespaces", None)
    if namespaces is None or getattr(namespaces, "network", None) is None:
        return None
    return materialization_issue(
        address,
        "runtime.container.namespaces.network",
        profile,
        "selected backend cannot independently read back the joined network namespace owner",
    )


def _custom_init_issue(
    address: str,
    runtime: object,
    profile: RuntimeMaterializationProfile,
) -> RuntimeMaterializationIssue | None:
    """Reject custom init semantics while allowing the standard toggle."""

    init_process = getattr(getattr(runtime, "container", None), "init_process", None)
    selected = init_process is not None and any(
        _present(getattr(init_process, name, None))
        for name in ("implementation", "executable_path", "reaps_children", "argv")
    )
    if not selected:
        return None
    return materialization_issue(
        address,
        "runtime.container.init_process",
        profile,
        "selected backend supports the standard init toggle but not a custom init contract",
    )


def _unsupported_container_issue(
    address: str,
    fields: dict[str, object],
    profile: RuntimeMaterializationProfile,
) -> RuntimeMaterializationIssue | None:
    """Reject known or unknown fields without faithful lowering."""

    unsupported = next(
        (name for name in fields if name in _COMPOSE_UNSUPPORTED_FIELDS), None
    )
    unknown = next((name for name in fields if name not in _COMPOSE_FIELDS), None)
    selected = unsupported or unknown
    if selected is None:
        return None
    limitation = (
        "Docker Compose has no faithful lowering for this field"
        if unsupported is not None
        else "selected backend has no faithful lowering for this field"
    )
    return materialization_issue(
        address,
        f"runtime.container.{selected}",
        profile,
        limitation,
    )


def _container_issues(
    node: object,
    *,
    image_backed: bool,
    profile: RuntimeMaterializationProfile,
) -> list[RuntimeMaterializationIssue]:
    """Return the first unsupported container selection for one node."""

    runtime = getattr(node, "runtime", None)
    if runtime is None:
        return []
    address = str(getattr(node, "address", ""))
    fields = _container_fields(runtime)
    capabilities = getattr(runtime, "linux_capabilities", None)
    issue = next(
        (
            candidate
            for candidate in (
                _generic_container_issue(
                    address, fields, capabilities, image_backed, profile
                ),
                _capability_issue(address, capabilities, profile),
                _namespace_issue(address, runtime, profile),
                _custom_init_issue(address, runtime, profile),
                _unsupported_container_issue(address, fields, profile),
            )
            if candidate is not None
        ),
        None,
    )
    return [issue] if issue is not None else []


def _enum_value(value: object) -> str:
    """Return an enum's value or its string representation."""

    return str(getattr(value, "value", value) or "")


def _mount_shape_issue(
    address: str,
    field: str,
    mount: object,
    *,
    image_backed: bool,
    profile: RuntimeMaterializationProfile,
) -> RuntimeMaterializationIssue | None:
    """Reject mount kinds and options without faithful lowering."""

    kind = _enum_value(getattr(mount, "source_kind", ""))
    source = str(getattr(mount, "source", "") or "")
    limitation = None
    if not image_backed and kind != "volume":
        limitation = "generic substrate faithfully lowers named volumes only"
    elif kind not in {"bind", "volume", "tmpfs"}:
        limitation = (
            f"selected backend has no faithful {kind or 'unspecified'} mount lowering"
        )
    elif kind in {"bind", "volume"} and not source:
        limitation = f"{kind} source requires an operator-resolvable concrete value"
    elif getattr(mount, "filesystem_type", "") or getattr(mount, "options", ()):
        limitation = "selected backend cannot faithfully lower mount filesystem options"
    return (
        materialization_issue(address, field, profile, limitation)
        if limitation is not None
        else None
    )


def _mount_propagation_issue(
    address: str,
    field: str,
    mount: object,
    profile: RuntimeMaterializationProfile,
) -> RuntimeMaterializationIssue | None:
    """Reject propagation outside Docker Compose's bind vocabulary."""

    kind = _enum_value(getattr(mount, "source_kind", ""))
    fields_set = getattr(mount, "model_fields_set", set())
    if "propagation" not in fields_set:
        return None
    propagation = _enum_value(getattr(mount, "propagation", ""))
    supported = kind == "bind" and propagation in {
        "private",
        "rprivate",
        "shared",
        "rshared",
        "slave",
        "rslave",
    }
    if supported:
        return None
    return materialization_issue(
        address,
        field,
        profile,
        "mount propagation is not faithfully expressible for this mount",
    )


def _mount_issue(
    node: object,
    index: int,
    mount: object,
    *,
    image_backed: bool,
    profile: RuntimeMaterializationProfile,
) -> RuntimeMaterializationIssue | None:
    """Return the first unsupported property of one authored mount."""

    address = str(getattr(node, "address", ""))
    field = f"runtime.mounts[{index}]"
    return next(
        (
            candidate
            for candidate in (
                _mount_shape_issue(
                    address,
                    field,
                    mount,
                    image_backed=image_backed,
                    profile=profile,
                ),
                _mount_propagation_issue(address, field, mount, profile),
            )
            if candidate is not None
        ),
        None,
    )


def _mount_issues(
    node: object,
    *,
    image_backed: bool,
    profile: RuntimeMaterializationProfile,
) -> list[RuntimeMaterializationIssue]:
    """Return every unsupported mount on one node."""

    runtime = getattr(node, "runtime", None)
    mounts = getattr(runtime, "mounts", ()) if runtime is not None else ()
    return [
        issue
        for index, mount in enumerate(mounts)
        if (
            issue := _mount_issue(
                node,
                index,
                mount,
                image_backed=image_backed,
                profile=profile,
            )
        )
        is not None
    ]


def qualify_runtime_materialization(
    realization: DeploymentRealizationSpec,
    *,
    profile: RuntimeMaterializationProfile,
) -> tuple[RuntimeMaterializationIssue, ...]:
    """Qualify the complete graph without mutating deployment state."""

    imaged = {image.address for image in realization.images}
    issues = [
        issue
        for node in realization.nodes
        for issue in _container_issues(
            node,
            image_backed=node.address in imaged,
            profile=profile,
        )
    ]
    issues.extend(
        issue
        for node in realization.nodes
        for issue in _mount_issues(
            node,
            image_backed=node.address in imaged,
            profile=profile,
        )
    )
    return tuple(issues)
