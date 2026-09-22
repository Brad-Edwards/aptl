"""Lower RAES runtime settings to Docker Compose service fields."""

from __future__ import annotations

_ENVIRONMENT_BOUND_CLASSIFICATIONS = frozenset({"operator_secret", "secret_fixture"})
_CONTAINER_SEQUENCE_FIELDS = ("command", "entrypoint", "dns", "group_add")
_UNSUPPORTED_CONTAINER_FIELDS = (
    "masked_paths",
    "read_only_paths",
    "publish_all_ports",
)
_MOUNT_PROPAGATION = {
    "private",
    "rprivate",
    "shared",
    "rshared",
    "slave",
    "rslave",
}


def _truthy(value: object) -> bool:
    """Return whether a ``bool | str | None`` RAES flag is enabled."""

    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() in {"true", "1", "yes"}


def _enum_value(value: object) -> str:
    """Return an enum's value or its string representation."""

    return str(getattr(value, "value", value) or "")


def _environment_config(runtime: object) -> dict[str, str]:
    """Return the declared Compose environment map."""

    environment: dict[str, str] = {}
    for variable in getattr(runtime, "environment", ()):
        name = getattr(variable, "name", "")
        if not name or getattr(variable, "value_from", None) is not None:
            continue
        classification = _enum_value(getattr(variable, "value_classification", ""))
        environment[name] = (
            f"${{{name}}}"
            if classification == "operator_secret"
            or (
                classification in _ENVIRONMENT_BOUND_CLASSIFICATIONS
                and not variable.value
            )
            else variable.value
        )
    return environment


def _policy_config(runtime: object) -> dict[str, object]:
    """Return restart and memory-limit settings from operational policy."""

    policy = getattr(runtime, "operational_policy", None)
    if policy is None:
        return {}
    config: dict[str, object] = {}
    restart = _enum_value(getattr(policy, "restart", None))
    if restart:
        config["restart"] = restart.replace("_", "-")
    limits = getattr(policy, "resource_limits", None)
    memory = getattr(limits, "memory", None) if limits is not None else None
    if memory is not None:
        config["mem_limit"] = memory
    return config


def _capability_config(runtime: object, field: str) -> list[str]:
    """Return one Docker capability list without the kernel prefix."""

    capabilities = getattr(runtime, "linux_capabilities", None)
    selected = list(getattr(capabilities, field, ()) or ()) if capabilities else []
    return [capability.removeprefix("CAP_") for capability in selected]


def _operational_config(runtime: object) -> dict[str, object]:
    """Translate declared runtime desired-state into Compose fields."""

    if runtime is None:
        return {}
    config: dict[str, object] = {}
    sections = (
        ("environment", _environment_config(runtime)),
        ("volumes", _runtime_mount_config(runtime)),
        ("cap_add", _capability_config(runtime, "add")),
        ("cap_drop", _capability_config(runtime, "drop")),
    )
    for field, value in sections:
        if value:
            config[field] = value
    config.update(_policy_config(runtime))
    config.update(_container_config(getattr(runtime, "container", None)))
    return config


def _mount_shape(mount: object) -> tuple[str, str]:
    """Validate and return one mount's kind and source."""

    kind = _enum_value(getattr(mount, "source_kind", ""))
    source = str(getattr(mount, "source", "") or "")
    if kind not in {"bind", "volume", "tmpfs"}:
        raise ValueError(
            "aptl.provisioner.runtime-materialization-unsupported: "
            f"runtime.mounts source_kind={kind or 'unspecified'} has no faithful Compose lowering."
        )
    if kind in {"bind", "volume"} and not source:
        raise ValueError(
            "aptl.provisioner.runtime-materialization-unsupported: "
            f"runtime.mounts {kind} source is unresolved."
        )
    if getattr(mount, "filesystem_type", "") or getattr(mount, "options", ()):
        raise ValueError(
            "aptl.provisioner.runtime-materialization-unsupported: "
            "runtime.mounts filesystem options have no faithful Compose lowering."
        )
    return kind, source


def _mount_propagation(mount: object, kind: str) -> dict[str, str] | None:
    """Return one validated long-form bind propagation section."""

    if "propagation" not in getattr(mount, "model_fields_set", set()):
        return None
    propagation = _enum_value(getattr(mount, "propagation", ""))
    if kind != "bind" or propagation not in _MOUNT_PROPAGATION:
        raise ValueError(
            "aptl.provisioner.runtime-materialization-unsupported: "
            "runtime.mounts propagation is not faithfully expressible."
        )
    return {"propagation": propagation}


def _lower_runtime_mount(mount: object) -> dict[str, object]:
    """Lower one faithfully supported mount to long-form Compose."""

    kind, source = _mount_shape(mount)
    item: dict[str, object] = {
        "type": kind,
        "target": mount.target,
        "read_only": _truthy(getattr(mount, "read_only", False)),
    }
    if source:
        item["source"] = source
    propagation = _mount_propagation(mount, kind)
    if propagation is not None:
        item["bind"] = propagation
    return item


def _runtime_mount_config(runtime: object) -> list[dict[str, object]]:
    """Lower supported authored runtime mounts to long-form Compose."""

    return [_lower_runtime_mount(mount) for mount in getattr(runtime, "mounts", ())]


def _unsupported_container_field(container: object) -> str | None:
    """Return the first selected container field without faithful lowering."""

    return next(
        (
            field
            for field in _UNSUPPORTED_CONTAINER_FIELDS
            if getattr(container, field, None)
        ),
        None,
    )


def _container_config(container: object) -> dict[str, object]:
    """Return the Compose fields a declared container runtime sets."""

    if container is None:
        return {}
    unsupported = _unsupported_container_field(container)
    if unsupported is not None:
        raise ValueError(
            "aptl.provisioner.runtime-materialization-unsupported: "
            f"runtime.container.{unsupported} has no faithful Compose lowering."
        )
    config = _container_scalar_config(container)
    for field in _CONTAINER_SEQUENCE_FIELDS:
        value = getattr(container, field, None)
        if value:
            config[field] = list(value)
    for section in (
        _namespace_config(container),
        _device_config(container),
        _security_config(container),
        _host_integration_config(container),
        _logging_config(container),
        _init_config(container),
    ):
        config.update(section)
    if _truthy(getattr(container, "autoremove", None)):
        config["restart"] = "no"
    return config


def _container_scalar_config(container: object) -> dict[str, object]:
    """Return directly mapped scalar container settings."""

    config: dict[str, object] = {}
    if getattr(container, "shm_size", None):
        config["shm_size"] = container.shm_size
    if _truthy(getattr(container, "privileged", None)):
        config["privileged"] = True
    if _truthy(getattr(container, "read_only_rootfs", None)):
        config["read_only"] = True
    for runtime_field, compose_field in (
        ("cgroup_parent", "cgroup_parent"),
        ("runtime_name", "runtime"),
    ):
        value = getattr(container, runtime_field, "")
        if value:
            config[compose_field] = value
    return config


def _namespace_config(container: object) -> dict[str, object]:
    """Return supported namespace modes."""

    namespaces = getattr(container, "namespaces", None)
    if namespaces is None:
        return {}
    config: dict[str, object] = {}
    for runtime_field, compose_field in (
        ("pid", "pid"),
        ("ipc", "ipc"),
        ("userns", "userns_mode"),
        ("uts", "uts"),
        ("cgroup", "cgroup"),
    ):
        value = getattr(namespaces, runtime_field, "")
        if value:
            config[compose_field] = value
    return config


def _device_config(container: object) -> dict[str, object]:
    """Return exact device mappings and cgroup rules."""

    config: dict[str, object] = {}
    devices = getattr(container, "devices", ()) or ()
    if devices:
        config["devices"] = [
            ":".join(
                part
                for part in (
                    device.host_path,
                    device.container_path,
                    device.permissions,
                )
                if part
            )
            for device in devices
        ]
    rules = getattr(container, "device_cgroup_rules", ()) or ()
    if rules:
        config["device_cgroup_rules"] = list(rules)
    return config


def _security_config(container: object) -> dict[str, object]:
    """Return the combined security-option and seccomp contract."""

    security_opt = list(getattr(container, "security_opt", ()) or ())
    seccomp = getattr(container, "seccomp_profile", "")
    if not seccomp:
        return {"security_opt": security_opt} if security_opt else {}
    seccomp_option = f"seccomp={seccomp}"
    existing = [item for item in security_opt if item.startswith("seccomp=")]
    if existing and existing != [seccomp_option]:
        raise ValueError(
            "aptl.provisioner.runtime-materialization-unsupported: "
            "runtime.container.seccomp_profile conflicts with security_opt."
        )
    if seccomp_option not in security_opt:
        security_opt.append(seccomp_option)
    return {"security_opt": security_opt}


def _host_integration_config(container: object) -> dict[str, object]:
    """Return host, DNS, and supplemental-group selections."""

    config: dict[str, object] = {}
    extra_hosts = getattr(container, "extra_hosts", ()) or ()
    if extra_hosts:
        config["extra_hosts"] = [
            f"{entry.hostname}:{entry.address}" for entry in extra_hosts
        ]
    dns_options = getattr(container, "dns_options", ()) or ()
    if dns_options:
        config["dns_opt"] = list(dns_options)
    dns_search = getattr(container, "dns_search", ()) or ()
    if dns_search:
        config["dns_search"] = list(dns_search)
    return config


def _logging_config(container: object) -> dict[str, object]:
    """Return the selected daemon log driver and options."""

    log_driver = getattr(container, "log_driver", "")
    log_options = getattr(container, "log_options", {}) or {}
    if not log_driver and not log_options:
        return {}
    logging: dict[str, object] = {}
    if log_driver:
        logging["driver"] = log_driver
    if log_options:
        logging["options"] = dict(log_options)
    return {"logging": logging}


def _init_config(container: object) -> dict[str, object]:
    """Return the standard init toggle or reject custom init semantics."""

    init_process = getattr(container, "init_process", None)
    if init_process is None:
        return {}
    unsupported = any(
        getattr(init_process, field, None)
        for field in ("implementation", "executable_path", "reaps_children", "argv")
    )
    if unsupported:
        raise ValueError(
            "aptl.provisioner.runtime-materialization-unsupported: "
            "runtime.container.init_process requires an unsupported custom init."
        )
    return {"init": True} if _truthy(getattr(init_process, "enabled", None)) else {}
