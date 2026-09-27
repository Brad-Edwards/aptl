"""Native readback for RAES container-runtime fields."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from raes.runtime_configuration import RuntimeConfiguration

from aptl.backends._runtime_concern_disclosure import _disclose

CONTAINER_DAEMON_FIELDS = {
    "cgroup_parent": "runtime-container-cgroup-parent",
    "device_cgroup_rules": "runtime-container-device-cgroup-rules",
    "devices": "runtime-container-devices",
    "dns": "runtime-container-dns",
    "dns_options": "runtime-container-dns-options",
    "dns_search": "runtime-container-dns-search",
    "extra_hosts": "runtime-container-extra-hosts",
    "group_add": "runtime-container-group-add",
    "init_process": "runtime-container-init-process",
    "log_driver": "runtime-container-log-driver",
    "log_options": "runtime-container-log-options",
    "namespaces": "runtime-container-namespaces",
    "privileged": "runtime-container-privileged",
    "read_only_rootfs": "runtime-container-read-only-rootfs",
    "runtime_name": "runtime-container-runtime-name",
    "seccomp_profile": "runtime-container-seccomp-profile",
    "security_opt": "runtime-container-security-opt",
    "shm_size": "runtime-container-shm-size",
}
RUNTIME_CONTAINER_DAEMON_CONCERNS = frozenset(CONTAINER_DAEMON_FIELDS.values())


def _host_config(info: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return daemon HostConfig metadata as a mapping."""

    value = info.get("HostConfig")
    return value if isinstance(value, Mapping) else {}


def _json_value(value: object) -> object:
    """Return the portable JSON value carried by a RAES model field."""

    if hasattr(value, "model_dump"):
        result = value.model_dump(mode="json", by_alias=True)
    elif isinstance(value, tuple):
        result = list(value)
    elif isinstance(value, list):
        result = [
            item.model_dump(mode="json", by_alias=True)
            if hasattr(item, "model_dump")
            else item
            for item in value
        ]
    else:
        result = value
    return result


def _truthy(value: object) -> bool:
    """Normalize RAES bool-or-string runtime flags."""

    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() in {"true", "1", "yes"}


def _field_was_selected(container: object, field: str) -> bool:
    """Retain explicit empty or false closed-scope selections."""

    return field in getattr(container, "model_fields_set", set())


def observe_container_field(
    info: Mapping[str, Any],
    runtime: RuntimeConfiguration,
    *,
    field: str,
    concern_kind: str,
) -> object | None:
    """Disclose one authored container field after daemon corroboration."""

    container = runtime.container
    if container is None or not _field_was_selected(container, field):
        return None
    declared = getattr(container, field)
    corroborated = _container_field_matches(
        _host_config(info), container, field, declared
    )
    return _disclose(concern_kind, _json_value(declared)) if corroborated else None


def _container_field_matches(
    host: Mapping[str, Any],
    container: object,
    field: str,
    declared: object,
) -> bool:
    """Compare one supported RAES container field with native HostConfig."""

    direct = _direct_container_field_match(host, field, declared)
    if direct is not None:
        return direct
    handlers: dict[str, Callable[[Mapping[str, Any], object, object], bool]] = {
        "devices": _devices_match,
        "extra_hosts": _extra_hosts_match,
        "namespaces": _namespaces_match,
        "seccomp_profile": _security_options_match,
        "security_opt": _security_options_match,
        "log_driver": _log_driver_matches,
        "log_options": _log_options_match,
        "init_process": _init_process_matches,
    }
    handler = handlers.get(field)
    return handler(host, container, declared) if handler is not None else False


def _direct_container_field_match(
    host: Mapping[str, Any], field: str, declared: object
) -> bool | None:
    """Match scalar and list fields with direct HostConfig counterparts."""

    direct_fields = {
        "privileged": "Privileged",
        "read_only_rootfs": "ReadonlyRootfs",
        "shm_size": "ShmSize",
        "cgroup_parent": "CgroupParent",
        "runtime_name": "Runtime",
        "device_cgroup_rules": "DeviceCgroupRules",
        "group_add": "GroupAdd",
        "dns": "Dns",
        "dns_options": "DnsOptions",
        "dns_search": "DnsSearch",
    }
    native_field = direct_fields.get(field)
    if native_field is None:
        return None
    if field in {"privileged", "read_only_rootfs"}:
        expected = _truthy(declared)
    elif field in {
        "device_cgroup_rules",
        "group_add",
        "dns",
        "dns_options",
        "dns_search",
    }:
        expected = list(declared or ())
    else:
        expected = declared
    return host.get(native_field) == expected


def _devices_match(
    host: Mapping[str, Any], container: object, declared: object
) -> bool:
    """Compare exact device mappings."""

    del container
    expected = [
        {
            "PathOnHost": item.host_path,
            "PathInContainer": item.container_path,
            "CgroupPermissions": item.permissions,
        }
        for item in declared or ()
    ]
    return host.get("Devices") == expected


def _extra_hosts_match(
    host: Mapping[str, Any], container: object, declared: object
) -> bool:
    """Compare exact extra-host entries."""

    del container
    expected = [f"{item.hostname}:{item.address}" for item in declared or ()]
    return host.get("ExtraHosts") == expected


def _namespaces_match(
    host: Mapping[str, Any], container: object, declared: object
) -> bool:
    """Compare supported namespace modes without accepting network joins."""

    del container
    if getattr(declared, "network", None) is not None:
        return False
    pairs = (
        ("pid", "PidMode"),
        ("ipc", "IpcMode"),
        ("userns", "UsernsMode"),
        ("uts", "UTSMode"),
        ("cgroup", "CgroupnsMode"),
    )
    return all(
        not (expected := getattr(declared, runtime_field, ""))
        or host.get(native_field) == expected
        for runtime_field, native_field in pairs
    )


def _security_options_match(
    host: Mapping[str, Any], container: object, declared: object
) -> bool:
    """Compare exact security options plus Docker's privileged label effect."""

    del declared
    expected = set(getattr(container, "security_opt", ()) or ())
    seccomp = getattr(container, "seccomp_profile", "")
    if seccomp:
        expected.add(f"seccomp={seccomp}")
    native = host.get("SecurityOpt")
    if not isinstance(native, list) or not all(
        isinstance(item, str) for item in native
    ):
        return False
    allowed = set(expected)
    if _truthy(getattr(container, "privileged", None)):
        allowed.add("label=disable")
    return expected <= set(native) <= allowed


def _log_driver_matches(
    host: Mapping[str, Any], container: object, declared: object
) -> bool:
    """Compare the native log-driver identity."""

    del container
    config = host.get("LogConfig")
    return isinstance(config, Mapping) and config.get("Type") == declared


def _log_options_match(
    host: Mapping[str, Any], container: object, declared: object
) -> bool:
    """Compare the native log-driver options."""

    del container
    config = host.get("LogConfig")
    return isinstance(config, Mapping) and config.get("Config") == dict(declared or {})


def _init_process_matches(
    host: Mapping[str, Any], container: object, declared: object
) -> bool:
    """Compare the standard init toggle."""

    del container
    return host.get("Init") is _truthy(getattr(declared, "enabled", None))
