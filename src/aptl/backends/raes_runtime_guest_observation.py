"""Guest readback for materialized RAES runtime inventory concerns.

These observers execute bounded, non-shell queries inside the realized node.
They disclose a declared inventory only when every requested fact is
corroborated.  Unsupported detail or an inconclusive query returns no value so
RAES rejects the exact requirement instead of accepting planned state as proof.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from raes.runtime_configuration import RuntimeConfiguration

from aptl.backends._runtime_concern_disclosure import _disclose
from aptl.backends.raes_package_managers import manifest_query_argv

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

_PROCESS_LIMITS_PATH = "/proc/1/limits"
_PROCESS_LIMITS_MAX_BYTES = 16 * 1024
_PROCESS_LIMIT_LABELS = {
    "Max open files": "open_file_descriptors",
    "Max locked memory": "locked_memory_bytes",
}
_DEPENDENCY_MANIFEST_MAX_BYTES = 1024 * 1024


def observe_local_identity(
    backend: "DeploymentBackend",
    container_name: str,
    runtime: RuntimeConfiguration,
) -> object | None:
    """Corroborate local users, primary groups, and supplemental groups."""

    inventory = runtime.local_identity
    if inventory is None:
        return None
    for group in inventory.groups:
        row = _exec_stdout(backend, container_name, ["getent", "group", group.name])
        fields = row.strip().split(":") if row is not None else []
        if len(fields) != 4 or fields[0] != group.name:
            return None
        if group.gid is not None and fields[2] != str(group.gid):
            return None
        declared_members = set(group.members)
        observed_members = {item for item in fields[3].split(",") if item}
        if declared_members != observed_members:
            return None
    for user in inventory.users:
        row = _exec_stdout(
            backend,
            container_name,
            ["getent", "passwd", user.username],
        )
        fields = row.strip().split(":") if row is not None else []
        if len(fields) != 7 or fields[0] != user.username:
            return None
        if user.uid is not None and fields[2] != str(user.uid):
            return None
        if user.gecos and fields[4] != user.gecos:
            return None
        if user.home and fields[5] != user.home:
            return None
        if user.shell and fields[6] != user.shell:
            return None
        primary = _exec_stdout(
            backend,
            container_name,
            ["id", "-gn", user.username],
        )
        if primary is None or primary.strip() != user.primary_group:
            return None
        groups = _exec_stdout(
            backend,
            container_name,
            ["id", "-Gn", user.username],
        )
        expected_groups = {user.primary_group, *user.supplemental_groups}
        if groups is None or set(groups.split()) != expected_groups:
            return None
    return _disclose(
        "runtime-local-identity",
        inventory.model_dump(mode="json", by_alias=True),
    )


def observe_dependency_manifests(
    backend: "DeploymentBackend",
    container_name: str,
    runtime: RuntimeConfiguration,
) -> object | None:
    """Corroborate each manifest file and the package it installed."""

    manifests = tuple(runtime.dependency_manifests)
    if not manifests:
        return None
    for manifest in manifests:
        if not manifest.name:
            return None
        payload = backend.container_file_read(
            container_name,
            manifest.path,
            max_bytes=_DEPENDENCY_MANIFEST_MAX_BYTES,
        )
        if not payload:
            return None
        command = manifest_query_argv(manifest.ecosystem, manifest.name)
        if not _exec_ok(backend, container_name, command):
            return None
    return _disclose(
        "runtime-dependency-manifests",
        [item.model_dump(mode="json", by_alias=True) for item in manifests],
    )


def observe_packages(
    backend: "DeploymentBackend",
    container_name: str,
    runtime: RuntimeConfiguration,
) -> object | None:
    """Corroborate declared package identity, version, and architecture."""

    packages = tuple(runtime.packages)
    if not packages or any(
        package.source or package.purl or package.repository is not None
        for package in packages
    ):
        return None
    observed: dict[tuple[str, str], tuple[str, str]] = {}
    by_manager: dict[str, list[object]] = {}
    for package in packages:
        by_manager.setdefault(package.manager, []).append(package)
    for manager, selected in sorted(by_manager.items()):
        rows = _query_packages(
            backend,
            container_name,
            manager,
            tuple(sorted(package.name for package in selected)),
        )
        if rows is None:
            return None
        observed.update({(manager, name): value for name, value in rows.items()})
    for package in packages:
        installed = observed.get((package.manager, package.name))
        if installed is None:
            return None
        version, architecture = installed
        if package.version != "*" and package.version != version:
            return None
        if package.architecture and not _architecture_matches(
            package.architecture, architecture
        ):
            return None
    return _disclose(
        "runtime-packages",
        [package.model_dump(mode="json", by_alias=True) for package in packages],
    )


def observe_process_resource_limits(
    backend: "DeploymentBackend",
    container_name: str,
    runtime: RuntimeConfiguration,
) -> object | None:
    """Read the effective PID-1 limits that Compose applies to its subtree.

    APTL's image-backed substrate selects ``nofile`` and ``memlock`` defaults
    even when the open SDL leaves the collection empty.  Reading procfs through
    the provider avoids a workload-controlled executable while still observes
    the effective guest values.  Both selected dimensions must be present.
    """

    policy = runtime.operational_policy
    limits = policy.resource_limits if policy is not None else None
    if limits is not None and limits.process_limits:
        # Authored process subjects require a dedicated subject resolver.  Do
        # not pretend PID 1 proves an arbitrary authored process selection.
        return None
    payload = backend.container_file_read(
        container_name,
        _PROCESS_LIMITS_PATH,
        max_bytes=_PROCESS_LIMITS_MAX_BYTES,
    )
    observed = _parse_process_limits(payload)
    if observed.keys() != set(_PROCESS_LIMIT_LABELS.values()):
        return None
    records = [
        {
            "resource": resource,
            "soft": observed[resource][0],
            "hard": observed[resource][1],
            "subject": {"name": "container"},
            "scope": "subtree",
        }
        for resource in sorted(observed)
    ]
    return _disclose("process-resource-limits", records)


def _parse_process_limits(
    payload: bytes | None,
) -> dict[str, tuple[int | str, int | str]]:
    if payload is None:
        return {}
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return {}
    observed: dict[str, tuple[int | str, int | str]] = {}
    for line in text.splitlines():
        for label, resource in _PROCESS_LIMIT_LABELS.items():
            if not line.startswith(label):
                continue
            columns = line[len(label) :].split()
            if len(columns) != 3:
                return {}
            soft = _limit_value(columns[0])
            hard = _limit_value(columns[1])
            if soft is None or hard is None:
                return {}
            observed[resource] = (soft, hard)
    return observed


def _limit_value(value: str) -> int | str | None:
    if value == "unlimited":
        return value
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _query_packages(
    backend: "DeploymentBackend",
    container_name: str,
    manager: str,
    names: tuple[str, ...],
) -> dict[str, tuple[str, str]] | None:
    if manager == "apt":
        command = [
            "dpkg-query",
            "-W",
            "-f=${Package}\\t${Version}\\t${Architecture}\\n",
            *names,
        ]
        result = backend.container_exec(container_name, command, timeout=30)
        return _tabular_packages(result, fields=3)
    if manager in {"dnf", "yum"}:
        command = [
            "rpm",
            "-q",
            "--qf",
            "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n",
            *names,
        ]
        result = backend.container_exec(container_name, command, timeout=30)
        return _tabular_packages(result, fields=3)
    if manager == "pip":
        result = backend.container_exec(container_name, ["pip", "freeze"], timeout=30)
        if getattr(result, "returncode", 1) != 0:
            return None
        rows: dict[str, tuple[str, str]] = {}
        for line in _stdout(result).splitlines():
            name, separator, version = line.strip().partition("==")
            if separator and name and version:
                rows[name] = (version, "")
        return rows
    return None


def _tabular_packages(
    result: object, *, fields: int
) -> dict[str, tuple[str, str]] | None:
    if getattr(result, "returncode", 1) != 0:
        return None
    rows: dict[str, tuple[str, str]] = {}
    for line in _stdout(result).splitlines():
        columns = line.split("\t")
        if len(columns) != fields or not all(columns):
            return None
        name, version, architecture = columns
        rows[name] = (version, architecture)
    return rows


def _architecture_matches(declared: object, observed: str) -> bool:
    aliases = {
        "amd64": "x86_64",
        "x86-64": "x86_64",
        "aarch64": "arm64",
    }
    declared_text = str(getattr(declared, "value", declared)).casefold()
    observed_text = observed.casefold()
    return aliases.get(declared_text, declared_text) == aliases.get(
        observed_text, observed_text
    )


def observe_filesystem_inventory(
    backend: "DeploymentBackend",
    container_name: str,
    runtime: RuntimeConfiguration,
) -> object | None:
    """Corroborate bounded path presence and entry types inside the guest."""

    entries = tuple(runtime.filesystem_inventory)
    if not entries:
        return None
    for entry in entries:
        if not _filesystem_shape_supported(entry):
            return None
        presence = _value(entry.presence)
        if presence == "expected_absent":
            absent = _exec_ok(
                backend, container_name, ["test", "!", "-e", entry.path]
            ) and _exec_ok(backend, container_name, ["test", "!", "-L", entry.path])
            if not absent:
                return None
            continue
        flag = {
            "file": "-f",
            "directory": "-d",
            "symlink": "-L",
            "socket": "-S",
            "fifo": "-p",
        }.get(_value(entry.entry_type))
        if presence != "present" or flag is None:
            return None
        if not _exec_ok(backend, container_name, ["test", flag, entry.path]):
            return None
    return _disclose(
        "runtime-filesystem-inventory",
        [entry.model_dump(mode="json", by_alias=True) for entry in entries],
    )


def _filesystem_shape_supported(entry: object) -> bool:
    unsupported_values = (
        getattr(entry, "owner_user", ""),
        getattr(entry, "owner_group", ""),
        getattr(entry, "uid", None),
        getattr(entry, "gid", None),
        getattr(entry, "mode", ""),
        getattr(entry, "size", None),
        getattr(entry, "content_digest", ""),
        getattr(entry, "digest_algorithm", ""),
        getattr(entry, "source_path", ""),
        getattr(entry, "provenance", ""),
    )
    return not any(value not in ("", None) for value in unsupported_values) and (
        _value(getattr(entry, "stability", "unknown")) == "unknown"
        and _value(getattr(entry, "sensitivity", "unknown")) == "unknown"
    )


def observe_service_manager_units(
    backend: "DeploymentBackend",
    container_name: str,
    runtime: RuntimeConfiguration,
) -> object | None:
    """Corroborate declared systemd unit presence, enablement, and activity."""

    units = tuple(runtime.service_manager_units)
    if not units:
        return None
    for unit in units:
        if not _service_unit_shape_supported(unit):
            return None
        load_state = _exec_value(
            backend,
            container_name,
            ["systemctl", "show", "--property=LoadState", "--value", unit.unit_name],
        )
        if load_state in {None, "", "not-found", "error"}:
            return None
        declared_load = _value(unit.load_state).replace("_", "-")
        if declared_load != "unknown" and declared_load != load_state:
            return None
        enabled = _exec_value(
            backend, container_name, ["systemctl", "is-enabled", unit.unit_name]
        )
        declared_enabled = _value(unit.enabled_state).replace("_", "-")
        if declared_enabled != "unknown" and declared_enabled != enabled:
            return None
        active = _exec_value(
            backend, container_name, ["systemctl", "is-active", unit.unit_name]
        )
        declared_active = _value(unit.active_state).replace("_", "-")
        if declared_active != "unknown" and declared_active != active:
            return None
    return _disclose(
        "runtime-service-manager-units",
        [unit.model_dump(mode="json", by_alias=True) for unit in units],
    )


def _service_unit_shape_supported(unit: object) -> bool:
    return (
        _value(getattr(unit, "manager_kind", "unknown")) == "systemd"
        and _value(getattr(unit, "unit_type", "other")) in {"other", "unknown"}
        and not getattr(unit, "unit_file_path", "")
        and getattr(unit, "exec_start", None) is None
        and not getattr(unit, "service", "")
    )


def _exec_ok(
    backend: "DeploymentBackend", container_name: str, command: list[str]
) -> bool:
    return (
        getattr(
            backend.container_exec(container_name, command, timeout=30),
            "returncode",
            1,
        )
        == 0
    )


def _exec_stdout(
    backend: "DeploymentBackend", container_name: str, command: list[str]
) -> str | None:
    result = backend.container_exec(container_name, command, timeout=30)
    if getattr(result, "returncode", 1) != 0:
        return None
    return _stdout(result)


def _exec_value(
    backend: "DeploymentBackend", container_name: str, command: list[str]
) -> str | None:
    result = backend.container_exec(container_name, command, timeout=30)
    value = _stdout(result).strip().casefold().replace("_", "-")
    return value or None


def _stdout(result: object) -> str:
    value = getattr(result, "stdout", "")
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="strict")
    return value if isinstance(value, str) else ""


def _value(value: object) -> str:
    return str(getattr(value, "value", value)).casefold()


__all__ = [
    "observe_dependency_manifests",
    "observe_filesystem_inventory",
    "observe_local_identity",
    "observe_packages",
    "observe_process_resource_limits",
    "observe_service_manager_units",
]
