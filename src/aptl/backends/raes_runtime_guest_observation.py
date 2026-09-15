"""Guest readback for materialized RAES runtime inventory concerns.

These observers execute bounded, non-shell queries inside the realized node.
They disclose a declared inventory only when every requested fact is
corroborated.  Unsupported detail or an inconclusive query returns no value so
RAES rejects the exact requirement instead of accepting planned state as proof.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from raes.runtime_configuration import RuntimeConfiguration

from aptl.backends._runtime_concern_disclosure import _disclose
from aptl.backends._raes_guest_package_observation import observe_packages
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
    if not all(
        _group_matches(backend, container_name, group) for group in inventory.groups
    ) or not all(
        _user_matches(backend, container_name, user) for user in inventory.users
    ):
        return None
    return _disclose(
        "runtime-local-identity",
        inventory.model_dump(mode="json", by_alias=True),
    )


def _group_matches(
    backend: "DeploymentBackend", container_name: str, group: object
) -> bool:
    """Return whether guest group identity and membership match exactly."""

    name = getattr(group, "name", "")
    row = _exec_stdout(backend, container_name, ["getent", "group", name])
    fields = row.strip().split(":") if row is not None else []
    declared_gid = getattr(group, "gid", None)
    declared_members = set(getattr(group, "members", ()))
    return bool(
        len(fields) == 4
        and fields[0] == name
        and (declared_gid is None or fields[2] == str(declared_gid))
        and {item for item in fields[3].split(",") if item} == declared_members
    )


def _user_matches(
    backend: "DeploymentBackend", container_name: str, user: object
) -> bool:
    """Return whether guest passwd and group records match one user."""

    username = getattr(user, "username", "")
    row = _exec_stdout(backend, container_name, ["getent", "passwd", username])
    fields = row.strip().split(":") if row is not None else []
    if len(fields) != 7 or fields[0] != username:
        return False
    uid = getattr(user, "uid", None)
    field_values_match = (
        (uid is None or fields[2] == str(uid))
        and (not user.gecos or fields[4] == user.gecos)
        and (not user.home or fields[5] == user.home)
        and (not user.shell or fields[6] == user.shell)
    )
    primary = _exec_stdout(backend, container_name, ["id", "-gn", username])
    groups = _exec_stdout(backend, container_name, ["id", "-Gn", username])
    expected_groups = {user.primary_group, *user.supplemental_groups}
    return bool(
        field_values_match
        and primary is not None
        and primary.strip() == user.primary_group
        and groups is not None
        and set(groups.split()) == expected_groups
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
    if not all(
        _dependency_manifest_matches(backend, container_name, manifest)
        for manifest in manifests
    ):
        return None
    return _disclose(
        "runtime-dependency-manifests",
        [item.model_dump(mode="json", by_alias=True) for item in manifests],
    )


def _dependency_manifest_matches(
    backend: "DeploymentBackend", container_name: str, manifest: object
) -> bool:
    """Return whether a manifest file and its installed package are present."""

    name = getattr(manifest, "name", "")
    if not name:
        return False
    payload = backend.container_file_read(
        container_name,
        manifest.path,
        max_bytes=_DEPENDENCY_MANIFEST_MAX_BYTES,
    )
    command = manifest_query_argv(manifest.ecosystem, name)
    return bool(payload) and _exec_ok(backend, container_name, command)


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
    """Parse the bounded procfs limit rows APTL selects and observes."""

    if payload is None:
        return {}
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return {}
    observed: dict[str, tuple[int | str, int | str]] = {}
    valid = True
    for line in text.splitlines():
        for label, resource in _PROCESS_LIMIT_LABELS.items():
            if not line.startswith(label):
                continue
            columns = line[len(label) :].split()
            if len(columns) != 3:
                valid = False
                break
            soft = _limit_value(columns[0])
            hard = _limit_value(columns[1])
            if soft is None or hard is None:
                valid = False
                break
            observed[resource] = (soft, hard)
        if not valid:
            break
    return observed if valid else {}


def _limit_value(value: str) -> int | str | None:
    """Parse a finite non-negative process limit or the unlimited sentinel."""

    if value == "unlimited":
        return value
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def observe_filesystem_inventory(
    backend: "DeploymentBackend",
    container_name: str,
    runtime: RuntimeConfiguration,
) -> object | None:
    """Corroborate bounded path presence and entry types inside the guest."""

    entries = tuple(runtime.filesystem_inventory)
    if not entries:
        return None
    if not all(
        _filesystem_entry_matches(backend, container_name, entry) for entry in entries
    ):
        return None
    return _disclose(
        "runtime-filesystem-inventory",
        [entry.model_dump(mode="json", by_alias=True) for entry in entries],
    )


def _filesystem_entry_matches(
    backend: "DeploymentBackend", container_name: str, entry: object
) -> bool:
    """Corroborate one supported filesystem entry shape and presence."""

    if not _filesystem_shape_supported(entry):
        return False
    presence = _value(entry.presence)
    if presence == "expected_absent":
        return _exec_ok(
            backend, container_name, ["test", "!", "-e", entry.path]
        ) and _exec_ok(backend, container_name, ["test", "!", "-L", entry.path])
    flag = {
        "file": "-f",
        "directory": "-d",
        "symlink": "-L",
        "socket": "-S",
        "fifo": "-p",
    }.get(_value(entry.entry_type))
    return bool(
        presence == "present"
        and flag is not None
        and _exec_ok(backend, container_name, ["test", flag, entry.path])
    )


def _filesystem_shape_supported(entry: object) -> bool:
    """Return whether APTL can corroborate every selected entry dimension."""

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
    if not all(_service_unit_matches(backend, container_name, unit) for unit in units):
        return None
    return _disclose(
        "runtime-service-manager-units",
        [unit.model_dump(mode="json", by_alias=True) for unit in units],
    )


def _service_unit_matches(
    backend: "DeploymentBackend", container_name: str, unit: object
) -> bool:
    """Corroborate one supported systemd unit through bounded commands."""

    if not _service_unit_shape_supported(unit):
        return False
    load_state = _exec_value(
        backend,
        container_name,
        ["systemctl", "show", "--property=LoadState", "--value", unit.unit_name],
    )
    enabled = _exec_value(
        backend, container_name, ["systemctl", "is-enabled", unit.unit_name]
    )
    active = _exec_value(
        backend, container_name, ["systemctl", "is-active", unit.unit_name]
    )
    return bool(
        load_state not in {None, "", "not-found", "error"}
        and _declared_state_matches(unit.load_state, load_state)
        and _declared_state_matches(unit.enabled_state, enabled)
        and _declared_state_matches(unit.active_state, active)
    )


def _declared_state_matches(declared: object, observed: str | None) -> bool:
    """Return whether an observed unit state satisfies its declaration."""

    declared_value = _value(declared).replace("_", "-")
    return declared_value == "unknown" or declared_value == observed


def _service_unit_shape_supported(unit: object) -> bool:
    """Return whether every selected unit dimension is systemd-observable."""

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
    """Return whether one bounded non-shell guest command succeeded."""

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
    """Return stdout for one successful bounded guest command."""

    result = backend.container_exec(container_name, command, timeout=30)
    if getattr(result, "returncode", 1) != 0:
        return None
    return _stdout(result)


def _exec_value(
    backend: "DeploymentBackend", container_name: str, command: list[str]
) -> str | None:
    """Return one normalized guest-command value when non-empty."""

    result = backend.container_exec(container_name, command, timeout=30)
    value = _stdout(result).strip().casefold().replace("_", "-")
    return value or None


def _stdout(result: object) -> str:
    """Decode a command result's strict UTF-8 stdout."""

    value = getattr(result, "stdout", "")
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="strict")
    return value if isinstance(value, str) else ""


def _value(value: object) -> str:
    """Normalize an enum or scalar vocabulary value for comparison."""

    return str(getattr(value, "value", value)).casefold()


__all__ = [
    "observe_dependency_manifests",
    "observe_filesystem_inventory",
    "observe_local_identity",
    "observe_packages",
    "observe_process_resource_limits",
    "observe_service_manager_units",
]
