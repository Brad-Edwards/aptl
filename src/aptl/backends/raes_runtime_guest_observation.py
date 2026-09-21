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
from aptl.backends._raes_guest_process_limits import observe_process_resource_limits
from aptl.backends.raes_package_managers import manifest_query_argv

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

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
    expected_members = {group.name: set(group.members) for group in inventory.groups}
    for user in inventory.users:
        for group_name in user.supplemental_groups:
            if group_name in expected_members:
                expected_members[group_name].add(user.username)
    if not all(
        _group_matches(
            backend,
            container_name,
            group,
            expected_members=expected_members[group.name],
        )
        for group in inventory.groups
    ) or not all(
        _user_matches(backend, container_name, user) for user in inventory.users
    ):
        return None
    return _disclose(
        "runtime-local-identity",
        inventory.model_dump(mode="json", by_alias=True),
    )


def _group_matches(
    backend: "DeploymentBackend",
    container_name: str,
    group: object,
    *,
    expected_members: set[str],
) -> bool:
    """Return whether guest group identity and membership match exactly."""

    name = getattr(group, "name", "")
    row = _exec_stdout(backend, container_name, ["getent", "group", name])
    fields = row.strip().split(":") if row is not None else []
    declared_gid = getattr(group, "gid", None)
    return bool(
        len(fields) == 4
        and fields[0] == name
        and (declared_gid is None or fields[2] == str(declared_gid))
        and {item for item in fields[3].split(",") if item} == expected_members
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
    primary = _exec_stdout(backend, container_name, ["id", "-gn", username])
    groups = _exec_stdout(backend, container_name, ["id", "-Gn", username])
    return _passwd_fields_match(fields, user) and _group_records_match(
        primary, groups, user
    )


def _passwd_fields_match(fields: list[str], user: object) -> bool:
    """Compare the supported passwd fields for one declared user."""

    uid = getattr(user, "uid", None)
    return bool(
        (uid is None or fields[2] == str(uid))
        and (not user.gecos or fields[4] == user.gecos)
        and (not user.home or fields[5] == user.home)
        and (not user.shell or fields[6] == user.shell)
    )


def _group_records_match(primary: str | None, groups: str | None, user: object) -> bool:
    """Compare a user's primary and supplemental guest group records."""

    observed_primary = primary.strip() if primary is not None else ""
    declared_primary = user.primary_group
    expected = {observed_primary, *user.supplemental_groups}
    return bool(
        observed_primary
        and (not declared_primary or observed_primary == declared_primary)
        and groups is not None
        and set(groups.split()) == expected
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


def observe_software_components(
    backend: "DeploymentBackend",
    container_name: str,
    runtime: RuntimeConfiguration,
) -> object | None:
    """Corroborate the supported Wazuh agent component in the guest."""

    components = tuple(runtime.software_components)
    if len(components) != 1 or not _supported_wazuh_agent(components[0]):
        return None
    component = components[0]
    output = _exec_stdout(
        backend, container_name, ["/var/ossec/bin/wazuh-control", "info"]
    )
    if output is None or not _wazuh_info_matches(
        output, str(getattr(component, "version", "") or "")
    ):
        return None
    return _disclose(
        "runtime-software-components",
        [component.model_dump(mode="json", by_alias=True)],
    )


def _supported_wazuh_agent(component: object) -> bool:
    """Admit only the one Wazuh agent shape this observer can corroborate."""

    return bool(
        getattr(component, "component_id", "") == "wazuh-agent"
        and _value(getattr(component, "component_type", "")) == "application"
        and _value(getattr(component, "presence", "")) == "required"
        and str(getattr(component, "version", "") or "")
    )


def _wazuh_info_matches(output: str, version: str) -> bool:
    """Require one exact agent type and version in guest Wazuh output."""

    lines = output.splitlines()
    return bool(
        sum(line == f'WAZUH_VERSION="v{version}"' for line in lines) == 1
        and sum(line == 'WAZUH_TYPE="agent"' for line in lines) == 1
        and sum(line.startswith("WAZUH_VERSION=") for line in lines) == 1
        and sum(line.startswith("WAZUH_TYPE=") for line in lines) == 1
    )


def _filesystem_entry_matches(
    backend: "DeploymentBackend", container_name: str, entry: object
) -> bool:
    """Corroborate one supported filesystem entry and its physical metadata."""

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
    present = bool(
        presence == "present"
        and flag is not None
        and _exec_ok(backend, container_name, ["test", flag, entry.path])
    )
    return present and _filesystem_metadata_matches(backend, container_name, entry)


def _filesystem_metadata_matches(
    backend: "DeploymentBackend", container_name: str, entry: object
) -> bool:
    """Compare every selected owner/id/mode/size dimension using guest stat."""

    selected = (
        getattr(entry, "owner_user", ""),
        getattr(entry, "owner_group", ""),
        getattr(entry, "uid", None),
        getattr(entry, "gid", None),
        getattr(entry, "mode", ""),
        getattr(entry, "size", None),
    )
    if not any(value not in ("", None) for value in selected):
        return True
    row = _exec_stdout(
        backend,
        container_name,
        ["stat", "-c", "%U:%G:%u:%g:%a:%s", entry.path],
    )
    fields = row.strip().split(":") if row is not None else []
    if len(fields) != 6:
        return False
    owner, group, uid, gid, mode, size = fields
    declared_mode = str(getattr(entry, "mode", ""))
    if declared_mode.startswith("0o"):
        declared_mode = declared_mode[2:]
    return all(
        _selected_dimension_matches(actual, expected)
        for actual, expected in (
            (owner, entry.owner_user),
            (group, entry.owner_group),
            (uid, entry.uid),
            (gid, entry.gid),
            (mode.zfill(4), declared_mode.zfill(4) if entry.mode else ""),
            (size, entry.size),
        )
    )


def _selected_dimension_matches(actual: str, expected: object) -> bool:
    """Compare one selected guest metadata dimension."""

    return expected in ("", None) or actual == str(expected)


def _filesystem_shape_supported(entry: object) -> bool:
    """Return whether APTL can corroborate every selected entry dimension."""

    unsupported_values = (
        getattr(entry, "content_digest", ""),
        getattr(entry, "digest_algorithm", ""),
        getattr(entry, "source_path", ""),
        getattr(entry, "provenance", ""),
    )
    # Stability and sensitivity classify the authored fact; they are not
    # physical filesystem attributes.  Preserve them in the disclosed value
    # once every selected physical dimension has been read back.
    return not any(value not in ("", None) for value in unsupported_values)


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
