"""Generic, scenario-agnostic node materializer planner (ADR-047).

Turns a node's declared ACES desired state (`os` plus a
`RuntimeConfiguration`) into an ordered tuple of generic materialization
operations. The planner is *pure* and *product-agnostic*: it contains no
per-product, per-node, or per-scenario branch. Two nodes with identical
declared state produce identical operations regardless of any name. All
capability-specific knowledge (which packages, which users, which service
units make a working Wazuh) lives in the SDL; this module only lowers declared
state into generic OS provisioning steps.

The operations are backend-neutral. A deployment backend consumes them through
typed operations (package install, identity creation, service-unit control),
never a raw argv passthrough, and verifies the result by read-after-write.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aces_sdl.runtime_configuration import (
    RuntimeConfiguration,
    ServiceUnitActiveState,
    ServiceUnitEnabledState,
)

# Fixed, scenario-independent base substrate per OS family. A node runs on a
# generic OS base image; its scenario-meaningful software is materialized onto
# that base from declared state, never baked into an appliance image (ADR-047).
_BASE_IMAGE_MAP: dict[str, str] = {
    "linux": "debian:12-slim",
}

# Generic OS + init substrate for nodes that declare service units, so a service
# manager (systemd) actually runs inside the container. Still generic: OS + init
# only, no product. Built from containers/generic-systemd-base/Dockerfile and
# validated locally against Docker.
_SERVICE_BASE_IMAGE_MAP: dict[str, str] = {
    "linux": "aptl/generic-systemd-base:latest",
}


class UnsupportedOsFamilyError(ValueError):
    """Raised when APTL has no generic base substrate for an OS family.

    Fail closed: an unmapped OS family is an admission error, never a guessed
    image.
    """


@dataclass(frozen=True)
class BaseSubstrateOp:
    """Start a generic base-OS container for the node."""

    image_ref: str


@dataclass(frozen=True)
class InstallPackagesOp:
    """Install declared packages through one declared package manager."""

    manager: str
    packages: tuple[str, ...]


@dataclass(frozen=True)
class EnsureGroupOp:
    """Ensure a local group exists."""

    name: str
    gid: int | str | None = None


@dataclass(frozen=True)
class EnsureUserOp:
    """Ensure a local user exists with its declared, non-secret attributes."""

    username: str
    uid: int | str | None = None
    primary_group: str = ""
    supplemental_groups: tuple[str, ...] = ()
    shell: str = ""
    home: str = ""


@dataclass(frozen=True)
class EnableServiceUnitOp:
    """Enable a service-manager unit (start on boot)."""

    unit_name: str


@dataclass(frozen=True)
class StartServiceUnitOp:
    """Start a service-manager unit now."""

    unit_name: str


MaterializationOp = (
    BaseSubstrateOp
    | InstallPackagesOp
    | EnsureGroupOp
    | EnsureUserOp
    | EnableServiceUnitOp
    | StartServiceUnitOp
)


def base_image_for_os(os: str, os_version: str, *, runs_services: bool = False) -> str:
    """Return the generic base image for an OS family, or fail closed.

    Deterministic: the same (os, os_version, runs_services) always maps to the
    same base. A node that declares service units gets an init-capable generic
    substrate so a service manager can run; otherwise a minimal generic base.
    `os_version` is accepted for forward compatibility (family plus version keys)
    but the current maps key on family only.
    """

    family = (os or "").strip().lower()
    table = _SERVICE_BASE_IMAGE_MAP if runs_services else _BASE_IMAGE_MAP
    image = table.get(family)
    if image is None:
        raise UnsupportedOsFamilyError(
            f"no generic base substrate for OS family {os!r}"
        )
    return image


def _package_ops(runtime: RuntimeConfiguration) -> list[InstallPackagesOp]:
    by_manager: dict[str, set[str]] = {}
    for package in runtime.packages:
        by_manager.setdefault(package.manager, set()).add(package.name)
    return [
        InstallPackagesOp(manager=manager, packages=tuple(sorted(names)))
        for manager, names in sorted(by_manager.items())
    ]


def _identity_ops(runtime: RuntimeConfiguration) -> list[MaterializationOp]:
    inventory = runtime.local_identity
    if inventory is None:
        return []
    ops: list[MaterializationOp] = [
        EnsureGroupOp(name=group.name, gid=group.gid) for group in inventory.groups
    ]
    ops.extend(
        EnsureUserOp(
            username=user.username,
            uid=user.uid,
            primary_group=user.primary_group,
            supplemental_groups=tuple(user.supplemental_groups),
            shell=user.shell,
            home=user.home,
        )
        for user in inventory.users
    )
    return ops


def _service_unit_ops(runtime: RuntimeConfiguration) -> list[MaterializationOp]:
    ops: list[MaterializationOp] = [
        EnableServiceUnitOp(unit_name=unit.unit_name)
        for unit in runtime.service_manager_units
        if unit.enabled_state == ServiceUnitEnabledState.ENABLED
    ]
    ops.extend(
        StartServiceUnitOp(unit_name=unit.unit_name)
        for unit in runtime.service_manager_units
        if unit.active_state == ServiceUnitActiveState.ACTIVE
    )
    return ops


def plan_node_materialization(
    *,
    os: str,
    os_version: str,
    runtime: RuntimeConfiguration | None,
) -> tuple[MaterializationOp, ...]:
    """Lower one node's declared desired state into ordered generic operations.

    Order is dependency-safe: base substrate, package installs, groups, users,
    service-unit enable, service-unit start. Emits nothing product-specific.
    """

    runs_services = bool(runtime is not None and runtime.service_manager_units)
    ops: list[MaterializationOp] = [
        BaseSubstrateOp(
            image_ref=base_image_for_os(os, os_version, runs_services=runs_services)
        )
    ]
    if runtime is not None:
        ops.extend(_package_ops(runtime))
        ops.extend(_identity_ops(runtime))
        ops.extend(_service_unit_ops(runtime))
    return tuple(ops)
