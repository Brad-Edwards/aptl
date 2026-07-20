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

# Fixed, scenario-independent base substrate per (OS family, package family). A
# node runs on a generic OS base image; its scenario-meaningful software is
# materialized onto that base from declared state, never baked into an appliance
# image (ADR-047). The package family (from the declared package manager) picks a
# base whose package manager matches: apt -> Debian, dnf/yum -> RHEL.
_NON_SERVICE_BASE_IMAGE: dict[tuple[str, str], str] = {
    ("linux", "debian"): "debian:12-slim",
    ("linux", "rhel"): "rockylinux:9",
}

# Generic OS + init substrate for nodes that declare service units, so a service
# manager (systemd) actually runs inside the container. Still generic: OS + init
# only, no product. Family-aware so an apt node keeps apt and a dnf node keeps
# dnf. Built from containers/generic-systemd-base{,-debian}/Dockerfile and
# validated locally against Docker.
_SERVICE_BASE_IMAGE: dict[tuple[str, str], str] = {
    ("linux", "debian"): "aptl/generic-systemd-base-debian:latest",
    ("linux", "rhel"): "aptl/generic-systemd-base:latest",
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
class PlaceFileOp:
    """Place a declared config file into the node at an absolute path.

    Content is inline text authored in the SDL (never a secret value; secrets go
    through the generated-config path). Ordered after identity and before service
    start so a config-dependent service starts with its config present.
    """

    path: str
    content: str
    mode: str = ""


@dataclass(frozen=True)
class PlaceProjectContentOp:
    """Copy a checked-in, project-contained file/directory into the node.

    ``source_relpath`` is project-relative (containment-validated at resolution
    time). Ordered with file placement, before service start.
    """

    dest_path: str
    source_relpath: str
    is_directory: bool = False


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
    | PlaceFileOp
    | PlaceProjectContentOp
    | EnableServiceUnitOp
    | StartServiceUnitOp
)


def package_family(runtime: RuntimeConfiguration | None) -> str:
    """Return the package family (``debian`` / ``rhel``) implied by declared
    package managers. Defaults to ``debian`` when nothing dnf/yum is declared."""

    if runtime is not None:
        for pkg in runtime.packages:
            if pkg.manager in ("dnf", "yum"):
                return "rhel"
    return "debian"


def base_image_for_os(
    os: str,
    os_version: str,
    *,
    runs_services: bool = False,
    family: str = "debian",
) -> str:
    """Return the generic base image for a node, or fail closed.

    Deterministic. A node that declares service units gets the validated
    init-capable RHEL/systemd substrate; otherwise a minimal generic base chosen
    by package family (apt -> Debian, dnf -> RHEL). `os_version` is accepted for
    forward compatibility but the current maps key on family only.
    """

    os_family = (os or "").strip().lower()
    if runs_services:
        image = _SERVICE_BASE_IMAGE.get((os_family, family))
    else:
        image = _NON_SERVICE_BASE_IMAGE.get((os_family, family))
    if image is None:
        raise UnsupportedOsFamilyError(
            f"no generic base substrate for OS family {os!r} (package family {family!r})"
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
    content: tuple[MaterializationOp, ...] = (),
) -> tuple[MaterializationOp, ...]:
    """Lower one node's declared desired state into ordered generic operations.

    Order is dependency-safe: base substrate, package installs, groups, users,
    config-file placement, service-unit enable, service-unit start. Config is
    placed before services so a config-dependent service starts configured.
    Emits nothing product-specific.
    """

    runs_services = bool(runtime is not None and runtime.service_manager_units)
    ops: list[MaterializationOp] = [
        BaseSubstrateOp(
            image_ref=base_image_for_os(
                os,
                os_version,
                runs_services=runs_services,
                family=package_family(runtime),
            )
        )
    ]
    if runtime is not None:
        ops.extend(_package_ops(runtime))
        ops.extend(_identity_ops(runtime))
    ops.extend(content)
    if runtime is not None:
        ops.extend(_service_unit_ops(runtime))
    return tuple(ops)
