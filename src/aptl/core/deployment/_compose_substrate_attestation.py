"""Attest a generic base container's realized posture against its spec (issue #955).

The ``docker run`` argv is intent, not proof. This module reads the daemon's own
inspect payload for a generic base container and decides whether it carries
exactly the posture APTL would create now. One check governs both paths:

* **after create**, before any service content is materialized, so a daemon that
  did not honor a requested option fails the node instead of silently running a
  different posture; and
* **on reuse**, so a container left by an earlier policy -- the retired
  privileged systemd recipe among them -- is recreated rather than adopted.
  Image identity is not realization identity: a stale container matches on name
  and image alone.

The comparison is closed-world. Every field it relies on must be present and
well-shaped; a missing or malformed field is an unknown posture, never an empty
safe set. It returns a stable reason key rather than raw inspect data, so a
caller can report the failure without echoing host paths or daemon output.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from aptl.core.deployment._compose_substrate_gate import WRITABLE_CGROUPS_OPTION

if TYPE_CHECKING:
    from aptl.backends.raes_base_substrate import BaseContainerSpec

# Namespace modes that would share a host namespace with the container. Docker
# reports an unshared namespace as "" or "private" (IPC also "shareable").
_HOST_NAMESPACE_FIELDS = ("PidMode", "IpcMode", "UsernsMode", "UTSMode")

# The only effective AppArmor profiles a generic base container may run under:
# the daemon's default, or none on a host without AppArmor (SELinux hosts,
# Docker Desktop's VM). Anything else was selected by something other than APTL.
_ACCEPTED_APPARMOR_PROFILES = frozenset({"", "docker-default"})

# Docker names an anonymous volume (an image's own ``VOLUME``) by a 64-hex id.
_ANONYMOUS_VOLUME_NAME = re.compile(r"^[0-9a-f]{64}$")

# Host fields that must be absent or empty on a generic base container: APTL
# maps no device, adds no device-cgroup rule, and drops no capability.
_EMPTY_HOST_FIELDS = ("Devices", "DeviceCgroupRules", "CapDrop")

_MALFORMED = "inspect-malformed"

_Payload = Mapping[str, Any]


def _first_mismatch(*checks: Callable[[], str | None]) -> str | None:
    """Return the first reason any check reports, running them in order."""

    return next((reason for check in checks if (reason := check()) is not None), None)


def _string_list(value: object) -> list[str] | None:
    """Return a list of strings, ``[]`` for Docker's null, or None if malformed."""

    if value is None:
        return []
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return None


def _normalized_capabilities(values: list[str]) -> frozenset[str]:
    """Normalize capability names; Docker echoes ``SYS_ADMIN`` or ``CAP_SYS_ADMIN``."""

    return frozenset(value.upper().removeprefix("CAP_") for value in values if value)


def _expected_capabilities(spec: "BaseContainerSpec") -> frozenset[str]:
    """Return the exact capability set APTL adds to this base container.

    Two sources, and only two: the init posture (the node's authored
    ``runtime.linux_capabilities.add``, since the substrate baseline is empty)
    and a backend-selected provider substrate's own measured minimum
    (``backend_run_capabilities``).
    """

    init_capabilities = spec.init.capabilities if spec.init is not None else ()
    return _normalized_capabilities(
        [*init_capabilities, *spec.backend_run_capabilities]
    )


def _expected_security_options(spec: "BaseContainerSpec") -> frozenset[str]:
    """Return the exact ``SecurityOpt`` set APTL requests for this container."""

    if spec.init is not None and spec.init.writable_cgroups:
        return frozenset({WRITABLE_CGROUPS_OPTION})
    return frozenset()


def _privileged_mismatch(host: _Payload) -> str | None:
    """A privileged container holds every capability and every device."""

    privileged = host.get("Privileged")
    if not isinstance(privileged, bool):
        return _MALFORMED
    return "privileged" if privileged else None


def _namespace_mismatch(host: _Payload) -> str | None:
    """Reject a PID, IPC, user, or UTS namespace shared with the host or a peer."""

    modes = [host.get(field) for field in _HOST_NAMESPACE_FIELDS]
    if not all(isinstance(mode, str) for mode in modes):
        return _MALFORMED
    shared = any(mode == "host" or mode.startswith("container:") for mode in modes)
    return "shared-host-namespace" if shared else None


def _device_mismatch(host: _Payload) -> str | None:
    """Reject mapped devices, device-cgroup rules, and dropped capabilities."""

    values = [host.get(field) for field in _EMPTY_HOST_FIELDS]
    if any(value is not None and not isinstance(value, list) for value in values):
        return _MALFORMED
    return "undeclared-device-or-capability-drop" if any(values) else None


def _apparmor_mismatch(info: _Payload) -> str | None:
    """Accept only the daemon's default AppArmor profile, or none at all."""

    profile = info.get("AppArmorProfile")
    if not isinstance(profile, str):
        return _MALFORMED
    return None if profile in _ACCEPTED_APPARMOR_PROFILES else "apparmor-profile"


def _cgroup_namespace_mismatch(cgroupns: str, spec: "BaseContainerSpec") -> str | None:
    """No base container shares the host's; an init node requires a private one."""

    requires_private = spec.init is not None and spec.init.cgroup_private
    wrong = cgroupns == "host" or (requires_private and cgroupns != "private")
    return "cgroup-namespace" if wrong else None


def _security_mismatch(host: _Payload, spec: "BaseContainerSpec") -> str | None:
    """Check capabilities, security options, and cgroup namespace mode."""

    capabilities = _string_list(host.get("CapAdd"))
    options = _string_list(host.get("SecurityOpt"))
    cgroupns = host.get("CgroupnsMode")
    if capabilities is None or options is None or not isinstance(cgroupns, str):
        return _MALFORMED
    return _first_mismatch(
        lambda: (
            "capabilities"
            if _normalized_capabilities(capabilities) != _expected_capabilities(spec)
            else None
        ),
        lambda: (
            "security-options"
            if frozenset(options) != _expected_security_options(spec)
            else None
        ),
        lambda: _cgroup_namespace_mismatch(cgroupns, spec),
    )


def _tmpfs_mismatch(host: _Payload, spec: "BaseContainerSpec") -> str | None:
    """Check the tmpfs set: the init's exactly, and none otherwise."""

    tmpfs = host.get("Tmpfs")
    if tmpfs is None:
        tmpfs = {}
    if not isinstance(tmpfs, Mapping):
        return _MALFORMED
    realized = frozenset(str(target) for target in tmpfs)
    expected = frozenset(spec.init.tmpfs) if spec.init is not None else frozenset()
    return "tmpfs" if realized != expected else None


def _binding_mismatch(entries: object, host_ip: str, host_port: str | None) -> str | None:
    """Check every realized entry for one container port against its declaration."""

    from aptl.backends._runtime_concern_excess import _port_entry_matches

    if not isinstance(entries, list) or not all(
        isinstance(entry, Mapping) for entry in entries
    ):
        return _MALFORMED
    matches = all(_port_entry_matches(entry, host_ip, host_port) for entry in entries)
    return None if matches else "published-ports"


def _published_ports_mismatch(host: _Payload, spec: "BaseContainerSpec") -> str | None:
    """Check the container publishes exactly the declared bindings.

    Compares each realized host address and host port with its declaration, not
    only the container-port key: a changed host IP or fixed host port must not
    let a container keep its old publication. An ephemeral declaration (no
    host port) accepts whatever port Docker recorded for it.
    """

    bindings = host.get("PortBindings")
    if bindings is None:
        bindings = {}
    if not isinstance(bindings, Mapping):
        return _MALFORMED
    expected = {
        f"{port.container_port}/{port.protocol}": (
            port.host_ip,
            None if port.host_port is None else str(port.host_port),
        )
        for port in spec.published_ports
    }
    realized = {key: value for key, value in bindings.items() if value}
    if set(realized) != set(expected):
        return "published-ports"
    reasons = (
        _binding_mismatch(entries, *expected[key]) for key, entries in realized.items()
    )
    return next((reason for reason in reasons if reason is not None), None)


def _host_bind_present(host: _Payload) -> bool | None:
    """Whether ``HostConfig.Binds`` names a host path; None if malformed."""

    binds = _string_list(host.get("Binds"))
    if binds is None:
        return None
    return any(bind.split(":", 1)[0].startswith("/") for bind in binds)


def _is_foreign_mount(mount: _Payload) -> bool:
    """A mount that is not a volume APTL could have created (a bind, above all)."""

    return mount.get("Type") != "volume" or not isinstance(
        mount.get("Destination"), str
    )


def _volume_set_mismatch(
    mounts: list[_Payload], spec: "BaseContainerSpec", volume_prefix: str
) -> str | None:
    """Declared volumes match exactly; any other volume must be anonymous."""

    declared = {
        mount.target: (f"{volume_prefix}_{mount.source}", not mount.read_only)
        for mount in spec.volume_mounts
    }
    realized = {
        mount["Destination"]: (mount.get("Name"), mount.get("RW")) for mount in mounts
    }
    undeclared_named = any(
        destination not in declared
        and not _ANONYMOUS_VOLUME_NAME.fullmatch(str(name or ""))
        for destination, (name, _) in realized.items()
    )
    declared_match = all(realized.get(target) == want for target, want in declared.items())
    return None if declared_match and not undeclared_named else "volume-mounts"


def _mounts_mismatch(
    info: _Payload, host: _Payload, spec: "BaseContainerSpec", volume_prefix: str
) -> str | None:
    """Check every mount is a declared volume or an image's anonymous volume.

    Declared volumes must match name, target, type, and access mode. A bind of
    any kind is state APTL never creates on a generic base container, the
    retired ``/sys/fs/cgroup`` bind among them. An anonymous volume is an
    image's own ``VOLUME`` and carries no host authority; rejecting it would
    recreate a correct container on every start.
    """

    mounts = info.get("Mounts")
    host_bind = _host_bind_present(host)
    if (
        host_bind is None
        or not isinstance(mounts, list)
        or not all(isinstance(mount, Mapping) for mount in mounts)
    ):
        return _MALFORMED
    if host_bind or any(_is_foreign_mount(mount) for mount in mounts):
        return "host-bind"
    return _volume_set_mismatch(mounts, spec, volume_prefix)


def substrate_posture_mismatch(
    info: object, spec: "BaseContainerSpec", *, volume_prefix: str
) -> str | None:
    """Return a stable reason the container differs from ``spec``, or None.

    ``volume_prefix`` is the project namespace the backend prefixes onto a
    declared volume's bare name when it creates the container. Network
    attachments are deliberately excluded: the post-start reconcile owns them.
    Declared environment is excluded too: it binds through an env file, and the
    caller compares the realized values with the resolved bindings (issue #965).
    """

    host = info.get("HostConfig") if isinstance(info, Mapping) else None
    if not isinstance(host, Mapping):
        return _MALFORMED
    return _first_mismatch(
        lambda: _privileged_mismatch(host),
        lambda: _namespace_mismatch(host),
        lambda: _device_mismatch(host),
        lambda: _apparmor_mismatch(info),
        lambda: _security_mismatch(host, spec),
        lambda: _tmpfs_mismatch(host, spec),
        lambda: _published_ports_mismatch(host, spec),
        lambda: _mounts_mismatch(info, host, spec, volume_prefix),
    )
