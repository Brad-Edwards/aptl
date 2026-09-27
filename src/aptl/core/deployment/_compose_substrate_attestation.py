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
from typing import TYPE_CHECKING

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


def _host_privilege_mismatch(info: dict, host: dict) -> str | None:
    """Check the fields that grant host authority beyond the spec."""

    if not isinstance(host.get("Privileged"), bool):
        return "inspect-malformed"
    if host["Privileged"]:
        return "privileged"
    for field in _HOST_NAMESPACE_FIELDS:
        mode = host.get(field)
        if not isinstance(mode, str):
            return "inspect-malformed"
        if mode == "host" or mode.startswith("container:"):
            return "shared-host-namespace"
    for field in ("Devices", "DeviceCgroupRules", "CapDrop"):
        values = host.get(field)
        if values is None:
            continue
        if not isinstance(values, list):
            return "inspect-malformed"
        if values:
            return "undeclared-device-or-capability-drop"
    profile = info.get("AppArmorProfile")
    if not isinstance(profile, str):
        return "inspect-malformed"
    if profile not in _ACCEPTED_APPARMOR_PROFILES:
        return "apparmor-profile"
    return None


def _security_mismatch(host: dict, spec: "BaseContainerSpec") -> str | None:
    """Check capabilities, security options, and cgroup namespace mode."""

    capabilities = _string_list(host.get("CapAdd"))
    options = _string_list(host.get("SecurityOpt"))
    cgroupns = host.get("CgroupnsMode")
    if capabilities is None or options is None or not isinstance(cgroupns, str):
        return "inspect-malformed"
    if _normalized_capabilities(capabilities) != _expected_capabilities(spec):
        return "capabilities"
    if frozenset(options) != _expected_security_options(spec):
        return "security-options"
    if cgroupns == "host":
        return "cgroup-namespace"
    if spec.init is not None and spec.init.cgroup_private and cgroupns != "private":
        return "cgroup-namespace"
    return None


def _tmpfs_mismatch(host: dict, spec: "BaseContainerSpec") -> str | None:
    """Check the tmpfs set: the init's exactly, and none otherwise."""

    tmpfs = host.get("Tmpfs")
    if tmpfs is not None and not isinstance(tmpfs, dict):
        return "inspect-malformed"
    realized = frozenset(tmpfs or {})
    expected = frozenset(spec.init.tmpfs) if spec.init is not None else frozenset()
    return None if realized == expected else "tmpfs"


def _published_ports_mismatch(host: dict, spec: "BaseContainerSpec") -> str | None:
    """Check the container publishes exactly the declared bindings.

    Compares each realized host address and host port with its declaration, not
    only the container-port key: a changed host IP or fixed host port must not
    let a container keep its old publication. An ephemeral declaration (no
    host port) accepts whatever port Docker recorded for it.
    """

    from aptl.backends._runtime_concern_excess import _port_entry_matches

    bindings = host.get("PortBindings")
    if bindings is not None and not isinstance(bindings, dict):
        return "inspect-malformed"
    expected = {
        f"{port.container_port}/{port.protocol}": (
            port.host_ip,
            None if port.host_port is None else str(port.host_port),
        )
        for port in spec.published_ports
    }
    realized = {key: value for key, value in (bindings or {}).items() if value}
    if set(realized) != set(expected):
        return "published-ports"
    for key, entries in realized.items():
        if not isinstance(entries, list) or not all(
            isinstance(entry, dict) for entry in entries
        ):
            return "inspect-malformed"
        host_ip, host_port = expected[key]
        if not all(_port_entry_matches(entry, host_ip, host_port) for entry in entries):
            return "published-ports"
    return None


def _host_bind_present(host: dict) -> bool | None:
    """Whether ``HostConfig.Binds`` names a host path; None if malformed."""

    binds = _string_list(host.get("Binds"))
    if binds is None:
        return None
    return any(bind.split(":", 1)[0].startswith("/") for bind in binds)


def _mounts_mismatch(
    info: dict, host: dict, spec: "BaseContainerSpec", volume_prefix: str
) -> str | None:
    """Check every mount is a declared volume or an image's anonymous volume.

    Declared volumes must match name, target, type, and access mode. A bind of
    any kind is state APTL never creates on a generic base container, the
    retired ``/sys/fs/cgroup`` bind among them. An anonymous volume is an
    image's own ``VOLUME`` and carries no host authority; rejecting it would
    recreate a correct container on every start.
    """

    mounts = info.get("Mounts")
    if not isinstance(mounts, list) or not all(isinstance(m, dict) for m in mounts):
        return "inspect-malformed"
    host_bind = _host_bind_present(host)
    if host_bind is None:
        return "inspect-malformed"
    if host_bind:
        return "host-bind"
    declared = {
        mount.target: (f"{volume_prefix}_{mount.source}", not mount.read_only)
        for mount in spec.volume_mounts
    }
    seen: set[str] = set()
    for mount in mounts:
        destination = mount.get("Destination")
        if mount.get("Type") != "volume" or not isinstance(destination, str):
            return "host-bind"
        if destination in declared:
            if (mount.get("Name"), mount.get("RW")) != declared[destination]:
                return "volume-mounts"
            seen.add(destination)
        elif not _ANONYMOUS_VOLUME_NAME.fullmatch(str(mount.get("Name") or "")):
            return "volume-mounts"
    return None if seen == set(declared) else "volume-mounts"


def substrate_posture_mismatch(
    info: object, spec: "BaseContainerSpec", *, volume_prefix: str
) -> str | None:
    """Return a stable reason the container differs from ``spec``, or None.

    ``volume_prefix`` is the project namespace the backend prefixes onto a
    declared volume's bare name when it creates the container. Network
    attachments are deliberately excluded: the post-start reconcile owns them.
    Declared environment names are excluded too: they bind through an env file,
    and a variable absent from the operator environment is legitimately omitted.
    """

    if not isinstance(info, dict) or not isinstance(info.get("HostConfig"), dict):
        return "inspect-malformed"
    host = info["HostConfig"]
    for check in (
        lambda: _host_privilege_mismatch(info, host),
        lambda: _security_mismatch(host, spec),
        lambda: _tmpfs_mismatch(host, spec),
        lambda: _published_ports_mismatch(host, spec),
        lambda: _mounts_mismatch(info, host, spec, volume_prefix),
    ):
        reason = check()
        if reason is not None:
            return reason
    return None
