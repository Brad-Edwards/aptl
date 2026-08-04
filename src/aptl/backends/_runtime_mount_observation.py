"""Corroborate the two mount-footprint runtime concerns (#876).

``runtime-mounts`` and ``forwarding-agents`` are the two concerns whose evidence
is the realized container's mount table, so they share the same primitives and
are split out of :mod:`aptl.backends.raes_runtime_observation` together. Both
read host-side ``docker inspect`` (daemon state the container cannot forge) and
never execute anything inside the attested container.

A declared element the mount table does not corroborate is dropped, so the
disclosed value diverges from the declaration and the EXACT gate rejects it
rather than being handed an echo of the plan.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from raes.runtime_configuration import RuntimeConfiguration

from aptl.backends._runtime_concern_disclosure import _PROTECTED, _disclose
from aptl.backends._runtime_concern_excess import (
    _STATEFUL_MOUNT_KINDS,
    _has_undeclared_mounts,
    _sensitivity,
)


def _observe_mounts(
    info: Mapping[str, Any],
    runtime: RuntimeConfiguration,
) -> object | None:
    """Disclose declared bind/tmpfs mounts the container inspection corroborates.

    Fails closed (returns None) when the container carries a bind/tmpfs mount the
    contract does not declare and the substrate itself did not add (a systemd
    node's cgroup bind is the only baseline mount ``docker inspect`` reports). An
    undeclared bind mount is excess host access -- a leftover from a reused
    container or a hostile addition -- and must not pass (issue #876 cycle-7
    review).
    """

    declared = [mount for mount in runtime.mounts if _mount_kind(mount) in _STATEFUL_MOUNT_KINDS]
    realized = info.get("Mounts") if isinstance(info, Mapping) else None
    realized_mounts = realized if isinstance(realized, list) else []
    if _has_undeclared_mounts(realized_mounts, declared, runtime) or not declared:
        return None
    disclosed = [
        mount.model_dump(mode="json", by_alias=True)
        for mount in declared
        if _mount_present(mount, realized_mounts)
    ]
    if not disclosed:
        return None
    return _disclose("runtime-mounts", disclosed)


def _observe_forwarding_agents(
    info: Mapping[str, Any], runtime: RuntimeConfiguration
) -> object | None:
    """Disclose declared forwarding agents whose realized footprint is present.

    A forwarding agent's declared data path has a host-observable footprint: the
    volumes/binds that carry its sources and its unix-socket reload channels are
    mounts the realized container must have. This reads those mounts back off
    ``docker inspect`` (daemon-observed, never by executing anything inside the
    attested container) and cross-references the node's declared mounts to map a
    ``unix_socket`` reload channel's ``target_ref`` to the volume that serves it.

    An agent whose declared footprint is fully realized is corroborated. If any
    declared agent's footprint is absent — or an agent declares no
    host-observable footprint at all — the whole concern is dropped (``None``),
    so the realized set diverges from the declared one and the EXACT requirement
    is rejected rather than handed a fabricated match. This is disclosure of real
    container state, not an echo of the plan.
    """

    declared = list(getattr(runtime, "forwarding_agents", ()) or ())
    if not declared:
        return None
    realized = info.get("Mounts") if isinstance(info, Mapping) else None
    realized_dests = {
        entry.get("Destination")
        for entry in (realized if isinstance(realized, list) else ())
        if isinstance(entry, Mapping)
    }
    declared_mounts = list(getattr(runtime, "mounts", ()) or ())
    disclosed = []
    for agent in declared:
        if not _forwarding_agent_corroborated(agent, realized_dests, declared_mounts):
            return None
        disclosed.append(agent.model_dump(mode="json", by_alias=True))
    return _disclose("forwarding-agents", disclosed)


def _forwarding_agent_corroborated(
    agent: object, realized_dests: set[object], declared_mounts: Sequence[object]
) -> bool:
    """Return whether a declared agent's realized mount footprint is present."""

    required_paths = _agent_source_paths(agent) | _agent_reload_channel_paths(
        agent, declared_mounts
    )
    if not required_paths:
        # No host-observable footprint means the honest observation is absence.
        return False
    return all(_path_covered(path, realized_dests) for path in required_paths)


def _agent_source_paths(agent: object) -> set[str]:
    """Return the absolute filesystem locations an agent's sources declare."""

    locations = (
        str(getattr(source, "location", "") or "")
        for source in getattr(agent, "sources", ()) or ()
    )
    return {location for location in locations if location.startswith("/")}


def _agent_reload_channel_paths(
    agent: object, declared_mounts: Sequence[object]
) -> set[str]:
    """Return the mount targets serving an agent's ``unix_socket`` reload channels."""

    paths: set[str] = set()
    for channel in getattr(agent, "reload_channels", ()) or ():
        if _enum_value(getattr(channel, "kind", "")) != "unix_socket":
            continue
        target_ref = str(getattr(channel, "target_ref", "") or "")
        if not target_ref:
            continue
        paths.update(_volume_targets_for_ref(target_ref, declared_mounts))
    return paths


def _volume_targets_for_ref(
    target_ref: str, declared_mounts: Sequence[object]
) -> set[str]:
    """Return the declared volume-mount targets whose source names ``target_ref``."""

    targets = (
        str(getattr(mount, "target", "") or "")
        for mount in declared_mounts
        if _mount_kind(mount) == "volume"
        and target_ref in str(getattr(mount, "source", "") or "")
    )
    return {target for target in targets if target}


def _path_covered(path: str, realized_dests: set[object]) -> bool:
    """Return whether a realized mount destination is or contains ``path``."""

    for dest in realized_dests:
        dest_str = str(dest or "")
        if not dest_str:
            continue
        if dest_str == path or path.startswith(dest_str.rstrip("/") + "/"):
            return True
    return False


def _enum_value(value: object) -> str:
    """Return an enum member's string value (or the string itself)."""

    return str(getattr(value, "value", value) or "")


def _mount_kind(mount: object) -> str:
    """Return a declared mount's source kind (``bind`` / ``tmpfs`` / ...)."""

    source_kind = getattr(mount, "source_kind", None)
    return str(getattr(source_kind, "value", source_kind) or "")


def _mount_present(mount: object, realized_mounts: Sequence[object]) -> bool:
    """Return whether the container carries this declared bind/tmpfs mount."""

    kind = _mount_kind(mount)
    target = getattr(mount, "target", "")
    protected = _sensitivity(getattr(mount, "source_sensitivity", "")) in _PROTECTED
    source = getattr(mount, "source", "")
    read_only = bool(getattr(mount, "read_only", False))
    return any(
        _mount_entry_matches(
            realized,
            kind=kind,
            target=target,
            source=source,
            protected=protected,
            read_only=read_only,
        )
        for realized in realized_mounts
        if isinstance(realized, Mapping)
    )


def _mount_entry_matches(
    realized: Mapping[str, Any],
    *,
    kind: str,
    target: str,
    source: str,
    protected: bool,
    read_only: bool,
) -> bool:
    """Return whether one realized mount entry corroborates the declared mount."""

    if realized.get("Type") != kind or realized.get("Destination") != target:
        return False
    source_mismatch = bool(
        kind == "bind" and source and not protected and realized.get("Source") != source
    )
    # Read-only is a declared access-contract field; a realized RW state equal to
    # the declared read_only flag is contradictory (they are inverse), i.e. a
    # material mismatch, not a match (issue #876 core review).
    rw_mismatch = (
        kind in ("bind", "tmpfs")
        and "RW" in realized
        and read_only == bool(realized.get("RW"))
    )
    return not source_mismatch and not rw_mismatch
