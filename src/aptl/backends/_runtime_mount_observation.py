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

    declared = [
        mount for mount in runtime.mounts if _mount_kind(mount) in _STATEFUL_MOUNT_KINDS
    ]
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
