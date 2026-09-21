"""Safe recovery state for scenario-admitted operator groups."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from aptl.utils.pathsafe import (
    REASON_NOT_FOUND,
    PathContainmentError,
    create_exclusive_nofollow,
    listdir_contained_nofollow,
    read_contained_nofollow,
)

_STATE_DIR = ".aptl/lifecycle/operator-groups-v1"
_SCHEMA = "aptl-admitted-operator-groups/v1"
_SAFE_GROUP = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")


def _validated(groups: object) -> tuple[str, ...]:
    if not isinstance(groups, (list, tuple, set, frozenset)) or any(
        not isinstance(group, str) or _SAFE_GROUP.fullmatch(group) is None
        for group in groups
    ):
        raise ValueError("invalid admitted operator groups")
    return tuple(sorted(set(groups)))


def persist_admitted_operator_groups(
    project_dir: Path, groups: object
) -> tuple[str, ...]:
    """Create one immutable recovery receipt for a validated admitted set."""

    selected = _validated(groups)
    payload = (
        json.dumps(
            {"schema_version": _SCHEMA, "groups": list(selected)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    digest = hashlib.sha256(payload).hexdigest()
    relative = f"{_STATE_DIR}/{digest}.json"
    try:
        create_exclusive_nofollow(project_dir, relative, payload)
    except FileExistsError:
        if read_contained_nofollow(project_dir, relative) != payload:
            raise ValueError("admitted operator-group receipt conflict") from None
    return selected


def load_admitted_operator_groups(project_dir: Path) -> tuple[str, ...]:
    """Return the safe union of immutable receipts for recovery commands."""

    try:
        names = listdir_contained_nofollow(project_dir, _STATE_DIR)
    except PathContainmentError as exc:
        if exc.reason == REASON_NOT_FOUND:
            return ()
        raise ValueError("operator-group recovery state unavailable") from exc
    groups: set[str] = set()
    for name in names:
        if not re.fullmatch(r"[0-9a-f]{64}\.json", name):
            raise ValueError("operator-group recovery state malformed")
        try:
            payload = read_contained_nofollow(project_dir, f"{_STATE_DIR}/{name}")
            value = json.loads(payload)
            if (
                not isinstance(value, dict)
                or set(value) != {"schema_version", "groups"}
                or value["schema_version"] != _SCHEMA
            ):
                raise ValueError
            selected = _validated(value["groups"])
            canonical = (
                json.dumps(
                    {"schema_version": _SCHEMA, "groups": list(selected)},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n"
            )
            if (
                payload != canonical
                or hashlib.sha256(canonical).hexdigest() + ".json" != name
            ):
                raise ValueError
        except (OSError, TypeError, ValueError, PathContainmentError) as exc:
            raise ValueError("operator-group recovery state malformed") from exc
        groups.update(selected)
    return tuple(sorted(groups))


__all__ = ["load_admitted_operator_groups", "persist_admitted_operator_groups"]
