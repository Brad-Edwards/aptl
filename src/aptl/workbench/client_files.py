"""Private, recoverable publication of one native project client document."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from aptl.core._soc_ca_io import _atomic_write
from aptl.utils.pathsafe import (
    REASON_NOT_FOUND,
    PathContainmentError,
    open_contained_nofollow,
    open_dir_contained_nofollow,
)
from aptl.workbench.access import SeatAccessRecord, require_current_access
from aptl.workbench.access_clients import render_claude, render_codex
from aptl.workbench.agent import _group_is_private_to_current_user
from aptl.workbench.profiles import WorkbenchConfigurationError


def _read(root: Path, relative: str) -> str | None:
    try:
        with open_contained_nofollow(root, relative) as handle:
            info = os.fstat(handle.fileno())
            if (
                info.st_uid != os.getuid()
                or info.st_mode & 0o002
                or (
                    info.st_mode & 0o020
                    and not _group_is_private_to_current_user(info.st_gid)
                )
            ):
                raise WorkbenchConfigurationError("client file ownership is unsafe")
            content = handle.read(1024 * 1024 + 1)
    except PathContainmentError as exc:
        if exc.reason == REASON_NOT_FOUND:
            return None
        raise WorkbenchConfigurationError("unsafe client configuration path") from exc
    if len(content) > 1024 * 1024:
        raise WorkbenchConfigurationError("client configuration exceeds size limit")
    return content.decode("utf-8")


def _private_directory(root: Path, name: str) -> None:
    path = root / name
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    descriptor = open_dir_contained_nofollow(root, name)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise WorkbenchConfigurationError("client state directory must be private")
    finally:
        os.close(descriptor)


def _digest(text: str | None) -> str:
    return hashlib.sha256((text or "").encode()).hexdigest()


def _validate_identity(previous: dict, record: SeatAccessRecord) -> None:
    old = previous["identity"]
    if (
        any(
            old[field] != getattr(record, field)
            for field in ("owner_id", "seat_id", "instance_id")
        )
        or record.generation < old["generation"]
    ):
        raise WorkbenchConfigurationError("stale or mismatched client identity")
    if record.generation == old["generation"] and old != _record_identity(record):
        raise WorkbenchConfigurationError(
            "transport identity changed without a new generation"
        )


def _record_identity(record):
    return record.model_dump(mode="json", exclude={"observed_at", "lifecycle_state"})


def publish_client_config(
    project: Path, client: str, record: SeatAccessRecord, entries: dict
) -> Path:
    """Recover ownership after interruption, preserve manual data, reject races."""
    import fcntl

    require_current_access(record, owner_id=record.owner_id, seat_id=record.seat_id)
    if client not in {"claude", "codex"}:
        raise WorkbenchConfigurationError("unsupported MCP client")
    root = project.resolve(strict=True)
    _private_directory(root, ".aptl")
    if client == "codex":
        _private_directory(root, ".codex")
    target_rel = ".mcp.json" if client == "claude" else ".codex/config.toml"
    state_rel = f".aptl/{client}-mcp-owned.json"
    pending_rel = f".aptl/{client}-mcp-pending.json"
    lock_path = root / ".aptl" / f"{client}-mcp.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return _publish(
            root, client, record, entries, target_rel, state_rel, pending_rel
        )
    finally:
        os.close(descriptor)


def _publish(root, client, record, entries, target_rel, state_rel, pending_rel):
    original = _read(root, target_rel)
    stored = _read(root, state_rel)
    previous = json.loads(stored) if stored is not None else None
    pending = _read(root, pending_rel)
    if pending is not None:
        journal = json.loads(pending)
        if _digest(original) == journal["candidate_sha256"]:
            previous = journal["state"]
            _atomic_write(root / state_rel, json.dumps(previous).encode(), mode=0o600)
        elif _digest(original) != journal["original_sha256"]:
            raise WorkbenchConfigurationError("interrupted client publication conflict")
        (root / pending_rel).unlink()
    if previous is not None:
        _validate_identity(previous, record)
    render = render_claude if client == "claude" else render_codex
    candidate = render(
        original or "", entries, previous=previous["entries"] if previous else None
    )
    identity = _record_identity(record)
    state = {"identity": identity, "entries": entries}
    journal = {
        "original_sha256": _digest(original),
        "candidate_sha256": _digest(candidate),
        "state": state,
    }
    _atomic_write(root / pending_rel, json.dumps(journal).encode(), mode=0o600)
    if _read(root, target_rel) != original:
        raise WorkbenchConfigurationError("concurrent client configuration edit")
    _atomic_write(root / target_rel, candidate.encode(), mode=0o600)
    _atomic_write(root / state_rel, json.dumps(state).encode(), mode=0o600)
    (root / pending_rel).unlink()
    return root / target_rel
