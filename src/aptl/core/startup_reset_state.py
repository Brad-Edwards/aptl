"""Durable, versioned pending-cleanup records for explicit volume resets.

A lab start records every host-side cleanup action the next ``aptl lab stop
-v`` must finish. Each record is a content-addressed, canonical JSON file
created once and never rewritten; a separate create-once completion marker
retires it only after its action succeeded. The ``action`` and
``action_version`` fields decide what may run. Pack and installed-provider
fields are admission provenance kept for audit and, for pack-owned work, the
exact identity a current handler must declare it supports.

Issue #1141 releases wrote ``startup-reset-v1`` receipts that named only the
provider whose ``reset`` hook should run. They are read in place, never
rewritten, classified into one of the actions below, and retired with their
original completion marker, so upgrades keep their bytes and history.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
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

ACTION_CLEAR_WAZUH_ENROLLMENT_BASELINE = "aptl.wazuh-enrollment-baseline.clear"
ACTION_PACK_RESET = "pack.reset"
ACTION_VERSION = "1"
SUPPORTED_ACTIONS = frozenset(
    {
        (ACTION_CLEAR_WAZUH_ENROLLMENT_BASELINE, ACTION_VERSION),
        (ACTION_PACK_RESET, ACTION_VERSION),
    }
)

_LIFECYCLE_DIR = ".aptl/lifecycle"
_LEGACY_DIR = "startup-reset-v1"
_LEGACY_COMPLETED_DIR = "startup-reset-completed-v1"
_LEGACY_SCHEMA = "aptl-startup-reset-authority/v1"
_LEGACY_COMPLETED_SCHEMA = "aptl-startup-reset-completion/v1"
_ACTION_DIR = "cleanup-actions-v1"
_ACTION_COMPLETED_DIR = "cleanup-actions-completed-v1"
_ACTION_SCHEMA = "aptl-lifecycle-cleanup-action/v1"
_ACTION_COMPLETED_SCHEMA = "aptl-lifecycle-cleanup-completion/v1"
_JSON_SUFFIX = ".json"
_RECORD_NAME = re.compile(r"[0-9a-f]{64}\.json")
_SAFE_TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
_SAFE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_DISPLAY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_PACK_FIELDS = ("pack_id", "pack_version", "pack_set_digest")
_PROVIDER_FIELDS = ("distribution", "distribution_version", "entry_point")
_LEGACY_KEYS = frozenset(
    {"schema_version", "admission_id", *_PACK_FIELDS, *_PROVIDER_FIELDS}
)
_ACTION_KEYS = _LEGACY_KEYS | {"action", "action_version"}

# Closed, verified history: every aptl-labs build that wrote a v1 receipt for
# these adapters (#1141 through #1179) implemented ``reset`` solely as removal
# of the APTL-owned Wazuh enrollment baseline. Other v1 receipts keep their
# pack-owned meaning and need a compatible installed handler.
_LEGACY_BASELINE_RESETS = frozenset(
    {
        ("aptl-labs", "techvault", "techvault"),
        ("aptl-labs", "techvault-participant-study", "techvault-participant-study"),
    }
)

REASON_MALFORMED = "cleanup-record-malformed"
REASON_UNSUPPORTED = "cleanup-action-unsupported"


@dataclass(frozen=True, order=True)
class CleanupAction:
    """One stable cleanup action admitted for a lab start."""

    action: str
    action_version: str
    admission_id: str
    pack_id: str = ""
    pack_version: str = ""
    pack_set_digest: str = ""
    distribution: str = ""
    distribution_version: str = ""
    entry_point: str = ""

    @property
    def subject(self) -> str:
        """Bounded human label for the admitted pack, when there is one."""

        if not self.pack_id:
            return "APTL"
        return f"{self.pack_id} {self.pack_version}"


@dataclass(frozen=True)
class PendingCleanup:
    """An authenticated record whose action has not been recorded complete."""

    record: str
    action: CleanupAction
    digest: str
    legacy: bool


@dataclass(frozen=True)
class UnprocessableCleanup:
    """A record that stays pending because it cannot be safely interpreted."""

    record: str
    reason: str


def _valid_text(value: object, *, required: bool) -> bool:
    """Return whether ``value`` is a bounded record token."""

    if not isinstance(value, str):
        return False
    if not value:
        return not required
    return _SAFE_TEXT.fullmatch(value) is not None


def _valid_pack(action: CleanupAction) -> bool:
    """Return whether the pack identity is absent or complete and well formed."""

    has_pack = any(getattr(action, name) for name in _PACK_FIELDS)
    if not isinstance(action.pack_set_digest, str):
        return False
    if not has_pack:
        return True
    return (
        _valid_text(action.pack_id, required=True)
        and _valid_text(action.pack_version, required=True)
        and _SAFE_DIGEST.fullmatch(action.pack_set_digest) is not None
    )


def _validated(action: CleanupAction) -> CleanupAction:
    """Validate one action's shape and its owner-specific provenance."""

    if not isinstance(action, CleanupAction):
        raise ValueError("invalid cleanup action")
    pack_owned = action.action == ACTION_PACK_RESET
    required = (action.action, action.action_version, action.admission_id)
    optional = (action.distribution, action.distribution_version)
    if (
        not all(_valid_text(value, required=True) for value in required)
        or not all(_valid_text(value, required=False) for value in optional)
        or not _valid_text(action.entry_point, required=pack_owned)
        or not _valid_pack(action)
        or (pack_owned and not action.pack_id)
    ):
        raise ValueError("invalid cleanup action")
    return action


def _encode(payload: dict[str, str]) -> bytes:
    """Return the canonical record encoding."""

    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )


def _action_payload(action: CleanupAction) -> bytes:
    """Encode one canonical cleanup-action record."""

    return _encode({"schema_version": _ACTION_SCHEMA, **asdict(_validated(action))})


def _completion_payload(schema: str, digest: str) -> bytes:
    """Encode the completion marker retiring one record digest."""

    return _encode({"schema_version": schema, "receipt_digest": digest})


def persist_cleanup_action(project_dir: Path, action: CleanupAction) -> None:
    """Create one no-follow, content-addressed pending cleanup record."""

    if (action.action, action.action_version) not in SUPPORTED_ACTIONS:
        raise ValueError("unsupported cleanup action")
    encoded = _action_payload(action)
    digest = hashlib.sha256(encoded).hexdigest()
    relative = f"{_LIFECYCLE_DIR}/{_ACTION_DIR}/{digest}{_JSON_SUFFIX}"
    try:
        try:
            create_exclusive_nofollow(project_dir, relative, encoded)
        except FileExistsError:
            if read_contained_nofollow(project_dir, relative) != encoded:
                raise ValueError("cleanup action record conflict") from None
    except PathContainmentError as exc:
        raise ValueError("cleanup action state unsafe") from exc


def _display(directory: str, name: str) -> str:
    """Return a bounded record label that never echoes untrusted text."""

    if _RECORD_NAME.fullmatch(name):
        return f"{directory}/{name[:12]}"
    if _DISPLAY_NAME.fullmatch(name):
        return f"{directory}/{name}"
    return f"{directory}/<unnamed>"


def _list(project_dir: Path, directory: str) -> list[str]:
    """List one lifecycle directory; an absent directory is empty."""

    try:
        return listdir_contained_nofollow(project_dir, f"{_LIFECYCLE_DIR}/{directory}")
    except PathContainmentError as exc:
        if exc.reason == REASON_NOT_FOUND:
            return []
        raise ValueError("cleanup state unavailable") from exc


def _completions(
    project_dir: Path, directory: str, schema: str
) -> tuple[frozenset[str], frozenset[str], tuple[str, ...]]:
    """Return completed digests, digests with bad markers, and stray names."""

    completed: set[str] = set()
    corrupt: set[str] = set()
    stray: list[str] = []
    for name in _list(project_dir, directory):
        digest = name.removesuffix(_JSON_SUFFIX)
        if _RECORD_NAME.fullmatch(name) is None:
            stray.append(name)
            continue
        try:
            encoded = read_contained_nofollow(
                project_dir, f"{_LIFECYCLE_DIR}/{directory}/{name}"
            )
        except (OSError, PathContainmentError):
            corrupt.add(digest)
            continue
        if encoded == _completion_payload(schema, digest):
            completed.add(digest)
        else:
            corrupt.add(digest)
    return frozenset(completed), frozenset(corrupt), tuple(stray)


def _read_record(project_dir: Path, directory: str, name: str) -> dict[str, object]:
    """Read one content-addressed record whose bytes match its name."""

    encoded = read_contained_nofollow(
        project_dir, f"{_LIFECYCLE_DIR}/{directory}/{name}"
    )
    raw = json.loads(encoded)
    if (
        not isinstance(raw, dict)
        or any(not isinstance(value, str) for value in raw.values())
        or hashlib.sha256(encoded).hexdigest() + _JSON_SUFFIX != name
        or encoded != _encode(raw)
    ):
        raise ValueError("cleanup record is not canonical")
    return raw


def _legacy_action(raw: dict[str, object]) -> CleanupAction:
    """Classify one authenticated v1 receipt into its stable action."""

    if set(raw) != _LEGACY_KEYS or raw["schema_version"] != _LEGACY_SCHEMA:
        raise ValueError("unknown v1 receipt shape")
    fields = {key: str(raw[key]) for key in _LEGACY_KEYS - {"schema_version"}}
    owner = (fields["distribution"], fields["pack_id"], fields["entry_point"])
    action = (
        ACTION_CLEAR_WAZUH_ENROLLMENT_BASELINE
        if owner in _LEGACY_BASELINE_RESETS
        else ACTION_PACK_RESET
    )
    classified = CleanupAction(action, ACTION_VERSION, **fields)
    if _SAFE_DIGEST.fullmatch(classified.pack_set_digest) is None or not all(
        (classified.pack_id, classified.pack_version, classified.entry_point)
    ):
        raise ValueError("incomplete v1 receipt")
    return _validated(classified)


def _current_action(raw: dict[str, object]) -> CleanupAction:
    """Parse one authenticated cleanup-action record."""

    if set(raw) != _ACTION_KEYS or raw["schema_version"] != _ACTION_SCHEMA:
        raise ValueError("unknown cleanup record shape")
    return CleanupAction(
        **{key: str(raw[key]) for key in _ACTION_KEYS - {"schema_version"}}
    )


def _load_directory(
    project_dir: Path,
    directory: str,
    completed_directory: str,
    completed_schema: str,
    parse: Callable[[dict[str, object]], CleanupAction],
) -> tuple[list[PendingCleanup], list[UnprocessableCleanup]]:
    """Load one record family, isolating every bad record from the others."""

    pending: list[PendingCleanup] = []
    rejected: list[UnprocessableCleanup] = []
    completed, corrupt, stray = _completions(
        project_dir, completed_directory, completed_schema
    )
    names = _list(project_dir, directory)
    # A completion marker that cannot be tied to a receipt is itself invalid
    # state; report it rather than letting it vanish from the pending result.
    orphaned = sorted(corrupt - {name.removesuffix(_JSON_SUFFIX) for name in names})
    for name in [*stray, *(f"{digest}{_JSON_SUFFIX}" for digest in orphaned)]:
        rejected.append(
            UnprocessableCleanup(_display(completed_directory, name), REASON_MALFORMED)
        )
    for name in names:
        record = _display(directory, name)
        digest = name.removesuffix(_JSON_SUFFIX)
        if _RECORD_NAME.fullmatch(name) is None or digest in corrupt:
            rejected.append(UnprocessableCleanup(record, REASON_MALFORMED))
            continue
        if digest in completed:
            continue
        try:
            action = parse(_read_record(project_dir, directory, name))
        except (OSError, TypeError, ValueError, PathContainmentError):
            rejected.append(UnprocessableCleanup(record, REASON_MALFORMED))
            continue
        if (action.action, action.action_version) not in SUPPORTED_ACTIONS:
            rejected.append(UnprocessableCleanup(record, REASON_UNSUPPORTED))
            continue
        try:
            _validated(action)
        except ValueError:
            rejected.append(UnprocessableCleanup(record, REASON_MALFORMED))
            continue
        pending.append(PendingCleanup(record, action, digest, directory == _LEGACY_DIR))
    return pending, rejected


def load_pending_cleanup(
    project_dir: Path,
) -> tuple[tuple[PendingCleanup, ...], tuple[UnprocessableCleanup, ...]]:
    """Return runnable pending records and records that must stay pending.

    Raises ``ValueError`` only when a lifecycle directory itself cannot be read
    safely; individual bad records never hide the valid ones.
    """

    legacy, legacy_rejected = _load_directory(
        project_dir,
        _LEGACY_DIR,
        _LEGACY_COMPLETED_DIR,
        _LEGACY_COMPLETED_SCHEMA,
        _legacy_action,
    )
    current, current_rejected = _load_directory(
        project_dir,
        _ACTION_DIR,
        _ACTION_COMPLETED_DIR,
        _ACTION_COMPLETED_SCHEMA,
        _current_action,
    )
    return (
        tuple(sorted([*legacy, *current], key=lambda item: item.record)),
        tuple(
            sorted([*legacy_rejected, *current_rejected], key=lambda item: item.record)
        ),
    )


def complete_pending_cleanup(project_dir: Path, pending: PendingCleanup) -> None:
    """Retire one record after its action succeeded, exactly once."""

    directory, completed_directory, schema = (
        (_LEGACY_DIR, _LEGACY_COMPLETED_DIR, _LEGACY_COMPLETED_SCHEMA)
        if pending.legacy
        else (_ACTION_DIR, _ACTION_COMPLETED_DIR, _ACTION_COMPLETED_SCHEMA)
    )
    name = f"{pending.digest}{_JSON_SUFFIX}"
    _read_record(project_dir, directory, name)
    encoded = _completion_payload(schema, pending.digest)
    relative = f"{_LIFECYCLE_DIR}/{completed_directory}/{name}"
    try:
        create_exclusive_nofollow(project_dir, relative, encoded)
    except FileExistsError:
        if read_contained_nofollow(project_dir, relative) != encoded:
            raise ValueError("cleanup completion marker conflict") from None


__all__ = [
    "ACTION_CLEAR_WAZUH_ENROLLMENT_BASELINE",
    "ACTION_PACK_RESET",
    "ACTION_VERSION",
    "SUPPORTED_ACTIONS",
    "CleanupAction",
    "PendingCleanup",
    "UnprocessableCleanup",
    "complete_pending_cleanup",
    "load_pending_cleanup",
    "persist_cleanup_action",
]
