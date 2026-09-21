"""Immutable recovery authority for scenario-adapter reset hooks."""

from __future__ import annotations

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

_STATE_DIR = ".aptl/lifecycle/startup-reset-v1"
_COMPLETED_STATE_DIR = ".aptl/lifecycle/startup-reset-completed-v1"
_SCHEMA = "aptl-startup-reset-authority/v1"
_COMPLETED_SCHEMA = "aptl-startup-reset-completion/v1"
_SAFE_TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
_SAFE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True, order=True)
class StartupResetAuthority:
    """Exact pack and installed entry-point provenance admitted at start."""

    pack_id: str
    pack_version: str
    pack_set_digest: str
    distribution: str
    distribution_version: str
    entry_point: str
    admission_id: str = "legacy"


def _validated(value: object) -> StartupResetAuthority:
    if not isinstance(value, StartupResetAuthority):
        raise ValueError("invalid startup reset authority")
    text = (
        value.pack_id,
        value.pack_version,
        value.entry_point,
        value.admission_id,
    )
    optional_text = (value.distribution, value.distribution_version)
    if (
        any(_SAFE_TEXT.fullmatch(item) is None for item in text)
        or any(item and _SAFE_TEXT.fullmatch(item) is None for item in optional_text)
        or _SAFE_DIGEST.fullmatch(value.pack_set_digest) is None
    ):
        raise ValueError("invalid startup reset authority")
    return value


def _payload(authority: StartupResetAuthority) -> bytes:
    return (
        json.dumps(
            {"schema_version": _SCHEMA, **asdict(authority)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _receipt_digest(authority: StartupResetAuthority) -> str:
    return hashlib.sha256(_payload(_validated(authority))).hexdigest()


def _completion_payload(receipt_digest: str) -> bytes:
    return (
        json.dumps(
            {
                "schema_version": _COMPLETED_SCHEMA,
                "receipt_digest": receipt_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def persist_startup_reset_authority(
    project_dir: Path, authority: StartupResetAuthority
) -> None:
    """Create one no-follow, content-addressed reset receipt."""

    encoded = _payload(_validated(authority))
    digest = _receipt_digest(authority)
    relative = f"{_STATE_DIR}/{digest}.json"
    try:
        create_exclusive_nofollow(project_dir, relative, encoded)
    except FileExistsError:
        if read_contained_nofollow(project_dir, relative) != encoded:
            raise ValueError("startup reset authority receipt conflict") from None


def complete_startup_reset_authority(
    project_dir: Path, authority: StartupResetAuthority
) -> None:
    """Persist an authenticated marker retiring one successful reset receipt."""

    digest = _receipt_digest(authority)
    receipt_relative = f"{_STATE_DIR}/{digest}.json"
    if read_contained_nofollow(project_dir, receipt_relative) != _payload(authority):
        raise ValueError("startup reset authority receipt conflict")
    encoded = _completion_payload(digest)
    relative = f"{_COMPLETED_STATE_DIR}/{digest}.json"
    try:
        create_exclusive_nofollow(project_dir, relative, encoded)
    except FileExistsError:
        if read_contained_nofollow(project_dir, relative) != encoded:
            raise ValueError("startup reset completion marker conflict") from None


def _completed_receipt_digests(project_dir: Path) -> frozenset[str]:
    try:
        names = listdir_contained_nofollow(project_dir, _COMPLETED_STATE_DIR)
    except PathContainmentError as exc:
        if exc.reason == REASON_NOT_FOUND:
            return frozenset()
        raise ValueError("startup reset completion state unavailable") from exc
    completed: set[str] = set()
    for name in names:
        if re.fullmatch(r"[0-9a-f]{64}\.json", name) is None:
            raise ValueError("startup reset completion state malformed")
        try:
            encoded = read_contained_nofollow(
                project_dir, f"{_COMPLETED_STATE_DIR}/{name}"
            )
            raw = json.loads(encoded)
            digest = name.removesuffix(".json")
            if raw != {
                "schema_version": _COMPLETED_SCHEMA,
                "receipt_digest": digest,
            } or encoded != _completion_payload(digest):
                raise ValueError
        except (OSError, TypeError, ValueError, PathContainmentError) as exc:
            raise ValueError("startup reset completion state malformed") from exc
        completed.add(digest)
    return frozenset(completed)


def load_startup_reset_authorities(
    project_dir: Path,
) -> tuple[StartupResetAuthority, ...]:
    """Load and authenticate every previously admitted reset receipt."""

    try:
        names = listdir_contained_nofollow(project_dir, _STATE_DIR)
    except PathContainmentError as exc:
        if exc.reason == REASON_NOT_FOUND:
            return ()
        raise ValueError("startup reset authority state unavailable") from exc
    authorities: list[StartupResetAuthority] = []
    completed = _completed_receipt_digests(project_dir)
    expected_keys = {
        "schema_version",
        "pack_id",
        "pack_version",
        "pack_set_digest",
        "distribution",
        "distribution_version",
        "entry_point",
        "admission_id",
    }
    for name in names:
        if re.fullmatch(r"[0-9a-f]{64}\.json", name) is None:
            raise ValueError("startup reset authority state malformed")
        try:
            encoded = read_contained_nofollow(project_dir, f"{_STATE_DIR}/{name}")
            raw = json.loads(encoded)
            if (
                not isinstance(raw, dict)
                or set(raw) != expected_keys
                or raw["schema_version"] != _SCHEMA
            ):
                raise ValueError
            authority = _validated(
                StartupResetAuthority(
                    pack_id=raw["pack_id"],
                    pack_version=raw["pack_version"],
                    pack_set_digest=raw["pack_set_digest"],
                    distribution=raw["distribution"],
                    distribution_version=raw["distribution_version"],
                    entry_point=raw["entry_point"],
                    admission_id=raw["admission_id"],
                )
            )
            canonical = _payload(authority)
            if (
                encoded != canonical
                or hashlib.sha256(canonical).hexdigest() + ".json" != name
            ):
                raise ValueError
        except (OSError, TypeError, ValueError, PathContainmentError) as exc:
            raise ValueError("startup reset authority state malformed") from exc
        if name.removesuffix(".json") not in completed:
            authorities.append(authority)
    return tuple(sorted(set(authorities)))


__all__ = [
    "StartupResetAuthority",
    "complete_startup_reset_authority",
    "load_startup_reset_authorities",
    "persist_startup_reset_authority",
]
