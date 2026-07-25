"""Content-addressed + run-scoped create-once evidence persistence (EXP-010 /
issue #752 preflight "Evidence ownership and persistence").

The preflight requires the ``RunStorageBackend`` boundary to be EXTENDED
narrowly for streamed content-addressed blob insertion and run-scoped
create-once canonical JSON — NOT a second evidence repository beside
``LocalRunStore``. These functions are that narrow extension: they operate on
the injected store (via its public ``base_dir`` / ``get_run_path``) and reuse
the store's own ID/path validation, canonicalization, secret-invariant, and
no-follow/create-exclusive primitives. The coordinator derives every location
from a validated id + the computed digest; a plugin never supplies a path.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from aptl.core.runstore import (
    LocalRunStore,
    RunStoreConflictError,
    _assert_no_secret_drift,
    _canonicalize_payload,
    _validate_id,
    _validate_relative_path,
)
from aptl.utils.pathsafe import create_exclusive_nofollow, read_contained_nofollow


@dataclass(frozen=True)
class ContentInsertion:
    """The result of a content-addressed evidence blob insertion.

    ``relative_path`` is the run-relative POSIX path of the stored object
    (``<subdir>/<sha256-hex>``); ``digest`` is its ``sha256:<hex>`` prefixed
    digest; ``size`` is the bytes actually retained; ``truncated`` is ``True``
    when the source exceeded the byte quota and only the first ``size`` bytes
    were kept (a distinct, disclosed outcome — never a silent drop).
    """

    relative_path: str
    digest: str
    size: int
    truncated: bool


def _accumulate_bounded(chunks: Iterable[bytes], max_bytes: int) -> tuple[bytes, bool]:
    """Accumulate ``chunks`` up to ``max_bytes``; return ``(bytes, truncated)``.

    The quota is enforced during iteration so an over-quota source is never
    buffered unbounded. Truncation is detected precisely — an over-filling
    chunk sets it directly; an exact fill peeks at most ONE further chunk
    (never draining the rest) to tell "ended at the cap" from "more dropped".
    """
    buf = bytearray()
    truncated = False
    iterator = iter(chunks)
    for chunk in iterator:
        space = max_bytes - len(buf)
        if len(chunk) < space:
            buf.extend(chunk)
            continue
        buf.extend(chunk[:space])
        truncated = len(chunk) > space or next(iterator, None) is not None
        break
    return bytes(buf), truncated


def create_content_addressed(
    store: LocalRunStore, run_id: str, chunks: Iterable[bytes], *, subdir: str, max_bytes: int
) -> ContentInsertion:
    """Stream ``chunks`` into a content-addressed blob under ``<run_id>/<subdir>/<sha256-hex>``.

    Enforces the byte quota WHILE streaming (over-quota input is truncated, not
    buffered unbounded), publishes descriptor-relative / no-follow /
    create-exclusive, and re-reads + re-verifies the stored object's digest and
    size. A repeated digest is idempotent only when the existing bytes agree; a
    collision with different bytes fails closed.
    """
    safe_run_id = _validate_id(run_id, "run_id")
    safe_subdir = _validate_relative_path(subdir)
    if max_bytes <= 0:
        raise ValueError("create_content_addressed max_bytes must be positive")

    data, truncated = _accumulate_bounded(chunks, max_bytes)
    digest_hex = hashlib.sha256(data).hexdigest()
    relative_path = f"{safe_subdir}/{digest_hex}"
    rel = f"{safe_run_id}/{relative_path}"

    base_dir = store.base_dir
    base_dir.mkdir(parents=True, exist_ok=True)
    try:
        create_exclusive_nofollow(base_dir, rel, data)
    except FileExistsError:
        if read_contained_nofollow(base_dir, rel) != data:
            raise RunStoreConflictError(
                f"create_content_addressed digest collision with different bytes: {run_id}/{relative_path}"
            ) from None

    stored = read_contained_nofollow(base_dir, rel)
    if len(stored) != len(data) or hashlib.sha256(stored).hexdigest() != digest_hex:
        raise RunStoreConflictError(
            f"create_content_addressed post-write verification failed: {run_id}/{relative_path}"
        )
    return ContentInsertion(
        relative_path=relative_path, digest=f"sha256:{digest_hex}", size=len(data), truncated=truncated
    )


def create_run_json_once(store: LocalRunStore, run_id: str, relative_path: str, payload: object) -> Path:
    """Create-once, canonical, no-follow JSON persistence UNDER the run dir.

    Like the store's ``create_json_once`` but run-scoped, so the evidence
    ledger travels in the exporter's per-run tar. Same secret invariant,
    RFC-8785 canonicalization, and idempotent-on-byte-match semantics; a
    differing existing target raises :class:`RunStoreConflictError`.
    """
    safe_run_id = _validate_id(run_id, "run_id")
    safe_rel = _validate_relative_path(relative_path)
    canonical, normalized = _canonicalize_payload(payload)
    _assert_no_secret_drift(normalized)

    base_dir = store.base_dir
    base_dir.mkdir(parents=True, exist_ok=True)
    rel = f"{safe_run_id}/{safe_rel}"
    target = store.get_run_path(run_id) / safe_rel
    try:
        create_exclusive_nofollow(base_dir, rel, canonical)
    except FileExistsError:
        if read_contained_nofollow(base_dir, rel) != canonical:
            raise RunStoreConflictError(
                f"create_run_json_once target already exists with different content: {run_id}/{relative_path}"
            ) from None
    return target
