"""Decide which seat VM disk boots, and when a newer one is merely offered.

A mutable tag such as ``:latest`` must not silently change what an operator
boots.  The digest a reference first resolved to is therefore *sticky*: it is
recorded and keeps booting until the operator adopts something else.  Checking
for a newer image is separate from adopting one, never gates the boot path,
and fails open so that a registry outage, a captive portal or an aeroplane
cannot stop a seat starting.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from aptl.appliance.seat.image import (
    SeatImageError,
    SeatImageReference,
    fetch_seat_disk,
    parse_seat_image_reference,
    resolve_disk_descriptor,
    resolve_seat_image,
    verified_cached_disk,
)

SELECTION_SCHEMA = "aptl.seat-image-selection/v1"

_HEX_KEY = re.compile(r"^[a-f0-9]{32}$")

# A warm start must not depend on the registry, so the update check is
# rate-limited rather than run on every launch.
DEFAULT_CHECK_INTERVAL_SECONDS = 24 * 60 * 60


@dataclass(frozen=True)
class SeatImageSelection:
    """The disk one reference boots, plus any newer one observed."""

    reference: SeatImageReference
    digest: str
    size_bytes: int
    path: Path
    available_digest: str | None = None
    available_size_bytes: int | None = None
    pulled: bool = False

    @property
    def update_available(self) -> bool:
        """Return whether a newer digest has been seen but not adopted."""

        return (
            self.available_digest is not None and self.available_digest != self.digest
        )


def _selection_path(cache_dir: Path, reference: SeatImageReference) -> Path:
    """Return the selection record for one reference.

    The reference is operator input that would otherwise become a filename, so
    the record is named by a digest of it rather than by the reference itself,
    and the result is confirmed to stay inside the cache.
    """

    key = hashlib.sha256(str(reference).encode()).hexdigest()[:32]
    if not _HEX_KEY.fullmatch(key):  # pragma: no cover - hexdigest is hex
        raise SeatImageError("seat image selection key is not a digest")
    path = cache_dir / "refs" / f"{key}.json"
    if not path.is_relative_to(cache_dir):
        raise SeatImageError("seat image selection record escapes the cache")
    return path


def load_selection(cache_dir: Path, reference: SeatImageReference) -> dict[str, object]:
    """Read the recorded selection for one reference, tolerating absence."""

    try:
        document = json.loads(
            _selection_path(cache_dir, reference).read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        return {}
    if not isinstance(document, dict) or document.get("schema_version") != (
        SELECTION_SCHEMA
    ):
        return {}
    return document


def save_selection(
    cache_dir: Path,
    reference: SeatImageReference,
    *,
    digest: str,
    size_bytes: int,
    available_digest: str | None = None,
    available_size_bytes: int | None = None,
    last_checked: float | None = None,
) -> None:
    """Record which digest this reference boots, atomically."""

    path = _selection_path(cache_dir, reference)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    document = {
        "schema_version": SELECTION_SCHEMA,
        "reference": str(reference),
        "digest": digest,
        "size_bytes": size_bytes,
        "available_digest": available_digest,
        "available_size_bytes": available_size_bytes,
        "last_checked": last_checked,
    }
    temporary = path.with_suffix(".partial")
    temporary.write_text(
        json.dumps(document, separators=(",", ":"), sort_keys=True), encoding="utf-8"
    )
    temporary.replace(path)


def check_for_update(
    cache_dir: Path,
    reference: SeatImageReference,
    *,
    selected_digest: str,
    now: float | None = None,
    interval_seconds: int = DEFAULT_CHECK_INTERVAL_SECONDS,
    force: bool = False,
) -> tuple[str, int] | None:
    """Return a newer ``(digest, size)`` when one is published, else ``None``.

    This never raises for a registry problem.  A seat that cannot reach the
    registry is not out of date as far as it can tell, and must still boot.
    """

    if reference.digest is not None:
        # A digest-pinned reference is exactly what the operator asked for.
        return None
    recorded = load_selection(cache_dir, reference)
    last_checked = recorded.get("last_checked")
    if (
        not force
        and isinstance(last_checked, int | float)
        and (now or time.time()) - last_checked < interval_seconds
    ):
        available = recorded.get("available_digest")
        size = recorded.get("available_size_bytes")
        if isinstance(available, str) and isinstance(size, int):
            return (available, size)
        return None

    try:
        remote = resolve_disk_descriptor(reference)
    except SeatImageError:
        return None

    available = None if remote.digest == selected_digest else remote.digest
    save_selection(
        cache_dir,
        reference,
        digest=selected_digest,
        size_bytes=int(recorded.get("size_bytes") or remote.size_bytes),
        available_digest=available,
        available_size_bytes=remote.size_bytes if available else None,
        last_checked=now or time.time(),
    )
    return (remote.digest, remote.size_bytes) if available else None


def select_seat_image(
    reference: str | SeatImageReference,
    *,
    cache_dir: Path,
    adopt: bool = False,
    adopt_digest: str | None = None,
    check: bool = True,
    now: float | None = None,
) -> SeatImageSelection:
    """Resolve which disk this seat boots, pulling only when it must.

    ``adopt`` moves the selection to whatever the reference resolves to now;
    ``adopt_digest`` moves it to a specific already-known digest, which is how
    a rollback re-selects a previous image.  Neither happens on an ordinary
    start.
    """

    parsed = (
        reference
        if isinstance(reference, SeatImageReference)
        else parse_seat_image_reference(reference)
    )
    recorded = load_selection(cache_dir, parsed)
    selected = recorded.get("digest")
    selected_size = recorded.get("size_bytes")

    if adopt_digest is not None:
        disk = verified_cached_disk(cache_dir, digest=adopt_digest)
        if disk is None:
            raise SeatImageError(
                f"seat image {adopt_digest} is not in the local cache; "
                "pull it before selecting it"
            )
        size = disk.stat().st_size
        save_selection(
            cache_dir, parsed, digest=adopt_digest, size_bytes=size, last_checked=now
        )
        return SeatImageSelection(
            reference=parsed, digest=adopt_digest, size_bytes=size, path=disk
        )

    # A pinned reference, a first use, or an explicit adoption all resolve
    # against the registry. Everything else boots what is already selected.
    if adopt or not isinstance(selected, str) or not isinstance(selected_size, int):
        staged = resolve_seat_image(parsed, cache_dir=cache_dir)
        save_selection(
            cache_dir,
            parsed,
            digest=staged.digest,
            size_bytes=staged.size_bytes,
            last_checked=now or time.time(),
        )
        return SeatImageSelection(
            reference=parsed,
            digest=staged.digest,
            size_bytes=staged.size_bytes,
            path=staged.path,
            pulled=not staged.reused,
        )

    disk = verified_cached_disk(cache_dir, digest=selected, size_bytes=selected_size)
    pulled = False
    if disk is None:
        # The selection survives a cleared cache: re-fetch that exact digest
        # rather than silently moving to whatever the tag points at now.
        disk = fetch_seat_disk(
            parsed, digest=selected, size_bytes=selected_size, cache_dir=cache_dir
        )
        pulled = True

    newer = (
        check_for_update(cache_dir, parsed, selected_digest=selected, now=now)
        if check
        else None
    )
    return SeatImageSelection(
        reference=parsed,
        digest=selected,
        size_bytes=selected_size,
        path=disk,
        available_digest=newer[0] if newer else None,
        available_size_bytes=newer[1] if newer else None,
        pulled=pulled,
    )


@dataclass(frozen=True)
class CachedSeatImage:
    """One seat disk in the local cache, and what still selects it."""

    digest: str
    size_bytes: int
    selected_by: tuple[str, ...]


def _selected_digests(cache_dir: Path) -> dict[str, list[str]]:
    """Map each selected digest to the references selecting it."""

    selected: dict[str, list[str]] = {}
    for path in sorted((cache_dir / "refs").glob("*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        digest = document.get("digest")
        reference = document.get("reference")
        if isinstance(digest, str) and isinstance(reference, str):
            selected.setdefault(digest, []).append(reference)
    return selected


def list_cached_images(cache_dir: Path) -> list[CachedSeatImage]:
    """List cached seat disks with the references that select them."""

    selected = _selected_digests(cache_dir)
    images: list[CachedSeatImage] = []
    for entry in sorted(cache_dir.glob("*/seat-disk.qcow2")):
        digest = "sha256:" + entry.parent.name
        try:
            size = entry.stat().st_size
        except OSError:
            continue
        images.append(
            CachedSeatImage(
                digest=digest,
                size_bytes=size,
                selected_by=tuple(selected.get(digest, ())),
            )
        )
    return images


def prune_cached_images(cache_dir: Path) -> tuple[str, ...]:
    """Remove cached disks no reference selects.

    A selected disk is never removed, so the image a seat boots and any
    rollback target that is still selected both survive.
    """

    removed: list[str] = []
    for image in list_cached_images(cache_dir):
        if image.selected_by:
            continue
        entry = cache_dir / image.digest.removeprefix("sha256:")
        for path in sorted(entry.glob("*")):
            path.chmod(0o600)
            path.unlink()
        entry.rmdir()
        removed.append(image.digest)
    return tuple(removed)
