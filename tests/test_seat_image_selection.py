"""Which seat VM disk boots, and when a newer one is only offered."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from aptl.appliance.seat import image_selection
from aptl.appliance.seat.image import (
    SeatDiskDescriptor,
    SeatImageError,
    parse_seat_image_reference,
    write_verification_stamp,
)
from aptl.appliance.seat.image_selection import (
    check_for_update,
    load_selection,
    select_seat_image,
)

REFERENCE = "ghcr.io/owner/seat:latest"


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


OLD = _digest(b"old-disk")
NEW = _digest(b"new-disk")


@pytest.fixture
def registry(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """A registry whose tag can be moved, recording every resolution."""

    state: dict[str, object] = {"digest": OLD, "size": 8, "resolutions": 0, "pulls": []}

    def fake_descriptor(reference):
        state["resolutions"] = int(state["resolutions"]) + 1
        parsed = (
            reference
            if not isinstance(reference, str)
            else parse_seat_image_reference(reference)
        )
        return SeatDiskDescriptor(
            reference=parsed,
            digest=str(state["digest"]),
            size_bytes=int(state["size"]),
            manifest_digest=_digest(b"manifest"),
            token="pull-token",
        )

    def fake_fetch(reference, *, digest, size_bytes, cache_dir, token=None):
        state["pulls"].append(digest)  # type: ignore[union-attr]
        disk = Path(cache_dir) / digest.removeprefix("sha256:") / "seat-disk.qcow2"
        disk.parent.mkdir(parents=True, exist_ok=True)
        disk.write_bytes(b"x" * size_bytes)
        disk.chmod(0o444)
        write_verification_stamp(disk, digest=digest, size_bytes=size_bytes)
        return disk

    monkeypatch.setattr(image_selection, "resolve_disk_descriptor", fake_descriptor)
    monkeypatch.setattr(image_selection, "fetch_seat_disk", fake_fetch)

    def fake_resolve(reference, *, cache_dir):
        descriptor = fake_descriptor(reference)
        path = fake_fetch(
            descriptor.reference,
            digest=descriptor.digest,
            size_bytes=descriptor.size_bytes,
            cache_dir=cache_dir,
        )

        class _Staged:
            digest = descriptor.digest
            size_bytes = descriptor.size_bytes
            reused = False

        _Staged.path = path
        return _Staged

    monkeypatch.setattr(image_selection, "resolve_seat_image", fake_resolve)
    return state


def test_first_use_pulls_and_records_the_selection(registry, tmp_path) -> None:
    selection = select_seat_image(REFERENCE, cache_dir=tmp_path, now=1000.0)

    assert selection.digest == OLD
    assert selection.pulled is True
    recorded = load_selection(tmp_path, parse_seat_image_reference(REFERENCE))
    assert recorded["digest"] == OLD


def test_warm_start_does_not_contact_the_registry(registry, tmp_path) -> None:
    select_seat_image(REFERENCE, cache_dir=tmp_path, now=1000.0)
    resolutions = registry["resolutions"]

    selection = select_seat_image(REFERENCE, cache_dir=tmp_path, now=1000.0)

    # Within the check interval a warm start is a pure cache hit: no manifest
    # resolution and no download.
    assert selection.digest == OLD
    assert selection.pulled is False
    assert registry["resolutions"] == resolutions
    assert registry["pulls"] == [OLD]


def test_a_moved_tag_does_not_change_what_boots(registry, tmp_path) -> None:
    select_seat_image(REFERENCE, cache_dir=tmp_path, now=1000.0)
    registry["digest"] = NEW

    later = select_seat_image(REFERENCE, cache_dir=tmp_path, now=1_000_000.0)

    # The whole point: :latest moved, and the seat still boots what it had.
    assert later.digest == OLD
    assert later.path.exists()
    assert NEW not in registry["pulls"]


def test_a_moved_tag_is_reported_as_available(registry, tmp_path) -> None:
    select_seat_image(REFERENCE, cache_dir=tmp_path, now=1000.0)
    registry["digest"] = NEW

    later = select_seat_image(REFERENCE, cache_dir=tmp_path, now=1_000_000.0)

    assert later.update_available is True
    assert later.available_digest == NEW


def test_adopting_moves_the_selection_and_keeps_the_old_disk(
    registry, tmp_path
) -> None:
    select_seat_image(REFERENCE, cache_dir=tmp_path, now=1000.0)
    registry["digest"] = NEW

    adopted = select_seat_image(
        REFERENCE, cache_dir=tmp_path, adopt=True, now=1_000_000.0
    )

    assert adopted.digest == NEW
    # Rollback is only possible because adoption does not delete the old disk.
    assert (tmp_path / OLD.removeprefix("sha256:") / "seat-disk.qcow2").exists()


def test_rollback_reselects_a_cached_digest(registry, tmp_path) -> None:
    select_seat_image(REFERENCE, cache_dir=tmp_path, now=1000.0)
    registry["digest"] = NEW
    select_seat_image(REFERENCE, cache_dir=tmp_path, adopt=True, now=1_000_000.0)

    rolled_back = select_seat_image(
        REFERENCE, cache_dir=tmp_path, adopt_digest=OLD, now=1_000_001.0
    )

    assert rolled_back.digest == OLD
    assert select_seat_image(REFERENCE, cache_dir=tmp_path, now=1_000_002.0).digest == (
        OLD
    )


def test_rollback_to_an_uncached_digest_is_refused(registry, tmp_path) -> None:
    select_seat_image(REFERENCE, cache_dir=tmp_path, now=1000.0)

    with pytest.raises(SeatImageError, match="not in the local cache"):
        select_seat_image(REFERENCE, cache_dir=tmp_path, adopt_digest=NEW)


def test_cleared_cache_refetches_the_selected_digest_not_the_tag(
    registry, tmp_path
) -> None:
    select_seat_image(REFERENCE, cache_dir=tmp_path, now=1000.0)
    disk = tmp_path / OLD.removeprefix("sha256:") / "seat-disk.qcow2"
    disk.chmod(0o644)
    disk.unlink()
    registry["digest"] = NEW

    restored = select_seat_image(REFERENCE, cache_dir=tmp_path, now=1_000_000.0)

    # Losing the cache must not silently upgrade the operator.
    assert restored.digest == OLD
    assert registry["pulls"] == [OLD, OLD]


def test_registry_failure_never_blocks_a_warm_start(
    registry, tmp_path, monkeypatch
) -> None:
    select_seat_image(REFERENCE, cache_dir=tmp_path, now=1000.0)

    def unreachable(reference):
        raise SeatImageError("registry unreachable")

    monkeypatch.setattr(image_selection, "resolve_disk_descriptor", unreachable)

    selection = select_seat_image(REFERENCE, cache_dir=tmp_path, now=1_000_000.0)

    assert selection.digest == OLD
    assert selection.update_available is False


def test_update_check_is_rate_limited(registry, tmp_path) -> None:
    select_seat_image(REFERENCE, cache_dir=tmp_path, now=1000.0)
    resolutions = registry["resolutions"]

    select_seat_image(REFERENCE, cache_dir=tmp_path, now=1500.0)
    assert registry["resolutions"] == resolutions

    select_seat_image(REFERENCE, cache_dir=tmp_path, now=1000.0 + 90_000)
    assert registry["resolutions"] == resolutions + 1


def test_check_can_be_disabled_entirely(registry, tmp_path) -> None:
    select_seat_image(REFERENCE, cache_dir=tmp_path, now=1000.0)
    resolutions = registry["resolutions"]

    select_seat_image(REFERENCE, cache_dir=tmp_path, check=False, now=1_000_000.0)

    assert registry["resolutions"] == resolutions


def test_digest_pinned_reference_is_never_checked(registry, tmp_path) -> None:
    pinned = f"ghcr.io/owner/seat@{OLD}"
    select_seat_image(pinned, cache_dir=tmp_path, now=1000.0)
    resolutions = registry["resolutions"]

    selection = select_seat_image(pinned, cache_dir=tmp_path, now=1_000_000.0)

    assert selection.update_available is False
    assert registry["resolutions"] == resolutions


def test_distinct_references_keep_distinct_selections(registry, tmp_path) -> None:
    select_seat_image(REFERENCE, cache_dir=tmp_path, now=1000.0)
    registry["digest"] = NEW

    other = select_seat_image(
        "ghcr.io/owner/other:latest", cache_dir=tmp_path, now=1000.0
    )

    assert other.digest == NEW
    assert select_seat_image(REFERENCE, cache_dir=tmp_path, now=1000.0).digest == OLD


def test_check_for_update_reports_nothing_when_current(registry, tmp_path) -> None:
    select_seat_image(REFERENCE, cache_dir=tmp_path, now=1000.0)

    assert (
        check_for_update(
            tmp_path,
            parse_seat_image_reference(REFERENCE),
            selected_digest=OLD,
            force=True,
        )
        is None
    )
