"""Keep each staged generation independent of mutable shared cache selections."""

from __future__ import annotations

import errno
import os
import shutil
import tempfile
from pathlib import Path

from aptl.appliance.seat.image_disk_cache import SeatImageError, _cache_entry, write_verification_stamp
from aptl.appliance.seat.image_selection import SeatImageSelection, cached_selection, save_selection
from aptl.appliance.seat.image_trust import _key_path, configure_trust
from aptl.appliance.seat.persistence import load_seat_record
from aptl.utils.pathsafe import open_contained_nofollow


def cache_for_seat(seat_root: Path, reference: str, shared_cache: Path) -> Path:
    """Existing generations use their own disk, config, and publisher trust."""

    record = load_seat_record(seat_root)
    if record is not None and record.image_reference == reference:
        retained = seat_root / "image"
        selected = cached_selection(reference, cache_dir=retained)
        if selected is None or selected.digest != record.image_digest:
            raise SeatImageError("seat's retained image is unavailable or does not match its generation")
        return retained
    return shared_cache


def retain_image(seat_root: Path, shared_cache: Path, selection: SeatImageSelection) -> None:
    """Retain admitted bytes and metadata before publishing a staged generation."""

    destination = seat_root / "image"
    if shared_cache == destination:
        return
    seat_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    reference = str(selection.reference)
    # Revalidate before copying metadata; a copied stamp cannot establish trust.
    admitted = cached_selection(reference, cache_dir=shared_cache)
    if admitted is None or admitted.digest != selection.digest:
        raise SeatImageError("selected image changed before retention")
    temporary = Path(tempfile.mkdtemp(prefix=".image-", dir=seat_root))
    previous = seat_root / ".previous-image"
    try:
        target = _cache_entry(temporary, selection.digest)
        target.parent.mkdir(mode=0o700)
        try:
            os.link(selection.path, target, follow_symlinks=False)
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                raise
            with open_contained_nofollow(shared_cache, selection.path.relative_to(shared_cache)) as source:
                with target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
            target.chmod(0o444)
        write_verification_stamp(target, digest=selection.digest, size_bytes=selection.size_bytes)
        for name in ("seat-config.json", "seat-config-binding.json", "cosign-verification.json"):
            relative = selection.path.parent.relative_to(shared_cache) / name
            with open_contained_nofollow(shared_cache, relative) as source:
                with (target.parent / name).open("xb") as output:
                    os.fchmod(output.fileno(), 0o600)
                    shutil.copyfileobj(source, output)
        configure_trust(temporary, reference, _key_path(shared_cache, reference))
        save_selection(temporary, selection.reference, digest=selection.digest, size_bytes=selection.size_bytes)
        cached_selection(reference, cache_dir=temporary)
        if destination.exists():
            destination.rename(previous)
        try:
            temporary.rename(destination)
        except OSError:
            if previous.exists():
                previous.rename(destination)
            raise
        if previous.exists():
            shutil.rmtree(previous)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
