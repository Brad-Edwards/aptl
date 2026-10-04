"""Confirmed replacement of one stopped seat and its selected base image."""

from pathlib import Path

from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.image_selection import (
    SeatImageSelection, retire_cached_image, select_seat_image,
    load_selection, save_selection, _selection_path,
)
from aptl.appliance.seat.image import parse_seat_image_reference
from aptl.appliance.seat.lifecycle import (
    reset_seat, _seat_paths, _load_seat_image, _validated_mappings,
)
from aptl.appliance.seat.prereqs import require_host_prerequisites
from aptl.appliance.seat.models import SeatRecord
from aptl.appliance.seat.locking import serialized_seat_mutation
from aptl.appliance.seat.persistence import load_seat_record
from aptl.appliance.seat.vm import read_vm_pid
from aptl.appliance.seat.launch_descriptor import SeatLaunchDescriptor
from aptl.utils.strict_json import model_validate_json_strict


def _validate_replacement(
    seat_root: Path, image_reference: str, cache: Path, previous: SeatRecord | None,
    desktop_mode: str | None,
) -> None:
    """Admit capacity and existing mappings before discarding any seat state."""

    paths = _seat_paths(
        seat_root, seat_id=previous.seat_id if previous else "seat-01",
        image_reference=image_reference, image_cache_dir=cache,
    )
    image = _load_seat_image(paths, use_retained=False)
    previous_mode = None
    descriptor_path = seat_root / "launch/appliance-launch.json"
    if previous is not None and descriptor_path.is_file():
        previous_mode = model_validate_json_strict(
            SeatLaunchDescriptor, descriptor_path.read_bytes()
        ).desktop_mode
    selected_mode = desktop_mode if desktop_mode is not None else previous_mode
    supported = image.config.desktop_privilege_contract is not None
    if supported and selected_mode not in {"administrative", "event"}:
        raise SeatLauncherError("invalid-desktop-mode", "select administrative or event desktop mode")
    if not supported and selected_mode is not None:
        raise SeatLauncherError("unsupported-desktop-mode", "selected image does not support desktop modes")
    require_host_prerequisites(
        image.config.resources, seat_root=seat_root,
        required_free_disk_bytes=image.runtime_disk_bytes,
    )
    _validated_mappings(image.policy, previous.mappings if previous else None)


@serialized_seat_mutation
def update_seat_image(
    seat_root: Path, *, image_reference: str, image_cache_dir: Path,
    to_digest: str | None = None,
    desktop_mode: str | None = None,
) -> tuple[SeatImageSelection, tuple[str, ...]]:
    """Download and verify first; reset and retire only after successful admission."""

    if read_vm_pid(seat_root) is not None:
        raise SeatLauncherError("seat-running", "stop the seat before updating its image")
    previous = load_seat_record(seat_root)
    reference = parse_seat_image_reference(image_reference)
    recorded = load_selection(image_cache_dir, reference)
    try:
        selection = select_seat_image(
            image_reference, cache_dir=image_cache_dir,
            adopt=to_digest is None, adopt_digest=to_digest, check=False,
        )
        _validate_replacement(
            seat_root, image_reference, image_cache_dir, previous, desktop_mode
        )
    except Exception:
        # The cache lock prevents another seat observing the candidate selection.
        if recorded:
            save_selection(
                image_cache_dir, reference,
                **{key: value for key, value in recorded.items()
                   if key not in {"schema_version", "reference"}},
            )
        else:
            _selection_path(image_cache_dir, reference).unlink(missing_ok=True)
        raise
    removed: tuple[str, ...] = ()
    if previous is not None:
        reset_seat(
            seat_root, seat_id=previous.seat_id, image_reference=image_reference,
            image_cache_dir=image_cache_dir, replace_image=True,
            desktop_mode=desktop_mode,
        )
    old_digest = previous.image_digest if previous else recorded.get("digest")
    if isinstance(old_digest, str) and old_digest != selection.digest:
        if retire_cached_image(image_cache_dir, old_digest):
            removed = (old_digest,)
    return selection, removed
