"""Image replacement must not destroy a backing file used by another seat."""

import subprocess
import sys
from pathlib import Path

from aptl.appliance.seat.overlay import create_seat_overlay

import pytest
from unittest.mock import Mock
from aptl.appliance.seat.errors import SeatLauncherError


def test_overlay_survives_cache_retirement(tmp_path: Path) -> None:
    import shutil
    if shutil.which("qemu-img") is None:
        pytest.skip("QEMU tooling is unavailable")
    base = tmp_path / "cache" / "seat.qcow2"
    base.parent.mkdir()
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(base), "1M"], check=True, capture_output=True)
    base.chmod(0o444)
    overlay = tmp_path / "seat" / "overlay.qcow2"
    create_seat_overlay(overlay, image_path=base)
    base.unlink()

    result = subprocess.run(
        ["qemu-img", "check", str(overlay)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_update_refuses_running_vm_before_download(tmp_path, monkeypatch) -> None:
    from aptl.appliance.seat import image_update
    monkeypatch.setattr(image_update, "read_vm_pid", lambda root: 123)
    download = Mock()
    monkeypatch.setattr(image_update, "select_seat_image", download)
    with pytest.raises(SeatLauncherError, match="stop"):
        image_update.update_seat_image(
            tmp_path / "seat", image_reference="ghcr.io/example/seat:latest",
            image_cache_dir=tmp_path / "cache",
        )
    download.assert_not_called()


def test_reset_removes_nested_state_without_following_links(tmp_path) -> None:
    from aptl.appliance.seat.overlay_cleanup import remove_overlay_artifacts
    state = tmp_path / "state"
    (state / "nested").mkdir(parents=True)
    (state / "nested" / "generated-state").write_text("discard")
    outside = tmp_path / "outside"
    outside.mkdir()
    retained = outside / "retained"
    retained.write_text("keep")
    (state / "linked").symlink_to(outside, target_is_directory=True)
    remove_overlay_artifacts(state)
    assert not state.exists()
    assert retained.read_text() == "keep"


def test_cache_prune_cannot_race_another_operation(tmp_path) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from aptl.appliance.seat.locking import seat_mutation_lock
    from aptl.appliance.seat.image_selection import prune_cached_images

    cache = tmp_path / "cache"
    with seat_mutation_lock(cache), ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(prune_cached_images, cache)
        with pytest.raises(SeatLauncherError, match="another"):
            pending.result(timeout=5)


def test_failed_update_admission_preserves_selection_and_overlay(tmp_path, monkeypatch) -> None:
    from types import SimpleNamespace
    from aptl.appliance.seat import image_update
    from aptl.appliance.seat.image_selection import save_selection, load_selection
    from aptl.appliance.seat.image import parse_seat_image_reference

    root, cache = tmp_path / "seat", tmp_path / "cache"
    root.mkdir()
    overlay = root / "overlay.qcow2"
    overlay.write_bytes(b"existing state")
    reference = parse_seat_image_reference("ghcr.io/example/seat:latest")
    old, new = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    save_selection(cache, reference, digest=old, size_bytes=1)
    before = load_selection(cache, reference)
    monkeypatch.setattr(image_update, "read_vm_pid", lambda root: None)
    monkeypatch.setattr(image_update, "load_seat_record", lambda root: SimpleNamespace(
        image_digest=old, seat_id="seat-01", mappings=(),
    ))
    def acquire(*args, **kwargs):
        save_selection(cache, reference, digest=new, size_bytes=2)
        return SimpleNamespace(digest=new, size_bytes=2, reference=reference)
    monkeypatch.setattr(image_update, "select_seat_image", acquire)
    monkeypatch.setattr(image_update, "_validate_replacement", Mock(side_effect=SeatLauncherError(
        "insufficient-disk", "not enough disk space"
    )), raising=False)
    reset = Mock()
    monkeypatch.setattr(image_update, "reset_seat", reset)
    with pytest.raises(SeatLauncherError, match="disk space"):
        image_update.update_seat_image(root, image_reference=str(reference), image_cache_dir=cache)
    reset.assert_not_called()
    assert load_selection(cache, reference) == before
    assert overlay.read_bytes() == b"existing state"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux seat lifecycle")
def test_updating_one_seat_retains_another_seats_offline_image(tmp_path, monkeypatch):
    import hashlib
    from aptl.appliance.seat import image, image_trust, lifecycle, image_update
    from aptl.appliance.seat.image_selection import save_selection, select_seat_image
    from aptl.appliance.seat.image_disk_cache import write_verification_stamp
    from tests.test_seat_image_config import _config
    from tests.test_seat_image_trust import public_key, claims, MANIFEST, REFERENCE

    cache = tmp_path / "shared"
    reference = image.parse_seat_image_reference(REFERENCE)
    image_trust.configure_trust(cache, REFERENCE, public_key(tmp_path))
    monkeypatch.setattr(image_trust.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 0, claims(), b""))
    config = _config()
    monkeypatch.setattr(image, "fetch_https_metadata", lambda *a, **k: config)
    def seed(payload):
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        disk = cache / digest[7:] / "seat-disk.qcow2"
        disk.parent.mkdir(parents=True)
        disk.write_bytes(payload)
        disk.chmod(0o444)
        write_verification_stamp(disk, digest=digest, size_bytes=len(payload))
        config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
        descriptor = image.SeatDiskDescriptor(reference, digest, len(payload), MANIFEST, None, config_digest, len(config))
        image.cache_seat_image_config(descriptor, cache)
        receipt = image_trust.verify_remote_image(cache, REFERENCE, MANIFEST, digest, config_digest)
        image_trust.publish_verified_image(cache, receipt)
        save_selection(cache, reference, digest=digest, size_bytes=len(payload))
        return select_seat_image(reference, cache_dir=cache, check=False)
    old = seed(b"old disk")
    monkeypatch.setattr(lifecycle, "require_host_prerequisites", lambda *a, **k: None)
    monkeypatch.setattr(image_update, "require_host_prerequisites", lambda *a, **k: None)
    monkeypatch.setattr(lifecycle, "stop_vm", lambda *a: None)
    monkeypatch.setattr(lifecycle, "invalidate_host_access", lambda *a, **k: None)
    roots = [tmp_path / "seat-a", tmp_path / "seat-b"]
    for root in roots:
        lifecycle.stage_seat(root, seat_id="seat-01", image_reference=REFERENCE, image_cache_dir=cache)
    descriptor_before = (roots[1] / "launch/appliance-launch.json").read_bytes()
    new = seed(b"new disk")
    monkeypatch.setattr(image_update, "select_seat_image", lambda *a, **k: new)
    image_update.update_seat_image(roots[0], image_reference=REFERENCE, image_cache_dir=cache)
    assert not old.path.exists()  # The shared copy really was retired.
    monkeypatch.setattr(image, "resolve_disk_descriptor", lambda *a: pytest.fail("offline restart contacted registry"))
    for root, expected in zip(roots, (new, old), strict=True):
        paths = lifecycle._seat_paths(root, seat_id="seat-01", image_reference=REFERENCE, image_cache_dir=cache)
        restored = lifecycle._load_seat_image(paths)
        assert restored.selection.digest == expected.digest
        assert restored.selection.path.is_relative_to(root)
    assert (roots[1] / "launch/appliance-launch.json").read_bytes() == descriptor_before
