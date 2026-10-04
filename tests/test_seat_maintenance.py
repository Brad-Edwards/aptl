"""Host administrator rescue keeps a stopped event overlay intact."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import subprocess
import sys

import pytest

from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.maintenance import rescue_seat_overlay
from aptl.appliance.seat.models import SeatRecord
from aptl.appliance.seat.persistence import persist_seat_record
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint


def _seat(tmp_path: Path) -> Path:
    root = tmp_path / "seat"
    overlay = root / "instances/seat-01.qcow2"
    overlay.parent.mkdir(parents=True, mode=0o700)
    overlay.write_bytes(b"overlay")
    overlay.chmod(0o600)
    (root / ".lifecycle.lock").write_bytes(b"")
    (root / ".lifecycle.lock").chmod(0o600)
    persist_seat_record(root, SeatRecord(
        schema_version="aptl.seat-record/v2",
        seat_id="seat-01",
        image_reference="ghcr.io/owner/seat:latest",
        image_digest="sha256:" + "a" * 64,
        launch_descriptor_digest="sha256:" + "b" * 64,
        overlay_path="instances/seat-01.qcow2",
        host_observation_id="host-1",
        lifecycle_state="staged",
        taint_state="clean",
        host_boot_id="boot-1",
        mappings=(BoundaryEndpoint(
            audience="participant", address="127.0.0.1", port=8080,
            protocol="tcp", guest_address="127.0.0.1", guest_port=8080,
        ),),
    ))
    return root


def test_host_admin_rescues_stopped_overlay_without_reset(tmp_path: Path) -> None:
    root = _seat(tmp_path)
    with (
        patch("aptl.appliance.seat.maintenance.os.geteuid", return_value=0),
        patch("aptl.appliance.seat.maintenance.shutil.which", return_value="/usr/bin/tool"),
        patch("aptl.appliance.seat.maintenance.read_vm_pid", return_value=None),
        patch("aptl.appliance.seat.maintenance.subprocess.run",
              return_value=SimpleNamespace(returncode=0)) as run,
    ):
        rescue_seat_overlay(root)
    argv = run.call_args.args[0]
    assert argv[:7] == ["runuser", "-u", argv[2], "--", "virt-rescue", "--rw", "--inspector"]
    assert argv[-1] == str(root / "instances/seat-01.qcow2")
    assert (root / "instances/seat-01.qcow2").read_bytes() == b"overlay"


def test_rescue_requires_host_root_and_stopped_vm(tmp_path: Path) -> None:
    root = _seat(tmp_path)
    with patch("aptl.appliance.seat.maintenance.os.geteuid", return_value=1000):
        with pytest.raises(SeatLauncherError, match="host root"):
            rescue_seat_overlay(root)
    with (
        patch("aptl.appliance.seat.maintenance.os.geteuid", return_value=0),
        patch("aptl.appliance.seat.maintenance.shutil.which", return_value="/usr/bin/tool"),
        patch("aptl.appliance.seat.maintenance.read_vm_pid", return_value=1234),
        patch("aptl.appliance.seat.maintenance.subprocess.run") as run,
    ):
        with pytest.raises(SeatLauncherError, match="stop the seat"):
            rescue_seat_overlay(root)
    run.assert_not_called()


def test_rescue_module_import_does_not_require_posix_pwd() -> None:
    result = subprocess.run(
        [sys.executable, "-c", (
            "import sys; sys.modules['pwd'] = None; "
            "import aptl.appliance.seat.maintenance"
        )],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
