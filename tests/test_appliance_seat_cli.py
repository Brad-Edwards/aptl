"""CLI tests for the appliance seat launcher."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from aptl.appliance.seat.models import SeatRecord
from aptl.cli.main import app

runner = CliRunner()


def _seat_record() -> SeatRecord:
    return SeatRecord(
        schema_version="aptl.seat-record/v1",
        seat_id="seat-01",
        selected_release_id="aptl-v1",
        launch_descriptor_digest="sha256:" + "a" * 64,
        overlay_path="instances/seat-01.qcow2",
        host_observation_id="host-1",
        lifecycle_state="ready",
        taint_state="clean",
        host_boot_id="boot-1",
    )


def _common_seat_args() -> list[str]:
    return [
        "--seat-root",
        "/tmp/seat",
        "--release-dir",
        "/tmp/release",
        "--release-public-key",
        "/tmp/release.pem",
        "--qualification-public-key",
        "/tmp/qualification.pem",
    ]


def test_seat_help_lists_supported_commands() -> None:
    result = runner.invoke(app, ["seat", "--help"])

    assert result.exit_code == 0
    assert "stage" in result.stdout
    assert "reset" in result.stdout
    assert "recover" in result.stdout
    assert "open-kiosk" in result.stdout


def test_seat_status_emits_bounded_json(tmp_path: Path) -> None:
    result = runner.invoke(app, ["seat", "status", "--seat-root", str(tmp_path)])

    assert result.exit_code == 0
    assert "lifecycle_state" in result.stdout
    assert "credential" not in result.stdout.lower()


def test_seat_stage_error_is_bounded() -> None:
    with patch(
        "aptl.cli.seat.stage_seat",
        side_effect=__import__(
            "aptl.appliance.seat.errors", fromlist=["SeatLauncherError"]
        ).SeatLauncherError("no-kvm", "hardware virtualization is unavailable"),
    ):
        result = runner.invoke(app, ["seat", "stage", *_common_seat_args()])

    assert result.exit_code == 2
    assert "no-kvm" in result.stderr
    assert "qemu-img" not in result.stderr


def test_seat_stage_success_emits_json() -> None:
    record = _seat_record().model_copy(update={"lifecycle_state": "staged"})
    with patch("aptl.cli.seat.stage_seat", return_value=record):
        result = runner.invoke(app, ["seat", "stage", *_common_seat_args()])

    assert result.exit_code == 0
    assert '"staged":true' in result.stdout.replace(" ", "")


def test_seat_start_success_emits_json() -> None:
    with patch("aptl.cli.seat.start_seat", return_value=_seat_record()):
        result = runner.invoke(app, ["seat", "start", *_common_seat_args()])

    assert result.exit_code == 0
    assert '"started":true' in result.stdout.replace(" ", "")


def test_seat_start_error_is_bounded() -> None:
    with patch(
        "aptl.cli.seat.start_seat",
        side_effect=__import__(
            "aptl.appliance.seat.errors", fromlist=["SeatLauncherError"]
        ).SeatLauncherError("boundary.host-listener-missing", "host boundary inventory failed"),
    ):
        result = runner.invoke(app, ["seat", "start", *_common_seat_args()])

    assert result.exit_code == 2
    assert "boundary.host-listener-missing" in result.stderr


def test_seat_stop_success_emits_json() -> None:
    with patch(
        "aptl.cli.seat.stop_seat",
        return_value=_seat_record().model_copy(update={"lifecycle_state": "staged"}),
    ):
        result = runner.invoke(app, ["seat", "stop", "--seat-root", "/tmp/seat"])

    assert result.exit_code == 0
    assert '"stopped":true' in result.stdout.replace(" ", "")


def test_seat_reset_and_recover_success_emit_json() -> None:
    staged = _seat_record().model_copy(update={"lifecycle_state": "staged"})
    with patch("aptl.cli.seat.reset_seat", return_value=staged):
        reset = runner.invoke(app, ["seat", "reset", *_common_seat_args()])
    with patch("aptl.cli.seat.recover_seat", return_value=_seat_record()):
        recover = runner.invoke(app, ["seat", "recover", *_common_seat_args()])

    assert reset.exit_code == 0
    assert '"reset":true' in reset.stdout.replace(" ", "")
    assert recover.exit_code == 0
    assert '"recovered":true' in recover.stdout.replace(" ", "")


def test_seat_reconcile_success_emits_json() -> None:
    with patch(
        "aptl.cli.seat.reconcile_seat_after_reboot",
        return_value=_seat_record().model_copy(update={"host_boot_id": "boot-2"}),
    ):
        result = runner.invoke(app, ["seat", "reconcile", "--seat-root", "/tmp/seat"])

    assert result.exit_code == 0
    assert '"reconciled":true' in result.stdout.replace(" ", "")


def test_open_kiosk_dry_run_does_not_spawn_browser() -> None:
    with patch("aptl.appliance.seat.lifecycle.subprocess.Popen") as popen:
        result = runner.invoke(
            app,
            ["seat", "open-kiosk", "--dry-run"],
        )

    assert result.exit_code == 0
    popen.assert_not_called()
    assert "https://127.0.0.1:443/" in result.stdout


def test_open_kiosk_honors_browser_command() -> None:
    with patch("aptl.appliance.seat.lifecycle.subprocess.Popen") as popen:
        result = runner.invoke(
            app,
            [
                "seat",
                "open-kiosk",
                "--browser-command",
                "/usr/bin/custom-browser",
                "--dry-run",
            ],
        )

    assert result.exit_code == 0
    popen.assert_not_called()
    assert "/usr/bin/custom-browser" in result.stdout

