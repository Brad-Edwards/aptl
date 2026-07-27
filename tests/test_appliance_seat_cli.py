"""CLI tests for the appliance seat launcher."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from aptl.appliance.seat.models import SeatRecord
from aptl.cli.main import app

runner = CliRunner()


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
        result = runner.invoke(
            app,
            [
                "seat",
                "stage",
                "--seat-root",
                "/tmp/seat",
                "--release-dir",
                "/tmp/release",
                "--release-public-key",
                "/tmp/release.pem",
                "--qualification-public-key",
                "/tmp/qualification.pem",
            ],
        )

    assert result.exit_code == 2
    assert "no-kvm" in result.stderr
    assert "qemu-img" not in result.stderr


def test_open_kiosk_dry_run_does_not_spawn_browser() -> None:
    with patch("aptl.appliance.seat.lifecycle.subprocess.Popen") as popen:
        result = runner.invoke(
            app,
            ["seat", "open-kiosk", "--dry-run"],
        )

    assert result.exit_code == 0
    popen.assert_not_called()
    assert "https://127.0.0.1:443/" in result.stdout
