"""Kiosk wrapper tests for the appliance seat launcher."""

from __future__ import annotations

from unittest.mock import patch

from aptl.appliance.seat.kiosk import build_kiosk_launch_plan


def test_build_kiosk_launch_plan_uses_custom_browser() -> None:
    plan = build_kiosk_launch_plan(
        participant_port=8443,
        browser_command="/usr/bin/custom-browser",
    )

    assert plan.url == "https://127.0.0.1:8443/"
    assert plan.argv[0] == "/usr/bin/custom-browser"
    assert "--kiosk" in plan.argv


def test_build_kiosk_launch_plan_falls_back_to_xdg_open() -> None:
    with patch("aptl.appliance.seat.kiosk.shutil.which", return_value=None):
        plan = build_kiosk_launch_plan()

    assert plan.argv[0] == "xdg-open"
