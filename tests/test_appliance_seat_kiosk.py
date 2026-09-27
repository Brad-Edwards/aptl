"""Kiosk wrapper tests for the appliance seat launcher."""

from __future__ import annotations

from unittest.mock import patch

from aptl.appliance.seat.kiosk import build_kiosk_launch_plan


def test_build_kiosk_launch_plan_uses_custom_browser() -> None:
    plan = build_kiosk_launch_plan(
        participant_port=8443,
        browser_command="/usr/bin/custom-browser",
    )

    assert plan.url == "http://127.0.0.1:8443/"
    assert plan.argv[0] == "/usr/bin/custom-browser"
    assert "--kiosk" in plan.argv


def test_build_kiosk_launch_plan_falls_back_to_xdg_open() -> None:
    with patch("aptl.appliance.seat.kiosk.shutil.which", return_value=None):
        plan = build_kiosk_launch_plan()

    assert plan.argv[0] == "xdg-open"


def test_kiosk_login_token_is_only_in_owner_private_bootstrap(tmp_path) -> None:
    import stat
    from aptl.appliance.seat.kiosk import open_participant_kiosk

    token = "fixture-private-login-token"
    directory = tmp_path / "kiosk"
    with patch("aptl.appliance.seat.kiosk.subprocess.Popen") as launch:
        plan = open_participant_kiosk(
            launch_token=token, bootstrap_directory=directory,
            browser_command="browser",
        )
    assert token not in repr(plan)
    assert token not in repr(launch.call_args)
    bootstrap = directory / "login.html"
    assert token in bootstrap.read_text()
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(bootstrap.stat().st_mode) == 0o600
    assert launch.call_args.args[0][-1] == bootstrap.as_uri()


def test_kiosk_dry_run_never_writes_or_emits_login_token(tmp_path) -> None:
    from aptl.appliance.seat.kiosk import open_participant_kiosk
    plan = open_participant_kiosk(
        launch_token="private-token", dry_run=True,
        bootstrap_directory=tmp_path / "absent",
    )
    assert "private-token" not in repr(plan)
    assert not (tmp_path / "absent").exists()
