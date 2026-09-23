"""Participant kiosk presentation wrapper."""

from __future__ import annotations

import html
import os
import secrets
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode


@dataclass(frozen=True)
class KioskLaunchPlan:
    """Browser command for one loopback participant endpoint."""

    argv: tuple[str, ...]
    url: str


def build_kiosk_launch_plan(
    *,
    participant_port: int = 443,
    browser_command: str | None = None,
    launch_token: str | None = None,
) -> KioskLaunchPlan:
    """Return a fullscreen browser argv for the participant origin."""

    url = f"http://127.0.0.1:{participant_port}/"
    # Plans are safe to print; credentials only enter the private bootstrap.
    del launch_token
    browser = browser_command or _default_browser()
    argv = (
        browser,
        "--kiosk",
        "--no-first-run",
        "--disable-translate",
        "--disable-session-crashed-bubble",
        url,
    )
    return KioskLaunchPlan(argv=argv, url=url)


def open_participant_kiosk(
    *,
    participant_port: int = 443,
    browser_command: str | None = None,
    dry_run: bool = False,
    bootstrap_directory: Path | None = None,
    launch_token: str | None = None,
) -> KioskLaunchPlan:
    """Launch or plan the participant kiosk browser wrapper."""

    plan = build_kiosk_launch_plan(
        participant_port=participant_port,
        browser_command=browser_command,
        launch_token=launch_token,
    )
    if dry_run:
        return plan
    if launch_token is not None:
        if bootstrap_directory is None:
            raise ValueError("authenticated kiosk requires a private bootstrap directory")
        from aptl.appliance.seat.persistence import _ensure_seat_root
        _ensure_seat_root(bootstrap_directory)
        login = plan.url + "api/auth/login?" + urlencode({"token": launch_token})
        payload = ('<!doctype html><meta name="referrer" content="no-referrer">'
                   '<meta http-equiv="refresh" content="0;url=' + html.escape(login, quote=True)
                   + '">').encode()
        bootstrap = bootstrap_directory / "login.html"
        temporary = bootstrap_directory / (".login-" + secrets.token_hex(8))
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
            os.replace(temporary, bootstrap)
        finally:
            temporary.unlink(missing_ok=True)
        plan = KioskLaunchPlan(argv=(*plan.argv[:-1], bootstrap.absolute().as_uri()), url=plan.url)
    subprocess.Popen(
        list(plan.argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    return plan


def _default_browser() -> str:
    """Pick the first installed fullscreen-capable browser on the host."""

    for candidate in ("chromium-browser", "chromium", "google-chrome", "firefox"):
        if shutil.which(candidate):
            return candidate
    return "xdg-open"
