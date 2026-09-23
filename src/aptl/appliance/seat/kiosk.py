"""Participant kiosk presentation wrapper."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


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
    if launch_token is not None:
        url += f"api/auth/login?token={launch_token}"
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
