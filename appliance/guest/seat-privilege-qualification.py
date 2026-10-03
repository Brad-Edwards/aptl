#!/usr/bin/python3
"""Check a live-booted seat's stopped overlay using the guest's own sudo/PAM."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

MODE = sys.argv[1] if len(sys.argv) == 2 else ""
PASSWORD_INPUT = Path("/root/seat-qualification-password")
RESULT = Path("/root/seat-privilege-qualification.json")
OVERLAY = Path("/var/lib/aptl/overlay")
SUDOERS = Path("/etc/sudoers.d/90-aptl-desktop")
HANDOFF = Path("/home/aptl/.config/aptl/run-ready")


def _as_aptl(*argv: str, input_value: str | None = None) -> bool:
    result = subprocess.run(
        ["runuser", "-u", "aptl", "--", *argv], input=input_value,
        text=True, capture_output=True, timeout=30, check=False,
    )
    return result.returncode == 0


def check() -> dict[str, bool]:
    """Return only booleans; never include the chosen account credential."""

    if os.geteuid() != 0 or MODE not in {"event", "password", "passwordless"}:
        raise ValueError("invalid qualification context")
    state = json.loads((OVERLAY / "desktop-privileges.json").read_text())
    groups = set(subprocess.run(
        ["id", "-nG", "aptl"], check=True, text=True,
        capture_output=True, timeout=15,
    ).stdout.split())
    rdp = json.loads((OVERLAY / "desktop/credentials.json").read_text())["rdp"]
    sql = (OVERLAY / "desktop/initdb/002-seat.sql").read_text()
    expected_mode = "event" if MODE == "event" else "administrative"
    expected_auth = "none" if MODE == "event" else MODE
    checks = {
        "state": state.get("mode") == expected_mode
        and state.get("authentication") == expected_auth,
        "groups": not groups.intersection({"docker", "sudo"}),
        "docker_socket": _as_aptl(
            "/bin/sh", "-c",
            "test ! -r /var/run/docker.sock && test ! -w /var/run/docker.sock",
        ),
        "rdp": isinstance(rdp, str) and bool(rdp) and rdp.encode().hex() in sql,
        "desktop_handoff": HANDOFF.is_file(),
    }
    sudoers = SUDOERS
    checks["sudo_without_password"] = _as_aptl(
        "sudo", "-n", "-k", "/bin/true"
    ) == (MODE == "passwordless")
    if MODE == "event":
        checks["sudoers"] = not sudoers.exists()
        checks["password_file"] = not (OVERLAY / "desktop-admin-password").exists()
    else:
        expected = (
            "aptl ALL=(ALL:ALL) NOPASSWD:ALL\n" if MODE == "passwordless"
            else "aptl ALL=(ALL:ALL) ALL\n"
        )
        checks["sudoers"] = sudoers.read_text() == expected
        checks["password_file"] = (
            (OVERLAY / "desktop-admin-password").exists() == (MODE == "password")
        )
    if MODE == "password":
        password = PASSWORD_INPUT.read_text()
        checks["chosen_password"] = _as_aptl(
            "sudo", "-S", "-p", "", "-k", "/bin/true",
            input_value=password + "\n",
        ) and rdp == password
        checks["wrong_password"] = not _as_aptl(
            "sudo", "-S", "-p", "", "-k", "/bin/true",
            input_value="definitely-not-the-chosen-password\n",
        )
    return checks


def main() -> int:
    try:
        checks = check()
        passed = all(checks.values())
        RESULT.write_text(json.dumps({"mode": MODE, "passed": passed, "checks": checks}))
        return 0 if passed else 1
    finally:
        PASSWORD_INPUT.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
