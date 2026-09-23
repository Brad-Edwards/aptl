"""Offline guest web launch checks."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from aptl.appliance.guest_web import start_guest_web


def test_guest_web_requires_boot_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APTL_API_TOKEN", raising=False)
    monkeypatch.delenv("APTL_WEB_LAUNCH_TOKEN", raising=False)
    with pytest.raises(ValueError, match="credentials"):
        start_guest_web(Path("/opt/aptl/project"), "aptl-w123")


def test_guest_web_uses_realized_project_and_forbids_builds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APTL_API_TOKEN", "a" * 64)
    monkeypatch.setenv("APTL_WEB_LAUNCH_TOKEN", "b" * 43)
    with patch("aptl.appliance.guest_web.subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0)
        start_guest_web(Path("/opt/aptl/project"), "aptl-w123")
    argv = run.call_args.args[0]
    assert argv[:4] == ["docker", "compose", "--project-name", "aptl-w123"]
    assert argv[-2:] == ["aptl-web-api", "aptl-web-ui"]
    assert "--no-build" in argv and "never" in argv


def test_guest_web_fails_when_compose_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APTL_API_TOKEN", "a" * 64)
    monkeypatch.setenv("APTL_WEB_LAUNCH_TOKEN", "b" * 43)
    with patch("aptl.appliance.guest_web.subprocess.run") as run, patch(
        "aptl.appliance.guest_web.time.sleep"
    ) as sleep:
        run.return_value = subprocess.CompletedProcess([], 1, stderr="port unavailable")
        with pytest.raises(RuntimeError, match="failed to start"):
            start_guest_web(Path("/opt/aptl/project"), "aptl-w123")
    assert run.call_count == 3
    assert sleep.call_count == 2


def test_guest_web_recovers_after_transient_compose_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APTL_API_TOKEN", "a" * 64)
    monkeypatch.setenv("APTL_WEB_LAUNCH_TOKEN", "b" * 43)
    with patch("aptl.appliance.guest_web.subprocess.run") as run, patch(
        "aptl.appliance.guest_web.time.sleep"
    ):
        run.side_effect = [
            subprocess.CompletedProcess([], 1, stderr="port unavailable"),
            subprocess.CompletedProcess([], 0),
        ]
        start_guest_web(Path("/opt/aptl/project"), "aptl-w123")
    assert run.call_count == 2
    assert "--force-recreate" not in run.call_args_list[0].args[0]
    assert "--force-recreate" in run.call_args_list[1].args[0]


def test_guest_web_redacts_boot_credentials_from_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "a" * 64
    monkeypatch.setenv("APTL_API_TOKEN", secret)
    monkeypatch.setenv("APTL_WEB_LAUNCH_TOKEN", "b" * 43)
    with patch("aptl.appliance.guest_web.subprocess.run") as run, patch(
        "aptl.appliance.guest_web.time.sleep"
    ):
        run.return_value = subprocess.CompletedProcess([], 1, stderr=f"bad {secret}")
        with pytest.raises(RuntimeError) as error:
            start_guest_web(Path("/opt/aptl/project"), "aptl-w123")
    assert secret not in str(error.value)
    assert "[redacted]" in str(error.value)
