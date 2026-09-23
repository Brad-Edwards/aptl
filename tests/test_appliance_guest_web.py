"""Offline guest web launch checks."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest

from aptl.appliance.guest_web import start_guest_web
from aptl.core.lab_types import LabResult


def test_guest_web_requires_boot_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APTL_API_TOKEN", raising=False)
    monkeypatch.delenv("APTL_WEB_LAUNCH_TOKEN", raising=False)
    backend = Mock()
    project = Path("/opt/aptl/project")
    with pytest.raises(ValueError, match="credentials"):
        start_guest_web(backend, project)


def test_guest_web_uses_owned_backend_without_building(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APTL_API_TOKEN", "a" * 64)
    monkeypatch.setenv("APTL_WEB_LAUNCH_TOKEN", "b" * 43)
    backend = Mock()
    backend.start.return_value = LabResult(success=True)

    start_guest_web(backend, Path("/opt/aptl/project"))

    backend.start.assert_called_once_with(
        ["web"],
        build=False,
        only_services=("aptl-web-api", "aptl-web-ui"),
        scenario_root=Path("/opt/aptl/project"),
    )


def test_guest_web_reports_failure_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_token = "a" * 64
    launch_token = "b" * 43
    monkeypatch.setenv("APTL_API_TOKEN", api_token)
    monkeypatch.setenv("APTL_WEB_LAUNCH_TOKEN", launch_token)
    backend = Mock()
    backend.start.return_value = LabResult(
        success=False,
        error=f"bad {api_token} {launch_token}",
    )

    with pytest.raises(RuntimeError) as error:
        start_guest_web(backend, Path("/opt/aptl/project"))

    assert api_token not in str(error.value)
    assert launch_token not in str(error.value)
    assert "[redacted]" in str(error.value)
