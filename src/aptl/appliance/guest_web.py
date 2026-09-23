"""Start the offline web profile through the lab's owned Compose backend."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

from aptl.core.lab_types import LabResult


class GuestWebBackend(Protocol):
    """The receipt-backed Compose operation needed by the seat web profile."""

    def start(
        self,
        profiles: list[str],
        *,
        build: bool,
        only_services: tuple[str, ...],
        scenario_root: Path,
    ) -> LabResult: ...


def start_guest_web(backend: GuestWebBackend, project_dir: Path) -> None:
    """Bring up and receipt both web services in the realized Compose project."""

    api_token = os.environ.get("APTL_API_TOKEN")
    launch_token = os.environ.get("APTL_WEB_LAUNCH_TOKEN")
    if not api_token or not launch_token:
        raise ValueError("appliance web credentials are unavailable")
    result = backend.start(
        ["web"],
        build=False,
        only_services=("aptl-web-api", "aptl-web-ui"),
        scenario_root=project_dir,
    )
    if not result.success:
        failure = (result.error or "Compose startup failed")[-2000:]
        for secret in (api_token, launch_token):
            failure = failure.replace(secret, "[redacted]")
        raise RuntimeError(f"offline appliance web services failed to start: {failure}")
