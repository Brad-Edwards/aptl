"""Start the offline web profile after the scenario owns its networks."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def start_guest_web(project_dir: Path, project_name: str) -> None:
    """Bring up the two baked web services in the realized Compose project."""

    if not os.environ.get("APTL_API_TOKEN") or not os.environ.get(
        "APTL_WEB_LAUNCH_TOKEN"
    ):
        raise ValueError("appliance web credentials are unavailable")
    result = subprocess.run(
        [
            "docker", "compose", "--project-name", project_name,
            "--project-directory", str(project_dir),
            "--file", str(project_dir / "docker-compose.yml"),
            "--profile", "web", "up", "--detach", "--no-build",
            "--pull", "never", "aptl-web-api", "aptl-web-ui",
        ],
        cwd=project_dir,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("offline appliance web services failed to start")
