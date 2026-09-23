"""Start the offline web profile after the scenario owns its networks."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path


def start_guest_web(project_dir: Path, project_name: str) -> None:
    """Bring up the two baked web services in the realized Compose project."""

    if not os.environ.get("APTL_API_TOKEN") or not os.environ.get(
        "APTL_WEB_LAUNCH_TOKEN"
    ):
        raise ValueError("appliance web credentials are unavailable")
    command = [
        "docker", "compose", "--project-name", project_name,
        "--project-directory", str(project_dir),
        "--file", str(project_dir / "docker-compose.yml"),
        "--profile", "web", "up", "--detach", "--no-build",
        "--pull", "never", "aptl-web-api", "aptl-web-ui",
    ]
    failure = "unknown Compose failure"
    for attempt in range(3):
        try:
            result = subprocess.run(
                command,
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired:
            failure = "Compose startup timed out"
        else:
            if result.returncode == 0:
                return
            failure = (result.stderr or result.stdout).strip()[-2000:]
            for secret in (
                os.environ["APTL_API_TOKEN"],
                os.environ["APTL_WEB_LAUNCH_TOKEN"],
            ):
                failure = failure.replace(secret, "[redacted]")
        if attempt < 2:
            time.sleep(3)
    raise RuntimeError(f"offline appliance web services failed to start: {failure}")
