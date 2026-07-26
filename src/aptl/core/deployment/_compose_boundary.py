"""Selected-daemon host enforcement for appliance boundary policy."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Protocol

from aptl.core.deployment.boundary import (
    AcesBoundarySpec,
    BoundaryEnforcementSpec,
)
from aptl.core.lab_types import LabResult

DEFAULT_BOUNDARY_HELPER_IMAGE = "aptl-network-boundary-helper:1"
_BOUNDARY_TIMEOUT = 30


class _BoundaryRunner(Protocol):
    @property
    def project_dir(self) -> Path: ...

    def _run(
        self,
        cmd: list[str],
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess: ...

    def _run_with_input(
        self,
        cmd: list[str],
        payload: str,
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess: ...


def _helper_command(
    action: str,
    image: str = DEFAULT_BOUNDARY_HELPER_IMAGE,
) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "host",
        "--cap-drop=ALL",
        "--cap-add=NET_ADMIN",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--tmpfs=/run:rw,noexec,nosuid,nodev,size=1m",
        "-i",
        image,
        action,
        "--stdin",
    ]


def realize_boundary(
    backend: _BoundaryRunner,
    policy: BoundaryEnforcementSpec,
    *,
    helper_image: str = DEFAULT_BOUNDARY_HELPER_IMAGE,
) -> LabResult:
    """Atomically apply/clean one owned policy and verify effective readback."""

    helper = _ensure_helper(backend, helper_image)
    if helper is not None:
        return helper
    payload = policy.canonical_json()
    action = (
        "cleanup"
        if isinstance(policy, AcesBoundarySpec) and not policy.rules
        else "apply"
    )
    mutation = backend._run_with_input(
        _helper_command(action, helper_image),
        payload,
        timeout=_BOUNDARY_TIMEOUT,
    )
    if mutation.returncode != 0:
        return LabResult(success=False, error="Boundary policy mutation failed.")
    observation = mutation
    if action == "apply":
        observation = backend._run_with_input(
            _helper_command("observe", helper_image),
            payload,
            timeout=_BOUNDARY_TIMEOUT,
        )
    if observation.returncode != 0:
        return LabResult(success=False, error="Boundary policy observation failed.")
    try:
        receipt = json.loads(observation.stdout)
    except (TypeError, ValueError):
        return LabResult(
            success=False, error="Boundary policy observation was invalid."
        )
    expected_families = [] if action == "cleanup" else ["bridge", "inet"]
    expected = {
        "authority": policy.authority,
        "owner": policy.owner,
        "enforcement_digest": policy.digest(),
        "families": expected_families,
        "default_deny": policy.authority == "platform",
    }
    if receipt != expected:
        return LabResult(
            success=False,
            error="Boundary policy readback did not match desired state.",
        )
    return LabResult(success=True, message="Boundary policy enforced and observed.")


def _ensure_helper(
    backend: _BoundaryRunner,
    helper_image: str,
) -> LabResult | None:
    inspection = backend._run(
        ["docker", "image", "inspect", helper_image],
        timeout=_BOUNDARY_TIMEOUT,
    )
    if inspection.returncode == 0:
        return None
    if helper_image != DEFAULT_BOUNDARY_HELPER_IMAGE:
        return LabResult(
            success=False,
            error="Signed boundary enforcement helper was unavailable.",
        )
    dockerfile = backend.project_dir / "containers/network-boundary-helper/Dockerfile"
    build = backend._run(
        [
            "docker",
            "build",
            "-t",
            helper_image,
            "-f",
            str(dockerfile),
            str(backend.project_dir),
        ],
        timeout=600,
    )
    if build.returncode != 0:
        return LabResult(
            success=False,
            error="Boundary enforcement helper was unavailable.",
        )
    return None
