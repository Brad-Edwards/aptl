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

_HELPER_IMAGE = "aptl-network-boundary-helper:1"
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


def _helper_command(action: str) -> list[str]:
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
        _HELPER_IMAGE,
        action,
        "--stdin",
    ]


def realize_boundary(
    backend: _BoundaryRunner,
    policy: BoundaryEnforcementSpec,
) -> LabResult:
    """Atomically apply/clean one owned policy and verify effective readback."""

    helper = _ensure_helper(backend)
    if helper is not None:
        return helper
    payload = policy.canonical_json()
    action = (
        "cleanup"
        if isinstance(policy, AcesBoundarySpec) and not policy.rules
        else "apply"
    )
    mutation = backend._run_with_input(
        _helper_command(action),
        payload,
        timeout=_BOUNDARY_TIMEOUT,
    )
    if mutation.returncode != 0:
        return LabResult(success=False, error="Boundary policy mutation failed.")
    observation = mutation
    if action == "apply":
        observation = backend._run_with_input(
            _helper_command("observe"),
            payload,
            timeout=_BOUNDARY_TIMEOUT,
        )
    if observation.returncode != 0:
        return LabResult(success=False, error="Boundary policy observation failed.")
    try:
        receipt = json.loads(observation.stdout)
    except (TypeError, ValueError):
        return LabResult(success=False, error="Boundary policy observation was invalid.")
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


def _ensure_helper(backend: _BoundaryRunner) -> LabResult | None:
    inspection = backend._run(
        ["docker", "image", "inspect", _HELPER_IMAGE],
        timeout=_BOUNDARY_TIMEOUT,
    )
    if inspection.returncode == 0:
        return None
    dockerfile = backend.project_dir / "containers/network-boundary-helper/Dockerfile"
    build = backend._run(
        [
            "docker",
            "build",
            "-t",
            _HELPER_IMAGE,
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
