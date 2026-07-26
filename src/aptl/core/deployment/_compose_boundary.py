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
    """Narrow selected-daemon operation surface used by the fixed helper."""

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
    *,
    pull_never: bool = False,
) -> list[str]:
    """Build the fixed, capability-minimal helper invocation."""

    return [
        "docker",
        "run",
        *(["--pull=never"] if pull_never else []),
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
    pull_never = bool(getattr(backend, "_offline_staged", False))
    action = (
        "cleanup"
        if isinstance(policy, AcesBoundarySpec) and not policy.rules
        else "apply"
    )
    mutation = backend._run_with_input(
        _helper_command(action, helper_image, pull_never=pull_never),
        payload,
        timeout=_BOUNDARY_TIMEOUT,
    )
    if mutation.returncode != 0:
        return LabResult(success=False, error="Boundary policy mutation failed.")
    observation = (
        backend._run_with_input(
            _helper_command("observe", helper_image, pull_never=pull_never),
            payload,
            timeout=_BOUNDARY_TIMEOUT,
        )
        if action == "apply"
        else mutation
    )
    return _boundary_observation_result(policy, action, observation)


def _boundary_observation_result(
    policy: BoundaryEnforcementSpec,
    action: str,
    observation: subprocess.CompletedProcess,
) -> LabResult:
    """Validate the helper's exact normalized kernel-readback receipt."""

    error: str | None = None
    receipt: object = None
    if observation.returncode != 0:
        error = "Boundary policy observation failed."
    try:
        if error is None:
            receipt = json.loads(observation.stdout)
    except (TypeError, ValueError):
        error = "Boundary policy observation was invalid."
    expected_families = [] if action == "cleanup" else ["bridge", "inet"]
    expected = {
        "authority": policy.authority,
        "owner": policy.owner,
        "enforcement_digest": policy.digest(),
        "families": expected_families,
        "default_deny": policy.authority == "platform",
    }
    if error is None and receipt != expected:
        error = "Boundary policy readback did not match desired state."
    return (
        LabResult(success=False, error=error)
        if error is not None
        else LabResult(success=True, message="Boundary policy enforced and observed.")
    )


def _ensure_helper(
    backend: _BoundaryRunner,
    helper_image: str,
) -> LabResult | None:
    """Require the selected helper image, building only the developer tag."""

    inspection = backend._run(
        ["docker", "image", "inspect", helper_image],
        timeout=_BOUNDARY_TIMEOUT,
    )
    result: LabResult | None = None
    offline_staged = bool(getattr(backend, "_offline_staged", False))
    if inspection.returncode != 0 and (
        offline_staged or helper_image != DEFAULT_BOUNDARY_HELPER_IMAGE
    ):
        result = LabResult(
            success=False,
            error="Signed boundary enforcement helper was unavailable.",
        )
    elif inspection.returncode != 0:
        dockerfile = (
            backend.project_dir / "containers/network-boundary-helper/Dockerfile"
        )
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
            result = LabResult(
                success=False,
                error="Boundary enforcement helper was unavailable.",
            )
    return result
