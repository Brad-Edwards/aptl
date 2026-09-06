"""Prepare spawned-child images for admitted runtime authorities."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re

from aptl.core.deployment._compose_runtime_orchestration import (
    deployment_spawn_image_requirements,
)
from aptl.core.deployment._docker_image_identity import (
    EXACT_IMAGE_INSPECT_FORMAT,
    IMAGE_ID_INSPECT_FORMAT,
    DockerPlatform,
    exact_inspected_image_identity,
    inspected_image_id,
    normalized_platform,
    platform_is_compatible,
)
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.lab_types import LabResult
from aptl.runtime_authority import DeploymentSpawnImageRequirement

_IMAGE_REALIZATION_TIMEOUT = 2400
_ALIAS_NOT_FOUND = re.compile(
    r"^(?:(?:error response from daemon|error): )?no such (?:image|object)(?::|$)"
)


class _AliasState(str, Enum):
    """Whether one local alias was positively found, absent, or unreadable."""

    PRESENT = "present"
    ABSENT = "absent"
    ERROR = "error"


@dataclass(frozen=True)
class _AliasInspection:
    """Typed alias readback that never conflates absence with an error."""

    state: _AliasState
    image_id: str | None = None


def prepare_spawn_images(
    backend: object,
    realization: DeploymentRealizationSpec,
) -> LabResult | None:
    """Prepare every exact child image on the authority's bound daemon."""

    failure: LabResult | None = None
    requirements: tuple[DeploymentSpawnImageRequirement, ...] = ()
    try:
        requirements = deployment_spawn_image_requirements(realization)
    except ValueError as exc:
        failure = LabResult(success=False, error=str(exc))
    if failure is None and requirements:
        failure = _prepare_on_bound_daemon(backend, requirements)
    return failure


def _prepare_on_bound_daemon(
    backend: object,
    requirements: tuple[DeploymentSpawnImageRequirement, ...],
) -> LabResult | None:
    """Validate the selected daemon and prepare each unique image once."""

    endpoint = backend.revalidate_local_docker_socket()
    failure = None if endpoint.success else endpoint
    expected: DockerPlatform | None = None
    if failure is None:
        expected, failure = _daemon_platform(backend)
    if failure is None and expected is not None:
        failure = _prepare_unique_images(backend, requirements, expected)
    return failure


def _daemon_platform(backend: object) -> tuple[DockerPlatform | None, LabResult | None]:
    """Return the selected daemon platform or one bounded diagnostic."""

    try:
        result = backend._run(
            ["docker", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"],
            timeout=_IMAGE_REALIZATION_TIMEOUT,
        )
    except BackendTimeoutError:
        return None, LabResult(
            success=False,
            error="Docker platform query timed out.",
        )
    platform = normalized_platform(result.stdout) if result.returncode == 0 else None
    failure = (
        None
        if platform is not None
        else LabResult(success=False, error="Docker platform query failed.")
    )
    return platform, failure


def _prepare_unique_images(
    backend: object,
    requirements: tuple[DeploymentSpawnImageRequirement, ...],
    expected: DockerPlatform,
) -> LabResult | None:
    """Prepare each exact image once using its shortest authored timeout."""

    by_image = {
        image_ref: min(
            (item for item in requirements if item.image_ref == image_ref),
            key=lambda item: item.execution_timeout_seconds,
        )
        for image_ref in dict.fromkeys(item.image_ref for item in requirements)
    }
    failure = None
    for requirement in by_image.values():
        failure = _prepare_one_image(backend, requirement, expected)
        if failure is not None:
            break
    return failure


def _prepare_one_image(
    backend: object,
    requirement: DeploymentSpawnImageRequirement,
    expected: DockerPlatform,
) -> LabResult | None:
    """Acquire when allowed, then attest one exact image and platform."""

    timeout = min(
        _IMAGE_REALIZATION_TIMEOUT,
        requirement.execution_timeout_seconds,
    )
    failure = None
    if not backend._offline_staged:
        failure = _pull_spawn_image(backend, requirement, timeout=timeout)
    if failure is None:
        failure = _inspect_spawn_image(
            backend,
            requirement,
            expected,
            timeout=timeout,
        )
    return failure


def _pull_spawn_image(
    backend: object,
    requirement: DeploymentSpawnImageRequirement,
    *,
    timeout: int,
) -> LabResult | None:
    """Pull one exact child image within its authored ceiling."""

    try:
        result = backend._run(
            ["docker", "pull", requirement.image_ref],
            timeout=timeout,
        )
    except BackendTimeoutError:
        result = None
    if result is None or result.returncode != 0:
        return _spawn_image_failure("pull failed", requirement)
    return None


def _inspect_spawn_image(
    backend: object,
    requirement: DeploymentSpawnImageRequirement,
    expected: DockerPlatform,
    *,
    timeout: int,
) -> LabResult | None:
    """Attest exact local identity and native platform for one child image."""

    try:
        result = backend._run(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                EXACT_IMAGE_INSPECT_FORMAT,
                requirement.image_ref,
            ],
            timeout=timeout,
        )
    except BackendTimeoutError:
        result = None
    failure: LabResult | None = None
    identity = None
    if result is None or result.returncode != 0:
        failure = _spawn_image_failure("missing", requirement)
    else:
        identity = exact_inspected_image_identity(result.stdout, requirement.image_ref)
    if failure is None and identity is None:
        failure = _spawn_image_failure("identity unavailable", requirement)
    if (
        failure is None
        and identity is not None
        and not platform_is_compatible(expected, identity.platform)
    ):
        failure = _spawn_image_failure("platform incompatible", requirement)
    if failure is None and identity is not None and requirement.runtime_alias:
        failure = _prepare_runtime_alias(
            backend,
            requirement,
            expected_image_id=identity.image_id,
            timeout=timeout,
        )
    return failure


def _prepare_runtime_alias(
    backend: object,
    requirement: DeploymentSpawnImageRequirement,
    *,
    expected_image_id: str,
    timeout: int,
) -> LabResult | None:
    """Verify or locally create one tag alias without overwriting stale state."""

    assert requirement.runtime_alias is not None
    inspected = _inspect_alias(
        backend,
        requirement.runtime_alias,
        timeout=timeout,
    )
    if inspected.state is _AliasState.PRESENT:
        return (
            None
            if inspected.image_id == expected_image_id
            else _spawn_image_failure("runtime alias stale", requirement)
        )
    if inspected.state is not _AliasState.ABSENT:
        return _spawn_image_failure("runtime alias inspection failed", requirement)
    try:
        tagged = backend._run(
            [
                "docker",
                "tag",
                requirement.image_ref,
                requirement.runtime_alias,
            ],
            timeout=timeout,
        )
    except BackendTimeoutError:
        tagged = None
    if tagged is None or tagged.returncode != 0:
        return _spawn_image_failure("runtime alias unavailable", requirement)
    inspected = _inspect_alias(
        backend,
        requirement.runtime_alias,
        timeout=timeout,
    )
    if (
        inspected.state is not _AliasState.PRESENT
        or inspected.image_id != expected_image_id
    ):
        return _spawn_image_failure("runtime alias unavailable", requirement)
    return None


def _inspect_alias(backend: object, alias: str, *, timeout: int) -> _AliasInspection:
    """Read one alias while distinguishing a proven miss from every error."""

    try:
        result = backend._run(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                IMAGE_ID_INSPECT_FORMAT,
                alias,
            ],
            timeout=timeout,
        )
    except BackendTimeoutError:
        return _AliasInspection(_AliasState.ERROR)
    if result.returncode == 0:
        image_id = inspected_image_id(result.stdout)
        return _AliasInspection(
            _AliasState.PRESENT if image_id is not None else _AliasState.ERROR,
            image_id,
        )
    error = result.stderr.strip().lower()
    if not result.stdout.strip() and _ALIAS_NOT_FOUND.match(error):
        return _AliasInspection(_AliasState.ABSENT)
    return _AliasInspection(_AliasState.ERROR)


def _spawn_image_failure(
    condition: str,
    requirement: DeploymentSpawnImageRequirement,
) -> LabResult:
    """Build one stable child-image diagnostic."""

    return LabResult(
        success=False,
        error=(
            f"Spawn image {condition} for "
            f"{requirement.node_address}/{requirement.template_id}."
        ),
    )
