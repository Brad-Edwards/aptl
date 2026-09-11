"""Prepare spawned-child images for admitted runtime authorities."""

from __future__ import annotations

from aptl.core.deployment._compose_runtime_orchestration import (
    deployment_spawn_image_requirements,
)
from aptl.core.deployment._docker_image_identity import (
    EXACT_IMAGE_INSPECT_FORMAT,
    DockerPlatform,
    exact_inspected_image_identity,
    normalized_platform,
    platform_is_compatible,
)
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.lab_types import LabResult
from aptl.runtime_authority import DeploymentSpawnImageRequirement

_IMAGE_REALIZATION_TIMEOUT = 2400


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
    return failure


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
