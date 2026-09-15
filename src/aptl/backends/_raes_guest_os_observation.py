"""Guest operating-system readback for realized containers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from raes_contracts.realization_observation import ObservedOperatingSystemIdentity

from aptl.backends.raes_operating_systems import parse_os_release
from aptl.core.deployment.errors import BackendTimeoutError

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.deployment.observation import DeploymentObservationContext

_OS_RELEASE_PATH = "/etc/os-release"
_MAX_OS_RELEASE_BYTES = 64 * 1024


def guest_operating_system(
    backend: DeploymentBackend,
    container_name: str,
    observation_context: DeploymentObservationContext | None = None,
) -> ObservedOperatingSystemIdentity | None:
    """Read guest OS identity without a shell or planned-state fallback."""

    payload = _running_os_release(backend, container_name)
    if payload is None and observation_context is not None:
        payload = observation_context.completed_file_read(
            container_name,
            _OS_RELEASE_PATH,
            max_bytes=_MAX_OS_RELEASE_BYTES,
        )
    return parse_os_release(payload) if payload is not None else None


def _running_os_release(
    backend: DeploymentBackend, container_name: str
) -> str | bytes | None:
    """Read os-release from a running guest, then its retained filesystem."""

    try:
        result = backend.container_exec(container_name, ["cat", _OS_RELEASE_PATH])
    except (BackendTimeoutError, OSError):
        result = None
    if result is not None and getattr(result, "returncode", 1) == 0:
        return getattr(result, "stdout", b"")
    reader = getattr(backend, "container_file_read", None)
    if not callable(reader):
        return None
    try:
        return reader(
            container_name,
            _OS_RELEASE_PATH,
            max_bytes=_MAX_OS_RELEASE_BYTES,
        )
    except (BackendTimeoutError, OSError):
        return None


__all__ = ("guest_operating_system",)
