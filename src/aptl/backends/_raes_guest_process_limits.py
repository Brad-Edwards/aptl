"""Bounded PID-1 process-limit readback for RAES guest runtime concerns."""

from __future__ import annotations

from typing import TYPE_CHECKING

from raes.runtime_configuration import RuntimeConfiguration

from aptl.backends._runtime_concern_disclosure import _disclose

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

_PROCESS_LIMITS_PATH = "/proc/1/limits"
_PROCESS_LIMITS_MAX_BYTES = 16 * 1024
_PROCESS_LIMIT_LABELS = {
    "Max open files": "open_file_descriptors",
    "Max locked memory": "locked_memory_bytes",
}


def observe_process_resource_limits(
    backend: "DeploymentBackend",
    container_name: str,
    runtime: RuntimeConfiguration,
) -> object | None:
    """Read the effective PID-1 limits that Compose applies to its subtree.

    APTL's image-backed substrate selects ``nofile`` and ``memlock`` defaults
    even when the open SDL leaves the collection empty. Reading procfs through
    the provider avoids a workload-controlled executable while still observes
    the effective guest values. Both selected dimensions must be present.
    """

    policy = runtime.operational_policy
    limits = policy.resource_limits if policy is not None else None
    if limits is not None and limits.process_limits:
        # Authored process subjects require a dedicated subject resolver. Do
        # not pretend PID 1 proves an arbitrary authored process selection.
        return None
    payload = backend.container_file_read(
        container_name,
        _PROCESS_LIMITS_PATH,
        max_bytes=_PROCESS_LIMITS_MAX_BYTES,
    )
    observed = _parse_process_limits(payload)
    if observed.keys() != set(_PROCESS_LIMIT_LABELS.values()):
        return None
    records = [
        {
            "resource": resource,
            "soft": observed[resource][0],
            "hard": observed[resource][1],
            "subject": {"name": "container"},
            "scope": "subtree",
        }
        for resource in sorted(observed)
    ]
    return _disclose("process-resource-limits", records)


def _parse_process_limits(
    payload: bytes | None,
) -> dict[str, tuple[int | str, int | str]]:
    """Parse the bounded procfs limit rows APTL selects and observes."""

    text = _decode_process_limits(payload)
    observed: dict[str, tuple[int | str, int | str]] = {}
    valid = text is not None
    for line in text.splitlines() if text is not None else ():
        valid, row = _process_limit_row(line)
        if not valid:
            break
        if row is not None:
            resource, soft, hard = row
            observed[resource] = (soft, hard)
    return observed if valid else {}


def _decode_process_limits(payload: bytes | None) -> str | None:
    """Decode a bounded procfs limits payload as strict UTF-8."""

    if payload is None:
        return None
    try:
        return payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _process_limit_row(
    line: str,
) -> tuple[bool, tuple[str, int | str, int | str] | None]:
    """Parse one selected procfs limit row and distinguish irrelevant rows."""

    selected = next(
        (
            (label, resource)
            for label, resource in _PROCESS_LIMIT_LABELS.items()
            if line.startswith(label)
        ),
        None,
    )
    if selected is None:
        return True, None
    label, resource = selected
    columns = line[len(label) :].split()
    if len(columns) != 3:
        return False, None
    soft = _limit_value(columns[0])
    hard = _limit_value(columns[1])
    valid = soft is not None and hard is not None
    return valid, (resource, soft, hard) if valid else None


def _limit_value(value: str) -> int | str | None:
    """Parse a finite non-negative process limit or the unlimited sentinel."""

    if value == "unlimited":
        return value
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None
