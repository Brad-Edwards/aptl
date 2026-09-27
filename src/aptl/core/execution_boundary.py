"""Bounded observation of the Docker daemon selected by a deployment backend.

This describes where lab authority runs. It does not qualify containment or
describe the VM/container requirements authored inside a RAES scenario.
"""

from __future__ import annotations

import json
import hashlib
import platform
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field


_PROBE_TIMEOUT = 15
_MAX_RESPONSE_BYTES = 65536
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$")


class _Process(Protocol):
    """Minimal command result needed by an optional Docker probe."""

    returncode: int
    stdout: str


class BoundaryProbeBackend(Protocol):
    """Existing selected-backend command and transport surfaces."""

    def docker_transport_environment(self) -> dict[str, str]: ...

    def _run(self, argv: list[str], *, timeout: int) -> _Process: ...


class ExecutionBoundaryObservation(BaseModel):
    """Public, credential-free facts about one selected Docker endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["aptl.execution-boundary/v1"] = (
        "aptl.execution-boundary/v1"
    )
    transport: Literal[
        "local-unix", "local-npipe", "remote-ssh", "remote-tcp", "unknown"
    ]
    override_source: Literal[
        "none", "docker-host", "docker-context", "active-context", "conflicting-overrides"
    ]
    daemon_runtime: Literal["native-linux", "docker-vm", "unknown"]
    host_containment: Literal[
        "native-docker", "docker-vm-unverified", "remote-unverified",
        "seat-guest-unverified", "unknown"
    ]
    observation_status: Literal["observed", "partial", "unknown", "mismatch"]
    host_os: Literal["linux", "macos", "windows", "unknown"]
    host_kernel: str = Field(default="", max_length=80)
    docker_version: str = Field(default="", max_length=80)
    containment_verified: bool = False
    profile_ref: str = Field(default="", max_length=80)
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class BoundarySelection:
    """Attempt-local public observation and private selected-daemon identity."""

    observation: ExecutionBoundaryObservation
    endpoint_digest: str = ""
    daemon_digest: str = ""


def _digest(value: object) -> str:
    """Keep selected-daemon identity private while allowing comparison."""

    return (
        hashlib.sha256(value.encode("utf-8")).hexdigest()
        if isinstance(value, str) and value
        else ""
    )


def _safe_version(value: object) -> str:
    """Keep untrusted daemon/host text out of public output unless shape-safe."""

    return value if isinstance(value, str) and _SAFE_VERSION.fullmatch(value) else ""


def _host_os() -> Literal["linux", "macos", "windows", "unknown"]:
    """Normalize the CLI host platform for public boundary reporting."""

    system = platform.system().lower()
    return {
        "linux": "linux",
        "darwin": "macos",
        "windows": "windows",
    }.get(system, "unknown")  # type: ignore[return-value]


def _probe(backend: BoundaryProbeBackend, argv: list[str]) -> str | None:
    """Run a bounded Docker probe without exposing command failure details."""

    try:
        result = backend._run(argv, timeout=_PROBE_TIMEOUT)
    except Exception:
        # Backends translate timeouts to their own exception type. An optional
        # observation must never expose that exception's endpoint/argv text.
        return None
    if (
        result.returncode != 0
        or not isinstance(result.stdout, str)
        or len(result.stdout) > _MAX_RESPONSE_BYTES
    ):
        return None
    return result.stdout.strip() or None


def _context_endpoint(backend: BoundaryProbeBackend) -> str | None:
    """Read the selected context endpoint, accepting only a bounded string."""

    raw = _probe(
        backend,
        ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
    )
    if raw is None:
        return None
    try:
        endpoint = json.loads(raw)
    except (TypeError, ValueError):
        endpoint = None
    return endpoint if isinstance(endpoint, str) and len(endpoint) <= 2048 else None


def _context_source(docker_context: str, endpoint: str | None) -> str:
    """Distinguish an explicit context from an active non-default context."""

    if docker_context:
        return "docker-context"
    if endpoint and not endpoint.startswith("unix:///var/run/docker.sock"):
        return "active-context"
    return "none"


def _endpoint(
    backend: BoundaryProbeBackend, environment: dict[str, str]
) -> tuple[str | None, str]:
    """Resolve only the endpoint used by this backend's Docker transport."""

    docker_host = environment.get("DOCKER_HOST", "").strip()
    docker_context = environment.get("DOCKER_CONTEXT", "").strip()
    if docker_host and docker_context:
        return None, "conflicting-overrides"
    if docker_host:
        return docker_host, "docker-host"
    endpoint = _context_endpoint(backend)
    return endpoint, _context_source(docker_context, endpoint)


def _transport(endpoint: str | None) -> str:
    """Reduce an endpoint URI to a credential-free transport label."""

    if not endpoint:
        return "unknown"
    try:
        scheme = urlsplit(endpoint).scheme.lower()
    except ValueError:
        return "unknown"
    return {
        "unix": "local-unix",
        "npipe": "local-npipe",
        "ssh": "remote-ssh",
        "tcp": "remote-tcp",
    }.get(scheme, "unknown")


def _daemon_info(backend: BoundaryProbeBackend) -> dict[str, object] | None:
    """Read bounded facts from the same selected Docker backend."""

    raw = _probe(backend, ["docker", "info", "--format", "{{json .}}"])
    if raw is None:
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _transport_environment(backend: BoundaryProbeBackend) -> dict[str, str]:
    """Retain only Docker selection overrides from the backend environment."""

    try:
        environment = backend.docker_transport_environment()
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        environment = {}
    if not isinstance(environment, Mapping):
        environment = {}
    return {
        key: value for key, value in environment.items()
        if key in {"DOCKER_HOST", "DOCKER_CONTEXT"} and isinstance(value, str)
    }


def _is_docker_vm(system: str, transport: str, daemon_os: object) -> bool:
    """Recognize a Docker Desktop daemon without claiming host containment."""

    desktop = isinstance(daemon_os, str) and daemon_os.startswith("Docker Desktop")
    local_desktop_host = system in {"macos", "windows"} and transport in {
        "local-unix", "local-npipe"
    }
    return desktop or local_desktop_host


def _is_native_linux(system: str, transport: str, daemon_kernel: str, kernel: str) -> bool:
    """Require a matching local Unix daemon before reporting native Docker."""

    return (
        system == "linux"
        and transport == "local-unix"
        and bool(daemon_kernel)
        and daemon_kernel == kernel
    )


def _classify_linux_daemon(
    system: str, transport: str, daemon_os: object, daemon_kernel: str, kernel: str
) -> tuple[str, str, str]:
    """Classify a local Linux daemon without treating a VM label as proof."""

    runtime, containment, status = "unknown", "unknown", "partial"
    if _is_docker_vm(system, transport, daemon_os):
        runtime, containment, status = "docker-vm", "docker-vm-unverified", "observed"
    elif _is_native_linux(system, transport, daemon_kernel, kernel):
        runtime, containment, status = "native-linux", "native-docker", "observed"
    return runtime, containment, status


def _classify_daemon(
    source: str,
    transport: str,
    info: dict[str, object] | None,
    system: str,
    kernel: str,
    daemon_kernel: str,
) -> tuple[str, str, str]:
    """Report only classifications supported by the selected daemon probe."""

    runtime, containment, status = "unknown", "unknown", "unknown"
    if source == "conflicting-overrides":
        status = "mismatch"
    elif info and transport.startswith("remote-"):
        containment, status = "remote-unverified", "partial"
    elif info and info.get("OSType") == "linux":
        runtime, containment, status = _classify_linux_daemon(
            system, transport, info.get("OperatingSystem"), daemon_kernel, kernel
        )
    elif info:
        status = "partial"
    return runtime, containment, status


def capture_execution_boundary(
    backend: BoundaryProbeBackend,
    *,
    host_system: str | None = None,
    host_kernel: str | None = None,
) -> BoundarySelection:
    """Capture public facts and a non-public identity for the selected daemon."""

    system = host_system or _host_os()
    if system not in {"linux", "macos", "windows"}:
        system = "unknown"
    kernel = _safe_version(host_kernel if host_kernel is not None else platform.release())
    endpoint, source = _endpoint(backend, _transport_environment(backend))
    transport = _transport(endpoint)
    info = _daemon_info(backend) if transport != "unknown" else None
    docker_version = _safe_version(info.get("ServerVersion")) if info else ""
    daemon_kernel = _safe_version(info.get("KernelVersion")) if info else ""
    daemon_runtime, containment, status = _classify_daemon(
        source, transport, info, system, kernel, daemon_kernel
    )

    profiles = {
        "native-docker": "aptl/native-docker-observed/v1",
        "docker-vm-unverified": "aptl/docker-vm-observed/v1",
        "remote-unverified": "aptl/remote-docker-observed/v1",
    }
    observed = ExecutionBoundaryObservation(
        transport=transport,
        override_source=source,  # type: ignore[arg-type]
        daemon_runtime=daemon_runtime,  # type: ignore[arg-type]
        host_containment=containment,  # type: ignore[arg-type]
        observation_status=status,  # type: ignore[arg-type]
        host_os=system,  # type: ignore[arg-type]
        host_kernel=kernel,
        docker_version=docker_version,
        profile_ref=profiles.get(containment, ""),
    )
    return BoundarySelection(
        observation=observed,
        endpoint_digest=_digest(endpoint),
        daemon_digest=_digest(info.get("ID")) if info else "",
    )


def observe_execution_boundary(
    backend: BoundaryProbeBackend,
    *,
    host_system: str | None = None,
    host_kernel: str | None = None,
) -> ExecutionBoundaryObservation:
    """Observe the effective endpoint without mistaking a label for proof."""

    return capture_execution_boundary(
        backend, host_system=host_system, host_kernel=host_kernel
    ).observation


def with_verified_seat_guest(
    observed: ExecutionBoundaryObservation,
) -> ExecutionBoundaryObservation:
    """Distinguish a signed guest launch from independently proved host VM state."""

    if observed.transport != "local-unix":
        return observed
    return ExecutionBoundaryObservation.model_validate(
        {
            **observed.model_dump(),
            "host_containment": "seat-guest-unverified",
            "observation_status": "partial",
            "containment_verified": False,
            "profile_ref": "aptl/seat-vm-guest/v1",
            "evidence_refs": (),
        }
    )


def bind_execution_boundary(
    backend: BoundaryProbeBackend,
    *,
    seat_guest: bool = False,
    host_system: str | None = None,
    host_kernel: str | None = None,
) -> ExecutionBoundaryObservation:
    """Bind one attempt to its selected endpoint and daemon without publishing IDs."""

    selected = capture_execution_boundary(
        backend, host_system=host_system, host_kernel=host_kernel
    )
    if seat_guest:
        selected = BoundarySelection(
            observation=with_verified_seat_guest(selected.observation),
            endpoint_digest=selected.endpoint_digest,
            daemon_digest=selected.daemon_digest,
        )
    backend._execution_boundary_selection = selected
    backend._execution_boundary_disclosure = selected.observation
    return selected.observation


def _same_daemon(selected: BoundarySelection, current: BoundarySelection) -> bool:
    """Require both private identities to match before reusing a bound report."""

    return (
        bool(selected.endpoint_digest and selected.daemon_digest)
        and selected.endpoint_digest == current.endpoint_digest
        and selected.daemon_digest == current.daemon_digest
    )


def _identity_changed(selected: BoundarySelection, current: BoundarySelection) -> bool:
    """Distinguish a changed identity from an identity that became unreadable."""

    endpoint_changed = bool(
        selected.endpoint_digest
        and current.endpoint_digest
        and selected.endpoint_digest != current.endpoint_digest
    )
    daemon_changed = bool(
        selected.daemon_digest
        and current.daemon_digest
        and selected.daemon_digest != current.daemon_digest
    )
    return endpoint_changed or daemon_changed


def _unbound_disclosure(
    current: BoundarySelection, *, changed: bool
) -> ExecutionBoundaryObservation:
    """Remove any containment claim when the bound identity no longer matches."""

    return ExecutionBoundaryObservation.model_validate(
        {
            **current.observation.model_dump(),
            "daemon_runtime": "unknown",
            "host_containment": "unknown",
            "observation_status": "mismatch" if changed else "unknown",
            "containment_verified": False,
            "profile_ref": "",
            "evidence_refs": (),
        }
    )


def revalidate_execution_boundary(
    backend: BoundaryProbeBackend,
    *,
    host_system: str | None = None,
    host_kernel: str | None = None,
) -> ExecutionBoundaryObservation:
    """Project the bound attempt observation, or expose a changed/unknown daemon."""

    selected = getattr(backend, "_execution_boundary_selection", None)
    if not isinstance(selected, BoundarySelection):
        return bind_execution_boundary(
            backend,
            seat_guest=isinstance(getattr(backend, "_appliance_boundary", None), tuple),
            host_system=host_system,
            host_kernel=host_kernel,
        )
    current = capture_execution_boundary(
        backend, host_system=host_system, host_kernel=host_kernel
    )
    observed = (
        selected.observation
        if _same_daemon(selected, current)
        else _unbound_disclosure(current, changed=_identity_changed(selected, current))
    )
    backend._execution_boundary_disclosure = observed
    return observed


def disclosed_execution_boundary(
    backend: BoundaryProbeBackend,
) -> ExecutionBoundaryObservation | None:
    """Read the latest attempt-scoped disclosure without probing again."""

    observed = getattr(backend, "_execution_boundary_disclosure", None)
    return observed if isinstance(observed, ExecutionBoundaryObservation) else None


def has_bound_daemon_identity(backend: BoundaryProbeBackend) -> bool:
    """A required seat cannot depend on an endpoint or daemon that went unread."""

    selected = getattr(backend, "_execution_boundary_selection", None)
    return (
        isinstance(selected, BoundarySelection)
        and bool(selected.endpoint_digest and selected.daemon_digest)
    )
