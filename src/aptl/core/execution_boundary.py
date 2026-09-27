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
    return (
        hashlib.sha256(value.encode("utf-8")).hexdigest()
        if isinstance(value, str) and value
        else ""
    )


def _safe_version(value: object) -> str:
    """Keep untrusted daemon/host text out of public output unless shape-safe."""

    return value if isinstance(value, str) and _SAFE_VERSION.fullmatch(value) else ""


def _host_os() -> Literal["linux", "macos", "windows", "unknown"]:
    system = platform.system().lower()
    return {
        "linux": "linux",
        "darwin": "macos",
        "windows": "windows",
    }.get(system, "unknown")  # type: ignore[return-value]


def _probe(backend: BoundaryProbeBackend, argv: list[str]) -> str | None:
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


def _endpoint(
    backend: BoundaryProbeBackend, environment: dict[str, str]
) -> tuple[str | None, str]:
    docker_host = environment.get("DOCKER_HOST", "").strip()
    docker_context = environment.get("DOCKER_CONTEXT", "").strip()
    if docker_host and docker_context:
        return None, "conflicting-overrides"
    if docker_host:
        return docker_host, "docker-host"
    raw = _probe(
        backend,
        ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
    )
    if raw is None:
        return None, "docker-context" if docker_context else "none"
    try:
        endpoint = json.loads(raw)
    except (TypeError, ValueError):
        endpoint = None
    if not isinstance(endpoint, str) or len(endpoint) > 2048:
        return None, "docker-context" if docker_context else "none"
    source = "docker-context" if docker_context else (
        "active-context" if not endpoint.startswith("unix:///var/run/docker.sock") else "none"
    )
    return endpoint, source


def _transport(endpoint: str | None) -> str:
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
    raw = _probe(backend, ["docker", "info", "--format", "{{json .}}"])
    if raw is None:
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


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
    try:
        environment = backend.docker_transport_environment()
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        environment = {}
    if not isinstance(environment, Mapping):
        environment = {}
    environment = {
        key: value for key, value in environment.items()
        if key in {"DOCKER_HOST", "DOCKER_CONTEXT"} and isinstance(value, str)
    }
    endpoint, source = _endpoint(backend, environment)
    transport = _transport(endpoint)
    info = _daemon_info(backend) if transport != "unknown" else None
    docker_version = _safe_version(info.get("ServerVersion")) if info else ""
    daemon_kernel = _safe_version(info.get("KernelVersion")) if info else ""
    daemon_os = info.get("OperatingSystem") if info else None
    os_type = info.get("OSType") if info else None

    containment = "unknown"
    daemon_runtime = "unknown"
    status = "unknown"
    if source == "conflicting-overrides":
        status = "mismatch"
    elif transport.startswith("remote-") and info:
        containment, status = "remote-unverified", "partial"
    elif info and os_type == "linux":
        if isinstance(daemon_os, str) and daemon_os.startswith("Docker Desktop"):
            daemon_runtime = "docker-vm"
            containment, status = "docker-vm-unverified", "observed"
        elif system in {"macos", "windows"} and transport in {
            "local-unix", "local-npipe"
        }:
            daemon_runtime = "docker-vm"
            containment, status = "docker-vm-unverified", "observed"
        elif (
            system == "linux"
            and transport == "local-unix"
            and daemon_kernel
            and daemon_kernel == kernel
        ):
            daemon_runtime = "native-linux"
            containment, status = "native-docker", "observed"
        else:
            status = "partial"
    elif info:
        status = "partial"

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
    matched = (
        bool(selected.endpoint_digest and selected.daemon_digest)
        and selected.endpoint_digest == current.endpoint_digest
        and selected.daemon_digest == current.daemon_digest
    )
    if matched:
        observed = selected.observation
    else:
        changed = bool(
            (selected.endpoint_digest and current.endpoint_digest
             and selected.endpoint_digest != current.endpoint_digest)
            or (selected.daemon_digest and current.daemon_digest
                and selected.daemon_digest != current.daemon_digest)
        )
        observed = ExecutionBoundaryObservation.model_validate(
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
