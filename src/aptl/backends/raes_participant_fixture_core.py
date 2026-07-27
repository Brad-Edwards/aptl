"""Shared state and I/O primitives for bounded participant fixtures."""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

_LAB_HTTP_ORIGIN = "http://webapp:8080"  # NOSONAR - isolated synthetic lab service
_LOGIN_ENDPOINT = "/login"
_BENIGN_ACCOUNT_ACTIVE = "benign-customer|active"
_PROFILE_CONTACT_EMAIL = "profile.contact_email"
_PROFILE_DEPARTMENT = "profile.department"
_PROFILE_PROTECTED_ACCOUNT_ID = "profile.protected_account_id"
_SUPPORT_REQUEST = "support.request"
_SUPPORT_NOTE = "support.note"
_RESPONSE_STATUS = "response.status"
_RESPONSE_CONTENT_TYPE = "response.content-type"
_RESPONSE_CONTENT_LENGTH = "response.content-length"
_RESPONSE_LOCATION = "response.location"
_RESPONSE_LATEST = "response.latest"
_WEBAPP_SESSION = "webapp.session"
_DB_SUPPORT_REQUEST = "db.support.request"
_DEBUG_ENDPOINT = "/debug"
_WEBAPP_ASSESSOR_ACCESS = "webapp.assessor-access"
_KALI_LAST_AUTH_OUTCOME = "kali.last-auth-outcome"
_ASSESSOR_CONTAINMENT = "response.contain:identities.synthetic-assessor"
_WEBAPP_BENIGN_ACCESS = "webapp.benign-access"


@dataclass(frozen=True)
class VerifiedParticipantOperation:
    """One native operation plus independently read semantic state."""

    success: bool
    summary: str
    pre_state: Mapping[str, str]
    post_state: Mapping[str, str]
    established_preconditions: tuple[str, ...] = ()
    established_effects: tuple[str, ...] = ()
    diagnostic: str | None = None
    failure_class: str | None = None

    @property
    def pre_state_digest(self) -> str:
        """Return the canonical pre-state digest."""

        return _mapping_digest(self.pre_state)

    @property
    def post_state_digest(self) -> str:
        """Return the canonical post-state digest."""

        return _mapping_digest(self.post_state)

    @property
    def state_changed(self) -> bool:
        """Report whether trusted semantic state changed."""

        return self.pre_state_digest != self.post_state_digest


@dataclass(frozen=True)
class _OperationContext:
    """Bind one verified operation to its backend state."""

    backend: "DeploymentBackend"
    containers: Mapping[str, str]
    state_dir: str
    arguments: Mapping[str, object]

    def container(self, node: str) -> str:
        """Resolve a realized node to its backend container."""

        return self.containers[node]

    def path(self, name: str) -> str:
        """Resolve one episode-state artifact path."""

        return f"{self.state_dir}/{name}"


def _ensure_fixture(
    context: _OperationContext,
    target_nodes: tuple[str, ...],
) -> None:
    """Create the reset-equivalent synthetic state before the pre-state cut."""

    defaults = {
        "webapp": {
            "session": "inactive",
            "assessor-access": "allowed",
            "benign-access": "allowed",
            "help.account-access": "Use the assigned synthetic account.",
            "help.profile-corrections": "Only permitted profile fields may change.",
            "help.support-requests": "Use an approved support request template.",
        },
        "db": {
            "account": _BENIGN_ACCOUNT_ACTIVE,
            _PROFILE_CONTACT_EMAIL: "green.user@techvault.local",
            _PROFILE_DEPARTMENT: "Engineering",
            _PROFILE_PROTECTED_ACCOUNT_ID: "TV-SYNTHETIC-001",
            _SUPPORT_REQUEST: "none",
            _SUPPORT_NOTE: "none",
        },
        "kali": {
            "last-response": "none",
            _RESPONSE_STATUS: "none",
            _RESPONSE_CONTENT_TYPE: "none",
            _RESPONSE_CONTENT_LENGTH: "none",
            _RESPONSE_LOCATION: "none",
            "last-auth-outcome": "none",
        },
        "defender-console": {
            "alert.auth-001": (
                "authentication|synthetic-assessor|kali|webapp|"
                "2026-01-01T00:00:01Z|assigned"
            ),
            "alert.actor-001": (
                "actor-activity|synthetic-assessor|kali|webapp|"
                "2026-01-01T00:00:02Z|assigned"
            ),
            "alert.response-001": (
                "response-needed|synthetic-assessor|kali|webapp|"
                "2026-01-01T00:00:03Z|assigned"
            ),
            "context.host.webapp": "webapp|synthetic-service|reachable",
            "context.identity.benign-customer": "benign-customer|assigned",
            "context.identity.synthetic-assessor": "synthetic-assessor|assigned",
            "auth-event": "none",
        },
        "event-store": {
            "events.identities.benign-customer": (
                "login|account-view|profile-view|support-request|sign-out"
            ),
            "events.identities.synthetic-assessor": (
                "surface-view|endpoint-probe|authentication|objective-discovery|"
                "marker-retrieval"
            ),
            "classification.alerts.auth-001": "unclassified",
            "classification.alerts.actor-001": "unclassified",
            "classification.alerts.response-001": "unclassified",
            _RESPONSE_LATEST: "none",
        },
    }
    for node in target_nodes:
        values = defaults.get(node, {})
        container = context.containers.get(node)
        if container is None:
            continue
        for name, value in values.items():
            _ensure_value(context.backend, container, context.path(name), value)


def _values(
    context: _OperationContext,
    node: str,
    names: tuple[str, ...],
) -> dict[str, str]:
    """Read the internal operation for the bounded participant workflow."""
    container = context.container(node)
    return {
        f"{node}.{name}": _read_value(
            context.backend,
            container,
            context.path(name),
        )
        for name in names
    }


def _combined_values(
    context: _OperationContext,
    groups: tuple[tuple[str, tuple[str, ...]], ...],
) -> dict[str, str]:
    """Read values for the bounded participant workflow."""
    values: dict[str, str] = {}
    for node, names in groups:
        values.update(_values(context, node, names))
    return values


def _ensure_value(
    backend: "DeploymentBackend",
    container: str,
    path: str,
    value: str,
) -> None:
    """Ensure value for the bounded participant workflow."""
    _checked_exec(
        backend,
        container,
        [
            "sh",
            "-c",
            (
                'umask 077; mkdir -p -- "$(dirname -- "$1")"; '
                'if test ! -f "$1"; then printf \'%s\' "$2" > "$1"; fi'
            ),
            "aptl-bpa-ensure",
            path,
            value,
        ],
    )


def _write_value(
    backend: "DeploymentBackend",
    container: str,
    path: str,
    value: str,
) -> None:
    """Write value for the bounded participant workflow."""
    _checked_exec(
        backend,
        container,
        [
            "sh",
            "-c",
            ('umask 077; mkdir -p -- "$(dirname -- "$1")"; printf \'%s\' "$2" > "$1"'),
            "aptl-bpa-write",
            path,
            value,
        ],
    )


def _read_value(
    backend: "DeploymentBackend",
    container: str,
    path: str,
) -> str:
    """Read value for the bounded participant workflow."""
    return _checked_exec(
        backend,
        container,
        [
            "sh",
            "-c",
            'test -f "$1" && cat -- "$1"',
            "aptl-bpa-read",
            path,
        ],
    ).strip()


def _read_absolute(
    backend: "DeploymentBackend",
    container: str,
    path: str,
) -> str:
    """Read absolute for the bounded participant workflow."""
    return _checked_exec(
        backend,
        container,
        ["cat", "--", path],
    ).strip()


def _http_status(
    context: _OperationContext,
    source_node: str,
    endpoint: str,
    method: str,
) -> str:
    """Observe status for the bounded participant workflow."""
    command = [
        "curl",
        "-sS",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--max-time",
        "10",
        "--max-redirs",
        "0",
        "--proto",
        "=http",
        "-X",
        method,
    ]
    command.append(f"{_LAB_HTTP_ORIGIN}{endpoint}")
    return _checked_exec(
        context.backend,
        context.container(source_node),
        command,
    ).strip()


def _http_response_metadata(
    context: _OperationContext,
    source_node: str,
    endpoint: str,
    method: str,
) -> tuple[str, str, str, str]:
    """Observe the bounded response fields retained for a later inspection."""

    command = [
        "curl",
        "-sS",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}\\n%{content_type}\\n%{size_download}\\n%{redirect_url}",
        "--max-time",
        "10",
        "--max-redirs",
        "0",
        "--proto",
        "=http",
        "-X",
        method,
        f"{_LAB_HTTP_ORIGIN}{endpoint}",
    ]
    observed = _checked_exec(
        context.backend,
        context.container(source_node),
        command,
    )
    lines = observed.splitlines()
    lines.extend("" for _ in range(4 - len(lines)))
    status, content_type, content_length, location = lines[:4]
    if not status:
        raise OSError("bounded HTTP response omitted its status")
    return (
        status,
        content_type or "absent",
        content_length or "0",
        location or "absent",
    )


def _checked_exec(
    backend: "DeploymentBackend",
    container: str,
    command: list[str],
) -> str:
    """Execute exec for the bounded participant workflow."""
    result = backend.container_exec(container, command, timeout=30)
    if not isinstance(result, subprocess.CompletedProcess):
        raise OSError("deployment backend returned an invalid operation result")
    if result.returncode != 0:
        raise OSError(f"native operation return code {result.returncode}")
    output = result.stdout
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return str(output)


def _scalar(
    arguments: Mapping[str, object],
    name: str,
    *,
    default: str | None = None,
) -> str:
    """Resolve the internal operation for the bounded participant workflow."""
    value = arguments.get(name, default)
    if isinstance(value, int):
        return str(value)
    if not isinstance(value, str) or not value:
        raise ValueError(f"governed argument {name!r} is not scalar")
    return value


def _many(arguments: Mapping[str, object], name: str) -> tuple[str, ...]:
    """Resolve the internal operation for the bounded participant workflow."""
    value = arguments.get(name)
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, list | tuple) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ValueError(f"governed argument {name!r} is not a string collection")
    return tuple(value)


def _verified(
    success: bool,
    summary: str,
    pre_state: Mapping[str, str],
    post_state: Mapping[str, str],
    precondition: str,
    *effects: str,
) -> VerifiedParticipantOperation:
    """Handle the internal operation for the bounded participant workflow."""
    if success:
        return VerifiedParticipantOperation(
            success=True,
            summary=summary,
            pre_state=dict(pre_state),
            post_state=dict(post_state),
            established_preconditions=(precondition,),
            established_effects=tuple(effects),
        )
    return VerifiedParticipantOperation(
        success=False,
        summary="trusted semantic readback did not establish the action contract",
        pre_state=dict(pre_state),
        post_state=dict(post_state),
        diagnostic=summary,
        failure_class="backend_error",
    )


def _failed(
    diagnostic: str,
    failure_class: str = "precondition_unsatisfied",
) -> VerifiedParticipantOperation:
    """Build the internal operation for the bounded participant workflow."""
    return VerifiedParticipantOperation(
        success=False,
        summary="bounded semantic operation failed closed",
        pre_state={},
        post_state={},
        diagnostic=diagnostic,
        failure_class=failure_class,
    )


def _mapping_digest(value: Mapping[str, Any]) -> str:
    """Compute digest for the bounded participant workflow."""
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def participant_episode_state_dir(
    participant_address: str,
    episode_id: str,
) -> str:
    """Return the fixed backend state root for one synthetic episode."""

    token = hashlib.sha256(f"{participant_address}\0{episode_id}".encode()).hexdigest()[
        :24
    ]
    return f"/run/aptl/bounded-participant/{token}"
