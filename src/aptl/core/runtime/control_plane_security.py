"""Security policy for the per-target runtime control plane."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ControlPlaneRole(str, Enum):
    """Authorization roles for control-plane callers."""

    BACKEND = "backend"
    OPERATOR = "operator"
    AUDITOR = "auditor"


@dataclass(frozen=True)
class ControlPlaneIdentity:
    """Authenticated control-plane principal."""

    identity: str
    roles: frozenset[ControlPlaneRole] = field(default_factory=frozenset)
    target_name: str | None = None


@dataclass(frozen=True)
class ControlPlaneSecurityConfig:
    """Reference security settings for the HTTP/JSON control-plane adapter."""

    require_verified_identity: bool = True
    verified_header: str = "x-aptl-client-verified"
    identity_header: str = "x-aptl-client-identity"
    max_request_bytes: int = 1_000_000
    trusted_identities: dict[str, ControlPlaneIdentity] = field(default_factory=dict)
    bearer_tokens: dict[str, ControlPlaneIdentity] = field(default_factory=dict)

    @classmethod
    def strict_defaults(
        cls,
        *,
        target_name: str | None = None,
    ) -> "ControlPlaneSecurityConfig":
        backend_identity = ControlPlaneIdentity(
            identity="backend-service",
            roles=frozenset({ControlPlaneRole.BACKEND}),
            target_name=target_name,
        )
        operator_identity = ControlPlaneIdentity(
            identity="operator",
            roles=frozenset({ControlPlaneRole.OPERATOR, ControlPlaneRole.AUDITOR}),
            target_name=target_name,
        )
        return cls(
            require_verified_identity=True,
            trusted_identities={
                backend_identity.identity: backend_identity,
            },
            bearer_tokens={
                "operator-token": operator_identity,
            },
        )
