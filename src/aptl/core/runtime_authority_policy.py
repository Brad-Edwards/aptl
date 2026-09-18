"""Operator authorization for contained runtime-orchestration authority.

The policy authorizes use of one operator-selected target for one immutable
scenario-pack identity.  It never changes SDL meaning and is deliberately
separate from :class:`aptl.core.config.AptlConfig`; that config may point at a
policy document, but the grant vocabulary and fail-closed loader live here.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aptl.core.scenario_bundle import PackIdentity
from aptl.utils.pathsafe import read_contained_nofollow

_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_DAEMON_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_ADDRESS = re.compile(r"^[a-z0-9][a-z0-9._-]*(?:\.[a-z0-9][a-z0-9._-]*)+$")


class _StrictPolicyModel(BaseModel):
    """Closed, immutable policy input."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class RuntimeAuthorityTarget(_StrictPolicyModel):
    """One operator-selected Docker target candidate.

    Selection and endpoint identity authorize a target; they do not establish
    the independent containment evidence a high-authority profile requires.
    """

    profile_id: str = Field(pattern=_IDENTIFIER.pattern)
    provider: Literal["ssh-compose"]
    ssh_host: str = Field(min_length=1, max_length=253)
    daemon_id: str = Field(pattern=_DAEMON_ID.pattern)
    endpoint_source: str

    @field_validator("ssh_host")
    @classmethod
    def validate_ssh_host(cls, value: str) -> str:
        """Keep the contained target off the controller's loopback boundary."""

        cleaned = value.strip()
        if not cleaned or cleaned == "localhost" or cleaned.endswith(".localhost"):
            raise ValueError("ssh_host must name a remote non-loopback target")
        candidate = cleaned.removeprefix("[").removesuffix("]")
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return cleaned
        if address.is_loopback or address.is_unspecified:
            raise ValueError("ssh_host must name a remote non-loopback target")
        return cleaned

    @field_validator("endpoint_source")
    @classmethod
    def validate_endpoint_source(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path != PurePosixPath("/var/run/docker.sock"):
            raise ValueError(
                "endpoint_source must be the contained target Docker socket"
            )
        return value


class RuntimeAuthorityGrant(_StrictPolicyModel):
    """Authorization for one immutable pack/component/authority tuple."""

    pack_id: str = Field(pattern=_IDENTIFIER.pattern)
    pack_version: str = Field(min_length=1, max_length=128)
    pack_set_digest: str
    component_address: str = Field(pattern=_ADDRESS.pattern)
    authority_id: str = Field(pattern=_IDENTIFIER.pattern)
    endpoint_source: str
    image_template_ids: tuple[str, ...] = ()
    delegated_template_ids: tuple[str, ...] = ()

    @field_validator("pack_set_digest")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if not _DIGEST.fullmatch(value):
            raise ValueError("pack_set_digest must be sha256:<lowercase hex>")
        return value

    @field_validator("endpoint_source")
    @classmethod
    def validate_endpoint_source(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path != PurePosixPath("/var/run/docker.sock"):
            raise ValueError(
                "endpoint_source must be the contained target Docker socket"
            )
        return value

    @field_validator("image_template_ids", "delegated_template_ids")
    @classmethod
    def validate_template_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)) or any(
            not _IDENTIFIER.fullmatch(value) for value in values
        ):
            raise ValueError("template ids must be unique canonical identifiers")
        return values

    @model_validator(mode="after")
    def validate_delegation_narrows(self) -> RuntimeAuthorityGrant:
        if not set(self.delegated_template_ids) <= set(self.image_template_ids):
            raise ValueError("delegated template ids must narrow image template ids")
        return self

    def matches(
        self,
        identity: PackIdentity,
        *,
        component_address: str,
        authority_id: str,
        endpoint_source: str,
        image_template_ids: tuple[str, ...],
    ) -> bool:
        """Return whether this grant exactly authorizes the carried decision."""

        return bool(
            self.pack_id == identity.pack_id
            and self.pack_version == identity.pack_version
            and self.pack_set_digest == identity.set_digest
            and self.component_address == component_address
            and self.authority_id == authority_id
            and self.endpoint_source == endpoint_source
            and set(image_template_ids) <= set(self.image_template_ids)
        )


class RuntimeAuthorityPolicy(_StrictPolicyModel):
    """One selected target plus immutable scenario grants for that target."""

    schema_version: Literal["aptl.runtime-authority-policy/v1"]
    target: RuntimeAuthorityTarget | None = None
    grants: tuple[RuntimeAuthorityGrant, ...] = ()

    @classmethod
    def empty(cls) -> RuntimeAuthorityPolicy:
        """Return the canonical default-deny policy."""

        return cls(schema_version="aptl.runtime-authority-policy/v1")

    @model_validator(mode="after")
    def validate_policy(self) -> RuntimeAuthorityPolicy:
        if self.grants and self.target is None:
            raise ValueError("runtime authority grants require one selected target")
        keys = [
            (
                grant.pack_id,
                grant.pack_version,
                grant.pack_set_digest,
                grant.component_address,
                grant.authority_id,
            )
            for grant in self.grants
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("runtime authority grants must be unique")
        if self.target is not None and any(
            grant.endpoint_source != self.target.endpoint_source
            for grant in self.grants
        ):
            raise ValueError("grant endpoint_source must match the selected target")
        return self

    def grant_for(
        self,
        identity: PackIdentity | None,
        *,
        component_address: str,
        authority_id: str,
        endpoint_source: str,
        image_template_ids: tuple[str, ...],
    ) -> RuntimeAuthorityGrant | None:
        """Return the exact matching grant, never a pack-id-only fallback."""

        if identity is None:
            return None
        return next(
            (
                grant
                for grant in self.grants
                if grant.matches(
                    identity,
                    component_address=component_address,
                    authority_id=authority_id,
                    endpoint_source=endpoint_source,
                    image_template_ids=image_template_ids,
                )
            ),
            None,
        )


def load_runtime_authority_policy(
    project_root: Path,
    relative_path: str | None,
) -> RuntimeAuthorityPolicy:
    """Load one strict no-follow policy; absence means zero grants."""

    if relative_path is None:
        return RuntimeAuthorityPolicy.empty()
    payload = read_contained_nofollow(project_root, relative_path)
    return RuntimeAuthorityPolicy.model_validate_json(payload)


__all__ = [
    "RuntimeAuthorityGrant",
    "RuntimeAuthorityPolicy",
    "RuntimeAuthorityTarget",
    "load_runtime_authority_policy",
]
