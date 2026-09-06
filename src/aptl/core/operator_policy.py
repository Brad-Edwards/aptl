"""Strict local operator grants kept separate from portable scenario intent."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aptl.utils.pathsafe import (
    REASON_NOT_FOUND,
    PathContainmentError,
    read_contained_nofollow,
)

OPERATOR_POLICY_FILENAME = "operator-policy.json"
_IDENTITY_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,254}$")
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class DockerAuthorityGrant(BaseModel):
    """One immutable-pack grant for a host-root-equivalent Docker authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pack_id: str = Field(strict=True)
    pack_version: str = Field(strict=True)
    pack_set_digest: str = Field(strict=True)
    component_address: str = Field(strict=True)
    authority_id: str = Field(strict=True)
    endpoint_source: Literal["/var/run/docker.sock"]
    image_template_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    delegated_template_ids: tuple[str, ...] = Field(
        default_factory=tuple, max_length=64
    )

    @field_validator(
        "pack_id",
        "pack_version",
        "component_address",
        "authority_id",
    )
    @classmethod
    def validate_identity(cls, value: str) -> str:
        """Require one bounded, non-ambiguous policy identity."""

        if not _IDENTITY_PATTERN.fullmatch(value):
            raise ValueError("operator policy identity is invalid")
        return value

    @field_validator("pack_set_digest")
    @classmethod
    def validate_pack_digest(cls, value: str) -> str:
        """Require the immutable content-set identity validated by env-packs."""

        if not _DIGEST_PATTERN.fullmatch(value):
            raise ValueError("operator policy pack digest is invalid")
        return value

    @field_validator("image_template_ids", "delegated_template_ids")
    @classmethod
    def validate_template_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Reject duplicate, malformed, or order-ambiguous template ids."""

        if len(values) != len(set(values)) or any(
            _IDENTITY_PATTERN.fullmatch(value) is None for value in values
        ):
            raise ValueError("operator policy template ids must be unique and valid")
        return values

    @model_validator(mode="after")
    def validate_delegated_templates(self) -> DockerAuthorityGrant:
        """Delegation may only narrow the exact admitted image inventory."""

        if not set(self.delegated_template_ids) <= set(self.image_template_ids):
            raise ValueError(
                "delegated_template_ids must be a subset of image_template_ids"
            )
        return self


class OperatorPolicy(BaseModel):
    """Versioned local policy whose grants intersect pack intent and capability."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["aptl.operator-policy/v1"] = "aptl.operator-policy/v1"
    docker_authority_grants: tuple[DockerAuthorityGrant, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )

    @model_validator(mode="after")
    def validate_unique_docker_grants(self) -> OperatorPolicy:
        """One immutable pack/component/authority tuple has one policy owner."""

        keys = [
            (
                grant.pack_id,
                grant.pack_version,
                grant.pack_set_digest,
                grant.component_address,
                grant.authority_id,
            )
            for grant in self.docker_authority_grants
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("Docker authority grants must be unique")
        return self


def load_operator_policy(project_dir: Path) -> OperatorPolicy:
    """Load the fixed local policy no-follow; an absent file means no grants."""

    try:
        payload = read_contained_nofollow(project_dir, OPERATOR_POLICY_FILENAME)
    except PathContainmentError as exc:
        if exc.reason == REASON_NOT_FOUND:
            return OperatorPolicy()
        raise ValueError("operator policy could not be read safely") from exc
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("operator policy is not valid JSON") from exc
    return OperatorPolicy.model_validate(document)


__all__ = [
    "DockerAuthorityGrant",
    "OPERATOR_POLICY_FILENAME",
    "OperatorPolicy",
    "load_operator_policy",
]
