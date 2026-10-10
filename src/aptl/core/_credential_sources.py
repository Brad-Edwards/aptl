"""Credential-source locators for ``aptl.json``: names of sources, never values.

:class:`ProcessEnvironmentCredentialSource` selects an installed participant's
credential (issue #856). :class:`EnvironmentGrant` binds one source to one
variable that one node of an admitted pack declares (issue #965). They live
here so :mod:`aptl.core.config`, which uses both, stays within its size budget.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_CREDENTIAL_SOURCE_VARIABLE_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_ENVIRONMENT_VARIABLE_PATTERN = re.compile(r"^[A-Za-z_]\w{0,127}$", flags=re.ASCII)
# The same shape as other aptl.json names: a pack id or an SDL node name.
_GRANT_IDENTITY_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


class ProcessEnvironmentCredentialSource(BaseModel):
    """Select one exact parent-process variable without storing its value."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["process-environment"]
    variable: str = Field(strict=True, min_length=1, max_length=128)

    @field_validator("variable")
    @classmethod
    def validate_variable(cls, value: str) -> str:
        """Admit one bounded POSIX-style environment variable locator."""

        if not _CREDENTIAL_SOURCE_VARIABLE_PATTERN.fullmatch(value):
            raise ValueError("credential source variable is invalid")
        return value

    def descriptor_digest(self) -> str:
        """Identify this non-secret descriptor without publishing its locator."""

        payload = json.dumps(
            self.model_dump(mode="json"),
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()


class ProjectEnvironmentFileSource(BaseModel):
    """Select one exact key of the project's private ``.env`` without its value."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["project-env-file"]
    variable: str = Field(strict=True, min_length=1, max_length=128)

    @field_validator("variable")
    @classmethod
    def validate_variable(cls, value: str) -> str:
        """Admit one bounded ``.env`` key, in either case."""

        if not _ENVIRONMENT_VARIABLE_PATTERN.fullmatch(value):
            raise ValueError("environment grant source variable is invalid")
        return value


class EnvironmentGrant(BaseModel):
    """Grant one configured source to one declared variable of one pack node.

    The grant names the admitted pack (its ``pack_id``), the consuming node and
    the variable that node declares, plus the exact source to read. It stores
    locators, never a value, so ``aptl.json`` stays a non-secret file.
    """

    model_config = ConfigDict(extra="forbid")

    pack: str = Field(strict=True, min_length=1, max_length=128)
    consumer: str = Field(strict=True, min_length=1, max_length=128)
    variable: str = Field(strict=True, min_length=1, max_length=128)
    source: ProcessEnvironmentCredentialSource | ProjectEnvironmentFileSource = Field(
        discriminator="kind"
    )

    @field_validator("pack", "consumer")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        """Admit a pack id or SDL node name, never a path or pattern."""

        if not _GRANT_IDENTITY_PATTERN.fullmatch(value):
            raise ValueError("environment grant pack or consumer is invalid")
        return value

    @field_validator("variable")
    @classmethod
    def validate_target(cls, value: str) -> str:
        """Admit only a name an env file can carry."""

        if not _ENVIRONMENT_VARIABLE_PATTERN.fullmatch(value):
            raise ValueError("environment grant variable is invalid")
        return value

    @property
    def key(self) -> tuple[str, str, str]:
        """Return the ``(pack, consumer, variable)`` this grant binds."""

        return (self.pack, self.consumer, self.variable)

    @property
    def source_identity(self) -> str:
        """Name the source without its value, for logs, errors and evidence."""

        return f"{self.source.kind}:{self.source.variable}"


__all__ = (
    "EnvironmentGrant",
    "ProcessEnvironmentCredentialSource",
    "ProjectEnvironmentFileSource",
)
