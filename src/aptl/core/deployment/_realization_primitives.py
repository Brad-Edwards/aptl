"""Primitive image, network, and environment realization values."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

ImageRealizationMode = Literal["pull", "build"]

# An omitted author host address binds loopback, never all interfaces.
LOOPBACK_HOST_IP = "127.0.0.1"
_ENVIRONMENT_VARIABLE_NAME = re.compile(r"[A-Za-z_]\w*", flags=re.ASCII)


def valid_environment_variable_name(value: object) -> bool:
    """Return whether ``value`` is a conventional, env-file-safe name."""

    return bool(
        isinstance(value, str)
        and _ENVIRONMENT_VARIABLE_NAME.fullmatch(value) is not None
    )


# Docker's --env-file reader keeps everything after a line's first "=" as is,
# but it splits lines on line feeds, drops one trailing carriage return, and
# refuses a line longer than 65535 bytes before its newline (Go bufio.Scanner).
_DOCKER_ENV_FILE_LINE_LIMIT = 65535
# Compose's env_file reader also trims unquoted values, starts a comment at
# "#", honours quotes and backslashes, and interpolates "$NAME" from the
# Compose process environment, so an unquoted value is exact only without them.
_COMPOSE_ENV_FILE_SPECIALS = frozenset("#$'\"\\\r")


class EnvironmentDeliveryRefused(ValueError):
    """An env-file transport cannot carry a binding exactly or safely.

    The message names the variable and the reason, never the value.
    """


def environment_file_line(name: str, value: str, *, compose: bool = False) -> str:
    """Return the ``NAME=value`` env-file line that carries ``value`` exactly.

    Docker's ``--env-file`` and Compose's ``env_file`` read the same line format
    by different rules; ``compose`` selects which reader the line is for. The
    value either survives that reader unchanged or is refused with
    :class:`EnvironmentDeliveryRefused`. It is never trimmed, escaped or cut.
    """

    if not valid_environment_variable_name(name):
        raise EnvironmentDeliveryRefused("invalid environment variable name")
    line = f"{name}={value}"
    problem = _env_file_value_problem(value) or (
        _compose_env_file_problem(value) if compose else _docker_env_file_problem(line)
    )
    if problem is not None:
        reader = "a Compose env file" if compose else "a Docker env file"
        raise EnvironmentDeliveryRefused(
            f"{reader} cannot carry {name} exactly: {problem}"
        )
    return line + "\n"


def _env_file_value_problem(value: str) -> str | None:
    """Return why no env-file line can hold ``value``, or ``None``."""

    problem = None
    if "\n" in value:
        problem = "the value contains a line break"
    elif "\x00" in value:
        problem = "the value contains a NUL character"
    elif not _is_utf8_encodable(value):
        problem = "the value is not valid UTF-8"
    return problem


def _is_utf8_encodable(value: str) -> bool:
    """Whether ``value`` has a UTF-8 encoding (no lone surrogates)."""

    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _docker_env_file_problem(line: str) -> str | None:
    """Return what Docker's env-file reader would change in ``line``."""

    if line.endswith("\r"):
        return "Docker drops a trailing carriage return"
    if len(line.encode("utf-8")) > _DOCKER_ENV_FILE_LINE_LIMIT:
        return "the line exceeds Docker's 64 KiB env-file line limit"
    return None


def _compose_env_file_problem(value: str) -> str | None:
    """Return what Compose's env-file reader would change in ``value``."""

    if value[:1].isspace() or value[-1:].isspace():
        return "Compose trims leading and trailing whitespace"
    if not _COMPOSE_ENV_FILE_SPECIALS.isdisjoint(value):
        return "Compose interprets #, $, quotes, backslashes and carriage returns"
    return None


@dataclass(frozen=True)
class DeploymentImageRealization:
    """One image operation resolved from authored or open backend authority."""

    address: str
    service_name: str
    source_name: str
    source_version: str
    image_ref: str
    mode: ImageRealizationMode
    policy_rule: str
    dockerfile_path: str | None = None
    context_path: str | None = None
    provenance: dict[str, int] | None = None

    def details(self) -> dict[str, object]:
        """Return a serializable image realization projection."""

        details: dict[str, object] = {
            "address": self.address,
            "service_name": self.service_name,
            "source_name": self.source_name,
            "source_version": self.source_version,
            "image_ref": self.image_ref,
            "mode": self.mode,
            "policy_rule": self.policy_rule,
        }
        if self.dockerfile_path is not None:
            details["dockerfile_path"] = self.dockerfile_path
        if self.context_path is not None:
            details["context_path"] = self.context_path
        if self.provenance is not None:
            details["provenance"] = dict(self.provenance)
        return details


@dataclass(frozen=True)
class DeploymentNetworkRealization:
    """One scenario-declared network the backend may materialize."""

    name: str
    cidr: str | None = None
    gateway: str | None = None
    internal: bool | None = None


@dataclass(frozen=True)
class DeploymentNetworkAttachment:
    """One node-to-network attachment requested by the scenario."""

    network: str
    ipv4_address: str | None = None
    # The admitted network's declared CIDR, so post-start providers can scope
    # native policy to the declared network instead of a copied constant.
    cidr: str | None = None


__all__ = (
    "DeploymentImageRealization",
    "DeploymentNetworkAttachment",
    "DeploymentNetworkRealization",
    "ImageRealizationMode",
    "LOOPBACK_HOST_IP",
    "valid_environment_variable_name",
)
