"""Shared types and bounded command helpers for TechVault database realization."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Protocol

TIMEOUT = 60
RESTART_TIMEOUT = 120

FAILURE_SELECTION = "TechVault database declaration or internal client is unavailable"
FAILURE_CLUSTER = "TechVault PostgreSQL cluster is unavailable"
FAILURE_LISTENER = "TechVault PostgreSQL internal listener could not be realized"
FAILURE_CLIENT = "TechVault portal database client does not match the declaration"
FAILURE_AUTH = "TechVault PostgreSQL client authentication could not be realized"
FAILURE_OBJECTS = (
    "TechVault PostgreSQL role, database, or pack SQL could not be realized"
)
FAILURE_FOREIGN_STATE = "TechVault database holds state this startup did not initialize"


class DatabaseBackend(Protocol):
    """Container command boundary supplied by the running lab backend."""

    def container_exec(
        self, name: str, cmd: list[str], *, timeout: int | None = None
    ) -> object:
        """Run a bounded command in the named scenario container."""
        ...

    def container_exec_with_input(
        self, name: str, cmd: list[str], payload: str, *, timeout: int | None = None
    ) -> object:
        """Run a bounded command that reads its body from stdin."""
        ...


@dataclass(frozen=True)
class DeclaredDatabase:
    """The one PostgreSQL service, client, and network the pack declares."""

    db_container: str
    web_container: str
    database: str
    role: str
    db_address: str
    scope: ipaddress.IPv4Network
    listen_address: str
    port: int
    tables: frozenset[str]


class RealizationFailure(Exception):
    """A bounded, nonsecret realization failure."""


def exec_command(
    backend: DatabaseBackend, container: str, argv: list[str], timeout: int = TIMEOUT
) -> object:
    """Execute a bounded database setup command."""
    return backend.container_exec(container, argv, timeout=timeout)


def read_output(
    backend: DatabaseBackend, container: str, argv: list[str]
) -> str | None:
    """Read successful command output, preserving failure as None."""
    result = exec_command(backend, container, argv)
    if getattr(result, "returncode", 1) != 0:
        return None
    return str(getattr(result, "stdout", "") or "").strip()


def succeeded(
    backend: DatabaseBackend, container: str, argv: list[str], timeout: int = TIMEOUT
) -> bool:
    """Return whether a database setup command succeeded."""
    result = exec_command(backend, container, argv, timeout)
    return getattr(result, "returncode", 1) == 0


def psql(statement: str, database: str = "postgres") -> list[str]:
    """Build a fixed, nonsecret local PostgreSQL query without a shell."""
    return ["runuser", "-u", "postgres", "--", "psql", "-X", "-d", database, "-Atqc", statement]  # fmt: skip


def query(
    backend: DatabaseBackend,
    container: str,
    statement: str,
    database: str = "postgres",
    failure: str = FAILURE_OBJECTS,
) -> str:
    """Read a catalog query, distinguishing failure from an empty answer."""
    output = read_output(backend, container, psql(statement, database))
    if output is None:
        raise RealizationFailure(failure)
    return output
