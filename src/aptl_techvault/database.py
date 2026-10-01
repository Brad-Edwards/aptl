"""Realize TechVault's declared PostgreSQL state from its pack-owned SQL.

The pack-qualified startup provider calls this after the generic nodes exist.
The generic materializer places the exact SQL artifacts, but does not execute
them or configure a PostgreSQL cluster. This adapter closes that gap without
changing the customer portal or its intended weaknesses.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Protocol

from aptl_techvault.log_source_support import _postgres_cluster

_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]*\Z")
# TechVault's authored, guest-only network; this is not an external endpoint.
_INTERNAL_NETWORK = ipaddress.ip_network("172.20.2.0/24")  # NOSONAR
_SCHEMA = "/opt/db-init/01-schema.sql"
_SEED = "/opt/db-init/02-seed-data.sql"
_EXPECTED_TABLES = frozenset(
    {
        "users",
        "customers",
        "files",
        "api_keys",
        "audit_log",
        "backup_config",
        "sessions",
        "comments",
    }
)


class DatabaseBackend(Protocol):
    """Container command boundary supplied by the running lab backend."""

    def container_exec(
        self, name: str, cmd: list[str], *, timeout: int | None = None
    ) -> object:
        """Run a bounded command in the named scenario container."""
        ...


def _value(item: object) -> str:
    """Normalize a declared enum or string value."""
    return str(getattr(item, "value", item) or "")


def _exec(backend: DatabaseBackend, container: str, argv: list[str]) -> object:
    """Execute a bounded database setup command."""
    return backend.container_exec(container, argv, timeout=60)


def _read(backend: DatabaseBackend, container: str, argv: list[str]) -> str | None:
    """Read successful command output, preserving failure as None."""
    result = _exec(backend, container, argv)
    if getattr(result, "returncode", 1) != 0:
        return None
    return str(getattr(result, "stdout", "") or "").strip()


def _ok(backend: DatabaseBackend, container: str, argv: list[str]) -> bool:
    """Return whether a database setup command succeeded."""
    return getattr(_exec(backend, container, argv), "returncode", 1) == 0


def _psql(statement: str, database: str = "postgres") -> list[str]:
    """Build a local PostgreSQL query without invoking a shell."""
    return [
        "runuser",
        "-u",
        "postgres",
        "--",
        "psql",
        "-d",
        database,
        "-Atqc",
        statement,
    ]


def _internal_address(node: object) -> str | None:
    """Read the one declared address on TechVault's internal network."""
    addresses = [
        str(getattr(attachment, "ipv4_address", "") or "")
        for attachment in getattr(node, "network_attachments", ())
        if getattr(attachment, "network", "") == "internal-net"
    ]
    if len(addresses) != 1:
        return None
    try:
        address = ipaddress.ip_address(addresses[0])
    except ValueError:
        return None
    return str(address) if address in _INTERNAL_NETWORK else None


def _declared_nodes(nodes: tuple[object, ...]) -> tuple[object, object] | None:
    """Require exactly one database and one portal node."""
    db_nodes = [node for node in nodes if getattr(node, "name", "") == "db"]
    web_nodes = [node for node in nodes if getattr(node, "name", "") == "webapp"]
    return (db_nodes[0], web_nodes[0]) if len(db_nodes) == len(web_nodes) == 1 else None


def _postgres_service(db_node: object) -> object | None:
    """Require the single PostgreSQL service declared by the pack."""
    runtime = getattr(db_node, "runtime", None)
    services = getattr(runtime, "database_services", ())
    return services[0] if len(services) == 1 and _value(services[0].engine) == "postgresql" else None


def _declared_listener(service: object) -> bool:
    """Require the pack's single PostgreSQL listener on all guest interfaces."""
    listeners = getattr(service, "listeners", ())
    return (
        len(listeners) == 1
        and listeners[0].address == "0.0.0.0"
        and listeners[0].port == 5432
    )


def _service_identity(service: object | None) -> tuple[str, str] | None:
    """Select one valid scenario database and login role."""
    if service is None:
        return None
    databases = [
        entry.name for entry in service.databases if _value(entry.origin) == "scenario"
    ]
    roles = [
        entry.name
        for entry in service.roles
        if _value(entry.origin) == "scenario" and entry.can_login
    ]
    if (
        not _declared_listener(service)
        or len(databases) != 1
        or len(roles) != 1
        or not all(_IDENTIFIER.fullmatch(name) for name in (*databases, *roles))
    ):
        return None
    return databases[0], roles[0]


def _declared_database(
    nodes: tuple[object, ...],
) -> tuple[str, str, str, str, str] | None:
    """Select one pack-declared DB, role, and web client without guessing."""

    selected_nodes = _declared_nodes(nodes)
    if selected_nodes is None:
        return None
    db_node, web_node = selected_nodes
    db_address, web_address = _internal_address(db_node), _internal_address(web_node)
    identity = _service_identity(_postgres_service(db_node))
    db_container = str(getattr(db_node, "container_name", "") or "")
    web_container = str(getattr(web_node, "container_name", "") or "")
    if db_address and web_address and identity and db_container and web_container:
        database, role = identity
        return db_container, web_container, database, role, db_address
    return None


def _configure_network(
    backend: DatabaseBackend,
    container: str,
    version: str,
    cluster: str,
    database: str,
    role: str,
) -> bool:
    """Apply the declared listener and authored internal-subnet trust posture."""

    if not _ok(
        backend,
        container,
        ["pg_conftool", version, cluster, "set", "listen_addresses", "0.0.0.0"],
    ):
        return False
    path = f"/etc/postgresql/{version}/{cluster}/pg_hba.conf"
    rule = f"host {database} {role} {_INTERNAL_NETWORK} trust"
    script = (
        f"set -eu; grep -Fqx '{rule}' '{path}' || printf '%s\\n' '{rule}' >> '{path}'"
    )
    return (
        _ok(backend, container, ["sh", "-c", script])
        and _ok(backend, container, ["pg_ctlcluster", version, cluster, "restart"])
        and _read(backend, container, _psql("SHOW listen_addresses")) == "0.0.0.0"
    )


def _ensure_role(backend: DatabaseBackend, container: str, role: str) -> bool:
    """Create the declared login role only when it is absent."""
    role_exists = _read(
        backend, container, _psql(f"SELECT 1 FROM pg_roles WHERE rolname = '{role}'")
    )
    if role_exists not in ("", "1"):
        return False
    return bool(role_exists) or _ok(
        backend,
        container,
        ["runuser", "-u", "postgres", "--", "createuser", "--login", role],
    )


def _ensure_database(
    backend: DatabaseBackend, container: str, database: str, role: str
) -> bool:
    """Create the declared database with the pack role as owner."""
    database_exists = _read(
        backend,
        container,
        _psql(f"SELECT 1 FROM pg_database WHERE datname = '{database}'"),
    )
    if database_exists not in ("", "1"):
        return False
    return bool(database_exists) or _ok(
        backend,
        container,
        ["runuser", "-u", "postgres", "--", "createdb", "-O", role, database],
    )


def _tables(backend: DatabaseBackend, container: str, database: str) -> str | None:
    """Read the schema tables visible in the declared database."""
    return _read(
        backend,
        container,
        _psql(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
            database,
        ),
    )


def _seed_tables(
    backend: DatabaseBackend, container: str, database: str, role: str
) -> str | None:
    """Run both pack SQL files in one transaction as the declared role."""
    if not _ok(
        backend,
        container,
        [
            "runuser", "-u", "postgres", "--", "psql", "-d", database,
            "-1", "-v", "ON_ERROR_STOP=1", "-c", f"SET ROLE {role}",
            "-f", _SCHEMA, "-f", _SEED,
        ],
    ):
        return None
    return _tables(backend, container, database)


def _verify_seed(backend: DatabaseBackend, container: str, database: str, tables: str | None) -> bool:
    """Confirm the exact authored schema and at least one seeded user."""
    if tables is None or set(tables.splitlines()) != _EXPECTED_TABLES:
        return False
    count = _read(backend, container, _psql("SELECT count(*) FROM users", database))
    return count is not None and count.isdecimal() and int(count) > 0


def _ensure_objects(
    backend: DatabaseBackend,
    container: str,
    database: str,
    role: str,
) -> bool:
    """Install the declared role, database, and pack SQL idempotently."""
    if not all(
        _ok(backend, container, ["test", "-s", path]) for path in (_SCHEMA, _SEED)
    ):
        return False
    if not _ensure_role(backend, container, role) or not _ensure_database(
        backend, container, database, role
    ):
        return False
    tables = _tables(backend, container, database)
    if tables == "":
        tables = _seed_tables(backend, container, database, role)
    return _verify_seed(backend, container, database, tables)


def _portal_can_query(backend: DatabaseBackend, container: str) -> bool:
    """Probe through the participant portal's own database client."""
    probe = (
        "import sys; sys.path.insert(0, '/app'); import app; "
        "connection = app.get_db(); cursor = connection.cursor(); "
        "cursor.execute('SELECT count(*) FROM users'); "
        "assert cursor.fetchone()[0] > 0; connection.close()"
    )
    return _ok(backend, container, ["python3", "-c", probe])


def realize_database(backend: DatabaseBackend, nodes: tuple[object, ...]) -> list[str]:
    """Build and verify the declared DB; return only bounded, nonsecret errors."""

    selected = _declared_database(nodes)
    if selected is None:
        return ["TechVault database declaration or internal client is unavailable"]
    container, web_container, database, role, db_address = selected
    cluster = _postgres_cluster(backend, container)
    if cluster is None:
        failure = "TechVault PostgreSQL cluster is unavailable"
    elif not _configure_network(backend, container, *cluster, database, role):
        failure = "TechVault PostgreSQL internal listener could not be realized"
    elif not _ensure_objects(backend, container, database, role):
        failure = "TechVault PostgreSQL role, database, or pack SQL could not be realized"
    # The participant web process, not a local postgres superuser, must be able
    # to use the declared network route and read its own seeded users table.
    elif not _portal_can_query(backend, web_container):
        failure = f"TechVault portal cannot query PostgreSQL at {db_address}:5432"
    else:
        failure = None
    return [failure] if failure else []
