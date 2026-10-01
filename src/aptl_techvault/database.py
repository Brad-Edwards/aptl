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
_INTERNAL_NETWORK = ipaddress.ip_network("172.20.2.0/24")
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
    def container_exec(
        self, name: str, cmd: list[str], *, timeout: int | None = None
    ) -> object: ...


def _value(item: object) -> str:
    return str(getattr(item, "value", item) or "")


def _exec(backend: DatabaseBackend, container: str, argv: list[str]) -> object:
    return backend.container_exec(container, argv, timeout=60)


def _read(backend: DatabaseBackend, container: str, argv: list[str]) -> str | None:
    result = _exec(backend, container, argv)
    if getattr(result, "returncode", 1) != 0:
        return None
    return str(getattr(result, "stdout", "") or "").strip()


def _ok(backend: DatabaseBackend, container: str, argv: list[str]) -> bool:
    return getattr(_exec(backend, container, argv), "returncode", 1) == 0


def _psql(statement: str, database: str = "postgres") -> list[str]:
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


def _declared_database(
    nodes: tuple[object, ...],
) -> tuple[str, str, str, str, str] | None:
    """Select one pack-declared DB, role, and web client without guessing."""

    db_nodes = [node for node in nodes if getattr(node, "name", "") == "db"]
    web_nodes = [node for node in nodes if getattr(node, "name", "") == "webapp"]
    if len(db_nodes) != 1 or len(web_nodes) != 1:
        return None
    db_node, web_node = db_nodes[0], web_nodes[0]
    db_address, web_address = _internal_address(db_node), _internal_address(web_node)
    if not db_address or not web_address:
        return None
    runtime = getattr(db_node, "runtime", None)
    services = getattr(runtime, "database_services", ())
    if len(services) != 1 or _value(services[0].engine) != "postgresql":
        return None
    service = services[0]
    listeners = getattr(service, "listeners", ())
    databases = [
        entry.name for entry in service.databases if _value(entry.origin) == "scenario"
    ]
    roles = [
        entry.name
        for entry in service.roles
        if _value(entry.origin) == "scenario" and entry.can_login
    ]
    if (
        len(listeners) != 1
        or listeners[0].address != "0.0.0.0"
        or listeners[0].port != 5432
        or len(databases) != 1
        or len(roles) != 1
        or not all(_IDENTIFIER.fullmatch(name) for name in (*databases, *roles))
    ):
        return None
    db_container = str(getattr(db_node, "container_name", "") or "")
    web_container = str(getattr(web_node, "container_name", "") or "")
    if not db_container or not web_container:
        return None
    return db_container, web_container, databases[0], roles[0], db_address


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


def _ensure_objects(
    backend: DatabaseBackend,
    container: str,
    database: str,
    role: str,
) -> bool:
    if not all(
        _ok(backend, container, ["test", "-s", path]) for path in (_SCHEMA, _SEED)
    ):
        return False
    role_exists = _read(
        backend, container, _psql(f"SELECT 1 FROM pg_roles WHERE rolname = '{role}'")
    )
    if role_exists not in ("", "1"):
        return False
    if not role_exists and not _ok(
        backend,
        container,
        ["runuser", "-u", "postgres", "--", "createuser", "--login", role],
    ):
        return False
    database_exists = _read(
        backend,
        container,
        _psql(f"SELECT 1 FROM pg_database WHERE datname = '{database}'"),
    )
    if database_exists not in ("", "1"):
        return False
    if not database_exists and not _ok(
        backend,
        container,
        ["runuser", "-u", "postgres", "--", "createdb", "-O", role, database],
    ):
        return False
    tables = _read(
        backend,
        container,
        _psql(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
            database,
        ),
    )
    if tables is None:
        return False
    if not tables:
        if not _ok(
            backend,
            container,
            [
                "runuser",
                "-u",
                "postgres",
                "--",
                "psql",
                "-d",
                database,
                "-1",
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                f"SET ROLE {role}",
                "-f",
                _SCHEMA,
                "-f",
                _SEED,
            ],
        ):
            return False
        tables = _read(
            backend,
            container,
            _psql(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
                database,
            ),
        )
    if tables is None or set(tables.splitlines()) != _EXPECTED_TABLES:
        return False
    count = _read(backend, container, _psql("SELECT count(*) FROM users", database))
    return count is not None and count.isdecimal() and int(count) > 0


def realize_database(backend: DatabaseBackend, nodes: tuple[object, ...]) -> list[str]:
    """Build and verify the declared DB; return only bounded, nonsecret errors."""

    selected = _declared_database(nodes)
    if selected is None:
        return ["TechVault database declaration or internal client is unavailable"]
    container, web_container, database, role, db_address = selected
    cluster = _postgres_cluster(backend, container)
    if cluster is None:
        return ["TechVault PostgreSQL cluster is unavailable"]
    if not _configure_network(backend, container, *cluster, database, role):
        return ["TechVault PostgreSQL internal listener could not be realized"]
    if not _ensure_objects(backend, container, database, role):
        return [
            "TechVault PostgreSQL role, database, or pack SQL could not be realized"
        ]
    # The participant web process, not a local postgres superuser, must be able
    # to use the declared network route and read its own seeded users table.
    probe = (
        "import sys; sys.path.insert(0, '/app'); import app; "
        "connection = app.get_db(); cursor = connection.cursor(); "
        "cursor.execute('SELECT count(*) FROM users'); "
        "assert cursor.fetchone()[0] > 0; connection.close()"
    )
    if not _ok(backend, web_container, ["python3", "-c", probe]):
        return [f"TechVault portal cannot query PostgreSQL at {db_address}:5432"]
    return []
