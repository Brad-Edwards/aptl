"""Realize TechVault's declared PostgreSQL state from its pack-owned SQL.

The pack-qualified startup provider calls this after the generic nodes exist.
The generic materializer places the exact SQL artifacts, but does not execute
them or configure a PostgreSQL cluster. This adapter closes that gap without
changing the customer portal or its intended weaknesses.

Every realized fact is read from the admitted declaration: the PostgreSQL
service, listener, scenario database, schema tables, login role, and the
network the database and portal share. Client authentication is the one open
posture; ``database_access`` applies the backend's selection.
"""

from __future__ import annotations

import ipaddress
import re

from aptl.core.deployment.errors import BackendTimeoutError
from aptl_techvault.database_access import apply_configuration, ensure_credential
from aptl_techvault.database_support import (
    FAILURE_CLUSTER,
    FAILURE_FOREIGN_STATE,
    FAILURE_OBJECTS,
    FAILURE_SELECTION,
    RESTART_TIMEOUT,
    DatabaseBackend,
    DeclaredDatabase,
    RealizationFailure,
    query,
    read_output,
    succeeded,
)
from aptl_techvault.log_source_support import _postgres_cluster

_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]*\Z")
_CLIENT_NODE = "webapp"
_SCHEMA = "/opt/db-init/01-schema.sql"
_SEED = "/opt/db-init/02-seed-data.sql"
_MARKER_PREFIX = "aptl-techvault-db-init"
_PENDING_PREFIX = f"{_MARKER_PREFIX}-pending"
# The in-guest seed deadline stays below the host exec budget, so a timed-out
# host call never leaves a seed transaction running inside the container.
_SEED_DEADLINE = 90
_SEED_LOCK_TIMEOUT = "30s"
_SEED_STATEMENT_TIMEOUT = "60s"
# Authenticates through the portal's own client settings, bounded in time.
_PORTAL_QUERY = (
    "import sys; sys.path.insert(0, '/app'); import app, psycopg2; "
    "connection = psycopg2.connect(**dict(app.DB_CONFIG, connect_timeout=10)); "
    "cursor = connection.cursor(); "
    "cursor.execute('SELECT current_database(), current_user'); "
    "row = cursor.fetchone(); connection.close(); "
    "sys.exit(0 if list(row) == sys.argv[1:3] else 3)"
)

_Attachments = dict[str, tuple[ipaddress.IPv4Address, ipaddress.IPv4Network]]


def _value(item: object) -> str:
    """Normalize a declared enum or string value."""
    return str(getattr(item, "value", item) or "")


# --- Declaration selection ---------------------------------------------------


def _attachments(node: object) -> _Attachments:
    """Map each declared network to the node's address and the network CIDR."""
    selected: _Attachments = {}
    for attachment in getattr(node, "network_attachments", ()):
        try:
            address = ipaddress.IPv4Address(
                str(getattr(attachment, "ipv4_address", "") or "")
            )
            network = ipaddress.IPv4Network(str(getattr(attachment, "cidr", "") or ""))
        except ValueError:
            continue
        if address in network:
            selected[str(getattr(attachment, "network", ""))] = (address, network)
    return selected


def _postgres_service(node: object) -> object | None:
    """Return the node's single declared PostgreSQL service, if it has one."""
    services = getattr(getattr(node, "runtime", None), "database_services", ())
    single = len(services) == 1 and _value(services[0].engine) == "postgresql"
    return services[0] if single else None


def _service_identity(service: object) -> tuple[str, str, frozenset[str]] | None:
    """Select one scenario database, its declared tables, and one login role."""
    databases = [
        entry for entry in service.databases if _value(entry.origin) == "scenario"
    ]
    roles = [
        entry.name
        for entry in service.roles
        if _value(entry.origin) == "scenario" and entry.can_login
    ]
    if len(databases) != 1 or len(roles) != 1:
        return None
    tables = frozenset(
        f"{schema.name}.{table.name}"
        for schema in databases[0].schemas
        for table in schema.tables
    )
    names = [databases[0].name, roles[0], *(p for t in tables for p in t.split("."))]
    valid = bool(tables) and all(_IDENTIFIER.fullmatch(name) for name in names)
    return (databases[0].name, roles[0], tables) if valid else None


def _service_listener(service: object) -> tuple[str, int] | None:
    """Require the single declared IPv4 listener."""
    listeners = getattr(service, "listeners", ())
    try:
        address = str(ipaddress.IPv4Address(str(listeners[0].address)))
        port = int(listeners[0].port)
    except (IndexError, TypeError, ValueError):
        return None
    return (address, port) if len(listeners) == 1 and 0 < port < 65536 else None


def _shared_network(
    db_node: object, web_node: object
) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Network] | None:
    """Return the database's address on the one network it shares with the portal."""
    db_networks, web_networks = _attachments(db_node), _attachments(web_node)
    shared = [
        name
        for name, (_, scope) in db_networks.items()
        if name in web_networks and web_networks[name][1] == scope
    ]
    return db_networks[shared[0]] if len(shared) == 1 else None


def _declaration(db_node: object, web_node: object) -> DeclaredDatabase | None:
    """Build the declaration from one database node and its portal client."""
    service = _postgres_service(db_node)
    identity = _service_identity(service)
    listener = _service_listener(service)
    network = _shared_network(db_node, web_node)
    db_container = str(getattr(db_node, "container_name", "") or "")
    web_container = str(getattr(web_node, "container_name", "") or "")
    complete = identity and listener and network and db_container and web_container
    if not complete:
        return None
    database, role, tables = identity
    return DeclaredDatabase(
        db_container=db_container,
        web_container=web_container,
        database=database,
        role=role,
        db_address=str(network[0]),
        scope=network[1],
        listen_address=listener[0],
        port=listener[1],
        tables=tables,
    )


def _declared_database(nodes: tuple[object, ...]) -> DeclaredDatabase | None:
    """Select one pack-declared DB, role, client network, and tables."""
    db_nodes = [node for node in nodes if _postgres_service(node) is not None]
    web_nodes = [node for node in nodes if getattr(node, "name", "") == _CLIENT_NODE]
    unique = len(db_nodes) == 1 and len(web_nodes) == 1
    return _declaration(db_nodes[0], web_nodes[0]) if unique else None


# --- Role, database, and pack SQL --------------------------------------------


def _ensure_absent_then_create(
    backend: DatabaseBackend, container: str, probe: str, create: list[str]
) -> None:
    """Create a catalog object only when a successful probe found it absent."""
    if query(backend, container, probe) == "1":
        return
    if not succeeded(backend, container, ["runuser", "-u", "postgres", "--", *create]):
        raise RealizationFailure(FAILURE_OBJECTS)


def _init_digests(backend: DatabaseBackend, container: str) -> str:
    """Identify the exact pack SQL by digest, without secret bytes."""
    present = all(
        succeeded(backend, container, ["test", "-s", path]) for path in (_SCHEMA, _SEED)
    )
    output = read_output(backend, container, ["sha256sum", _SCHEMA, _SEED]) or ""
    digests = [line.split()[0] for line in output.splitlines() if line.strip()]
    if (
        not present
        or len(digests) != 2
        or not all(re.fullmatch(r"[0-9a-f]{64}", item) for item in digests)
    ):
        raise RealizationFailure(FAILURE_OBJECTS)
    return f"sha256:{digests[0]} sha256:{digests[1]}"


def _current_marker(backend: DatabaseBackend, selected: DeclaredDatabase) -> str:
    """Read the database comment that records initialization state."""
    return query(
        backend,
        selected.db_container,
        "SELECT coalesce(shobj_description(oid, 'pg_database'), '') "
        f"FROM pg_database WHERE datname = '{selected.database}'",
    )


def _declared_tables_present(
    backend: DatabaseBackend, selected: DeclaredDatabase
) -> frozenset[str]:
    """Read which tables exist in the declared schemas."""
    schemas = sorted({table.split(".")[0] for table in selected.tables})
    listed = ", ".join(f"'{schema}'" for schema in schemas)
    output = query(
        backend,
        selected.db_container,
        "SELECT schemaname || '.' || tablename FROM pg_tables "
        f"WHERE schemaname IN ({listed}) ORDER BY 1",
        selected.database,
    )
    return frozenset(line for line in output.splitlines() if line)


def _seed(backend: DatabaseBackend, selected: DeclaredDatabase, marker: str) -> None:
    """Run both pack SQL files and the marker in one bounded transaction."""
    argv = [
        "runuser", "-u", "postgres", "--",
        "timeout", "-k", "5", str(_SEED_DEADLINE),
        "psql", "-X", "-d", selected.database, "-1", "-v", "ON_ERROR_STOP=1",
        "-c", f"SET LOCAL lock_timeout = '{_SEED_LOCK_TIMEOUT}'",
        "-c", f"SET LOCAL statement_timeout = '{_SEED_STATEMENT_TIMEOUT}'",
        "-c", "SELECT pg_advisory_xact_lock(hashtext('aptl-techvault-db-init'))",
        "-c", f"SET ROLE {selected.role}",
        "-f", _SCHEMA, "-f", _SEED,
        "-c", f"COMMENT ON DATABASE {selected.database} IS '{marker}'",
    ]  # fmt: skip
    try:
        committed = succeeded(backend, selected.db_container, argv, RESTART_TIMEOUT)
    except BackendTimeoutError:
        # The outcome is unknown until the marker is read back.
        committed = False
    # A failure after commit (or a concurrent initializer) is settled by the
    # marker, which only a committed initialization writes.
    if not committed and _current_marker(backend, selected) != marker:
        raise RealizationFailure(FAILURE_OBJECTS)
    if _declared_tables_present(backend, selected) != selected.tables:
        raise RealizationFailure(FAILURE_OBJECTS)


def _ensure_objects(backend: DatabaseBackend, selected: DeclaredDatabase) -> None:
    """Install the declared role, database, and pack SQL exactly once.

    The database is created together with a pending marker, so only storage
    this adapter created (or an interrupted bootstrap of the same pack SQL) is
    ever seeded; any other unmarked database is left alone and reported.
    """
    container = selected.db_container
    digests = _init_digests(backend, container)
    complete, pending = f"{_MARKER_PREFIX} {digests}", f"{_PENDING_PREFIX} {digests}"
    _ensure_absent_then_create(
        backend,
        container,
        f"SELECT 1 FROM pg_roles WHERE rolname = '{selected.role}'",
        ["createuser", "--login", selected.role],
    )
    _ensure_absent_then_create(
        backend,
        container,
        f"SELECT 1 FROM pg_database WHERE datname = '{selected.database}'",
        ["createdb", "-O", selected.role, selected.database, pending],
    )
    current = _current_marker(backend, selected)
    # A complete marker means this run was initialized; participant changes stand.
    if current == complete:
        return
    if current != pending or _declared_tables_present(backend, selected):
        raise RealizationFailure(FAILURE_FOREIGN_STATE)
    _seed(backend, selected, complete)


# --- Orchestration -----------------------------------------------------------


def _realize(backend: DatabaseBackend, selected: DeclaredDatabase) -> None:
    """Configure, initialize, and verify the selected database."""
    cluster = _postgres_cluster(backend, selected.db_container)
    if cluster is None:
        raise RealizationFailure(FAILURE_CLUSTER)
    apply_configuration(backend, selected, cluster)
    _ensure_objects(backend, selected)
    ensure_credential(backend, selected)
    # The participant web process, not a local postgres superuser, must be able
    # to authenticate over the declared network route as the declared role.
    portal = ["python3", "-c", _PORTAL_QUERY, selected.database, selected.role]
    if not succeeded(backend, selected.web_container, portal):
        raise RealizationFailure(
            "TechVault portal cannot query PostgreSQL at "
            f"{selected.db_address}:{selected.port}"
        )


def realize_database(backend: DatabaseBackend, nodes: tuple[object, ...]) -> list[str]:
    """Build and verify the declared DB; return only bounded, nonsecret errors."""
    selected = _declared_database(nodes)
    try:
        if selected is None:
            raise RealizationFailure(FAILURE_SELECTION)
        _realize(backend, selected)
    except RealizationFailure as failure:
        return [str(failure)]
    return []
