"""Realize TechVault's declared PostgreSQL state from its pack-owned SQL.

The pack-qualified startup provider calls this after the generic nodes exist.
The generic materializer places the exact SQL artifacts, but does not execute
them or configure a PostgreSQL cluster. This adapter closes that gap without
changing the customer portal or its intended weaknesses.

The pack declares the listener, database, schema, tables, and login role, but
not how clients authenticate (OpenRAE/env-packs#411). That posture is backend
open, so this adapter selects one that keeps the authored intent: the role
requires the password the authored portal client presents (the same value the
workstation's leaked ``.pgpass`` loot carries), from the network the database
and portal share. Every other fact is read from the admitted declaration.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from dataclasses import dataclass
from typing import Protocol

from aptl.core.deployment.errors import BackendTimeoutError
from aptl_techvault.log_source_support import _postgres_cluster

_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]*\Z")
_HBA_PATH = re.compile(r"/[A-Za-z0-9_./-]+\Z")
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
_AUTH_METHOD = "scram-sha-256"
_SCRAM_ITERATIONS = 4096
_TIMEOUT = 60
_RESTART_TIMEOUT = 120
_HOST_TYPES = frozenset({"host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc"})
# Edits pg_hba.conf in place, keeping its owner and mode: drop only the exact
# rule an earlier APTL release wrote, then append the selected rule once.
_HBA_EDIT = """set -eu
path=$1 rule=$2 legacy=$3
[ -f "$path" ] && [ -r "$path" ] && [ -w "$path" ]
before=$(cksum < "$path")
status=0
kept=$(grep -Fvx -- "$legacy" "$path") || status=$?
[ "$status" -le 1 ]
printf '%s\\n' "$kept" > "$path"
grep -Fqx -- "$rule" "$path" || printf '%s\\n' "$rule" >> "$path"
if [ "$before" = "$(cksum < "$path")" ]; then echo unchanged; else echo changed; fi
"""
# Reads the portal's own database client settings without connecting.
_PORTAL_CONFIG = (
    "import json, sys; sys.path.insert(0, '/app'); import app; "
    "config = app.DB_CONFIG; "
    "sys.stdout.write(json.dumps({key: str(config.get(key, '')) "
    "for key in ('user', 'dbname', 'password')}))"
)
# Authenticates through the portal's own client settings, bounded in time.
_PORTAL_QUERY = (
    "import sys; sys.path.insert(0, '/app'); import app, psycopg2; "
    "connection = psycopg2.connect(**dict(app.DB_CONFIG, connect_timeout=10)); "
    "cursor = connection.cursor(); "
    "cursor.execute('SELECT current_database(), current_user'); "
    "row = cursor.fetchone(); connection.close(); "
    "sys.exit(0 if list(row) == sys.argv[1:3] else 3)"
)

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


class _Failure(Exception):
    """A bounded, nonsecret realization failure."""


def _value(item: object) -> str:
    """Normalize a declared enum or string value."""
    return str(getattr(item, "value", item) or "")


def _exec(
    backend: DatabaseBackend, container: str, argv: list[str], timeout: int = _TIMEOUT
) -> object:
    """Execute a bounded database setup command."""
    return backend.container_exec(container, argv, timeout=timeout)


def _read(backend: DatabaseBackend, container: str, argv: list[str]) -> str | None:
    """Read successful command output, preserving failure as None."""
    result = _exec(backend, container, argv)
    if getattr(result, "returncode", 1) != 0:
        return None
    return str(getattr(result, "stdout", "") or "").strip()


def _ok(
    backend: DatabaseBackend, container: str, argv: list[str], timeout: int = _TIMEOUT
) -> bool:
    """Return whether a database setup command succeeded."""
    return getattr(_exec(backend, container, argv, timeout), "returncode", 1) == 0


def _psql(statement: str, database: str = "postgres") -> list[str]:
    """Build a fixed, nonsecret local PostgreSQL query without a shell."""
    return [
        "runuser",
        "-u",
        "postgres",
        "--",
        "psql",
        "-X",
        "-d",
        database,
        "-Atqc",
        statement,
    ]


def _query(
    backend: DatabaseBackend,
    container: str,
    statement: str,
    database: str = "postgres",
    failure: str = FAILURE_OBJECTS,
) -> str:
    """Read a catalog query, distinguishing failure from an empty answer."""
    output = _read(backend, container, _psql(statement, database))
    if output is None:
        raise _Failure(failure)
    return output


# --- Declaration selection -------------------------------------------------


def _attachments(
    node: object,
) -> dict[str, tuple[ipaddress.IPv4Address, ipaddress.IPv4Network]]:
    """Map each declared network to the node's address and the network CIDR."""
    selected: dict[str, tuple[ipaddress.IPv4Address, ipaddress.IPv4Network]] = {}
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
    return (
        services[0]
        if len(services) == 1 and _value(services[0].engine) == "postgresql"
        else None
    )


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
    names = [
        databases[0].name,
        roles[0],
        *(part for item in tables for part in item.split(".")),
    ]
    if not tables or not all(_IDENTIFIER.fullmatch(name) for name in names):
        return None
    return databases[0].name, roles[0], tables


def _service_listener(service: object) -> tuple[str, int] | None:
    """Require the single declared IPv4 listener."""
    listeners = getattr(service, "listeners", ())
    if len(listeners) != 1:
        return None
    try:
        address = ipaddress.IPv4Address(str(listeners[0].address))
        port = int(listeners[0].port)
    except (TypeError, ValueError):
        return None
    return (str(address), port) if 0 < port < 65536 else None


def _declared_database(nodes: tuple[object, ...]) -> DeclaredDatabase | None:
    """Select one pack-declared DB, role, client network, and tables."""

    db_nodes = [node for node in nodes if _postgres_service(node) is not None]
    web_nodes = [node for node in nodes if getattr(node, "name", "") == _CLIENT_NODE]
    if len(db_nodes) != 1 or len(web_nodes) != 1:
        return None
    db_node, web_node = db_nodes[0], web_nodes[0]
    service = _postgres_service(db_node)
    identity = _service_identity(service)
    listener = _service_listener(service)
    db_networks, web_networks = _attachments(db_node), _attachments(web_node)
    shared = [name for name in db_networks if name in web_networks]
    db_container = str(getattr(db_node, "container_name", "") or "")
    web_container = str(getattr(web_node, "container_name", "") or "")
    if (
        identity is None
        or listener is None
        or len(shared) != 1
        or not db_container
        or not web_container
    ):
        return None
    db_address, scope = db_networks[shared[0]]
    if web_networks[shared[0]][1] != scope:
        return None
    database, role, tables = identity
    return DeclaredDatabase(
        db_container=db_container,
        web_container=web_container,
        database=database,
        role=role,
        db_address=str(db_address),
        scope=scope,
        listen_address=listener[0],
        port=listener[1],
        tables=tables,
    )


# --- Listener and client authentication ------------------------------------


def _realize_listener(backend: DatabaseBackend, selected: DeclaredDatabase) -> bool:
    """Set the declared listener; return whether a restart is required."""
    container = selected.db_container
    desired = {"listen_addresses": selected.listen_address, "port": str(selected.port)}
    changed = False
    for setting, value in desired.items():
        if (
            _query(backend, container, f"SHOW {setting}", failure=FAILURE_LISTENER)
            == value
        ):
            continue
        literal = f"'{value}'" if setting == "listen_addresses" else value
        if not _ok(
            backend, container, _psql(f"ALTER SYSTEM SET {setting} = {literal}")
        ):
            raise _Failure(FAILURE_LISTENER)
        changed = True
    return changed


def _hba_rule(selected: DeclaredDatabase, method: str) -> str:
    """Render one host rule for the declared database, role, and network."""
    return f"host {selected.database} {selected.role} {selected.scope} {method}"


def _edit_hba(backend: DatabaseBackend, selected: DeclaredDatabase) -> bool:
    """Install the selected rule; return whether the file changed."""
    container = selected.db_container
    path = _query(backend, container, "SHOW hba_file", failure=FAILURE_AUTH)
    if not _HBA_PATH.fullmatch(path) or ".." in path.split("/"):
        raise _Failure(FAILURE_AUTH)
    result = backend.container_exec_with_input(
        container,
        [
            "sh",
            "-s",
            "--",
            path,
            _hba_rule(selected, _AUTH_METHOD),
            _hba_rule(selected, "trust"),
        ],
        _HBA_EDIT,
        timeout=_TIMEOUT,
    )
    outcome = str(getattr(result, "stdout", "") or "").strip()
    if getattr(result, "returncode", 1) != 0 or outcome not in ("changed", "unchanged"):
        raise _Failure(FAILURE_AUTH)
    return outcome == "changed"


def _rule_may_match(fields: list[str], selected: DeclaredDatabase) -> bool:
    """Whether a parsed HBA row could apply to the portal's connection."""
    _, kind, databases, users, address, netmask, _, _ = fields
    if kind not in _HOST_TYPES:
        return False
    database_keywords = {"all", "sameuser", "samerole", selected.database}
    user_values = users.split(",")
    if not database_keywords.intersection(databases.split(",")):
        return False
    if not (
        {"all", selected.role} & set(user_values)
        or any(v[:1] in "+@" for v in user_values)
    ):
        return False
    if address in ("all", "samehost", "samenet"):
        return True
    try:
        host = ipaddress.ip_address(address)
    except ValueError:
        return True  # a hostname rule could match any client; treat it as shadowing
    if host.version != 4:
        return False  # the portal connects over the declared IPv4 network
    try:
        prefix = bin(int(ipaddress.IPv4Address(netmask))).count("1") if netmask else 32
        network = ipaddress.IPv4Network(f"{host}/{prefix}", strict=False)
    except ValueError:
        return True
    return network.overlaps(selected.scope)


def _verify_hba(backend: DatabaseBackend, selected: DeclaredDatabase) -> None:
    """Require valid rules and that the first applicable rule is the selection."""
    rows = _query(
        backend,
        selected.db_container,
        "SELECT line_number, type, array_to_string(database, ','), "
        "array_to_string(user_name, ','), coalesce(address, ''), coalesce(netmask, ''), "
        "coalesce(auth_method, ''), coalesce(error, '') "
        "FROM pg_hba_file_rules ORDER BY line_number",
        failure=FAILURE_AUTH,
    )
    parsed = [line.split("|") for line in rows.splitlines() if line]
    if not parsed or any(len(fields) != 8 or fields[7] for fields in parsed):
        raise _Failure(FAILURE_AUTH)
    applicable = [fields for fields in parsed if _rule_may_match(fields, selected)]
    expected = [
        "host",
        selected.database,
        selected.role,
        str(selected.scope.network_address),
        str(selected.scope.netmask),
        _AUTH_METHOD,
    ]
    if not applicable or applicable[0][1:7] != expected:
        raise _Failure(FAILURE_AUTH)


def _apply_configuration(
    backend: DatabaseBackend, selected: DeclaredDatabase, cluster: tuple[str, str]
) -> None:
    """Apply listener and HBA changes, restarting or reloading only on change."""
    restart = _realize_listener(backend, selected)
    reload = _edit_hba(backend, selected)
    if restart:
        if (
            not _ok(
                backend,
                selected.db_container,
                ["pg_ctlcluster", *cluster, "restart"],
                _RESTART_TIMEOUT,
            )
            or _query(
                backend,
                selected.db_container,
                "SHOW listen_addresses",
                failure=FAILURE_LISTENER,
            )
            != selected.listen_address
        ):
            raise _Failure(FAILURE_LISTENER)
    elif (
        reload
        and _query(
            backend,
            selected.db_container,
            "SELECT pg_reload_conf()",
            failure=FAILURE_AUTH,
        )
        != "t"
    ):
        raise _Failure(FAILURE_AUTH)
    _verify_hba(backend, selected)


# --- Credential -------------------------------------------------------------


def _scram_verifier(password: str, *, salt: bytes | None = None) -> str:
    """Return a PostgreSQL SCRAM-SHA-256 verifier (RFC 5802/7677)."""
    salt = secrets.token_bytes(16) if salt is None else salt
    salted = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _SCRAM_ITERATIONS
    )
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()

    def encode(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    return (
        f"SCRAM-SHA-256${_SCRAM_ITERATIONS}:{encode(salt)}"
        f"${encode(stored_key)}:{encode(server_key)}"
    )


def _portal_password(backend: DatabaseBackend, selected: DeclaredDatabase) -> str:
    """Read the credential the authored portal client presents."""
    output = _read(backend, selected.web_container, ["python3", "-c", _PORTAL_CONFIG])
    try:
        config = json.loads(output or "")
    except ValueError:
        config = None
    if not isinstance(config, dict):
        raise _Failure(FAILURE_CLIENT)
    password = config.get("password")
    if (
        config.get("user") != selected.role
        or config.get("dbname") != selected.database
        or not isinstance(password, str)
        or not 0 < len(password) <= 1024
        or not password.isprintable()
    ):
        raise _Failure(FAILURE_CLIENT)
    return password


def _ensure_credential(backend: DatabaseBackend, selected: DeclaredDatabase) -> None:
    """Give a password-less role the portal's credential; never rotate one."""
    container = selected.db_container
    missing = _query(
        backend,
        container,
        f"SELECT rolpassword IS NULL FROM pg_authid WHERE rolname = '{selected.role}'",
    )
    if missing == "f":
        return
    if missing != "t":
        raise _Failure(FAILURE_OBJECTS)
    verifier = _scram_verifier(_portal_password(backend, selected))
    result = backend.container_exec_with_input(
        container,
        [
            "runuser",
            "-u",
            "postgres",
            "--",
            "psql",
            "-X",
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            "-f",
            "-",
        ],
        f"ALTER ROLE {selected.role} PASSWORD '{verifier}';\n",
        timeout=_TIMEOUT,
    )
    if getattr(result, "returncode", 1) != 0:
        raise _Failure(FAILURE_AUTH)


# --- Role, database, and pack SQL ------------------------------------------


def _ensure_absent_then_create(
    backend: DatabaseBackend, container: str, probe: str, create: list[str]
) -> None:
    """Create a catalog object only when a successful probe found it absent."""
    if _query(backend, container, probe) == "1":
        return
    if not _ok(backend, container, ["runuser", "-u", "postgres", "--", *create]):
        raise _Failure(FAILURE_OBJECTS)


def _init_digests(backend: DatabaseBackend, container: str) -> str:
    """Identify the exact pack SQL by digest, without secret bytes."""
    if not all(
        _ok(backend, container, ["test", "-s", path]) for path in (_SCHEMA, _SEED)
    ):
        raise _Failure(FAILURE_OBJECTS)
    output = _read(backend, container, ["sha256sum", _SCHEMA, _SEED]) or ""
    digests = [line.split()[0] for line in output.splitlines() if line.strip()]
    if len(digests) != 2 or not all(
        re.fullmatch(r"[0-9a-f]{64}", item) for item in digests
    ):
        raise _Failure(FAILURE_OBJECTS)
    return f"sha256:{digests[0]} sha256:{digests[1]}"


def _current_marker(backend: DatabaseBackend, selected: DeclaredDatabase) -> str:
    """Read the database comment that records a committed initialization."""
    return _query(
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
    output = _query(
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
        committed = _ok(backend, selected.db_container, argv, _RESTART_TIMEOUT)
    except BackendTimeoutError:
        committed = False  # outcome unknown until the marker is read back
    # A failure after commit (or a concurrent initializer) is settled by the
    # marker, which only a committed initialization writes.
    if not committed and _current_marker(backend, selected) != marker:
        raise _Failure(FAILURE_OBJECTS)
    if _declared_tables_present(backend, selected) != selected.tables:
        raise _Failure(FAILURE_OBJECTS)


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
    if current == complete:
        return  # initialized earlier in this run; participant changes stand
    if current != pending or _declared_tables_present(backend, selected):
        raise _Failure(FAILURE_FOREIGN_STATE)
    _seed(backend, selected, complete)


def _portal_can_query(backend: DatabaseBackend, selected: DeclaredDatabase) -> bool:
    """Authenticate through the participant portal's own database client."""
    return _ok(
        backend,
        selected.web_container,
        ["python3", "-c", _PORTAL_QUERY, selected.database, selected.role],
    )


def realize_database(backend: DatabaseBackend, nodes: tuple[object, ...]) -> list[str]:
    """Build and verify the declared DB; return only bounded, nonsecret errors."""

    selected = _declared_database(nodes)
    if selected is None:
        return [FAILURE_SELECTION]
    cluster = _postgres_cluster(backend, selected.db_container)
    if cluster is None:
        return [FAILURE_CLUSTER]
    try:
        _apply_configuration(backend, selected, cluster)
        _ensure_objects(backend, selected)
        _ensure_credential(backend, selected)
    except _Failure as failure:
        return [str(failure)]
    # The participant web process, not a local postgres superuser, must be able
    # to authenticate over the declared network route as the declared role.
    if not _portal_can_query(backend, selected):
        return [
            f"TechVault portal cannot query PostgreSQL at {selected.db_address}:{selected.port}"
        ]
    return []
