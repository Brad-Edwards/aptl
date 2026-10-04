"""TechVault customer-database listener and client-authentication posture.

The pack declares the listener but not how clients authenticate
(OpenRAE/env-packs#411). This module applies the backend-selected posture:
SCRAM-SHA-256 for the declared role and database, from the network the
database and portal share, with the credential the authored portal client
presents (the same value the workstation's leaked ``.pgpass`` loot carries).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets

from aptl_techvault.database_support import (
    FAILURE_AUTH,
    FAILURE_CLIENT,
    FAILURE_LISTENER,
    FAILURE_OBJECTS,
    RESTART_TIMEOUT,
    TIMEOUT,
    DatabaseBackend,
    DeclaredDatabase,
    RealizationFailure,
    psql,
    query,
    read_output,
    succeeded,
)

_HBA_PATH = re.compile(r"/[A-Za-z0-9_./-]+\Z")
_AUTH_METHOD = "scram-sha-256"
_SCRAM_ITERATIONS = 100_000
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


# --- Listener ----------------------------------------------------------------


def _realize_listener(backend: DatabaseBackend, selected: DeclaredDatabase) -> bool:
    """Set the declared listener; return whether a restart is required."""
    container = selected.db_container
    desired = {"listen_addresses": selected.listen_address, "port": str(selected.port)}
    changed = False
    for setting, value in desired.items():
        current = query(backend, container, f"SHOW {setting}", failure=FAILURE_LISTENER)
        if current == value:
            continue
        literal = f"'{value}'" if setting == "listen_addresses" else value
        statement = psql(f"ALTER SYSTEM SET {setting} = {literal}")
        if not succeeded(backend, container, statement):
            raise RealizationFailure(FAILURE_LISTENER)
        changed = True
    return changed


# --- Host-based authentication -----------------------------------------------


def _hba_rule(selected: DeclaredDatabase, method: str) -> str:
    """Render one host rule for the declared database, role, and network."""
    return f"host {selected.database} {selected.role} {selected.scope} {method}"


def _edit_hba(backend: DatabaseBackend, selected: DeclaredDatabase) -> bool:
    """Install the selected rule; return whether the file changed."""
    container = selected.db_container
    path = query(backend, container, "SHOW hba_file", failure=FAILURE_AUTH)
    if not _HBA_PATH.fullmatch(path) or ".." in path.split("/"):
        raise RealizationFailure(FAILURE_AUTH)
    argv = ["sh", "-s", "--", path, _hba_rule(selected, _AUTH_METHOD), _hba_rule(selected, "trust")]  # fmt: skip
    result = backend.container_exec_with_input(
        container, argv, _HBA_EDIT, timeout=TIMEOUT
    )
    outcome = str(getattr(result, "stdout", "") or "").strip()
    if getattr(result, "returncode", 1) != 0 or outcome not in ("changed", "unchanged"):
        raise RealizationFailure(FAILURE_AUTH)
    return outcome == "changed"


def _rule_targets_role(
    kind: str, databases: str, users: str, selected: DeclaredDatabase
) -> bool:
    """Whether a rule's type, database, and user fields could cover the portal."""
    database_keywords = {"all", "sameuser", "samerole", selected.database}
    user_values = users.split(",")
    return (
        kind in _HOST_TYPES
        and bool(database_keywords.intersection(databases.split(",")))
        and (
            bool({"all", selected.role}.intersection(user_values))
            or any(value[:1] in "+@" for value in user_values)
        )
    )


def _rule_network(
    address: str, netmask: str
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Return a rule's client network, or None when it cannot be bounded.

    Keywords (``all``, ``samehost``, ``samenet``) and hostnames could match any
    client, so they have no bounded network.
    """
    try:
        host = ipaddress.ip_address(address)
        mask = ipaddress.ip_address(netmask) if netmask else None
        prefix = bin(int(mask)).count("1") if mask else host.max_prefixlen
        network = ipaddress.ip_network(f"{host}/{prefix}", strict=False)
    except ValueError:
        network = None
    return network


def _rule_may_match(fields: list[str], selected: DeclaredDatabase) -> bool:
    """Whether a parsed HBA row could apply to the portal's IPv4 connection."""
    _, kind, databases, users, address, netmask, _, _ = fields
    network = _rule_network(address, netmask)
    return _rule_targets_role(kind, databases, users, selected) and (
        network is None or (network.version == 4 and network.overlaps(selected.scope))
    )


def _verify_hba(backend: DatabaseBackend, selected: DeclaredDatabase) -> None:
    """Require valid rules and that the first applicable rule is the selection."""
    rows = query(
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
        raise RealizationFailure(FAILURE_AUTH)
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
        raise RealizationFailure(FAILURE_AUTH)


def _restart(
    backend: DatabaseBackend, selected: DeclaredDatabase, cluster: tuple[str, str]
) -> None:
    """Restart for a changed listener and confirm the declared address took."""
    container = selected.db_container
    restarted = succeeded(
        backend, container, ["pg_ctlcluster", *cluster, "restart"], RESTART_TIMEOUT
    )
    listening = restarted and (
        query(backend, container, "SHOW listen_addresses", failure=FAILURE_LISTENER)
        == selected.listen_address
    )
    if not listening:
        raise RealizationFailure(FAILURE_LISTENER)


def _reload(backend: DatabaseBackend, selected: DeclaredDatabase) -> None:
    """Reload PostgreSQL so a changed HBA file takes effect."""
    reloaded = query(
        backend,
        selected.db_container,
        "SELECT pg_reload_conf()",
        failure=FAILURE_AUTH,
    )
    if reloaded != "t":
        raise RealizationFailure(FAILURE_AUTH)


def apply_configuration(
    backend: DatabaseBackend, selected: DeclaredDatabase, cluster: tuple[str, str]
) -> None:
    """Apply listener and HBA changes, restarting or reloading only on change."""
    restart = _realize_listener(backend, selected)
    reload = _edit_hba(backend, selected)
    if restart:
        _restart(backend, selected, cluster)
    elif reload:
        _reload(backend, selected)
    _verify_hba(backend, selected)


# --- Credential --------------------------------------------------------------


def _b64(value: bytes) -> str:
    """Encode verifier bytes the way PostgreSQL stores them."""
    return base64.b64encode(value).decode("ascii")


def _scram_verifier(password: str, *, salt: bytes | None = None) -> str:
    """Return a PostgreSQL SCRAM-SHA-256 verifier (RFC 5802/7677)."""
    salt = secrets.token_bytes(16) if salt is None else salt
    salted = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _SCRAM_ITERATIONS
    )
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    return (
        f"SCRAM-SHA-256${_SCRAM_ITERATIONS}:{_b64(salt)}"
        f"${_b64(stored_key)}:{_b64(server_key)}"
    )


def _portal_password(backend: DatabaseBackend, selected: DeclaredDatabase) -> str:
    """Read the credential the authored portal client presents."""
    output = read_output(
        backend, selected.web_container, ["python3", "-c", _PORTAL_CONFIG]
    )
    try:
        config = json.loads(output or "")
    except ValueError:
        config = None
    if not isinstance(config, dict):
        raise RealizationFailure(FAILURE_CLIENT)
    password = config.get("password")
    if (
        config.get("user") != selected.role
        or config.get("dbname") != selected.database
        or not isinstance(password, str)
        or not 0 < len(password) <= 1024
        or not password.isprintable()
    ):
        raise RealizationFailure(FAILURE_CLIENT)
    return password


def ensure_credential(backend: DatabaseBackend, selected: DeclaredDatabase) -> None:
    """Give a password-less role the portal's credential; never rotate one."""
    container = selected.db_container
    missing = query(
        backend,
        container,
        f"SELECT rolpassword IS NULL FROM pg_authid WHERE rolname = '{selected.role}'",
    )
    if missing == "f":
        return
    if missing != "t":
        raise RealizationFailure(FAILURE_OBJECTS)
    verifier = _scram_verifier(_portal_password(backend, selected))
    argv = [
        "runuser", "-u", "postgres", "--",
        "psql", "-X", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-f", "-",
    ]  # fmt: skip
    result = backend.container_exec_with_input(
        container,
        argv,
        f"ALTER ROLE {selected.role} PASSWORD '{verifier}';\n",
        timeout=TIMEOUT,
    )
    if getattr(result, "returncode", 1) != 0:
        raise RealizationFailure(FAILURE_AUTH)
