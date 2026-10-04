"""The pack-qualified database startup must make the portal's SQL path live."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
from types import SimpleNamespace

import pytest
from raes.parser import parse_sdl_file

from aptl.core.deployment.errors import BackendTimeoutError
from aptl_techvault import database, database_access
from aptl_techvault.database import realize_database
from aptl_techvault.startup import TechVaultStartupProvider
from tests.helpers import techvault_scenario_path

_SCHEMA = "/opt/db-init/01-schema.sql"
_SEED = "/opt/db-init/02-seed-data.sql"
_HBA = "/etc/postgresql/15/main/pg_hba.conf"
_PORTAL_PASSWORD = "portal-fixture-credential"
_SCOPE = "172.20.2.0/24"
_RULE = f"host techvault techvault {_SCOPE} scram-sha-256"
_LEGACY = f"host techvault techvault {_SCOPE} trust"
_DEFAULT_HBA = (
    ("local", "all", "postgres", "", "peer"),
    ("local", "all", "all", "", "peer"),
    ("host", "all", "all", "127.0.0.1/32", "scram-sha-256"),
    ("host", "all", "all", "::1/128", "scram-sha-256"),
    ("host", "replication", "all", "127.0.0.1/32", "scram-sha-256"),
    ("host", "replication", "all", "::1/128", "scram-sha-256"),
)
_PENDING = f"aptl-techvault-db-init-pending sha256:{'a' * 64} sha256:{'b' * 64}"
_COMPLETE = f"aptl-techvault-db-init sha256:{'a' * 64} sha256:{'b' * 64}"
_DECLARED_TABLES = (
    "public.api_keys",
    "public.audit_log",
    "public.backup_config",
    "public.comments",
    "public.customers",
    "public.files",
    "public.sessions",
    "public.users",
)


def _nodes(tmp_path, *, web_network="internal-net", cidr=_SCOPE):
    scenario = parse_sdl_file(techvault_scenario_path(tmp_path))

    def node(name, network, address):
        return SimpleNamespace(
            name=name,
            container_name=f"aptl-{name}",
            runtime=scenario.nodes[name].runtime,
            network_attachments=(
                SimpleNamespace(network=network, ipv4_address=address, cidr=cidr),
            ),
        )

    return (
        node("db", "internal-net", "172.20.2.11"),
        node("webapp", web_network, "172.20.2.25"),
    )


class _Postgres:
    """Stateful PostgreSQL and portal double that rejects unknown commands."""

    def __init__(self):
        self.calls = []
        self.inputs = []
        self.listen = "localhost"
        self.port = "5432"
        self.role = False
        self.verifier = None
        self.database = False
        self.marker = ""
        self.tables = ()
        self.rows = 0
        self.hba = [" ".join(row) for row in _DEFAULT_HBA]
        self.restarts = 0
        self.reloads = 0
        self.seed_fails = False
        self.seed_commits_then_fails = False
        self.seed_timeout = None  # "before-commit" | "after-commit"
        self.portal = {
            "user": "techvault",
            "dbname": "techvault",
            "password": _PORTAL_PASSWORD,
        }
        self.portal_authenticates = None

    # The backend surface used by the adapter.
    def container_exec(self, name, command, *, timeout=None):
        assert timeout is not None
        assert timeout <= 120
        self.calls.append((name, list(command)))
        return self._dispatch(name, list(command))

    def container_exec_with_input(self, name, command, payload, *, timeout=None):
        assert timeout is not None
        assert timeout <= 120
        self.calls.append((name, list(command)))
        self.inputs.append((name, list(command), payload))
        if command[:2] == ["sh", "-s"]:
            return self._edit_hba(command, payload)
        if self._psql_target(command) == ("postgres", "stdin"):
            prefix = "ALTER ROLE techvault PASSWORD '"
            assert payload.startswith(prefix)
            assert payload.endswith("';\n")
            self.verifier = payload[len(prefix) : -3]
            return _ok()
        raise AssertionError(f"unexpected stdin command: {command}")

    def _dispatch(self, name, command):
        if name == "aptl-webapp":
            return self._portal(command)
        if command == ["pg_lsclusters", "--no-header"]:
            return _ok("15 main 5432 online postgres /var/lib/postgresql/15/main\n")
        if command[:2] == ["test", "-s"]:
            return _ok()
        if command == ["sha256sum", _SCHEMA, _SEED]:
            return _ok(f"{'a' * 64}  {_SCHEMA}\n{'b' * 64}  {_SEED}\n")
        if command == ["pg_ctlcluster", "15", "main", "restart"]:
            self.restarts += 1
            return _ok()
        if command[:4] == ["runuser", "-u", "postgres", "--"]:
            return self._postgres(command[4:])
        raise AssertionError(f"unexpected command: {command}")

    def _postgres(self, command):
        if command == ["createuser", "--login", "techvault"]:
            self.role = True
            return _ok()
        if command == ["createdb", "-O", "techvault", "techvault", _PENDING]:
            self.database = True
            self.marker = _PENDING
            return _ok()
        if command[:4] == ["timeout", "-k", "5", "90"]:
            return self._seed(command[4:])
        assert command[:2] == ["psql", "-X"], command
        assert command[2] == "-d", command
        assert command[4] == "-Atqc", command
        return self._query(command[3], command[5])

    def _query(self, database_name, statement):
        answers = {
            "SHOW listen_addresses": self.listen,
            "SHOW port": self.port,
            "SHOW hba_file": _HBA,
            "SELECT 1 FROM pg_roles WHERE rolname = 'techvault'": "1"
            if self.role
            else "",
            "SELECT 1 FROM pg_database WHERE datname = 'techvault'": "1"
            if self.database
            else "",
            "SELECT rolpassword IS NULL FROM pg_authid WHERE rolname = 'techvault'": (
                "t" if self.verifier is None else "f"
            ),
        }
        if statement in answers:
            return _ok(answers[statement] + "\n")
        if statement.startswith("ALTER SYSTEM SET listen_addresses = "):
            self.listen = statement.split("'")[1]
            return _ok()
        if statement.startswith("ALTER SYSTEM SET port = "):
            self.port = statement.rsplit(" ", 1)[1]
            return _ok()
        if statement == "SELECT pg_reload_conf()":
            self.reloads += 1
            return _ok("t\n")
        if "shobj_description" in statement:
            return _ok(self.marker + "\n")
        if "FROM pg_tables" in statement:
            assert database_name == "techvault"
            return _ok("".join(f"{table}\n" for table in self.tables))
        if "FROM pg_hba_file_rules" in statement:
            return _ok(self._hba_rows())
        raise AssertionError(f"unexpected query: {statement}")

    def _hba_rows(self):
        rows = []
        for number, line in enumerate(self.hba, start=1):
            fields = line.split()
            if fields[0] == "local":
                kind, db, user, method = fields
                address = netmask = ""
            else:
                kind, db, user, cidr, method = fields
                try:
                    network = ipaddress.ip_network(cidr)
                except ValueError:  # PostgreSQL reports hostnames unmasked
                    address, netmask = cidr, ""
                else:
                    address = str(network.network_address)
                    netmask = str(network.netmask)
            rows.append(f"{number}|{kind}|{db}|{user}|{address}|{netmask}|{method}|")
        return "\n".join(rows) + "\n"

    def _edit_hba(self, command, payload):
        assert command[:3] == ["sh", "-s", "--"]
        assert "set -eu" in payload
        path, rule, legacy = command[3:]
        assert path == _HBA
        before = list(self.hba)
        self.hba = [line for line in self.hba if line != legacy]
        if rule not in self.hba:
            self.hba.append(rule)
        return _ok("changed\n" if self.hba != before else "unchanged\n")

    def _seed(self, command):
        assert command[:8] == [
            "psql",
            "-X",
            "-d",
            "techvault",
            "-1",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
        ]
        assert command.index("-f") < command.index(_SEED)
        assert command[command.index(_SCHEMA) - 1] == "-f"
        assert "SET ROLE techvault" in command
        assert "SET LOCAL lock_timeout = '30s'" in command
        assert "SET LOCAL statement_timeout = '60s'" in command
        if self.seed_timeout == "before-commit":
            raise BackendTimeoutError("seed exec timed out")
        if self.seed_fails:
            return _fail()
        self.tables = _DECLARED_TABLES
        self.rows = 10
        self.marker = command[-1].split("'")[1]
        if self.seed_timeout == "after-commit":
            raise BackendTimeoutError("seed exec timed out")
        return _fail() if self.seed_commits_then_fails else _ok()

    def _psql_target(self, command):
        if command[:6] == ["runuser", "-u", "postgres", "--", "psql", "-X"]:
            return command[7], "stdin" if command[-2:] == ["-f", "-"] else "argv"
        return None

    def _portal(self, command):
        assert command[:2] == ["python3", "-c"], command
        script = command[2]
        if "json.dumps" in script:
            return _ok(json.dumps(self.portal))
        assert command[3:] == ["techvault", "techvault"]
        works = (
            self.portal_authenticates
            if self.portal_authenticates is not None
            else self.verifier is not None
            and self.listen == "0.0.0.0"
            and any(
                line.startswith("host techvault techvault ")
                and line.endswith(" scram-sha-256")
                for line in self.hba
            )
        )
        return _ok() if works else _fail()


def _ok(stdout=""):
    return SimpleNamespace(returncode=0, stdout=stdout)


def _fail():
    return SimpleNamespace(returncode=1, stdout="")


def _argv_text(backend):
    return "\n".join(" ".join(command) for _, command in backend.calls)


def test_selects_declared_service_client_network_and_tables(tmp_path):
    selected = database._declared_database(_nodes(tmp_path))

    assert selected is not None
    assert selected.db_container == "aptl-db"
    assert selected.web_container == "aptl-webapp"
    assert (selected.database, selected.role) == ("techvault", "techvault")
    assert selected.scope == ipaddress.ip_network(_SCOPE)
    assert selected.db_address == "172.20.2.11"
    assert (selected.listen_address, selected.port) == ("0.0.0.0", 5432)
    assert selected.tables == frozenset(_DECLARED_TABLES)


def test_selection_uses_the_admitted_network_cidr_not_a_constant(tmp_path):
    backend = _Postgres()
    nodes = _nodes(tmp_path, cidr="172.20.0.0/16")

    assert realize_database(backend, nodes) == []
    assert "host techvault techvault 172.20.0.0/16 scram-sha-256" in backend.hba


@pytest.mark.parametrize(
    "nodes_for",
    [
        lambda nodes: nodes[:1],
        lambda nodes: (nodes[0], nodes[1], nodes[1]),
        lambda nodes: (
            nodes[0],
            SimpleNamespace(**{**vars(nodes[1]), "network_attachments": ()}),
        ),
    ],
    ids=["missing-client", "duplicate-client", "unattached-client"],
)
def test_ambiguous_or_missing_declarations_mutate_nothing(tmp_path, nodes_for):
    backend = _Postgres()

    assert realize_database(backend, nodes_for(_nodes(tmp_path))) == [
        "TechVault database declaration or internal client is unavailable"
    ]
    assert backend.calls == []


def test_client_on_a_different_network_is_rejected(tmp_path):
    backend = _Postgres()

    assert realize_database(backend, _nodes(tmp_path, web_network="dmz-net")) == [
        "TechVault database declaration or internal client is unavailable"
    ]
    assert backend.calls == []


def test_fresh_realization_requires_password_and_seeds_once(tmp_path):
    backend = _Postgres()
    nodes = _nodes(tmp_path)

    assert realize_database(backend, nodes) == []

    assert _RULE in backend.hba
    assert not any(line.endswith(" trust") for line in backend.hba)
    assert backend.listen == "0.0.0.0"
    assert backend.verifier.startswith("SCRAM-SHA-256$100000:")
    assert backend.marker == _COMPLETE
    assert backend.restarts == 1
    seeds = [command for _, command in backend.calls if "-1" in command]
    assert len(seeds) == 1


def test_credential_and_verifier_never_reach_argv(tmp_path):
    backend = _Postgres()

    assert realize_database(backend, _nodes(tmp_path)) == []

    argv = _argv_text(backend)
    assert _PORTAL_PASSWORD not in argv
    assert backend.verifier not in argv
    assert all(_PORTAL_PASSWORD not in payload for _, _, payload in backend.inputs)


def test_restart_is_a_no_op_that_preserves_participant_data(tmp_path):
    backend = _Postgres()
    nodes = _nodes(tmp_path)
    assert realize_database(backend, nodes) == []
    verifier, restarts = backend.verifier, backend.restarts
    backend.tables = ("public.users",)  # a participant dropped tables
    backend.calls.clear()

    assert realize_database(backend, nodes) == []

    assert backend.verifier == verifier  # no rotation
    assert backend.restarts == restarts
    assert backend.reloads == 0
    assert not any("-1" in command for _, command in backend.calls)
    assert backend.tables == ("public.users",)


def test_previously_shipped_trust_rule_is_replaced_and_reloaded(tmp_path):
    backend = _Postgres()
    nodes = _nodes(tmp_path)
    assert realize_database(backend, nodes) == []
    backend.hba = [line for line in backend.hba if line != _RULE] + [_LEGACY]
    reloads = backend.reloads

    assert realize_database(backend, nodes) == []

    assert _LEGACY not in backend.hba
    assert backend.hba.count(_RULE) == 1
    assert backend.reloads == reloads + 1


def test_hostname_rule_before_the_selection_counts_as_shadowing(tmp_path):
    backend = _Postgres()
    backend.hba.insert(0, "host all all db.techvault.local trust")

    assert realize_database(backend, _nodes(tmp_path)) == [
        "TechVault PostgreSQL client authentication could not be realized"
    ]


def test_an_earlier_rule_that_shadows_the_selected_posture_fails(tmp_path):
    backend = _Postgres()
    backend.hba.insert(0, "host all all 0.0.0.0/0 trust")

    assert realize_database(backend, _nodes(tmp_path)) == [
        "TechVault PostgreSQL client authentication could not be realized"
    ]


def test_existing_tables_without_the_init_marker_are_not_reseeded(tmp_path):
    backend = _Postgres()
    backend.role = backend.database = True
    backend.tables = ("public.users",)

    assert realize_database(backend, _nodes(tmp_path)) == [
        "TechVault database holds state this startup did not initialize"
    ]
    assert not any("-1" in command for _, command in backend.calls)


def test_a_marker_from_different_pack_sql_fails_without_reseeding(tmp_path):
    backend = _Postgres()
    backend.role = backend.database = True
    backend.marker = f"aptl-techvault-db-init sha256:{'c' * 64} sha256:{'d' * 64}"

    assert realize_database(backend, _nodes(tmp_path)) == [
        "TechVault database holds state this startup did not initialize"
    ]
    assert not any("-1" in command for _, command in backend.calls)


def test_existing_unmarked_empty_database_is_not_treated_as_fresh(tmp_path):
    backend = _Postgres()
    backend.role = backend.database = True  # created by something else

    assert realize_database(backend, _nodes(tmp_path)) == [
        "TechVault database holds state this startup did not initialize"
    ]
    assert not any("-1" in command for _, command in backend.calls)


def test_interrupted_bootstrap_with_pending_marker_is_recovered(tmp_path):
    backend = _Postgres()
    backend.role = backend.database = True
    backend.marker = _PENDING  # created here; seed never committed

    assert realize_database(backend, _nodes(tmp_path)) == []
    assert backend.marker == _COMPLETE
    assert backend.tables == _DECLARED_TABLES


def test_pending_marker_with_tables_is_ambiguous_and_not_reseeded(tmp_path):
    backend = _Postgres()
    backend.role = backend.database = True
    backend.marker = _PENDING
    backend.tables = ("public.users",)

    assert realize_database(backend, _nodes(tmp_path)) == [
        "TechVault database holds state this startup did not initialize"
    ]
    assert not any("-1" in command for _, command in backend.calls)


def test_seed_timeout_after_commit_is_reconciled_by_marker(tmp_path):
    backend = _Postgres()
    backend.seed_timeout = "after-commit"

    assert realize_database(backend, _nodes(tmp_path)) == []
    assert backend.marker == _COMPLETE


def test_seed_timeout_before_commit_fails_and_stays_recoverable(tmp_path):
    backend = _Postgres()
    backend.seed_timeout = "before-commit"

    assert realize_database(backend, _nodes(tmp_path)) == [
        "TechVault PostgreSQL role, database, or pack SQL could not be realized"
    ]
    assert backend.marker == _PENDING
    backend.seed_timeout = None
    assert realize_database(backend, _nodes(tmp_path)) == []
    assert backend.marker == _COMPLETE


def test_failed_seed_transaction_is_reported(tmp_path):
    backend = _Postgres()
    backend.seed_fails = True

    assert realize_database(backend, _nodes(tmp_path)) == [
        "TechVault PostgreSQL role, database, or pack SQL could not be realized"
    ]


def test_seed_that_committed_before_failing_is_read_back(tmp_path):
    backend = _Postgres()
    backend.seed_commits_then_fails = True

    assert realize_database(backend, _nodes(tmp_path)) == []


def test_existing_role_password_is_not_rotated_and_must_work(tmp_path):
    backend = _Postgres()
    backend.verifier = "SCRAM-SHA-256$4096:existing"
    backend.portal_authenticates = False

    assert realize_database(backend, _nodes(tmp_path)) == [
        "TechVault portal cannot query PostgreSQL at 172.20.2.11:5432"
    ]
    assert backend.verifier == "SCRAM-SHA-256$4096:existing"


def test_portal_configured_for_another_identity_is_rejected(tmp_path):
    backend = _Postgres()
    backend.portal = {**backend.portal, "user": "postgres"}

    assert realize_database(backend, _nodes(tmp_path)) == [
        "TechVault portal database client does not match the declaration"
    ]
    assert backend.verifier is None


def test_transport_exception_fails_closed(tmp_path):
    class _Broken(_Postgres):
        def container_exec(self, name, command, *, timeout=None):
            raise TimeoutError("exec timed out")

    backend, nodes = _Broken(), _nodes(tmp_path)

    with pytest.raises(TimeoutError):
        realize_database(backend, nodes)


def test_scram_verifier_matches_rfc5802_derivation():
    salt = bytes(range(16))
    salted = hashlib.pbkdf2_hmac("sha256", b"pencil", salt, 100_000)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()

    assert database_access._scram_verifier("pencil", salt=salt) == (
        "SCRAM-SHA-256$100000:"
        + base64.b64encode(salt).decode()
        + "$"
        + base64.b64encode(stored_key).decode()
        + ":"
        + base64.b64encode(server_key).decode()
    )


def test_startup_declares_its_open_scope_database_selection():
    selections = TechVaultStartupProvider.runtime_selections

    assert [(item.node, item.subject) for item in selections] == [
        ("db", "database-client-authentication")
    ]
    assert "scram-sha-256" in selections[0].choice
    assert "OpenRAE/env-packs#411" in selections[0].reference


def test_pack_runtime_realizes_database_only_after_log_sources(monkeypatch):
    backend = object()
    nodes = (object(),)
    calls = []

    def logs(actual_backend, actual_nodes):
        calls.append(("logs", actual_backend, actual_nodes))
        return []

    def realize(actual_backend, actual_nodes):
        calls.append(("database", actual_backend, actual_nodes))
        return []

    monkeypatch.setattr("aptl_techvault.startup.realize_log_sources", logs)
    monkeypatch.setattr("aptl_techvault.startup.realize_database", realize)

    assert TechVaultStartupProvider.realize_runtime(backend, nodes) == []
    assert calls == [("logs", backend, nodes), ("database", backend, nodes)]

    calls.clear()
    monkeypatch.setattr(
        "aptl_techvault.startup.realize_log_sources",
        lambda *_args: ["log source unavailable"],
    )
    assert TechVaultStartupProvider.realize_runtime(backend, nodes) == [
        "log source unavailable"
    ]
    assert calls == []
