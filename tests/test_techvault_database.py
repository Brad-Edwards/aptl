"""The pack-qualified database startup must make the portal's SQL path live."""

from __future__ import annotations

from types import SimpleNamespace

from raes.parser import parse_sdl_file

from aptl_techvault.database import _declared_database, realize_database
from aptl_techvault.startup import TechVaultStartupProvider
from tests.helpers import techvault_scenario_path


def _nodes(tmp_path):
    scenario = parse_sdl_file(techvault_scenario_path(tmp_path))

    def node(name, address):
        return SimpleNamespace(
            name=name,
            container_name=f"aptl-{name}",
            runtime=scenario.nodes[name].runtime,
            network_attachments=(
                SimpleNamespace(network="internal-net", ipv4_address=address),
            ),
        )

    return (node("db", "172.20.2.11"), node("webapp", "172.20.2.25"))


class _Backend:
    def __init__(self):
        self.commands = []
        self.role = False
        self.database = False
        self.seeded = False
        self.listener = False
        self.web_connects = True

    def container_exec(self, name, command, *, timeout=None):
        del timeout
        self.commands.append((name, command))
        output = ""
        if command == ["pg_lsclusters", "--no-header"]:
            output = "17 main 5432 online postgres\n"
        elif command[:3] == ["runuser", "-u", "postgres"]:
            if "createuser" in command:
                self.role = True
            elif "createdb" in command:
                self.database = True
            elif "-1" in command:
                self.seeded = True
            elif "-Atqc" in command:
                statement = command[-1]
                if "pg_roles" in statement:
                    output = "1\n" if self.role else ""
                elif "pg_database" in statement:
                    output = "1\n" if self.database else ""
                elif "pg_tables" in statement:
                    output = (
                        "api_keys\naudit_log\nbackup_config\ncomments\n"
                        "customers\nfiles\nsessions\nusers\n"
                        if self.seeded
                        else ""
                    )
                elif "count(*) FROM users" in statement:
                    output = "6\n" if self.seeded else "0\n"
                elif "SHOW listen_addresses" in statement:
                    output = "0.0.0.0\n" if self.listener else "localhost\n"
                elif "ALTER SYSTEM SET listen_addresses" in statement:
                    self.listener = True
        elif name == "aptl-webapp" and command[:2] == ["python3", "-c"]:
            if not self.web_connects:
                return SimpleNamespace(returncode=1, stdout="")
        return SimpleNamespace(returncode=0, stdout=output)


def test_pack_declares_one_internal_postgresql_service_and_client(tmp_path):
    assert _declared_database(_nodes(tmp_path)) == (
        "aptl-db",
        "aptl-webapp",
        "techvault",
        "techvault",
        "172.20.2.11",
    )


def test_database_realization_uses_pack_sql_and_is_idempotent(tmp_path):
    backend = _Backend()
    nodes = _nodes(tmp_path)

    assert realize_database(backend, nodes) == []
    assert backend.seeded
    assert (
        "aptl-db",
        [
            "runuser",
            "-u",
            "postgres",
            "--",
            "psql",
            "-d",
            "postgres",
            "-Atqc",
            "ALTER SYSTEM SET listen_addresses = '0.0.0.0'",
        ],
    ) in backend.commands
    assert any(
        command[:2] == ["sh", "-c"]
        and "host techvault techvault 172.20.2.0/24 trust" in command[2]
        for _, command in backend.commands
    )
    seed_commands = [command for _, command in backend.commands if "-1" in command]
    assert len(seed_commands) == 1
    assert seed_commands[0][-4:] == [
        "-f",
        "/opt/db-init/01-schema.sql",
        "-f",
        "/opt/db-init/02-seed-data.sql",
    ]
    assert realize_database(backend, nodes) == []
    assert len([command for _, command in backend.commands if "-1" in command]) == 1


def test_database_realization_requires_a_web_tier_query(tmp_path):
    backend = _Backend()
    backend.web_connects = False

    assert realize_database(backend, _nodes(tmp_path)) == [
        "TechVault portal cannot query PostgreSQL at 172.20.2.11:5432"
    ]


def test_database_realization_rejects_missing_client_declaration(tmp_path):
    backend = _Backend()
    assert realize_database(backend, _nodes(tmp_path)[:1]) == [
        "TechVault database declaration or internal client is unavailable"
    ]
    assert backend.commands == []


def test_pack_runtime_realizes_database_only_after_log_sources(monkeypatch):
    backend = object()
    nodes = (object(),)
    calls = []

    def logs(actual_backend, actual_nodes):
        calls.append(("logs", actual_backend, actual_nodes))
        return []

    def database(actual_backend, actual_nodes):
        calls.append(("database", actual_backend, actual_nodes))
        return []

    monkeypatch.setattr("aptl_techvault.startup.realize_log_sources", logs)
    monkeypatch.setattr("aptl_techvault.startup.realize_database", database)

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
