"""Declared runtime environment binding (ADR-050 parity restoration).

The generic-materialization conversion dropped every environment variable the
pre-refactor components required — `webapp` lost its entire database binding,
`misp-suricata-sync` its MISP API wiring. The SDL now declares those variables,
and this covers how they reach a node.

The security property under test is that a value never reaches process argv.
Environment carries credentials; `-e NAME=value` would expose them to any local
process able to read `/proc`, and to anything that echoes the command.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from raes.parser import parse_sdl_file

from aptl.backends.raes_base_substrate import BaseContainerSpec, _environment_names

_SCENARIO = (
    Path(__file__).resolve().parents[1]
    / "scenarios"
    / "techvault-operational.sdl.yaml"
)


def _webapp_runtime():
    return parse_sdl_file(_SCENARIO).nodes["webapp"].runtime


def _backend(project_dir: Path):
    """Real mixin instance with only the project attributes it needs."""

    from aptl.core.deployment._compose_base_substrate import ComposeBaseSubstrateMixin

    backend = ComposeBaseSubstrateMixin()
    backend._project_dir = project_dir
    backend._project_name = "aptl"
    return backend


def _append(spec: BaseContainerSpec, project_dir: Path) -> list[str]:
    backend = _backend(project_dir)
    argv: list[str] = []
    backend._append_base_environment(argv, spec)
    return argv


def _spec(names: tuple[str, ...]) -> BaseContainerSpec:
    return BaseContainerSpec(
        node_address="provision.node.webapp",
        container_name="aptl-webapp",
        image_ref="debian:12-slim",
        runs_services=True,
        environment_names=names,
    )


def test_declared_environment_names_are_lowered():
    """The webapp's restored database binding reaches the realization spec."""

    names = _environment_names(_webapp_runtime())

    assert "DB_HOST" in names
    assert "DB_PASSWORD" in names
    assert len(names) == 11


def test_secret_values_never_reach_process_argv(tmp_path, monkeypatch):
    """Values are bound through a file, never as -e NAME=value."""

    monkeypatch.setenv("DB_PASSWORD", "s3cret-value")
    monkeypatch.setenv("DB_HOST", "db")

    argv = _append(_spec(("DB_HOST", "DB_PASSWORD")), tmp_path)

    assert argv[0] == "--env-file"
    assert not any(arg.startswith("-e") for arg in argv)
    joined = " ".join(argv)
    assert "s3cret-value" not in joined
    assert "DB_PASSWORD=" not in joined


def test_env_file_is_owner_only_and_carries_the_bindings(tmp_path, monkeypatch):
    """The file holding credentials is not readable by other local users."""

    monkeypatch.setenv("DB_PASSWORD", "s3cret-value")

    argv = _append(_spec(("DB_PASSWORD",)), tmp_path)
    path = Path(argv[1])

    assert path.read_text(encoding="utf-8") == "DB_PASSWORD=s3cret-value\n"
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == stat.S_IRUSR | stat.S_IWUSR, oct(mode)


def test_absent_variable_is_omitted_rather_than_bound_empty(tmp_path, monkeypatch):
    """A missing value must not become a silently blank credential."""

    monkeypatch.delenv("DB_PASSWORD", raising=False)
    monkeypatch.setenv("DB_HOST", "db")

    argv = _append(_spec(("DB_HOST", "DB_PASSWORD")), tmp_path)
    body = Path(argv[1]).read_text(encoding="utf-8")

    assert body == "DB_HOST=db\n"
    assert "DB_PASSWORD" not in body


def test_node_declaring_no_environment_binds_nothing(tmp_path):
    """No declaration means no env file and no flag."""

    assert _append(_spec(()), tmp_path) == []
    assert not (tmp_path / ".aptl" / "realization" / "env").exists()


def test_no_environment_is_bound_when_nothing_is_set(tmp_path, monkeypatch):
    """All declared variables absent yields no file rather than an empty one."""

    monkeypatch.delenv("DB_PASSWORD", raising=False)
    monkeypatch.delenv("DB_HOST", raising=False)

    assert _append(_spec(("DB_HOST", "DB_PASSWORD")), tmp_path) == []


def test_restored_named_volumes_are_lowered():
    """The persistent state the refactor dropped is declared and lowered again.

    Bind mounts of project keys and certificates are deliberately absent: they
    are authored as content placements, which carry containment, symlink
    rejection, and sensitivity handling that a raw bind does not.
    """

    from aptl.backends.raes_base_substrate import _volume_mounts

    scenario = parse_sdl_file(_SCENARIO)
    lowered = {
        name: {(m.source, m.target) for m in _volume_mounts(node.runtime)}
        for name, node in scenario.nodes.items()
        if getattr(node, "runtime", None) and node.runtime.mounts
    }

    assert ("db_data", "/var/lib/postgresql/data") in lowered["db"]
    assert ("webapp_logs", "/var/log/gunicorn") in lowered["webapp"]
    assert ("kali_operations", "/home/kali/operations") in lowered["kali"]
    assert ("fileshare_data", "/srv/shares") in lowered["fileshare"]
    assert sum(len(v) for v in lowered.values()) == 10
    # No raw host or project bind smuggled in alongside them.
    for mounts in lowered.values():
        assert all(not source.startswith((".", "/")) for source, _ in mounts)


def test_values_come_from_the_project_credential_boundary(tmp_path, monkeypatch):
    """APTL keeps values in the generated .env, never in this process.

    Reading only ``os.environ`` produced no bindings at all during a real lab
    start, because the lab-start process never exports them. The project's
    dotenv boundary is the actual source.
    """

    monkeypatch.delenv("DB_HOST", raising=False)
    (tmp_path / ".env").write_text("DB_HOST=db\n", encoding="utf-8")

    argv = _append(_spec(("DB_HOST",)), tmp_path)

    assert argv[0] == "--env-file"
    assert Path(argv[1]).read_text(encoding="utf-8") == "DB_HOST=db\n"


def test_process_environment_overrides_the_project_file(tmp_path, monkeypatch):
    """An operator can override one variable without editing credentials."""

    (tmp_path / ".env").write_text("DB_HOST=from-file\n", encoding="utf-8")
    monkeypatch.setenv("DB_HOST", "from-operator")

    argv = _append(_spec(("DB_HOST",)), tmp_path)

    assert Path(argv[1]).read_text(encoding="utf-8") == "DB_HOST=from-operator\n"
