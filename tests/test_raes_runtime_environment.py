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


class _Backend:
    """Minimal stand-in exposing what the env binding needs."""

    def __init__(self, project_dir: Path) -> None:
        self._project_dir = project_dir
        self._project_name = "aptl"


def _append(spec: BaseContainerSpec, project_dir: Path) -> list[str]:
    from aptl.core.deployment._compose_base_substrate import ComposeBaseSubstrateMixin

    backend = _Backend(project_dir)
    argv: list[str] = []
    ComposeBaseSubstrateMixin._append_base_environment(backend, argv, spec)
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
