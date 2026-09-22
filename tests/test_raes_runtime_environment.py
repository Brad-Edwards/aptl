"""Runtime environment binding and closed-scope preservation.

The generic binding path remains available for scenarios that author runtime
environment requirements.  TechVault 6.1.0 deliberately does not: its portable
semantic state leaves backend mechanics out of the scenario and resolves the
unspecified environment and mount scopes CLOSED.  APTL must preserve that
absence rather than restoring old Docker Compose details behind the author's
back.

The security property under test is that a value never reaches process argv.
Environment carries credentials; `-e NAME=value` would expose them to any local
process able to read `/proc`, and to anything that echoes the command.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from raes.parser import parse_sdl_file

from aptl.backends.raes_base_substrate import BaseContainerSpec, _environment_names
from tests.helpers import techvault_scenario_path


@pytest.fixture(scope="module")
def scenario_path(tmp_path_factory) -> Path:
    """Staged SDL path of the default TechVault env-pack scenario (#875)."""
    return techvault_scenario_path(tmp_path_factory.mktemp("raes-env"))


def _webapp_runtime(scenario_path: Path):
    return parse_sdl_file(scenario_path).nodes["webapp"].runtime


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
        image_ref="debian:13-slim",
        runs_services=True,
        environment_names=names,
    )


def test_closed_pack_environment_is_not_invented(scenario_path):
    """An empty closed environment remains empty at the base-container seam."""

    names = _environment_names(_webapp_runtime(scenario_path))

    assert names == ()


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


def test_closed_node_mounts_are_not_invented(scenario_path):
    """Backend-neutral nodes gain no Docker mount details through APTL."""

    from aptl.backends.raes_base_substrate import _volume_mounts

    scenario = parse_sdl_file(scenario_path)
    lowered = {
        name: {(m.source, m.target) for m in _volume_mounts(node.runtime)}
        for name, node in scenario.nodes.items()
        if getattr(node, "runtime", None) and node.runtime.mounts
    }

    assert lowered == {}

    # Explicit portable persistent-volume resources remain authored state; they
    # are not node-local Docker mount selections and keep their exact consumers.
    persistent = {
        name: {
            (consumer.node, consumer.mount_destination) for consumer in volume.consumers
        }
        for name, volume in scenario.persistent_volumes.items()
    }
    assert persistent["suricata_misp_rules"] == {
        ("suricata", "/var/lib/suricata/rules/misp"),
        ("misp-suricata-sync", "/var/lib/suricata/rules/misp"),
    }
    assert persistent["suricata_command_socket"] == {
        ("suricata", "/var/run/suricata"),
        ("misp-suricata-sync", "/var/run/suricata"),
    }


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


def test_closed_pack_environment_has_no_backend_defaults(scenario_path):
    """Old Compose literals are not smuggled into the backend-neutral pack."""

    from aptl.backends.raes_base_substrate import _environment_defaults

    defaults = dict(_environment_defaults(_webapp_runtime(scenario_path)))

    assert defaults == {}


def test_credentials_and_operator_overrides_beat_authored_defaults(
    tmp_path, monkeypatch
):
    """Precedence is operator, then project credentials, then authored default."""

    from aptl.backends.raes_base_substrate import BaseContainerSpec

    (tmp_path / ".env").write_text("DB_NAME=from-credentials\n", encoding="utf-8")
    monkeypatch.setenv("DB_HOST", "from-operator")
    monkeypatch.delenv("DB_NAME", raising=False)

    spec = BaseContainerSpec(
        node_address="provision.node.webapp",
        container_name="aptl-webapp",
        image_ref="debian:13-slim",
        runs_services=True,
        environment_names=("DB_HOST", "DB_NAME", "DB_PORT"),
        environment_defaults=(
            ("DB_HOST", "authored"),
            ("DB_NAME", "authored"),
            ("DB_PORT", "5432"),
        ),
    )
    body = Path(_append(spec, tmp_path)[1]).read_text(encoding="utf-8")

    assert "DB_HOST=from-operator" in body
    assert "DB_NAME=from-credentials" in body
    assert "DB_PORT=5432" in body


def test_closed_pack_credentials_are_not_reintroduced_as_environment(scenario_path):
    """A planted secret elsewhere in the scenario does not open this scope."""

    from aptl.backends.raes_base_substrate import _environment_defaults

    scenario = parse_sdl_file(scenario_path)

    db = dict(_environment_defaults(scenario.nodes["db"].runtime))
    webapp = dict(_environment_defaults(scenario.nodes["webapp"].runtime))

    assert db == {}
    assert webapp == {}


def test_a_real_operator_secret_is_still_authored_empty(scenario_path):
    """The distinction must cut both ways, or everything becomes a fixture."""

    from aptl.backends.raes_base_substrate import _environment_defaults

    scenario = parse_sdl_file(scenario_path)
    sync = dict(_environment_defaults(scenario.nodes["misp-suricata-sync"].runtime))

    # MISP's API key is a real deployment credential, not planted range content.
    assert "MISP_API_KEY" not in sync


def test_closed_pack_environment_has_no_values_to_reclassify(
    scenario_path,
):
    """APTL cannot reinterpret absent closed values as backend fixtures."""

    scenario = parse_sdl_file(scenario_path)

    assert scenario.nodes["db"].runtime.environment == []
    assert scenario.nodes["webapp"].runtime.environment == []
