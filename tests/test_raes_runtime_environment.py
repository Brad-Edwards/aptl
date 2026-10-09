"""Runtime environment binding and closed-scope preservation.

The generic binding path remains available for scenarios that author runtime
environment requirements.  TechVault 6.2.0 deliberately does not: its portable
semantic state leaves backend mechanics out of the scenario and resolves the
unspecified environment and mount scopes CLOSED.  APTL must preserve that
absence rather than restoring old Docker Compose details behind the author's
back.

The security property under test is that a value never reaches process argv.
Environment carries credentials; `-e NAME=value` would expose them to any local
process able to read `/proc`, and to anything that echoes the command.

A matching name is not authority to read a value (issue #965). A declared
variable takes its authored value (or none), a generated output, an operator
grant for its pack and node, or the admitted pack's startup adapter value. The
canary tests below plant same-named values in this process's environment and
in `.env` and show that neither reaches the container on its own.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tarfile
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from raes.parser import parse_sdl_file

from aptl.backends.raes_base_substrate import BaseContainerSpec, _environment_names
from aptl.core.config import EnvironmentGrant
from aptl.core.deployment._environment_bindings import EnvironmentBindingContext
from aptl.core.deployment.errors import BackendSeedError
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


def _spec(
    names: tuple[str, ...],
    *,
    sourced: tuple[str, ...] = (),
    defaults: tuple[tuple[str, str], ...] = (),
    node: str = "webapp",
) -> BaseContainerSpec:
    return BaseContainerSpec(
        node_address=f"provision.node.{node}",
        container_name=f"aptl-{node}",
        image_ref="debian:13-slim",
        runs_services=True,
        environment_names=names,
        environment_defaults=defaults,
        environment_sourced=sourced,
    )


_CANARY = "ambient-canary-value"
# Granted values are built at run time, so no password-shaped literal sits in
# the source for a secret scanner to flag.
_GRANTED = f"granted-{uuid.uuid4().hex[:12]}"
_OTHER = f"other-{uuid.uuid4().hex[:12]}"


def _grant(
    variable: str,
    source: str,
    *,
    kind: str = "process-environment",
    pack: str = "techvault",
    consumer: str = "webapp",
) -> EnvironmentGrant:
    return EnvironmentGrant(
        pack=pack,
        consumer=consumer,
        variable=variable,
        source={"kind": kind, "variable": source},
    )


def _granting(
    project_dir: Path,
    *grants: EnvironmentGrant,
    pack: str | None = "techvault",
    adapter_names: frozenset[str] = frozenset(),
):
    """A backend whose preflight recorded these grants for one admitted pack."""

    from aptl.core.env import load_dotenv

    backend = _backend(project_dir)
    env_file = project_dir / ".env"
    backend._environment_binding_context = EnvironmentBindingContext(
        pack_id=pack,
        adapter_names=adapter_names,
        grants=grants,
        project_environment=load_dotenv(env_file) if env_file.exists() else {},
        process_environment=os.environ,
    )
    backend._environment_consumers = {
        "provision.node.webapp": "webapp",
        "provision.node.db": "db",
    }
    return backend


def _bound_body(backend, spec: BaseContainerSpec) -> str:
    argv: list[str] = []
    backend._append_base_environment(argv, spec)
    return Path(argv[1]).read_text(encoding="utf-8")


def test_closed_pack_environment_is_not_invented(scenario_path):
    """An empty closed environment remains empty at the base-container seam."""

    names = _environment_names(_webapp_runtime(scenario_path))

    assert names == ()


def test_secret_values_never_reach_process_argv(tmp_path, monkeypatch):
    """Values are bound through a file, never as -e NAME=value."""

    monkeypatch.setenv("LAB_DB_PASSWORD", _GRANTED)
    backend = _granting(tmp_path, _grant("DB_PASSWORD", "LAB_DB_PASSWORD"))
    spec = _spec(
        ("DB_HOST", "DB_PASSWORD"),
        sourced=("DB_PASSWORD",),
        defaults=(("DB_HOST", "db"),),
    )

    argv: list[str] = []
    backend._append_base_environment(argv, spec)

    assert argv[0] == "--env-file"
    assert not any(arg.startswith("-e") for arg in argv)
    joined = " ".join(argv)
    assert _GRANTED not in joined
    assert "DB_PASSWORD=" not in joined


def test_env_file_is_owner_only_and_carries_the_bindings(tmp_path, monkeypatch):
    """The file holding credentials is not readable by other local users."""

    monkeypatch.setenv("LAB_DB_PASSWORD", _GRANTED)
    backend = _granting(tmp_path, _grant("DB_PASSWORD", "LAB_DB_PASSWORD"))

    argv: list[str] = []
    backend._append_base_environment(
        argv, _spec(("DB_PASSWORD",), sourced=("DB_PASSWORD",))
    )
    path = Path(argv[1])

    assert path.read_text(encoding="utf-8") == f"DB_PASSWORD={_GRANTED}\n"
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == stat.S_IRUSR | stat.S_IWUSR, oct(mode)


def test_a_valueless_declaration_is_delivered_empty_not_inherited(
    tmp_path, monkeypatch
):
    """A plain variable declared without a value is realized empty, as declared.

    The same-named canaries in this process's environment and in `.env` are
    exactly what the old name matching bound into the container.
    """

    monkeypatch.setenv("DB_HOST", _CANARY)
    (tmp_path / ".env").write_text(f"DB_HOST={_CANARY}-dotenv\n", encoding="utf-8")

    body = _bound_body(_granting(tmp_path), _spec(("DB_HOST",)))

    assert body == "DB_HOST=\n"


def test_node_declaring_no_environment_binds_nothing(tmp_path):
    """No declaration means no env file and no flag."""

    assert _append(_spec(()), tmp_path) == []
    assert not (tmp_path / ".aptl" / "realization" / "env").exists()


def test_a_node_that_binds_nothing_keeps_no_earlier_env_file(tmp_path):
    """A credential file from an earlier run does not outlive its bindings (#966)."""

    stale = tmp_path / ".aptl" / "realization" / "env" / "aptl-webapp.env"
    stale.parent.mkdir(parents=True)
    stale.write_text("OLD_SECRET=previous\n", encoding="utf-8")

    assert _append(_spec(()), tmp_path) == []
    assert not stale.exists()


def test_an_ungranted_secret_is_refused_not_inherited(tmp_path, monkeypatch):
    """Missing binding: a same-named canary is never taken as authority."""

    monkeypatch.setenv("DB_PASSWORD", _CANARY)
    (tmp_path / ".env").write_text(f"DB_PASSWORD={_CANARY}\n", encoding="utf-8")
    backend = _granting(tmp_path)
    spec = _spec(("DB_PASSWORD",), sourced=("DB_PASSWORD",))

    argv: list[str] = []
    with pytest.raises(BackendSeedError, match="no environment grant") as excinfo:
        backend._append_base_environment(argv, spec)

    assert _CANARY not in str(excinfo.value)
    assert argv == []
    assert not (tmp_path / ".aptl").exists()


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


def test_the_project_env_file_is_read_only_through_a_grant(tmp_path):
    """A `project-env-file` grant reads exactly the key it names."""

    (tmp_path / ".env").write_text(
        f"DB_PASSWORD={_CANARY}\nLAB_DB_PASSWORD={_GRANTED}\n", encoding="utf-8"
    )
    grant = _grant("DB_PASSWORD", "LAB_DB_PASSWORD", kind="project-env-file")

    body = _bound_body(
        _granting(tmp_path, grant), _spec(("DB_PASSWORD",), sourced=("DB_PASSWORD",))
    )

    assert body == f"DB_PASSWORD={_GRANTED}\n"


def test_the_process_environment_is_read_only_through_a_grant(tmp_path, monkeypatch):
    """A `process-environment` grant reads its variable, not the target's name."""

    monkeypatch.setenv("DB_PASSWORD", _CANARY)
    monkeypatch.setenv("LAB_DB_PASSWORD", _GRANTED)
    grant = _grant("DB_PASSWORD", "LAB_DB_PASSWORD")

    body = _bound_body(
        _granting(tmp_path, grant), _spec(("DB_PASSWORD",), sourced=("DB_PASSWORD",))
    )

    assert body == f"DB_PASSWORD={_GRANTED}\n"


def test_closed_pack_environment_has_no_backend_defaults(scenario_path):
    """Old Compose literals are not smuggled into the backend-neutral pack."""

    from aptl.backends.raes_base_substrate import _environment_defaults

    defaults = dict(_environment_defaults(_webapp_runtime(scenario_path)))

    assert defaults == {}


def test_authored_values_survive_same_named_ambient_and_project_values(
    tmp_path, monkeypatch
):
    """An authored fixture or setting is delivered exactly as written."""

    (tmp_path / ".env").write_text(f"DB_NAME={_CANARY}\n", encoding="utf-8")
    monkeypatch.setenv("DB_HOST", _CANARY)
    grant = _grant("DB_HOST", "LAB_DB_HOST")
    monkeypatch.setenv("LAB_DB_HOST", _CANARY)
    spec = _spec(
        ("DB_HOST", "DB_NAME"),
        defaults=(("DB_HOST", "authored-host"), ("DB_NAME", "authored-name")),
    )

    body = _bound_body(_granting(tmp_path, grant), spec)

    assert body == "DB_HOST=authored-host\nDB_NAME=authored-name\n"


def test_a_grant_binds_only_the_consumer_it_names(tmp_path, monkeypatch):
    """Wrong consumer: a grant for `db` never reaches `webapp`'s same variable."""

    monkeypatch.setenv("LAB_DB_PASSWORD", _GRANTED)
    backend = _granting(
        tmp_path, _grant("DB_PASSWORD", "LAB_DB_PASSWORD", consumer="db")
    )
    webapp = _spec(("DB_PASSWORD",), sourced=("DB_PASSWORD",))
    db = _spec(("DB_PASSWORD",), sourced=("DB_PASSWORD",), node="db")

    with pytest.raises(BackendSeedError, match="no environment grant") as excinfo:
        backend._append_base_environment([], webapp)

    assert _GRANTED not in str(excinfo.value)
    assert _bound_body(backend, db) == f"DB_PASSWORD={_GRANTED}\n"


@pytest.mark.parametrize(
    ("pack", "named"),
    [("other-pack", "pack other-pack"), (None, "no pack identity")],
    ids=["other-pack", "project-tree"],
)
def test_a_grant_binds_only_the_pack_it_names(tmp_path, monkeypatch, pack, named):
    """Pack identity: a grant for `techvault` binds nothing in any other run."""

    monkeypatch.setenv("LAB_DB_PASSWORD", _GRANTED)
    backend = _granting(tmp_path, _grant("DB_PASSWORD", "LAB_DB_PASSWORD"), pack=pack)
    spec = _spec(("DB_PASSWORD",), sourced=("DB_PASSWORD",))

    with pytest.raises(BackendSeedError, match=named) as excinfo:
        backend._append_base_environment([], spec)

    assert _GRANTED not in str(excinfo.value)


def test_an_empty_grant_source_is_refused_and_named(tmp_path, monkeypatch):
    """A granted source that holds no value is a missing binding, not a blank."""

    monkeypatch.setenv("LAB_DB_PASSWORD", "")
    backend = _granting(tmp_path, _grant("DB_PASSWORD", "LAB_DB_PASSWORD"))
    spec = _spec(("DB_PASSWORD",), sourced=("DB_PASSWORD",))

    with pytest.raises(
        BackendSeedError,
        match="source grant:process-environment:LAB_DB_PASSWORD has no value",
    ):
        backend._append_base_environment([], spec)


def test_the_startup_adapter_binds_only_the_names_it_declares(tmp_path):
    """An adapter value comes from `.env`; other `.env` keys stay unreachable."""

    (tmp_path / ".env").write_text(
        f"INDEXER_PASSWORD={_OTHER}\nAPTL_API_TOKEN={_CANARY}\n",
        encoding="utf-8",
    )
    backend = _granting(tmp_path, adapter_names=frozenset({"INDEXER_PASSWORD"}))
    fixture = _spec(("INDEXER_PASSWORD",), sourced=("INDEXER_PASSWORD",))
    control_plane = _spec(("APTL_API_TOKEN",), sourced=("APTL_API_TOKEN",))

    assert _bound_body(backend, fixture) == f"INDEXER_PASSWORD={_OTHER}\n"
    with pytest.raises(BackendSeedError, match="no environment grant") as excinfo:
        backend._append_base_environment([], control_plane)
    assert _CANARY not in str(excinfo.value)


def test_binding_logs_name_each_source_never_a_value(tmp_path, monkeypatch, caplog):
    """Logs carry the source identity only."""

    monkeypatch.setenv("LAB_DB_PASSWORD", _GRANTED)
    backend = _granting(tmp_path, _grant("DB_PASSWORD", "LAB_DB_PASSWORD"))
    spec = _spec(
        ("DB_HOST", "DB_PASSWORD"),
        sourced=("DB_PASSWORD",),
        defaults=(("DB_HOST", "db"),),
    )

    # Scope the level to APTL's logger: another test may have raised it.
    with caplog.at_level("INFO", logger="aptl"):
        backend._append_base_environment([], spec)

    assert (
        "DB_HOST from authored, DB_PASSWORD from "
        "grant:process-environment:LAB_DB_PASSWORD"
    ) in caplog.text
    assert _GRANTED not in caplog.text


def _base_node_realization(environment=None, **fields):
    from raes.runtime_configuration import RuntimeConfiguration

    from aptl.core.deployment.realization import (
        DeploymentNodeRealization,
        DeploymentRealizationSpec,
    )
    from aptl.core.scenario_bundle import PackIdentity

    runtime = RuntimeConfiguration.model_validate(
        {
            "environment": environment
            or [
                {
                    "name": "DB_PASSWORD",
                    "value_classification": "operator_secret",
                    "provenance": "operator",
                }
            ]
        }
    )
    node = DeploymentNodeRealization(
        address="provision.node.webapp",
        name="webapp",
        service_name=None,
        container_name=None,
        networks=(),
        os="linux",
        runtime=runtime,
    )
    return DeploymentRealizationSpec(
        profiles=(),
        nodes=(node,),
        networks=(),
        pack_identity=PackIdentity("techvault", "0.1.1", "sha256:" + "0" * 64),
        **fields,
    )


def test_a_missing_binding_stops_realize_before_any_docker_command(
    tmp_path, monkeypatch
):
    """Missing binding fails in the backend preflight, before any mutation."""

    from aptl.core.deployment.docker_compose import DockerComposeBackend

    monkeypatch.setenv("DB_PASSWORD", _CANARY)
    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    commands: list[list[str]] = []
    monkeypatch.setattr(backend, "_run", lambda cmd, **_: commands.append(cmd))

    result = backend.realize(_base_node_realization(), scenario_root=tmp_path)

    assert result.success is False
    assert result.error == (
        "Environment binding refused for node webapp: DB_PASSWORD has no "
        "environment grant for pack techvault."
    )
    assert commands == []
    assert not (tmp_path / ".aptl" / "realization").exists()


@pytest.mark.parametrize(
    "deployment",
    [
        {"provider": "docker-compose"},
        {
            "provider": "ssh-compose",
            "ssh_host": "server.example.com",
            "ssh_user": "deploy",
        },
    ],
    ids=["docker-compose", "ssh-compose"],
)
def test_a_granted_binding_passes_the_preflight(tmp_path, monkeypatch, deployment):
    """The same request passes once a grant in `aptl.json` names the variable.

    `get_backend` hands the grants to either provider. The SSH backend takes
    them through `use_environment_grants`, not through its constructor.
    """

    from aptl.core.config import load_config
    from aptl.core.deployment import get_backend

    grant = {
        "pack": "techvault",
        "consumer": "webapp",
        "variable": "DB_PASSWORD",
        "source": {"kind": "process-environment", "variable": "LAB_DB_PASSWORD"},
    }
    config_path = tmp_path / "aptl.json"
    config_path.write_text(
        json.dumps(
            {
                "lab": {"name": "grants"},
                "deployment": {**deployment, "environment_grants": [grant]},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("LAB_DB_PASSWORD", _GRANTED)

    backend = get_backend(load_config(config_path), tmp_path)

    assert backend._environment_grants == (_grant("DB_PASSWORD", "LAB_DB_PASSWORD"),)
    assert backend._environment_binding_preflight(_base_node_realization()) is None


def test_an_adapter_selected_for_another_pack_supplies_nothing(tmp_path):
    """Pack identity: adapter names apply only to the identity it was selected for."""

    from aptl.core.deployment._environment_bindings import binding_context
    from aptl.core.scenario_bundle import PackIdentity

    plan = SimpleNamespace(
        environment_fixtures=(SimpleNamespace(name="DB_PASSWORD"),),
        environment_aliases=(),
    )
    other = PackIdentity("techvault", "0.0.9", "sha256:" + "1" * 64)
    matching = _base_node_realization(
        startup_selection=SimpleNamespace(identity=None, plan=plan)
    )
    selected = SimpleNamespace(identity=matching.pack_identity, plan=plan)
    stale = SimpleNamespace(identity=other, plan=plan)

    names = {
        label: binding_context(
            replace(matching, startup_selection=selection), (), tmp_path
        ).adapter_names
        for label, selection in (("selected", selected), ("stale", stale))
    }

    assert names == {"selected": frozenset({"DB_PASSWORD"}), "stale": frozenset()}


def test_a_generated_value_never_replaces_an_authored_declaration(tmp_path):
    """Only a variable declared with value_from takes a generated output."""

    backend = _granting(tmp_path)
    backend._base_container_generated_environment = {
        "provision.node.webapp": {"DB_HOST": _CANARY}
    }

    body = _bound_body(
        backend, _spec(("DB_HOST",), defaults=(("DB_HOST", "authored"),))
    )

    assert body == "DB_HOST=authored\n"


def test_a_value_its_env_file_cannot_carry_stops_the_preflight(tmp_path, monkeypatch):
    """The preflight checks granted values against Docker's env-file rules."""

    from aptl.core.deployment.docker_compose import DockerComposeBackend

    monkeypatch.setenv("LAB_DB_PASSWORD", "first-line\nsecond-line")
    backend = DockerComposeBackend(
        tmp_path, environment_grants=(_grant("DB_PASSWORD", "LAB_DB_PASSWORD"),)
    )

    result = backend._environment_binding_preflight(_base_node_realization())

    assert result is not None
    assert "cannot carry DB_PASSWORD exactly: the value contains a line break" in (
        result.error
    )
    assert "first-line" not in result.error


def test_a_grant_source_is_read_once_when_the_start_is_checked(tmp_path, monkeypatch):
    """A source changed after the preflight does not change this start's value."""

    from aptl.core.deployment.docker_compose import DockerComposeBackend

    monkeypatch.setenv("LAB_DB_PASSWORD", _GRANTED)
    backend = DockerComposeBackend(
        tmp_path, environment_grants=(_grant("DB_PASSWORD", "LAB_DB_PASSWORD"),)
    )
    assert backend._environment_binding_preflight(_base_node_realization()) is None
    monkeypatch.setenv("LAB_DB_PASSWORD", _OTHER)

    body = _bound_body(backend, _spec(("DB_PASSWORD",), sourced=("DB_PASSWORD",)))

    assert body == f"DB_PASSWORD={_GRANTED}\n"


def test_a_secret_without_a_checked_context_is_refused(tmp_path, monkeypatch):
    """A start that skipped the preflight names why, not a missing pack."""

    monkeypatch.setenv("DB_PASSWORD", _CANARY)
    backend = _backend(tmp_path)
    spec = _spec(("DB_PASSWORD",), sourced=("DB_PASSWORD",))

    with pytest.raises(BackendSeedError, match="were not checked before this start"):
        backend._append_base_environment([], spec)


def test_an_unreadable_env_file_fails_only_a_variable_that_needs_it(tmp_path):
    """Only an adapter or grant value read from `.env` depends on it."""

    from aptl.core.deployment.docker_compose import DockerComposeBackend

    (tmp_path / ".env").write_bytes(b"\xff\xfe not utf-8")
    backend = DockerComposeBackend(tmp_path)
    plain = _base_node_realization(environment=[{"name": "DB_HOST", "value": "db"}])
    secret = _base_node_realization()
    adapter = replace(
        secret,
        startup_selection=SimpleNamespace(
            identity=secret.pack_identity,
            plan=SimpleNamespace(
                environment_fixtures=(SimpleNamespace(name="DB_PASSWORD"),),
                environment_aliases=(),
            ),
        ),
    )

    assert backend._environment_binding_preflight(plain) is None
    result = backend._environment_binding_preflight(adapter)

    assert "the project .env is unreadable, so DB_PASSWORD has no value" in result.error


def test_a_grant_that_matches_nothing_is_reported(tmp_path, monkeypatch, caplog):
    """A mistyped grant is named in the log instead of silently ignored."""

    from aptl.core.deployment.docker_compose import DockerComposeBackend

    monkeypatch.setenv("LAB_DB_PASSWORD", _GRANTED)
    grants = (
        _grant("DB_PASSWORD", "LAB_DB_PASSWORD"),
        _grant("DB_PASWORD", "LAB_DB_PASSWORD"),
    )
    backend = DockerComposeBackend(tmp_path, environment_grants=grants)

    with caplog.at_level("WARNING", logger="aptl"):
        assert backend._environment_binding_preflight(_base_node_realization()) is None

    assert "node webapp variable DB_PASWORD matched no value-less secret" in caplog.text
    assert "variable DB_PASSWORD matched" not in caplog.text
    assert _GRANTED not in caplog.text


def test_the_env_file_flag_is_followed_by_the_bound_names_label(tmp_path, monkeypatch):
    """The label names what was bound, so a later start can see a stale one."""

    monkeypatch.setenv("LAB_DB_PASSWORD", _GRANTED)
    backend = _granting(tmp_path, _grant("DB_PASSWORD", "LAB_DB_PASSWORD"))
    spec = _spec(
        ("DB_PASSWORD", "DB_HOST"),
        sourced=("DB_PASSWORD",),
        defaults=(("DB_HOST", "db"),),
    )

    argv: list[str] = []
    backend._append_base_environment(argv, spec)

    assert argv[2:] == ["--label", "aptl.environment.names=DB_HOST,DB_PASSWORD"]


def test_spec_lowering_marks_out_of_band_and_generated_names():
    """Value-less operator secrets, redacted values and fixtures need a source.

    A value-less `plain` variable, or one with RAES's default classification
    `unknown`, needs none: it keeps its declared name and is delivered empty.
    """

    from raes.runtime_configuration import RuntimeConfiguration

    from aptl.backends.raes_base_substrate import base_container_spec

    runtime = RuntimeConfiguration.model_validate(
        {
            "environment": [
                {"name": "SETTING", "value": "on"},
                {"name": "EMPTY_SETTING", "value_classification": "plain"},
                {"name": "UNCLASSIFIED"},
                {"name": "OPERATOR", "value_classification": "operator_secret"},
                {"name": "FIXTURE", "value_classification": "secret_fixture"},
                {"name": "WITHHELD", "value_classification": "redacted"},
                {
                    "name": "PLANTED",
                    "value": "changeme",
                    "value_classification": "secret_fixture",
                },
                {
                    "name": "GENERATED",
                    "value_from": {
                        "generated_artifact": "keys",
                        "output": "api-key",
                    },
                    "value_classification": "redacted",
                },
            ]
        }
    )

    spec = base_container_spec(
        "provision.node.webapp", os="linux", os_version="", runtime=runtime
    )

    assert {"EMPTY_SETTING", "UNCLASSIFIED"} <= set(spec.environment_names)
    assert spec.environment_sourced == ("OPERATOR", "FIXTURE", "WITHHELD")
    assert spec.environment_generated == ("GENERATED",)
    assert dict(spec.environment_defaults) == {"SETTING": "on", "PLANTED": "changeme"}


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


# Values Docker's env-file reader keeps byte for byte (#966). The last one makes
# its line exactly 65535 bytes, the longest line Docker accepts.
_EXACT_VALUES = {
    "FIXTURE_PADDED": "  padded value  ",
    "FIXTURE_MARKUP": "a#b $HOME ${X} 'single' \"double\" \\back",
    "FIXTURE_EQUALS": "=leading=and=inner=",
    "FIXTURE_UNICODE": "pässwörd-✓",
    "FIXTURE_INNER_CR": "carriage\rreturn",
    "FIXTURE_LONGEST": "x" * (65535 - len("FIXTURE_LONGEST=")),
}


def _fixture_spec(values: dict[str, str]) -> BaseContainerSpec:
    return BaseContainerSpec(
        node_address="provision.node.webapp",
        container_name="aptl-webapp",
        image_ref="debian:13-slim",
        runs_services=True,
        environment_names=tuple(values),
        environment_defaults=tuple(values.items()),
    )


def _docker_env_file_values(path: Path) -> dict[str, str]:
    """Read an env file by Docker's --env-file rules.

    Lines split on line feeds and lose one trailing carriage return; blank and
    ``#`` lines are skipped; a value is everything after the first ``=``,
    untrimmed. Confirmed against Docker 29.7.2 while fixing #966.
    """

    values = {}
    for raw in path.read_bytes().decode("utf-8").split("\n"):
        line = raw.removesuffix("\r").lstrip()
        if line and not line.startswith("#"):
            name, _, value = line.partition("=")
            values[name] = value
    return values


def test_env_file_carries_exact_values_through_dockers_reader(tmp_path):
    """Authored values arrive unchanged, never trimmed, quoted or escaped."""

    argv = _append(_fixture_spec(_EXACT_VALUES), tmp_path)

    assert _docker_env_file_values(Path(argv[1])) == _EXACT_VALUES


@pytest.mark.parametrize(
    ("value", "problem"),
    [
        ("trailing\r", "trailing carriage return"),
        ("nul\x00byte", "NUL character"),
        ("lone-\udcff-surrogate", "not valid UTF-8"),
        ("x" * 65536, "64 KiB"),
    ],
    ids=["trailing-cr", "nul", "surrogate", "over-64k"],
)
def test_values_dockers_reader_would_alter_are_refused_before_writing(
    tmp_path, value, problem
):
    """A value Docker cannot carry exactly is a reported limitation, not a guess."""

    backend = _backend(tmp_path)
    spec = _fixture_spec({"FIXTURE": value})
    argv: list[str] = []
    with pytest.raises(BackendSeedError, match=problem) as excinfo:
        backend._append_base_environment(argv, spec)

    assert "cannot carry FIXTURE exactly" in str(excinfo.value)
    assert value not in str(excinfo.value)
    assert argv == []
    assert not (tmp_path / ".aptl").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlinks")
@pytest.mark.parametrize(
    "link",
    [".aptl/realization/env/aptl-webapp.env", ".aptl/realization/env"],
    ids=["env-file", "env-directory"],
)
def test_a_symlinked_env_path_is_refused_and_its_target_untouched(tmp_path, link):
    """The writer used to follow these links and truncate what they named."""

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "aptl-webapp.env").write_text("keep\n", encoding="utf-8")
    target = outside / Path(link).name if link.endswith(".env") else outside
    (tmp_path / link).parent.mkdir(parents=True)
    (tmp_path / link).symlink_to(target)

    backend = _backend(tmp_path)
    spec = _fixture_spec({"FIXTURE": "value"})
    argv: list[str] = []
    with pytest.raises(BackendSeedError, match=r"\(symlink\)"):
        backend._append_base_environment(argv, spec)

    assert argv == []
    assert sorted(path.name for path in outside.iterdir()) == ["aptl-webapp.env"]
    assert (outside / "aptl-webapp.env").read_text(encoding="utf-8") == "keep\n"


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard links and modes")
def test_an_existing_env_file_is_replaced_owner_only_and_never_truncated(tmp_path):
    """A stale permissive file, or one hard-linked elsewhere, is replaced whole."""

    outside = tmp_path / "outside.txt"
    outside.write_text("keep\n", encoding="utf-8")
    env_dir = tmp_path / ".aptl" / "realization" / "env"
    env_dir.mkdir(parents=True)
    stale = env_dir / "aptl-webapp.env"
    stale.hardlink_to(outside)
    stale.chmod(0o644)

    argv = _append(_fixture_spec({"FIXTURE": "value"}), tmp_path)

    assert Path(argv[1]).read_text(encoding="utf-8") == "FIXTURE=value\n"
    assert stat.S_IMODE(Path(argv[1]).stat().st_mode) == 0o600
    assert stat.S_IMODE(env_dir.stat().st_mode) == 0o700
    assert outside.read_text(encoding="utf-8") == "keep\n"


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(["docker", "info"], capture_output=True, check=False)
    return probe.returncode == 0


@pytest.mark.integration
def test_docker_reads_the_env_file_back_exactly(tmp_path):
    """Value readback through the real Docker CLI, not a model of its parser.

    The container is created from an empty imported image and never started,
    so the check needs no registry access and leaves nothing behind.
    """

    if not _docker_ready():
        pytest.skip("requires a Docker daemon")
    env_file = _append(_fixture_spec(_EXACT_VALUES), tmp_path)[1]
    archive = tmp_path / "empty.tar"
    with tarfile.open(archive, "w"):
        pass
    image = f"lilrae-env-readback:{uuid.uuid4().hex[:12]}"
    subprocess.run(
        ["docker", "image", "import", str(archive), image],
        check=True,
        capture_output=True,
    )
    try:
        created = subprocess.run(
            ["docker", "create", "--env-file", env_file, image, "/none"],
            check=True,
            capture_output=True,
            text=True,
        )
        container = created.stdout.strip()
        try:
            inspected = subprocess.run(
                ["docker", "inspect", "--format", "{{json .Config.Env}}", container],
                check=True,
                capture_output=True,
                text=True,
            )
        finally:
            subprocess.run(["docker", "rm", container], capture_output=True)
    finally:
        subprocess.run(["docker", "image", "rm", image], capture_output=True)

    realized = dict(entry.split("=", 1) for entry in json.loads(inspected.stdout))
    assert realized == _EXACT_VALUES
