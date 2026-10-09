"""Compose-path canaries for explicit environment bindings (issue #965).

Compose reads ``${NAME}`` interpolation, and bare ``environment`` and
``build.args`` entries, from its own process environment before the bound
project ``.env``, and one invocation shares that environment across every
Compose file and service. These tests plant same-named canaries in APTL's
environment and show that none reaches a ``docker compose`` process, and that a
granted or startup-adapter value reaches only the service that declares it,
through that service's own env file.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import yaml
from raes.runtime_configuration import RuntimeConfiguration

from aptl.core.config import EnvironmentGrant
from aptl.core.deployment._compose_environment import (
    SOURCED_ENVIRONMENT_DIR,
    SOURCED_ENVIRONMENT_OVERRIDE,
    sourced_environment_file,
)
from aptl.core.deployment._compose_node_generation import (
    base_compose_file,
    render_realization_compose,
)
from aptl.core.deployment._compose_runtime_config import (
    _environment_config,
    compose_readback,
)
from aptl.core.deployment._environment_bindings import EnvironmentBindingError
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment.realization import (
    DeploymentImageRealization,
    DeploymentNodeRealization,
    DeploymentPersistentVolumeRealization,
    DeploymentPublishedPort,
    DeploymentRealizationSpec,
    DeploymentStatefulConsumer,
)
from aptl.core.deployment.runtime_materialization import (
    SHARED_DOCKER_PROFILE,
    effective_runtime_contract_issues,
)
from aptl.core.deployment.ssh_compose import SSHComposeBackend
from aptl.core.scenario_bundle import PackIdentity

_CANARY = "ambient-canary-value"
# Granted and adapter values are built at run time, so no password-shaped
# literal sits in the source for a secret scanner to flag.
_GRANTED = f"granted-{uuid.uuid4().hex[:12]}"
_ADAPTER = f"adapter-{uuid.uuid4().hex[:12]}"
# Values a single-quoted Compose env-file line cannot carry (#1256): a single
# quote ends the value early, and an unpaired final backslash escapes the
# closing quote.
_QUOTED = f"it's-{uuid.uuid4().hex[:12]}"
_BACKSLASHED = f"ends-with-{uuid.uuid4().hex[:12]}\\"
_PACK = PackIdentity("example-pack", "1.0.0", "sha256:" + "0" * 64)


def _service(name: str, *environment: dict[str, str]) -> DeploymentNodeRealization:
    return DeploymentNodeRealization(
        address=f"provision.node.{name}",
        name=name,
        service_name=name,
        container_name=f"aptl-{name}",
        networks=(),
        runtime=RuntimeConfiguration.model_validate({"environment": environment}),
    )


def _secret(name: str, classification: str = "operator_secret") -> dict[str, str]:
    return {"name": name, "value_classification": classification}


def _realization(*nodes, adapter_names=(), pack=_PACK) -> DeploymentRealizationSpec:
    images = tuple(
        DeploymentImageRealization(
            address=node.address,
            service_name=node.service_name,
            source_name="example/image",
            source_version="1",
            image_ref="example/image:1",
            mode="pull",
            policy_rule="test",
        )
        for node in nodes
    )
    plan = SimpleNamespace(
        environment_fixtures=tuple(SimpleNamespace(name=n) for n in adapter_names),
        environment_aliases=(),
    )
    return DeploymentRealizationSpec(
        profiles=(),
        nodes=nodes,
        networks=(),
        images=images,
        pack_identity=pack,
        startup_selection=SimpleNamespace(identity=pack, plan=plan, provider=None),
    )


def _grant(consumer: str, variable: str, source: str) -> EnvironmentGrant:
    return EnvironmentGrant(
        pack=_PACK.pack_id,
        consumer=consumer,
        variable=variable,
        source={"kind": "process-environment", "variable": source},
    )


def _compose_env(backend: DockerComposeBackend, monkeypatch) -> dict[str, str]:
    """Run one ``docker compose`` command and return the environment it got."""

    seen: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    backend._run(["docker", "compose", "-p", "aptl-test", "config"])
    environment = seen["env"]
    assert isinstance(environment, dict)
    return environment


def _delivered(
    backend: DockerComposeBackend, realization: DeploymentRealizationSpec, root: Path
) -> dict[str, str]:
    """Write the request's Compose env files; return each attached file's text."""

    override = backend._write_sourced_environment_override(realization, root)
    if override is None:
        return {}
    services = yaml.safe_load(override.read_text(encoding="utf-8"))["services"]
    return {
        service: "".join(
            Path(path).read_text(encoding="utf-8") for path in fields["env_file"]
        )
        for service, fields in services.items()
    }


def test_a_compose_command_never_inherits_scenario_or_host_secrets(
    tmp_path, monkeypatch
):
    """Only client coordinates and APTL's own settings reach Compose."""

    monkeypatch.setenv("GITHUB_TOKEN", _CANARY)
    monkeypatch.setenv("INDEXER_PASSWORD", _CANARY)
    client = {
        "DOCKER_HOST": "unix:///var/run/docker.sock",
        "APTL_HP_WAZUH_INDEXER_9200": "19200",
        "SSL_CERT_FILE": "/etc/ssl/corporate.pem",
        "COMPOSE_HTTP_TIMEOUT": "240",
        "BUILDKIT_PROGRESS": "plain",
        # Windows: where Docker Desktop installs the Compose CLI plugin.
        "PROGRAMFILES": r"C:\Program Files",
    }
    for name, value in client.items():
        monkeypatch.setenv(name, value)

    environment = _compose_env(DockerComposeBackend(tmp_path), monkeypatch)

    assert _CANARY not in environment.values()
    assert environment["PATH"] == os.environ["PATH"]
    assert {name: environment[name] for name in client} == client


@pytest.mark.parametrize("runner", ["_run_streaming", "_run_with_input"])
def test_every_compose_runner_uses_the_same_environment(tmp_path, monkeypatch, runner):
    monkeypatch.setenv("GITHUB_TOKEN", _CANARY)
    seen: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    backend = DockerComposeBackend(tmp_path)
    command = ["docker", "compose", "-p", "aptl-test", "config"]
    if runner == "_run_with_input":
        backend._run_with_input(command, "payload")
    else:
        backend._run_streaming(command)

    assert "GITHUB_TOKEN" not in seen["env"]


def test_other_docker_commands_keep_their_environment(tmp_path, monkeypatch):
    """A non-Compose Docker command interpolates nothing, so it is unchanged."""

    seen: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    DockerComposeBackend(tmp_path)._run(["docker", "inspect", "aptl-db"])

    assert "env" not in seen


def test_the_ssh_backend_keeps_its_remote_endpoint_for_compose(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", _CANARY)
    backend = SSHComposeBackend(tmp_path, host="example.test", user="aptl")

    environment = _compose_env(backend, monkeypatch)

    assert environment["DOCKER_HOST"] == "ssh://aptl@example.test"
    assert "GITHUB_TOKEN" not in environment


def test_a_granted_value_reaches_only_the_service_that_declares_it(
    tmp_path, monkeypatch
):
    """Wrong consumer: the grant's value is in db's env file and nowhere else."""

    monkeypatch.setenv("DB_PASSWORD", _CANARY)
    monkeypatch.setenv("LAB_DB_PASSWORD", _GRANTED)
    backend = DockerComposeBackend(
        tmp_path,
        environment_grants=(_grant("db", "DB_PASSWORD", "LAB_DB_PASSWORD"),),
    )
    realization = _realization(
        _service("db", _secret("DB_PASSWORD")),
        _service("worker", {"name": "WORKER_MODE", "value": "batch"}),
    )

    assert backend._environment_binding_preflight(realization, tmp_path) is None
    delivered = _delivered(backend, realization, tmp_path)
    environment = _compose_env(backend, monkeypatch)

    assert delivered == {"db": f"DB_PASSWORD='{_GRANTED}'\n"}
    assert "DB_PASSWORD" not in environment
    assert _GRANTED not in environment.values()
    env_file = tmp_path / sourced_environment_file("db")
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(env_file.parent.stat().st_mode) == 0o700
    override = (tmp_path / SOURCED_ENVIRONMENT_OVERRIDE).read_text(encoding="utf-8")
    assert _GRANTED not in override


def test_compose_binding_logs_name_each_source_never_a_value(
    tmp_path, monkeypatch, caplog
):
    (tmp_path / ".env").write_text(f"API_TOKEN={_ADAPTER}\n", encoding="utf-8")
    monkeypatch.setenv("LAB_DB_PASSWORD", _GRANTED)
    backend = DockerComposeBackend(
        tmp_path,
        environment_grants=(_grant("db", "DB_PASSWORD", "LAB_DB_PASSWORD"),),
    )
    realization = _realization(
        _service("db", _secret("DB_PASSWORD")),
        _service("worker", _secret("API_TOKEN", "secret_fixture")),
        adapter_names=("API_TOKEN",),
    )
    assert backend._environment_binding_preflight(realization, tmp_path) is None

    with caplog.at_level("INFO", logger="aptl"):
        _delivered(backend, realization, tmp_path)

    assert (
        "Compose service db environment: "
        "DB_PASSWORD from grant:process-environment:LAB_DB_PASSWORD"
    ) in caplog.text
    assert (
        "Compose service worker environment: "
        "API_TOKEN from startup-adapter:project-env-file:API_TOKEN"
    ) in caplog.text
    assert _GRANTED not in caplog.text
    assert _ADAPTER not in caplog.text


def test_two_services_get_their_own_value_for_one_name(tmp_path, monkeypatch):
    """One name, two sources: no shared interpolation scope joins them."""

    (tmp_path / ".env").write_text(f"API_TOKEN={_ADAPTER}\n", encoding="utf-8")
    monkeypatch.setenv("LAB_API_TOKEN", _GRANTED)
    backend = DockerComposeBackend(
        tmp_path,
        environment_grants=(_grant("db", "API_TOKEN", "LAB_API_TOKEN"),),
    )
    realization = _realization(
        _service("db", _secret("API_TOKEN")),
        _service("worker", _secret("API_TOKEN")),
        adapter_names=("API_TOKEN",),
    )

    assert backend._environment_binding_preflight(realization, tmp_path) is None

    assert _delivered(backend, realization, tmp_path) == {
        "db": f"API_TOKEN='{_GRANTED}'\n",
        "worker": f"API_TOKEN='{_ADAPTER}'\n",
    }


def test_a_declared_name_never_changes_the_compose_client_environment(
    tmp_path, monkeypatch
):
    """A scenario variable named like a client setting stays with its service."""

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.test:3128")
    monkeypatch.setenv("LAB_PROXY", _GRANTED)
    backend = DockerComposeBackend(
        tmp_path,
        environment_grants=(_grant("fetcher", "HTTPS_PROXY", "LAB_PROXY"),),
    )
    realization = _realization(_service("fetcher", _secret("HTTPS_PROXY")))

    assert backend._environment_binding_preflight(realization, tmp_path) is None
    delivered = _delivered(backend, realization, tmp_path)

    assert delivered == {"fetcher": f"HTTPS_PROXY='{_GRANTED}'\n"}
    environment = _compose_env(backend, monkeypatch)
    assert environment["HTTPS_PROXY"] == "http://proxy.example.test:3128"


def test_a_changed_source_reaches_the_env_file_on_the_next_start(tmp_path, monkeypatch):
    """Changed source: each start binds the value its source holds now."""

    backend = DockerComposeBackend(
        tmp_path,
        environment_grants=(_grant("db", "DB_PASSWORD", "LAB_DB_PASSWORD"),),
    )
    realization = _realization(_service("db", _secret("DB_PASSWORD")))
    seen = []
    values = [f"first-{uuid.uuid4().hex[:12]}", f"second-{uuid.uuid4().hex[:12]}"]
    for value in values:
        monkeypatch.setenv("LAB_DB_PASSWORD", value)
        assert backend._environment_binding_preflight(realization, tmp_path) is None
        seen.append(_delivered(backend, realization, tmp_path)["db"])

    assert seen == [f"DB_PASSWORD='{value}'\n" for value in values]


def test_a_later_request_never_reuses_an_earlier_granted_value(tmp_path, monkeypatch):
    """Run identity: a reused backend starts from nothing and removes old files."""

    monkeypatch.setenv("LAB_DB_PASSWORD", _GRANTED)
    backend = DockerComposeBackend(
        tmp_path,
        environment_grants=(_grant("db", "DB_PASSWORD", "LAB_DB_PASSWORD"),),
    )
    granted = _realization(_service("db", _secret("DB_PASSWORD")))
    assert backend._environment_binding_preflight(granted, tmp_path) is None
    assert _delivered(backend, granted, tmp_path)
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    assert backend._environment_binding_preflight(granted, tmp_path) is None

    assert _delivered(backend, granted, tmp_path) == {}
    assert os.listdir(tmp_path / SOURCED_ENVIRONMENT_DIR) == []


def test_an_adapter_value_comes_from_env_and_ambient_never_overrides_it(
    tmp_path, monkeypatch
):
    """The service gets the `.env` value; the ambient copy reaches nothing."""

    (tmp_path / ".env").write_text(f"INDEXER_PASSWORD={_ADAPTER}\n", encoding="utf-8")
    monkeypatch.setenv("INDEXER_PASSWORD", _CANARY)
    backend = DockerComposeBackend(tmp_path)
    realization = _realization(
        _service("wazuh-manager", _secret("INDEXER_PASSWORD", "secret_fixture")),
        adapter_names=("INDEXER_PASSWORD",),
    )

    assert backend._environment_binding_preflight(realization, tmp_path) is None

    delivered = _delivered(backend, realization, tmp_path)
    assert delivered == {"wazuh-manager": f"INDEXER_PASSWORD='{_ADAPTER}'\n"}
    assert "INDEXER_PASSWORD" not in _compose_env(backend, monkeypatch)


@pytest.mark.parametrize(
    ("realization", "grants", "env", "named"),
    [
        pytest.param(
            _realization(_service("worker", _secret("API_TOKEN"))),
            (),
            "",
            "node worker: API_TOKEN has no environment grant for pack example-pack",
            id="missing-binding",
        ),
        pytest.param(
            _realization(
                _service("db", _secret("API_TOKEN")),
                _service("worker", _secret("API_TOKEN")),
            ),
            (_grant("db", "API_TOKEN", "LAB_API_TOKEN"),),
            "",
            "node worker: API_TOKEN has no environment grant",
            id="wrong-consumer",
        ),
        pytest.param(
            _realization(
                _service("worker", _secret("API_TOKEN")),
                pack=PackIdentity("other-pack", "1.0.0", "sha256:" + "1" * 64),
            ),
            (_grant("worker", "API_TOKEN", "LAB_API_TOKEN"),),
            "",
            "API_TOKEN has no environment grant for pack other-pack",
            id="pack-identity",
        ),
        pytest.param(
            _realization(
                _service("worker", _secret("API_TOKEN", "secret_fixture")),
                adapter_names=("API_TOKEN",),
            ),
            (),
            "",
            "API_TOKEN source startup-adapter:project-env-file:API_TOKEN has no value",
            id="adapter-value-missing",
        ),
        pytest.param(
            _realization(
                _service("worker", _secret("API_TOKEN", "secret_fixture")),
                adapter_names=("API_TOKEN",),
            ),
            (),
            f'API_TOKEN="{_QUOTED}"\n',
            "a Compose env file cannot carry API_TOKEN exactly: "
            "the value contains a single quote",
            id="value-with-a-single-quote",
        ),
        pytest.param(
            _realization(
                _service("worker", _secret("API_TOKEN", "secret_fixture")),
                adapter_names=("API_TOKEN",),
            ),
            (),
            f"API_TOKEN={_BACKSLASHED}\n",
            "a Compose env file cannot carry API_TOKEN exactly: "
            "the value ends in an odd number of backslashes",
            id="value-ending-in-a-backslash",
        ),
    ],
)
def test_a_compose_service_without_its_binding_stops_before_mutation(
    tmp_path, monkeypatch, realization, grants, env, named
):
    (tmp_path / ".env").write_text(env, encoding="utf-8")
    monkeypatch.setenv("API_TOKEN", _CANARY)
    monkeypatch.setenv("LAB_API_TOKEN", _GRANTED)
    backend = DockerComposeBackend(tmp_path, environment_grants=grants)
    commands: list[list[str]] = []
    monkeypatch.setattr(backend, "_run", lambda cmd, **_: commands.append(cmd))

    result = backend.realize(realization, scenario_root=tmp_path)

    assert result.success is False
    assert named in result.error
    for value in (_CANARY, _GRANTED, _ADAPTER, _QUOTED, _BACKSLASHED):
        assert value not in result.error
    assert commands == []
    assert not (tmp_path / SOURCED_ENVIRONMENT_DIR).exists()


def test_an_in_tree_static_compose_file_keeps_its_own_references(tmp_path):
    """APTL binds only the Compose model it generates from the realization."""

    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    backend = DockerComposeBackend(tmp_path)
    realization = _realization(_service("worker", _secret("API_TOKEN")))

    assert backend._environment_binding_preflight(realization, tmp_path) is None
    assert backend._write_sourced_environment_override(realization, tmp_path) is None


def test_compose_files_for_an_unchecked_request_refuse_a_sourced_service(tmp_path):
    """Without the preflight, a value-less secret is refused, not omitted."""

    backend = DockerComposeBackend(tmp_path)
    realization = _realization(_service("worker", _secret("API_TOKEN")))

    with pytest.raises(EnvironmentBindingError, match="were not checked"):
        backend._write_sourced_environment_override(realization, tmp_path)


def test_a_symlinked_service_env_file_is_refused_and_not_followed(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("LAB_DB_PASSWORD", _GRANTED)
    backend = DockerComposeBackend(
        tmp_path,
        environment_grants=(_grant("db", "DB_PASSWORD", "LAB_DB_PASSWORD"),),
    )
    realization = _realization(_service("db", _secret("DB_PASSWORD")))
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched\n", encoding="utf-8")
    env_file = tmp_path / sourced_environment_file("db")
    env_file.parent.mkdir(parents=True)
    env_file.symlink_to(outside)
    assert backend._environment_binding_preflight(realization, tmp_path) is None

    with pytest.raises(EnvironmentBindingError, match=r"\(symlink\)"):
        backend._write_sourced_environment_override(realization, tmp_path)

    assert outside.read_text(encoding="utf-8") == "untouched\n"


def test_the_generated_compose_files_attach_each_service_env_file(
    tmp_path, monkeypatch
):
    """The override joins the file set Compose is run with."""

    monkeypatch.setenv("LAB_DB_PASSWORD", _GRANTED)
    backend = DockerComposeBackend(
        tmp_path,
        environment_grants=(_grant("db", "DB_PASSWORD", "LAB_DB_PASSWORD"),),
    )
    realization = _realization(_service("db", _secret("DB_PASSWORD")))
    assert backend._environment_binding_preflight(realization, tmp_path) is None

    files = backend._realization_compose_files(None, realization, tmp_path)

    assert files is not None
    assert tmp_path / SOURCED_ENVIRONMENT_OVERRIDE in files
    base = yaml.safe_load(files[0].read_text(encoding="utf-8"))
    assert "DB_PASSWORD" not in base["services"]["db"].get("environment", {})


def test_the_environment_map_holds_authored_values_only():
    """A sourced name has no `${NAME}` hole; the file writer escapes `$`."""

    runtime = RuntimeConfiguration.model_validate(
        {
            "environment": [
                {
                    "name": "PLANTED",
                    "value": "p@ss$HOME",
                    "value_classification": "secret_fixture",
                },
                {"name": "OPERATOR", "value_classification": "operator_secret"},
                {"name": "OPTIONAL"},
            ]
        }
    )

    assert _environment_config(runtime) == {"PLANTED": "p@ss$HOME", "OPTIONAL": ""}


# Pack-authored text that names values Compose could otherwise fill: the Wazuh
# and Grafana credentials in `.env`, the client's kept proxy setting, an APTL_*
# setting, and an unkept name with a default. `"$@"` is the catalog's
# container-shell pass-through, which must reach the container as written.
_NAMED_VARIABLES = (
    "echo ${INDEXER_PASSWORD} ${GRAFANA_ADMIN_PASSWORD} ${HTTPS_PROXY} "
    "${APTL_API_TOKEN} ${GITHUB_TOKEN:-unset}"
)
_PASS_THROUGH = ["/bin/sh", "-ec", 'exec "$@"', "--"]
_AUTHORED_VALUE = "p@ss$HOME"
_MOUNT_TARGET = "/run/${APTL_API_TOKEN}"
_VOLUME_TARGET = "/var/lib/${INDEXER_PASSWORD}"


def _authored_realization(
    host_ip: str | None = "${bind_ip}",
) -> DeploymentRealizationSpec:
    """One generated service whose authored fields name Compose variables."""

    runtime = RuntimeConfiguration.model_validate(
        {
            "container": {
                "command": ["sh", "-c", _NAMED_VARIABLES],
                "entrypoint": _PASS_THROUGH,
            },
            "environment": [{"name": "PLANTED", "value": _AUTHORED_VALUE}],
            "mounts": [{"source_kind": "tmpfs", "target": _MOUNT_TARGET}],
        }
    )
    ports = () if host_ip is None else (DeploymentPublishedPort(80, host_ip=host_ip),)
    node = replace(_service("app"), runtime=runtime, published_ports=ports)
    consumer = DeploymentStatefulConsumer(
        node.address, "app", "app", _VOLUME_TARGET, "read_write"
    )
    volume = DeploymentPersistentVolumeRealization(
        "provision.volume.data", "data", "ephemeral", "read_write_once", (consumer,)
    )
    return replace(_realization(node), persistent_volumes=(volume,))


def _interpolates_nothing(text: str) -> bool:
    """Compose reads `$$` as one literal `$`, so even runs leave nothing to fill."""

    return all(len(run) % 2 == 0 for run in re.findall(r"\$+", text))


def _generated_files(backend, realization, root: Path) -> tuple[Path, ...]:
    """Write the generated base and every override APTL adds to it."""

    assert backend._environment_binding_preflight(realization, root) is None
    base = base_compose_file(realization, root)
    files = backend._realization_compose_files((base,), realization, root)
    assert files is not None
    return files


def test_every_generated_compose_file_writes_authored_text_as_a_literal(tmp_path):
    """Command, entrypoint, value, mount paths and host address: no `$` is live."""

    realization = _authored_realization()
    files = _generated_files(DockerComposeBackend(tmp_path), realization, tmp_path)
    text = {path.name: path.read_text(encoding="utf-8") for path in files}

    for name in ("compose-base.yml", "compose.ports.yml", "compose.stateful.yml"):
        assert _interpolates_nothing(text[name])
    assert "$${INDEXER_PASSWORD}" in text["compose.stateful.yml"]
    assert "$${bind_ip}" in text["compose.ports.yml"]
    base = yaml.safe_load(text["compose-base.yml"])
    assert compose_readback(base) == render_realization_compose(realization)


def test_the_generated_model_check_reads_escaped_text_back_as_values(
    tmp_path, monkeypatch
):
    """The uninterpolated readback keeps `$$` and still matches the runtime."""

    realization = _realization(*_authored_realization().nodes)
    backend = DockerComposeBackend(tmp_path)
    base = base_compose_file(realization, tmp_path)
    readback = json.dumps(yaml.safe_load(base.read_text(encoding="utf-8")))
    monkeypatch.setattr(
        backend,
        "_run",
        lambda cmd, **_: subprocess.CompletedProcess(cmd, 0, readback, ""),
    )

    command = ["docker", "compose", "config"]
    assert backend._effective_compose_model_error(command, realization, tmp_path) is None


def _require_compose_cli() -> None:
    """Skip unless the Compose CLI runs; ``config`` needs no Docker daemon."""

    if shutil.which("docker") is None or (
        subprocess.run(["docker", "compose", "version"], capture_output=True).returncode
    ):
        pytest.skip("requires the Docker Compose CLI")


def test_compose_never_fills_a_variable_that_pack_text_names(tmp_path, monkeypatch):
    """Canary through Compose: no `.env` or client value reaches authored text.

    Before #965, an authored ``${INDEXER_PASSWORD}`` in a command was filled
    from `.env` with no grant, and ``${HTTPS_PROXY}`` from the kept client
    proxy setting, which can carry credentials. ``docker compose config``
    interpolates the model as ``up`` does, without a daemon;
    :func:`compose_readback` reads any ``$$`` it prints as the ``$`` the
    container receives.
    """

    _require_compose_cli()
    wazuh = f"wazuh-{uuid.uuid4().hex[:12]}"
    grafana = f"grafana-{uuid.uuid4().hex[:12]}"
    (tmp_path / ".env").write_text(
        f"INDEXER_PASSWORD={wazuh}\nGRAFANA_ADMIN_PASSWORD={grafana}\n"
        "bind_ip=0.0.0.0\n",
        encoding="utf-8",
    )
    proxy_host = f"proxy-{uuid.uuid4().hex[:12]}.example.test"
    monkeypatch.setenv("HTTPS_PROXY", f"http://{proxy_host}:3128")
    monkeypatch.setenv("APTL_API_TOKEN", _GRANTED)
    monkeypatch.setenv("GITHUB_TOKEN", _CANARY)
    backend = DockerComposeBackend(tmp_path)

    def config(realization: DeploymentRealizationSpec) -> list[str]:
        files = _generated_files(backend, realization, tmp_path)
        return backend._build_command(
            "config", [], compose_files=files, scenario_root=tmp_path
        )

    realization = _authored_realization(host_ip=None)
    result = backend._run([*config(realization), "--format", "json"])

    assert result.returncode == 0, result.stderr
    for value in (wazuh, grafana, proxy_host, _GRANTED, _CANARY):
        assert value not in result.stdout
    app = compose_readback(json.loads(result.stdout)["services"]["app"])
    assert app["command"] == ["sh", "-c", _NAMED_VARIABLES]
    assert app["entrypoint"] == _PASS_THROUGH
    assert app["environment"]["PLANTED"] == _AUTHORED_VALUE
    assert {mount["target"] for mount in app["volumes"]} == {
        _MOUNT_TARGET,
        _VOLUME_TARGET,
    }
    # The pre-start model check accepts the escaped model Compose reads back.
    command = config(realization)
    assert backend._effective_compose_model_error(command, realization, tmp_path) is None
    # A host address naming `.env`'s bind_ip never binds all interfaces.
    published = backend._run([*config(_authored_realization()), "--format", "json"])
    assert "0.0.0.0" not in published.stdout


def test_compose_gives_a_granted_value_to_its_service_only(tmp_path, monkeypatch):
    """Readback through Compose itself: another service's `${NAME}` stays empty.

    ``docker compose config`` resolves each service's environment without a
    daemon. ``other`` stands for any Compose file that interpolates the same
    name, such as APTL's own observability services.
    """

    _require_compose_cli()
    monkeypatch.setenv("DB_PASSWORD", _CANARY)
    monkeypatch.setenv("LAB_DB_PASSWORD", _GRANTED)
    backend = DockerComposeBackend(
        tmp_path,
        environment_grants=(_grant("db", "DB_PASSWORD", "LAB_DB_PASSWORD"),),
    )
    realization = _realization(_service("db", _secret("DB_PASSWORD")))
    assert backend._environment_binding_preflight(realization, tmp_path) is None
    files = backend._realization_compose_files(None, realization, tmp_path)
    other = tmp_path / "other.yml"
    other.write_text(
        "services:\n  other:\n    image: example/other:1\n"
        "    environment:\n      DB_PASSWORD: ${DB_PASSWORD:-}\n",
        encoding="utf-8",
    )
    command = ["docker", "compose", "-p", "aptl-env-readback"]
    for path in (*files, other):
        command += ["-f", str(path)]

    result = backend._run([*command, "config", "--format", "json"])

    assert result.returncode == 0, result.stderr
    services = json.loads(result.stdout)["services"]
    assert services["db"]["environment"]["DB_PASSWORD"] == _GRANTED
    assert services["other"]["environment"]["DB_PASSWORD"] == ""


@pytest.fixture(scope="module")
def techvault(tmp_path_factory):
    """The released TechVault realization and its own startup adapter plan."""

    from tests.test_env_pack_realization import _pack_root, _realize_pack

    from aptl.backends.scenario_startup import ScenarioStartupSelection
    from aptl.core.scenario_bundle import env_pack_bundle
    from aptl_techvault.startup import TechVaultStartupProvider

    root = tmp_path_factory.mktemp("techvault-bindings")
    realization = _realize_pack(root / "plan")
    bundle = env_pack_bundle(
        root / "bundle", identity="techvault", source_pack=_pack_root()
    )
    selection = ScenarioStartupSelection(
        identity=realization.pack_identity,
        provider=TechVaultStartupProvider,
        plan=TechVaultStartupProvider.resolve(bundle),
    )
    return realization.deployment_spec(
        sorted(realization.profiles), startup_selection=selection
    )


_TECHVAULT_WAZUH = ("INDEXER_USERNAME", "INDEXER_PASSWORD", "API_USERNAME")
_TECHVAULT_SOURCED = {
    "wazuh-manager": {*_TECHVAULT_WAZUH, "API_PASSWORD"},
    "wazuh-dashboard": {
        *_TECHVAULT_WAZUH,
        "API_PASSWORD",
        "DASHBOARD_USERNAME",
        "DASHBOARD_PASSWORD",
    },
    "misp": {"ADMIN_KEY"},
}


def test_the_released_techvault_pack_binds_from_its_own_adapter(
    techvault, tmp_path, monkeypatch
):
    """Every value-less Wazuh and MISP variable has an adapter source."""

    names = sorted(set().union(*_TECHVAULT_SOURCED.values()))
    (tmp_path / ".env").write_text(
        "".join(f"{name}={_ADAPTER}\n" for name in names), encoding="utf-8"
    )
    for name in names:
        monkeypatch.setenv(name, _CANARY)
    backend = DockerComposeBackend(tmp_path)

    assert backend._environment_binding_preflight(techvault, tmp_path) is None

    delivered = _delivered(backend, techvault, tmp_path)
    assert {
        service: {line.split("=", 1)[0] for line in text.splitlines()}
        for service, text in delivered.items()
    } == _TECHVAULT_SOURCED
    assert _CANARY not in "".join(delivered.values())
    assert _CANARY not in _compose_env(backend, monkeypatch).values()


def test_the_released_techvault_model_is_escaped_and_passes_the_model_check(
    techvault, tmp_path
):
    """The catalog's misp-redis `"$@"` pass-through is written as `"$$@"`."""

    text = base_compose_file(techvault, tmp_path).read_text(encoding="utf-8")
    model = yaml.safe_load(text)

    entrypoint = model["services"]["misp-redis"]["entrypoint"]
    assert entrypoint[2].endswith('exec docker-entrypoint.sh "$$@"')
    assert _interpolates_nothing(text)
    readback = compose_readback(model)
    issues = effective_runtime_contract_issues(
        readback, techvault, profile=SHARED_DOCKER_PROFILE
    )
    assert issues == ()


def test_the_released_techvault_pack_without_its_env_stops_before_mutation(
    techvault, tmp_path
):
    backend = DockerComposeBackend(tmp_path)
    backend._run = MagicMock()

    result = backend._environment_binding_preflight(techvault, tmp_path)

    assert result is not None
    assert "has no value" in result.error
    backend._run.assert_not_called()
