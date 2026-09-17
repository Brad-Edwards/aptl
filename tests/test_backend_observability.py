"""Backend apparatus must not depend on, or silently extend, scenario topology."""

from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.host_ports import published_port_specs


_ROOT = Path(__file__).resolve().parents[1]
_SERVICES = {"aptl-otel-collector", "aptl-tempo", "aptl-grafana-otel"}


@pytest.fixture
def engine(tmp_path, monkeypatch):
    root = tmp_path / "engine"
    root.mkdir()
    shutil.copytree(_ROOT / "config" / "otel", root / "config" / "otel")
    asset = _ROOT / "docker-compose.observability.yml"
    if asset.exists():
        shutil.copyfile(asset, root / asset.name)
    monkeypatch.setenv("GRAFANA_ADMIN_PASSWORD", "local-fixture-password-992")
    return root


def test_generated_compose_includes_isolated_backend_apparatus(engine, tmp_path):
    scenario = tmp_path / "pack"
    scenario.mkdir()
    backend = DockerComposeBackend(engine)
    backend._docker_daemon_id = "test-daemon"
    spec = DeploymentRealizationSpec(profiles=("otel",), nodes=(), networks=())
    files = backend._realization_compose_files(None, spec, scenario, engine)
    assert files, "even an empty pack needs backend observability"
    documents = [yaml.safe_load(path.read_text()) for path in files]
    services = {
        key: value
        for doc in documents
        for key, value in doc.get("services", {}).items()
    }
    assert set(services) == _SERVICES
    for service in services.values():
        assert set(service["networks"]) == {"aptl-observability"}
        assert all(port.startswith("127.0.0.1:") for port in service.get("ports", []))
        for mount in service.get("volumes", []):
            if mount["type"] == "bind":
                assert Path(mount["source"]).is_relative_to(engine)
                assert mount["read_only"] is True
    assert not list(scenario.iterdir()), "apparatus must not write into the pack"


@pytest.mark.parametrize(
    "section,name,definition",
    [
        ("services", "aptl-tempo", {"image": "busybox"}),
        ("services", "other", {"image": "busybox", "container_name": "aptl-tempo"}),
        ("networks", "aptl-observability", {}),
        ("volumes", "tempo_data", {}),
    ],
)
def test_reserved_ownership_collision_rejects_before_backend_mutation(
    engine, tmp_path, monkeypatch, section, name, definition
):
    scenario = tmp_path / "pack"
    scenario.mkdir()
    (scenario / "docker-compose.yml").write_text(
        yaml.safe_dump({section: {name: definition}})
    )
    backend = DockerComposeBackend(engine)
    backend._docker_daemon_id = "test-daemon"
    monkeypatch.setattr(
        backend, "_run", lambda *args, **kwargs: pytest.fail("mutated colliding world")
    )
    result = backend.realize(
        DeploymentRealizationSpec(profiles=("otel",), nodes=(), networks=()),
        scenario_root=scenario,
    )
    assert not result.success
    assert "observability-ownership-conflict" in result.error


@pytest.mark.parametrize("password", [None, "", "CHANGE_ME"])
def test_missing_or_placeholder_operator_credential_rejects_before_mutation(
    engine, tmp_path, monkeypatch, password
):
    if password is None:
        monkeypatch.delenv("GRAFANA_ADMIN_PASSWORD", raising=False)
    else:
        monkeypatch.setenv("GRAFANA_ADMIN_PASSWORD", password)
    scenario = tmp_path / "pack"
    scenario.mkdir()
    backend = DockerComposeBackend(engine)
    monkeypatch.setattr(
        backend,
        "_run",
        lambda *args, **kwargs: pytest.fail("started without credentials"),
    )
    result = backend.realize(
        DeploymentRealizationSpec(profiles=("otel",), nodes=(), networks=()),
        scenario_root=scenario,
    )
    assert not result.success
    assert "observability-credential-unavailable" in result.error


def test_port_resolver_sees_apparatus_without_scenario_compose(engine):
    specs = published_port_specs(engine, {"otel"})
    assert {spec.service for spec in specs} == _SERVICES


def test_apparatus_asset_is_part_of_distribution():
    from aptl._asset_manifest import ASSET_ROOTS

    assert "docker-compose.observability.yml" in ASSET_ROOTS


def test_static_scenario_compose_does_not_own_apparatus():
    model = yaml.safe_load((_ROOT / "docker-compose.yml").read_text())
    assert not (_SERVICES & model["services"].keys())


def test_collector_has_no_payload_bearing_debug_sink():
    model = yaml.safe_load(
        (_ROOT / "config/otel/otel-collector-config.yaml").read_text()
    )
    assert "debug" not in model["exporters"]
    assert model["service"]["pipelines"]["traces"]["exporters"] == ["otlp/tempo"]


def test_direct_static_start_includes_backend_file(engine, tmp_path, monkeypatch):
    scenario = tmp_path / "pack"
    scenario.mkdir()
    (scenario / "docker-compose.yml").write_text("services: {}\n")
    commands = []
    backend = DockerComposeBackend(engine)
    backend._docker_daemon_id = "test-daemon"

    def run(command, **kwargs):
        commands.append(command)
        if command[:3] in (
            ["docker", "network", "inspect"],
            ["docker", "volume", "inspect"],
        ):
            return subprocess.CompletedProcess(command, 1, "", "missing")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(backend, "_run", run)
    result = backend.start(["otel"], build=False, scenario_root=scenario)
    assert result.success
    up = next(command for command in commands if "up" in command)
    documents = [
        yaml.safe_load(Path(up[i + 1]).read_text())
        for i, value in enumerate(up)
        if value == "-f"
    ]
    assert _SERVICES <= {name for doc in documents for name in doc.get("services", {})}


def test_image_free_path_starts_apparatus_before_materialization(
    engine, tmp_path, monkeypatch
):
    from aptl.core.deployment import _compose_realization
    from aptl.core.deployment.realization import DeploymentNodeRealization

    scenario = tmp_path / "pack"
    scenario.mkdir()
    backend = DockerComposeBackend(engine)
    backend._docker_daemon_id = "test-daemon"
    started = []

    def run(command, **kwargs):
        if command[:3] in (
            ["docker", "network", "inspect"],
            ["docker", "volume", "inspect"],
        ):
            return subprocess.CompletedProcess(command, 1, "", "missing")
        if "up" in command:
            files = [
                Path(command[i + 1]) for i, arg in enumerate(command) if arg == "-f"
            ]
            started.extend(
                name
                for path in files
                for name in yaml.safe_load(path.read_text())["services"]
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    def materialize(*args, **kwargs):
        assert set(started) == _SERVICES
        return None

    monkeypatch.setattr(backend, "_run", run)
    monkeypatch.setattr(_compose_realization, "_realize_node_subset", materialize)
    node = DeploymentNodeRealization(
        address="provision.node.host",
        name="host",
        service_name=None,
        container_name="aptl-host",
        networks=(),
    )
    result = backend.realize(
        DeploymentRealizationSpec(profiles=("otel",), nodes=(node,), networks=()),
        scenario_root=scenario,
    )
    assert result.success


@pytest.mark.parametrize(
    "kind,name",
    [
        ("container", "aptl-tempo"),
        ("volume", "tempo_data"),
        ("network", "aptl-observability"),
    ],
)
def test_foreign_native_resource_is_never_adopted(
    engine, tmp_path, monkeypatch, kind, name
):
    import json

    scenario = tmp_path / "pack"
    scenario.mkdir()
    backend = DockerComposeBackend(engine)
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    backend._docker_daemon_id = "test-daemon"
    name = (
        ownership.container_name(name)
        if kind == "container"
        else f"{ownership.project_name}_{name}"
    )

    def run(command, **kwargs):
        if "up" in command:
            pytest.fail("started before rejecting foreign resource")
        output = ""
        if command[:3] == ["docker", kind, "ls"]:
            output = name + "\n"
        elif command[:3] == ["docker", "inspect", "--type"]:
            output = json.dumps(
                [
                    {
                        "Name": name,
                        "Labels": {"com.docker.compose.project": "foreign"},
                        "Config": {"Labels": {"com.docker.compose.project": "foreign"}},
                    }
                ]
            )
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(backend, "_run", run)
    result = backend.realize(
        DeploymentRealizationSpec(profiles=("otel",), nodes=(), networks=()),
        scenario_root=scenario,
    )
    assert not result.success
    assert "observability-ownership-conflict" in result.error
