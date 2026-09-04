"""Issue #913: consume Shuffle's released contract without post-start repair."""

from __future__ import annotations

import os
import subprocess
from importlib.metadata import version
from pathlib import Path

from raes.parser import parse_sdl_file

from tests.helpers import techvault_scenario_path
from tests.test_env_pack_realization import _realize_pack


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_ENVIRONMENT = {
    "SHUFFLE_APP_SDK_TIMEOUT": ("120", "plain"),
    "SHUFFLE_DEFAULT_APIKEY": (
        "31a211c4-ea5c-4a49-b022-5e2434e758a7",
        "secret_fixture",
    ),
    "SHUFFLE_DEFAULT_PASSWORD": ("ShuffleAdmin2024!", "secret_fixture"),
    "SHUFFLE_DEFAULT_USERNAME": ("admin", "plain"),
    "SHUFFLE_OPENSEARCH_PASSWORD": ("StrongPassword123!", "secret_fixture"),
    "SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY": ("true", "plain"),
    "SHUFFLE_OPENSEARCH_URL": ("https://shuffle-opensearch:9200", "plain"),
    "SHUFFLE_OPENSEARCH_USERNAME": ("admin", "plain"),
}


def _enum_value(value: object) -> object:
    return getattr(value, "value", value)


def test_released_pack_supplies_the_complete_shuffle_contract(tmp_path: Path) -> None:
    assert version("raes-env-packs") == "4.0.2"
    scenario = parse_sdl_file(techvault_scenario_path(tmp_path))
    backend = scenario.nodes["shuffle-backend"].runtime
    opensearch = scenario.nodes["shuffle-opensearch"].runtime

    environment = {
        item.name: (item.value, _enum_value(item.value_classification))
        for item in backend.environment
    }
    assert environment == EXPECTED_ENVIRONMENT

    listener = backend.service_listeners[0]
    assert listener.service == "shuffle-api"
    assert listener.readiness.probe == "shuffle-authenticated-datastore-operation"
    assert "authenticated" in listener.readiness.criteria.lower()

    application = backend.platform_applications[0]
    binding = application.upstream_bindings[0]
    assert _enum_value(application.capabilities[0].kind) == "workflow_automation"
    assert _enum_value(binding.role) == "index_backend"
    assert binding.target_node_ref == "shuffle-opensearch"
    assert binding.target_service_ref == "opensearch-rest"

    datastore = opensearch.datastore_services[0]
    endpoint = datastore.nodes[0].endpoints[0]
    assert datastore.service == "opensearch-rest"
    assert (endpoint.protocol, endpoint.address, endpoint.port) == (
        "https",
        "shuffle-opensearch",
        9200,
    )
    assert _enum_value(datastore.transport_security.mode) == "tls"
    assert datastore.transport_security.client_verification is False
    assert environment["SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY"] == ("true", "plain")

    assert scenario.persistent_volumes["shuffle_data"].consumers[0].node == (
        "shuffle-backend"
    )
    assert scenario.persistent_volumes[
        "shuffle_opensearch_data"
    ].consumers[0].node == "shuffle-opensearch"


def test_generated_compose_uses_only_the_admitted_shuffle_runtime(
    tmp_path: Path,
) -> None:
    from aptl.core.deployment._compose_node_generation import render_realization_compose

    realization = _realize_pack(tmp_path)
    spec = realization.deployment_spec(sorted(realization.profiles))
    document = render_realization_compose(spec)
    backend = document["services"]["shuffle-backend"]

    assert backend["profiles"] == ["soc"]
    assert backend["environment"] == {
        name: value for name, (value, _classification) in EXPECTED_ENVIRONMENT.items()
    }
    assert backend["depends_on"] == ["shuffle-opensearch"]
    assert "/var/run/docker.sock" not in repr(backend)

    volumes = {volume.name: volume for volume in spec.persistent_volumes}
    assert volumes["shuffle_data"].consumers[0].details() == {
        "target_address": "provision.node.shuffle-backend",
        "node_name": "shuffle-backend",
        "service_name": "shuffle-backend",
        "mount_destination": "/shuffle-database",
        "access_mode": "read_write",
        "selected_outputs": [],
    }
    assert volumes["shuffle_opensearch_data"].consumers[0].mount_destination == (
        "/usr/share/opensearch/data"
    )


def test_soar_fixups_wait_for_shuffle_without_recreating_backend(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker_log = tmp_path / "docker.log"
    docker = fake_bin / "docker"
    docker.write_text(
        """#!/bin/sh
printf '%s\\n' "$*" >> "$APTL_TEST_DOCKER_LOG"
if [ "$1" = inspect ] && [ "$2" = aptl-shuffle-backend ]; then
    exit 0
fi
if [ "$1" = inspect ]; then
    exit 1
fi
if [ "$1" = exec ] && [ "$2" = aptl-shuffle-backend ]; then
    printf '{"name":"Shuffle"}\\n'
fi
exit 0
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "APTL_PROJECT_DIR": str(PROJECT_ROOT),
        "APTL_TEST_DOCKER_LOG": str(docker_log),
    }

    result = subprocess.run(
        [PROJECT_ROOT / "scripts" / "envpack-soar-fixups.sh"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )

    assert result.returncode == 0, result.stderr
    operations = docker_log.read_text(encoding="utf-8").splitlines()
    assert any(
        line.startswith("exec aptl-shuffle-backend ") and "getenvironments" in line
        for line in operations
    )
    assert not any(
        line.startswith("rm -f aptl-shuffle-backend")
        or (line.startswith("run ") and "--name aptl-shuffle-backend" in line)
        or line.startswith("restart aptl-shuffle-backend")
        or line.startswith("restart aptl-shuffle-frontend")
        for line in operations
    )


def test_soar_fixups_fail_when_shuffle_never_reaches_readiness(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker_log = tmp_path / "docker.log"
    docker = fake_bin / "docker"
    docker.write_text(
        """#!/bin/sh
printf '%s\\n' "$*" >> "$APTL_TEST_DOCKER_LOG"
if [ "$1" = inspect ] && [ "$2" = aptl-shuffle-backend ]; then
    exit 0
fi
if [ "$1" = inspect ]; then
    exit 1
fi
exit 0
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    sleep = fake_bin / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    sleep.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "APTL_PROJECT_DIR": str(PROJECT_ROOT),
        "APTL_TEST_DOCKER_LOG": str(docker_log),
    }

    result = subprocess.run(
        [PROJECT_ROOT / "scripts" / "envpack-soar-fixups.sh"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )

    assert result.returncode == 1
    assert "ERROR: shuffle-backend not serving" in result.stdout
    operations = docker_log.read_text(encoding="utf-8").splitlines()
    assert sum("getenvironments" in line for line in operations) == 30
    assert not any(
        line.startswith("rm -f aptl-shuffle-backend")
        or (line.startswith("run ") and "--name aptl-shuffle-backend" in line)
        for line in operations
    )
