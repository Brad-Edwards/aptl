"""Issue #913: consume Shuffle's released contract without post-start repair."""

from __future__ import annotations

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


def test_released_pack_supplies_shuffle_semantics_and_leaves_mechanics_open(
    tmp_path: Path,
) -> None:
    assert version("raes-env-packs") == "6.1.0"
    scenario = parse_sdl_file(techvault_scenario_path(tmp_path))
    backend = scenario.nodes["shuffle-backend"].runtime
    opensearch = scenario.nodes["shuffle-opensearch"].runtime

    environment = {
        item.name: (item.value, _enum_value(item.value_classification))
        for item in backend.environment
    }
    assert environment == {}
    assert _enum_value(scenario.realization.default) == "open"

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

    assert scenario.persistent_volumes["shuffle_data"].consumers[0].node == (
        "shuffle-backend"
    )
    assert (
        scenario.persistent_volumes["shuffle_opensearch_data"].consumers[0].node
        == "shuffle-opensearch"
    )


def test_generated_compose_uses_only_the_admitted_shuffle_runtime(
    tmp_path: Path,
) -> None:
    from aptl.core.deployment._compose_node_generation import render_realization_compose

    realization = _realize_pack(tmp_path)
    # The pinned pack now admits the Orborus authority alongside Shuffle.
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
        "delivery_mode": "mount",
        "selected_outputs": [],
    }
    assert volumes["shuffle_opensearch_data"].consumers[0].mount_destination == (
        "/usr/share/opensearch/data"
    )


def test_release_manual_has_executable_reverse_negative_harness() -> None:
    manual = (PROJECT_ROOT / "docs" / "testing" / "smoke-test-plan.md").read_text(
        encoding="utf-8"
    )

    reverse_section = manual.split("### QA-MCP-REVERSE:", 1)[1].split(
        "### QA-ARCHIVE:", 1
    )[0]
    assert "aptl.validation.mcp_protocol" in reverse_section
    assert '"mcp/mcp-reverse/build/index.js"' in reverse_section
    assert '"reverse_run_command"' in reverse_section
    assert 'payload.get("success") is not False' in reverse_section
    assert '"outcome": "expected-unavailable"' in reverse_section


def test_release_manual_requires_valid_browser_trust_for_soc_uis() -> None:
    """The hands-on UI path must be executable without TLS bypasses."""

    manual = (PROJECT_ROOT / "docs" / "testing" / "smoke-test-plan.md").read_text(
        encoding="utf-8"
    )

    assert "config/wazuh_indexer_ssl_certs/root-ca.pem" in manual
    assert "config/soc_certs/lab-ca.pem" in manual
    assert "https://wazuh.dashboard:<reported-host-port>" in manual
    assert "443` is only the default" in manual
    assert "aptl lab status --json --output qa-start-status.json" in manual
    assert "certificate warning" in manual
    assert "aptl container shell aptl-suricata" in manual
    assert "does not claim passive visibility" in manual
