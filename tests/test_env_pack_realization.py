"""Issue #875: the TechVault env-pack interprets into a clean APTL realization.

This is the integration guard for the realization engine that consumes a pack
with no ``docker-compose.yml``: profile membership comes from the APTL component
grouping, node service identity is derived from the node, node-to-node
dependencies resolve against realized services, and component builds resolve from
the engine checkout (``component_root``), not the bundle. A regression in any of
those re-introduces provisioner diagnostics that block the boot.
"""

from __future__ import annotations

import importlib.resources as ir
from pathlib import Path
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _pack_root() -> Path:
    return Path(str(ir.files("raes_env_packs") / "resources" / "packs" / "techvault"))


def _realize_pack(tmp_path):
    from raes_runtime.manager import RuntimeManager

    from aptl.backends.raes import create_aptl_runtime_target, parse_sdl_file
    from aptl.backends.raes_realization import interpret_provisioning_plan
    from aptl.core.config import AptlConfig
    from aptl.core.scenario_bundle import env_pack_bundle

    bundle = env_pack_bundle(tmp_path, identity="techvault", source_pack=_pack_root())
    config = AptlConfig(
        lab={"name": "tv"},
        containers={
            "wazuh": True,
            "soc": True,
            "enterprise": True,
            "victim": True,
            "kali": True,
            "fileshare": True,
            "dns": True,
        },
    )
    target = create_aptl_runtime_target(
        project_dir=PROJECT_ROOT, config=config, backend=MagicMock(), bundle=bundle
    )
    scenario = parse_sdl_file(bundle.sdl_path)
    plan = RuntimeManager(target).plan(scenario)
    return interpret_provisioning_plan(
        plan=plan.provisioning,
        config=config,
        bundle=bundle,
        component_root=PROJECT_ROOT,
    )


def test_techvault_pack_realizes_without_provisioner_diagnostics(tmp_path):
    """Interpreting the pack yields nodes, networks, profiles and no errors."""

    realization = _realize_pack(tmp_path)

    codes = sorted({d.code for d in realization.diagnostics})
    assert codes == [], f"unexpected realization diagnostics: {codes}"
    assert len(realization.nodes) >= 30
    assert {"soc", "enterprise", "wazuh"} <= set(realization.profiles)


def test_generated_compose_covers_image_nodes_networks_and_ordering(tmp_path):
    """The generated base compose renders image nodes, networks, and safe deps."""

    from aptl.core.deployment._compose_node_generation import render_realization_compose

    realization = _realize_pack(tmp_path)
    spec = realization.deployment_spec(sorted(realization.profiles))
    document = render_realization_compose(spec)

    services = document["services"]
    # Image-backed SOC nodes are emitted as services...
    assert "misp" in services
    assert services["misp"]["image"]
    assert services["misp"]["container_name"] == "aptl-misp"
    assert services["misp"]["profiles"] == ["soc"]
    # ...image-free base-OS nodes are realized by the generic materializer, not here.
    assert "webapp" not in services
    assert "workstation" not in services

    # Networks use the aptl-<stem> keys and carry ipam from the SDL.
    networks = document["networks"]
    assert "aptl-security" in networks
    assert networks["aptl-security"]["ipam"]["config"][0]["subnet"] == "172.20.0.0/24"
    assert networks["aptl-dmz"]["internal"] is True

    # depends_on never references a service the document does not define.
    defined = set(services)
    for service in services.values():
        for dependency in service.get("depends_on", []):
            assert dependency in defined


def test_operational_config_translates_declared_runtime_fields():
    """command / environment / capabilities are translated from the SDL as-is."""

    from raes.runtime_configuration import RuntimeConfiguration

    from aptl.core.deployment._compose_node_generation import _operational_config

    runtime = RuntimeConfiguration.model_validate(
        {
            "environment": [
                {"name": "DISCOVERY_TYPE", "value": "single-node"},
                {"name": "JVM_OPTS", "value": "-Xms512m"},
            ],
            "container": {"command": ["--secret", "abc", "--cql-hostnames", "cass"]},
            "linux_capabilities": {"add": ["CAP_NET_ADMIN"]},
        }
    )

    config = _operational_config(runtime)

    assert config["environment"] == {
        "DISCOVERY_TYPE": "single-node",
        "JVM_OPTS": "-Xms512m",
    }
    assert config["command"] == ["--secret", "abc", "--cql-hostnames", "cass"]
    # RAES CAP_* form is translated to Docker's cap_add form.
    assert config["cap_add"] == ["NET_ADMIN"]


def test_operational_config_is_empty_for_a_bare_node():
    """A node with no declared runtime gets no operational Compose fields."""

    from aptl.core.deployment._compose_node_generation import _operational_config

    assert _operational_config(None) == {}


def test_component_build_nodes_resolve_their_image_from_the_engine_tree(tmp_path):
    """`materialization-specification` nodes (ad, wazuh-sidecar) resolve an image.

    Their build context lives in APTL's ``containers/`` tree, not the pack, so a
    realization that anchored the build context to the bundle would reject them
    with image-policy-rejected:untrusted-image.
    """

    realization = _realize_pack(tmp_path)
    by_name = {node.address.rsplit(".", 1)[-1]: node for node in realization.nodes}

    for name in ("ad", "wazuh-sidecar-db", "wazuh-sidecar-suricata"):
        node = by_name[name]
        assert node.image is not None, f"{name} did not resolve a component image"
        assert node.image.mode == "build"
