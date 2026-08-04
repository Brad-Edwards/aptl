"""APTL operator component->profile grouping (interim seam home, issue #895).

This grouping is operator packaging, not realization: it labels components the
core already realizes so an operator can boot a subset. These tests pin it as
behaviour-preserving with the retiring docker-compose.yml ``profiles:`` column,
since that is the invariant the env-pack boot depends on.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from aptl.backends._component_profiles import component_profile, component_profiles

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_component_profile_normalizes_dotted_and_cased_names():
    """Wazuh's dotted compose service names resolve through normalization."""

    assert component_profile("wazuh-manager") == "wazuh"
    assert component_profile("wazuh.manager") == "wazuh"
    assert component_profile("WAZUH-MANAGER") == "wazuh"


def test_component_profiles_returns_zero_or_one_profile():
    """A grouped name yields one profile; an unknown name yields none."""

    assert component_profiles("thehive") == frozenset({"soc"})
    assert component_profiles("not-a-component") == frozenset()
    assert component_profile("not-a-component") is None


def test_grouping_matches_the_retiring_compose_profiles_column():
    """Every docker-compose.yml service maps to the same profile here.

    The env-pack boot replaces the compose ``profiles:`` column with this table;
    a drift between them would silently change which components an operator
    toggle brings up.
    """

    compose = yaml.safe_load((PROJECT_ROOT / "docker-compose.yml").read_text())
    for service_name, service_def in compose.get("services", {}).items():
        if not isinstance(service_def, dict):
            continue
        declared = service_def.get("profiles") or []
        # The compose service name (e.g. wazuh.manager) and the container name
        # (aptl-wazuh-manager -> wazuh-manager) both normalize to the node name.
        container = service_def.get("container_name") or service_name
        node_name = container.removeprefix("aptl-")
        mapped = component_profile(node_name)
        assert mapped is not None, f"{service_name} ({node_name}) has no profile grouping"
        assert set(declared) == {mapped}, (
            f"{service_name}: grouping {mapped!r} != compose {declared!r}"
        )


def test_realize_node_derives_profile_from_grouping_with_empty_index():
    """An image node maps to its profile through the grouping when no static
    compose index exists (the env-pack case, issue #875).

    Without the grouping, an env-pack image node has empty ``profiles`` and the
    provisioner rejects it with ``node-profile-unresolved`` /
    ``no-configured-profile-matches``.
    """

    from raes_contracts.planning import PlannedResource
    from raes_contracts.runtime_state import RuntimeDomain

    from aptl.backends._compose_profile_index import ComposeProfileIndex
    from aptl.backends.raes_realization import _realize_node
    from aptl.core.config import AptlConfig

    empty_index = ComposeProfileIndex(
        alias_to_profiles={}, alias_to_services={}, services={}
    )
    resource = PlannedResource(
        address="provision.node.thehive",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="node",
        payload={"name": "thehive", "spec": {"node": {"name": "thehive"}}},
    )
    diagnostics: list = []
    node = _realize_node(
        resource,
        resource.payload,
        empty_index,
        PROJECT_ROOT,
        AptlConfig(lab={"name": "t"}),
        diagnostics,
    )

    assert "soc" in node.profiles
    # The node's own identity becomes its Compose service + container name, so
    # image resolution no longer fails with unmapped-service (issue #875).
    assert node.backend_services == ("thehive",)
    assert node.container_name == "aptl-thehive"
