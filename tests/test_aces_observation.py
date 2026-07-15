"""Unit tests for backend-observed realization (issue #578).

These pin the observation layer that lets the SEM-218 gate reject a backend that
did not realize what a scenario declared: a resource is recorded only when the
backend can actually be *seen* to have realized it, and an unobservable resource
fails closed (no snapshot entry) rather than being assumed realized.
"""

from __future__ import annotations

from aces_contracts.planning import (
    ChangeAction,
    PlannedResource,
    ProvisioningPlan,
    ProvisionOp,
    RuntimeDomain,
)

from aptl.backends.aces_observation import observe_realization
from aptl.backends.aces_realization_model import (
    AptlRealization,
    NetworkRealization,
    NodeRealization,
    PlacementRealization,
)
from aptl.core.deployment.realization import DeploymentContentRealization
from aptl.core.deployment._compose_realization_networks import _concrete_network_name
from aptl.core.deployment.errors import BackendTimeoutError

_PROJECT = "aptl"


class _Backend:
    """A deployment backend whose observed inventory the test controls."""

    project_name = _PROJECT

    def __init__(
        self,
        *,
        containers=(),
        networks=(),
        platform="linux",
        health="healthy",
        running=True,
        inspect_raises=False,
        networks_raise=False,
        project_owned=True,
        content_types=None,
        content_probe_raises=False,
    ):
        self._containers = set(containers)
        self._networks = [_concrete_network_name(n, self.project_name) for n in networks]
        self._platform = platform
        self._health = health
        self._running = running
        self._inspect_raises = inspect_raises
        self._networks_raise = networks_raise
        self._project_owned = project_owned
        self._content_types = content_types or {}
        self._content_probe_raises = content_probe_raises

    def container_exists(self, name):
        return self._project_owned and name in self._containers

    def container_inspect(self, name):
        if self._inspect_raises:
            raise BackendTimeoutError("docker inspect timed out")
        if name not in self._containers:
            return {}
        state = {"Running": self._running}
        if self._health is not None:
            state["Health"] = {"Status": self._health}
        return {
            "State": state,
            "Platform": self._platform,
            "NetworkSettings": {"Networks": {}},
        }

    def host_list_lab_networks(self, name_prefix):
        if self._networks_raise:
            raise BackendTimeoutError("docker network ls timed out")
        return [n for n in self._networks if name_prefix in n]

    def observe_content_type(self, content):
        if self._content_probe_raises:
            raise BackendTimeoutError("content probe timed out")
        return self._content_types.get(content.address)


def _node_plan(name="vm"):
    address = f"provision.node.{name}"
    payload = {"name": name, "node_type": "vm", "os_family": "linux"}
    resource = PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="node",
        payload=payload,
    )
    op = ProvisionOp(
        action=ChangeAction.CREATE,
        address=address,
        resource_type="node",
        payload=payload,
    )
    return address, ProvisioningPlan(resources={address: resource}, operations=[op])


def _node_realization(name="vm", container="aptl-vm"):
    return NodeRealization(
        address=f"provision.node.{name}",
        name=name,
        aliases=(),
        profiles=(),
        backend_services=(name,),
        container_name=container,
        services=(),
        networks=(),
        static_addresses=(),
    )


def test_running_healthy_node_is_realized_with_concerns():
    address, plan = _node_plan()
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(),),
        networks=(),
        placements=(),
        diagnostics=(),
    )
    obs = observe_realization(_Backend(containers=("aptl-vm",)), realization, plan)
    assert obs[address].realized is True
    assert obs[address].concerns == {("node_type",): "vm", ("os_family",): "linux"}


def test_non_running_node_is_not_realized():
    address, plan = _node_plan()
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(),),
        networks=(),
        placements=(),
        diagnostics=(),
    )
    backend = _Backend(containers=("aptl-vm",), running=False)
    assert observe_realization(backend, realization, plan)[address].realized is False


def test_unhealthy_node_is_not_realized():
    address, plan = _node_plan()
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(),),
        networks=(),
        placements=(),
        diagnostics=(),
    )
    backend = _Backend(containers=("aptl-vm",), health="unhealthy")
    assert observe_realization(backend, realization, plan)[address].realized is False


def test_inspect_timeout_fails_closed_not_crash():
    """A transient ``docker inspect`` failure reads as absent, not realized."""
    address, plan = _node_plan()
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(),),
        networks=(),
        placements=(),
        diagnostics=(),
    )
    backend = _Backend(containers=("aptl-vm",), inspect_raises=True)
    # Must not raise, and the unobservable node must not be reported realized.
    assert observe_realization(backend, realization, plan)[address].realized is False


def test_same_named_container_from_another_project_is_not_realized():
    """A foreign container name cannot satisfy this project's node concern."""
    address, plan = _node_plan()
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(),),
        networks=(),
        placements=(),
        diagnostics=(),
    )
    backend = _Backend(containers=("aptl-vm",), project_owned=False)

    assert observe_realization(backend, realization, plan)[address].realized is False


def test_switch_network_realized_under_project_prefixed_name():
    """A switch's network is recognized under Compose's real prefixed name."""
    address = "provision.network.redteam-net"
    resource = PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="network",
        payload={"name": "redteam-net", "node_type": "switch"},
    )
    op = ProvisionOp(
        action=ChangeAction.CREATE,
        address=address,
        resource_type="network",
        payload=resource.payload,
    )
    plan = ProvisioningPlan(resources={address: resource}, operations=[op])
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(),
        networks=(
            NetworkRealization(
                address=address,
                name="redteam-net",
                cidr=None,
                gateway=None,
                internal=None,
            ),
        ),
        placements=(),
        diagnostics=(),
    )
    backend = _Backend(networks=("redteam-net",))
    obs = observe_realization(backend, realization, plan)
    assert obs[address].realized is True
    assert obs[address].concerns == {("node_type",): "switch"}


def test_network_list_timeout_fails_closed():
    """A transient network-listing failure reads switches as not realized."""
    address = "provision.network.redteam-net"
    resource = PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="network",
        payload={"name": "redteam-net"},
    )
    op = ProvisionOp(
        action=ChangeAction.CREATE,
        address=address,
        resource_type="network",
        payload=resource.payload,
    )
    plan = ProvisioningPlan(resources={address: resource}, operations=[op])
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(),
        networks=(
            NetworkRealization(
                address=address,
                name="redteam-net",
                cidr=None,
                gateway=None,
                internal=None,
            ),
        ),
        placements=(),
        diagnostics=(),
    )
    backend = _Backend(networks=("redteam-net",), networks_raise=True)
    assert observe_realization(backend, realization, plan)[address].realized is False


def test_feature_binding_placement_resolves_via_target_address():
    """A feature-binding (no ``target_address`` in payload) resolves via the
    already-resolved placement target and reads realized when its node is up."""
    address = "provision.feature.x"
    resource = PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="feature-binding",
        payload={"node_address": "provision.node.vm", "name": "x"},
    )
    op = ProvisionOp(
        action=ChangeAction.CREATE,
        address=address,
        resource_type="feature-binding",
        payload=resource.payload,
    )
    plan = ProvisioningPlan(resources={address: resource}, operations=[op])
    placement = PlacementRealization(
        address=address,
        resource_type="feature-binding",
        name="x",
        target_address="provision.node.vm",
        target_node="vm",
    )
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(),),
        networks=(),
        placements=(placement,),
        diagnostics=(),
    )
    assert observe_realization(
        _Backend(containers=("aptl-vm",)), realization, plan
    )[address].realized is True


def test_placement_on_down_target_is_not_realized():
    address = "provision.feature.x"
    resource = PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="feature-binding",
        payload={"node_address": "provision.node.vm", "name": "x"},
    )
    op = ProvisionOp(
        action=ChangeAction.CREATE,
        address=address,
        resource_type="feature-binding",
        payload=resource.payload,
    )
    plan = ProvisioningPlan(resources={address: resource}, operations=[op])
    placement = PlacementRealization(
        address=address,
        resource_type="feature-binding",
        name="x",
        target_address="provision.node.vm",
        target_node="vm",
    )
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(),),
        networks=(),
        placements=(placement,),
        diagnostics=(),
    )
    # container aptl-vm absent -> target node down -> placement not realized
    assert observe_realization(_Backend(containers=()), realization, plan)[
        address
    ].realized is False


def _content_placement_fixture():
    address = "provision.content.notice"
    target_address = "provision.node.vm"
    resource = PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="content-placement",
        payload={
            "name": "notice",
            "target_address": target_address,
            "spec": {"type": "file", "path": "public/notice.txt"},
        },
    )
    plan = ProvisioningPlan(
        resources={address: resource},
        operations=[
            ProvisionOp(
                action=ChangeAction.CREATE,
                address=address,
                resource_type=resource.resource_type,
                payload=resource.payload,
            )
        ],
    )
    content = DeploymentContentRealization(
        address=address,
        target_address=target_address,
        content_name="notice",
        volume_suffix="fileshare_data",
        dest_relpath="public/notice.txt",
        source_kind="inline-text",
        inline_text="hello",
    )
    placement = PlacementRealization(
        address=address,
        resource_type="content-placement",
        name="notice",
        target_address=target_address,
        target_node="vm",
        content=content,
    )
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(),),
        networks=(),
        placements=(placement,),
        diagnostics=(),
    )
    return address, plan, realization


def test_content_type_comes_from_backend_probe_not_declared_payload():
    """A realized directory must not be echoed back as the planned file."""
    address, plan, realization = _content_placement_fixture()
    backend = _Backend(
        containers=("aptl-vm",),
        content_types={address: "directory"},
    )

    observation = observe_realization(backend, realization, plan)[address]

    assert observation.realized is True
    assert observation.concerns == {("spec", "type"): "directory"}


def test_content_probe_timeout_omits_concern_without_echoing_plan():
    """Unobservable exact content fails closed instead of becoming a file."""
    address, plan, realization = _content_placement_fixture()
    backend = _Backend(containers=("aptl-vm",), content_probe_raises=True)

    observation = observe_realization(backend, realization, plan)[address]

    assert observation.realized is True
    assert observation.concerns == {}
