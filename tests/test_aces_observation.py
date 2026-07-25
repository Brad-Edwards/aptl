"""Unit tests for backend-observed realization (issue #578).

These pin the observation layer that lets the SEM-218 gate reject a backend that
did not realize what a scenario declared: a resource is recorded only when the
backend can actually be *seen* to have realized it, and an unobservable resource
fails closed (no snapshot entry) rather than being assumed realized.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

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
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactOutput,
    DeploymentGeneratedArtifactRealization,
    DeploymentPersistentVolumeRealization,
    DeploymentStatefulConsumer,
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
        mounts=None,
        project_dir=None,
        authenticated_readiness=None,
        project_owned=True,
        content_types=None,
        content_probe_raises=False,
        exec_results=None,
        exec_raises=False,
        health_sequence=None,
    ):
        self._containers = set(containers)
        self._networks = [
            _concrete_network_name(n, self.project_name) for n in networks
        ]
        self._platform = platform
        self._health = health
        self._running = running
        self._inspect_raises = inspect_raises
        self._networks_raise = networks_raise
        self._mounts = mounts or {}
        self.project_dir = project_dir
        self.authenticated_readiness = authenticated_readiness or {}
        self._project_owned = project_owned
        self._content_types = content_types or {}
        self._content_probe_raises = content_probe_raises
        self._exec_results = exec_results
        self._exec_raises = exec_raises
        self._health_sequence = list(health_sequence or [])
        self._exec_call_counts: dict[str, int] = {}

    def container_exec(self, name, cmd, *, timeout=None):
        if self._exec_raises:
            raise BackendTimeoutError("docker exec timed out")
        assert self._exec_results is not None, "container_exec must not be called"
        entry = self._exec_results[name]
        if isinstance(entry, list):
            # Consecutive calls against the same container (e.g. `test -d`
            # then `test -f`) consume the list in order.
            index = self._exec_call_counts.get(name, 0)
            self._exec_call_counts[name] = index + 1
            returncode, stdout = entry[index]
        else:
            returncode, stdout = entry
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")

    def container_exists(self, name):
        return self._project_owned and name in self._containers

    def container_inspect(self, name):
        if self._inspect_raises:
            raise BackendTimeoutError("docker inspect timed out")
        if name not in self._containers:
            return {}
        health = self._health
        if self._health_sequence:
            health = self._health_sequence.pop(0)
        state = {"Running": self._running}
        if health is not None:
            state["Health"] = {"Status": health}
        return {
            "State": state,
            "Platform": self._platform,
            "NetworkSettings": {"Networks": {}},
            "Mounts": self._mounts.get(name, []),
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


_DECLARED_TOPOLOGY = {
    "domain_id": "techvault",
    "profile": "active_directory",
    "dns_name": "techvault.local",
    "netbios_name": "TECHVAULT",
    "authority_account_address": "provision.account.ad-emily-chen",
    "role": "controller",
    "controller_addresses": ("provision.node.ad",),
}

_SAMBA_DOMAIN_INFO = (
    "Forest           : techvault.local\n"
    "Domain           : techvault.local\n"
    "Netbios domain   : TECHVAULT\n"
    "DC name          : dc.techvault.local\n"
    "DC netbios name  : DC\n"
)


def _domain_node_plan():
    address = "provision.node.ad"
    payload = {
        "name": "ad",
        "node_type": "vm",
        "os_family": "linux",
        "domain_topology": dict(_DECLARED_TOPOLOGY),
    }
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


def _domain_realization():
    return AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(name="ad", container="aptl-ad"),),
        networks=(),
        placements=(),
        diagnostics=(),
    )


def test_domain_topology_attested_when_live_domain_matches():
    address, plan = _domain_node_plan()
    backend = _Backend(
        containers=("aptl-ad",),
        exec_results={"aptl-ad": (0, _SAMBA_DOMAIN_INFO)},
    )
    obs = observe_realization(backend, _domain_realization(), plan)
    assert obs[address].realized is True
    assert obs[address].concerns[("domain_topology",)] == _DECLARED_TOPOLOGY


def test_domain_topology_omitted_when_live_domain_differs():
    address, plan = _domain_node_plan()
    backend = _Backend(
        containers=("aptl-ad",),
        exec_results={
            "aptl-ad": (0, _SAMBA_DOMAIN_INFO.replace("TECHVAULT", "OTHERCORP"))
        },
    )
    obs = observe_realization(backend, _domain_realization(), plan)
    assert obs[address].realized is True
    assert ("domain_topology",) not in obs[address].concerns


def test_domain_topology_probe_failure_fails_closed():
    address, plan = _domain_node_plan()
    backend = _Backend(
        containers=("aptl-ad",),
        exec_results={"aptl-ad": (1, "")},
    )
    obs = observe_realization(backend, _domain_realization(), plan)
    assert obs[address].realized is True
    assert ("domain_topology",) not in obs[address].concerns


def test_domain_topology_exec_timeout_fails_closed_not_crash():
    address, plan = _domain_node_plan()
    backend = _Backend(containers=("aptl-ad",), exec_raises=True)
    obs = observe_realization(backend, _domain_realization(), plan)
    assert obs[address].realized is True
    assert ("domain_topology",) not in obs[address].concerns


def test_starting_node_settles_before_judgment(monkeypatch):
    """A transiently 'starting' container is waited out, not failed.

    Wazuh manager/indexer restart themselves once during first boot, so a
    consumer can read health='starting' between the realization health gate
    and observation (issue #677). 'starting' is transitional evidence, not an
    unrealized resource.
    """
    from aptl.backends import _aces_observation_helpers as helpers

    monkeypatch.setattr(helpers.time, "sleep", lambda _s: None)
    address, plan = _node_plan()
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(),),
        networks=(),
        placements=(),
        diagnostics=(),
    )
    backend = _Backend(
        containers=("aptl-vm",),
        health_sequence=["starting", "starting", "healthy"],
    )
    obs = observe_realization(backend, realization, plan)
    assert obs[address].realized is True
    assert obs[address].concerns[("node_type",)] == "vm"


def test_settle_deadline_returns_transitional_info_instead_of_hanging(monkeypatch):
    """A container stuck in 'starting' fails closed at the settle budget.

    The deadline is the fail-safe for a genuinely wedged container: settle
    must give up within `_SETTLE_TIMEOUT` and hand back the still-transitional
    info (judged unrealized) rather than loop forever.
    """
    from aptl.backends import _aces_observation_helpers as helpers

    clock = iter(
        [0.0, 1.0, helpers._SETTLE_TIMEOUT + 1.0, helpers._SETTLE_TIMEOUT + 2.0]
    )
    monkeypatch.setattr(helpers.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(helpers.time, "sleep", lambda _s: None)
    backend = _Backend(containers=("aptl-vm",), health="starting")

    info = helpers.settled_inspect(backend, "aptl-vm")

    assert info["State"]["Health"]["Status"] == "starting"
    assert helpers.container_realized(info) is False


def test_stopped_node_fails_immediately_without_settling(monkeypatch):
    from aptl.backends import _aces_observation_helpers as helpers

    def _no_sleep(_s):
        raise AssertionError("terminal states must not be waited on")

    monkeypatch.setattr(helpers.time, "sleep", _no_sleep)
    address, plan = _node_plan()
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(),),
        networks=(),
        placements=(),
        diagnostics=(),
    )
    obs = observe_realization(
        _Backend(containers=("aptl-vm",), running=False), realization, plan
    )
    assert obs[address].realized is False


def test_node_without_declared_topology_is_never_probed():
    address, plan = _node_plan()
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(),),
        networks=(),
        placements=(),
        diagnostics=(),
    )
    # No exec_results configured: the fake asserts if container_exec is called.
    backend = _Backend(containers=("aptl-vm",))
    obs = observe_realization(backend, realization, plan)
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
    assert (
        observe_realization(_Backend(containers=("aptl-vm",)), realization, plan)[
            address
        ].realized
        is True
    )


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
    assert (
        observe_realization(_Backend(containers=()), realization, plan)[
            address
        ].realized
        is False
    )


def test_generated_artifact_is_observed_from_outputs_and_read_only_mount(
    tmp_path, mocker
):
    address = "provision.generated-artifact.wazuh-indexer-certs"
    spec = {
        "generator": "certificate_bundle",
        "lifecycle": "reuse_valid",
        "provenance": "config/certs.yml",
        "outputs": [
            {"name": "root-ca", "path": "root-ca.pem", "sensitivity": "public"}
        ],
        "consumers": [
            {
                "node": "wazuh-indexer",
                "target_address": "provision.node.wazuh-indexer",
                "mount_destination": "/usr/share/wazuh-indexer/certs",
                "access_mode": "read_only",
            }
        ],
        # aces-sdl 0.23 carries dependency wiring inside the declared spec;
        # the observed spec renders the DTO's realized wiring in the same
        # author vocabulary (issue #677).
        "ordering_dependencies": [],
        "refresh_dependencies": [],
    }
    resource = PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="generated-artifact",
        payload={"name": "wazuh-indexer-certs", "spec": spec},
    )
    plan = ProvisioningPlan(resources={address: resource})
    certs = tmp_path / "config/wazuh_indexer_ssl_certs"
    certs.mkdir(parents=True)
    (certs / "root-ca.pem").write_text("public certificate fixture")
    consumer = DeploymentStatefulConsumer(
        target_address="provision.node.wazuh-indexer",
        node_name="wazuh-indexer",
        service_name="wazuh.indexer",
        mount_destination="/usr/share/wazuh-indexer/certs",
        access_mode="read_only",
    )
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization("wazuh-indexer", "aptl-wazuh-indexer"),),
        networks=(),
        placements=(),
        diagnostics=(),
        generated_artifacts=(
            DeploymentGeneratedArtifactRealization(
                address=address,
                name="wazuh-indexer-certs",
                generator="certificate_bundle",
                lifecycle="reuse_valid",
                provenance="config/certs.yml",
                outputs=(
                    DeploymentGeneratedArtifactOutput(
                        name="root-ca", path="root-ca.pem", sensitivity="public"
                    ),
                ),
                consumers=(consumer,),
            ),
        ),
    )
    backend = _Backend(
        containers=("aptl-wazuh-indexer",),
        project_dir=tmp_path,
        authenticated_readiness={"wazuh.indexer": True},
        mounts={
            "aptl-wazuh-indexer": [
                {
                    "Type": "bind",
                    "Source": str(certs / "root-ca.pem"),
                    "Destination": "/usr/share/wazuh-indexer/certs/root-ca.pem",
                    "RW": False,
                }
            ]
        },
    )
    certificate_evidence = mocker.patch(
        "aptl.backends._aces_stateful_observation.certificate_bundle_evidence",
        return_value={
            "public_root_sha256": "0" * 64,
            "chain_valid": True,
            "san_valid": True,
        },
    )

    observed = observe_realization(backend, realization, plan)[address]

    assert observed.realized is True
    assert observed.concerns == {("spec",): spec}
    assert observed.evidence["address"] == address
    assert observed.evidence["status"] == "ready"
    assert observed.evidence["authenticated_readiness"] == {"wazuh.indexer": True}
    assert observed.evidence["consumer_mounts"] == [
        {
            "target_address": "provision.node.wazuh-indexer",
            "destination": "/usr/share/wazuh-indexer/certs",
            "access_mode": "read_only",
            "service_health": "healthy",
        }
    ]
    backend.authenticated_readiness = {}
    assert observe_realization(backend, realization, plan)[address].realized is False
    backend.authenticated_readiness = {"wazuh.indexer": True}
    certificate_evidence.return_value = None
    assert observe_realization(backend, realization, plan)[address].realized is False


def test_rendered_config_observation_records_digest_not_content(tmp_path):
    address = "provision.generated-artifact.wazuh-manager-config"
    spec = {
        "generator": "rendered_config",
        "lifecycle": "regenerate_on_change",
        "provenance": "config/wazuh_cluster/wazuh_manager.conf",
        "outputs": [
            {
                "name": "manager-config",
                "path": "wazuh_manager.conf",
                "sensitivity": "secret",
            }
        ],
        "consumers": [
            {
                "node": "wazuh-manager",
                "target_address": "provision.node.wazuh-manager",
                "mount_destination": "/wazuh-config-mount/etc/ossec.conf",
                "access_mode": "read_only",
            }
        ],
    }
    resource = PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="generated-artifact",
        payload={"name": "wazuh-manager-config", "spec": spec},
    )
    rendered = tmp_path / ".aptl/config/wazuh_cluster/wazuh_manager.conf"
    rendered.parent.mkdir(parents=True)
    secret_content = b"<cluster><key>must-not-enter-evidence</key></cluster>"
    rendered.write_bytes(secret_content)
    consumer = DeploymentStatefulConsumer(
        target_address="provision.node.wazuh-manager",
        node_name="wazuh-manager",
        service_name="wazuh.manager",
        mount_destination="/wazuh-config-mount/etc/ossec.conf",
        access_mode="read_only",
    )
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization("wazuh-manager", "aptl-wazuh-manager"),),
        networks=(),
        placements=(),
        diagnostics=(),
        generated_artifacts=(
            DeploymentGeneratedArtifactRealization(
                address=address,
                name="wazuh-manager-config",
                generator="rendered_config",
                lifecycle="regenerate_on_change",
                provenance="config/wazuh_cluster/wazuh_manager.conf",
                outputs=(
                    DeploymentGeneratedArtifactOutput(
                        name="manager-config",
                        path="wazuh_manager.conf",
                        sensitivity="secret",
                    ),
                ),
                consumers=(consumer,),
            ),
        ),
    )
    backend = _Backend(
        containers=("aptl-wazuh-manager",),
        project_dir=tmp_path,
        authenticated_readiness={"wazuh.manager": True},
        mounts={
            "aptl-wazuh-manager": [
                {
                    "Type": "bind",
                    "Source": str(rendered),
                    "Destination": "/wazuh-config-mount/etc/ossec.conf",
                    "RW": False,
                }
            ]
        },
    )

    observed = observe_realization(
        backend, realization, ProvisioningPlan(resources={address: resource})
    )[address]

    assert observed.realized is True
    assert (
        observed.evidence["configuration_sha256"]
        == hashlib.sha256(secret_content).hexdigest()
    )
    assert "must-not-enter-evidence" not in str(observed.evidence)


def test_persistent_volume_is_observed_from_project_scoped_mount():
    address = "provision.persistent-volume.wazuh-indexer-data"
    spec = {
        "lifecycle": "retain",
        "access_mode": "read_write_once",
        "consumers": [
            {
                "node": "wazuh-indexer",
                "target_address": "provision.node.wazuh-indexer",
                "mount_destination": "/var/lib/wazuh-indexer",
                "access_mode": "read_write",
            }
        ],
        "ordering_dependencies": [],
        "refresh_dependencies": [],
    }
    resource = PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="persistent-volume",
        payload={"name": "wazuh-indexer-data", "spec": spec},
    )
    plan = ProvisioningPlan(resources={address: resource})
    consumer = DeploymentStatefulConsumer(
        target_address="provision.node.wazuh-indexer",
        node_name="wazuh-indexer",
        service_name="wazuh.indexer",
        mount_destination="/var/lib/wazuh-indexer",
        access_mode="read_write",
    )
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization("wazuh-indexer", "aptl-wazuh-indexer"),),
        networks=(),
        placements=(),
        diagnostics=(),
        persistent_volumes=(
            DeploymentPersistentVolumeRealization(
                address=address,
                name="wazuh-indexer-data",
                lifecycle="retain",
                access_mode="read_write_once",
                consumers=(consumer,),
            ),
        ),
    )
    backend = _Backend(
        containers=("aptl-wazuh-indexer",),
        authenticated_readiness={"wazuh.indexer": True},
        mounts={
            "aptl-wazuh-indexer": [
                {
                    "Type": "volume",
                    "Name": "aptl_wazuh-indexer-data",
                    "Destination": "/var/lib/wazuh-indexer",
                    "RW": True,
                }
            ]
        },
    )

    observed = observe_realization(backend, realization, plan)[address]

    assert observed.realized is True
    assert observed.concerns == {("spec",): spec}
    assert observed.evidence == {
        "address": address,
        "status": "ready",
        "volume_identity": "aptl_wazuh-indexer-data",
        "lifecycle": "retain",
        "consumer_mounts": [
            {
                "target_address": "provision.node.wazuh-indexer",
                "destination": "/var/lib/wazuh-indexer",
                "access_mode": "read_write",
                "service_health": "healthy",
            }
        ],
    }
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


def _image_free_content_placement_fixture():
    """Same shape as _content_placement_fixture but with no named volume
    (ADR-048): the generic materializer places content directly into the
    node's container filesystem, so volume_suffix is empty and the probe
    that reads a Compose named volume has nothing to inspect."""

    address = "provision.content.notice"
    target_address = "provision.node.vm"
    resource = PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="content-placement",
        payload={
            "name": "notice",
            "target_address": target_address,
            "spec": {"type": "file", "path": "/srv/shares/public/notice.txt"},
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
        volume_suffix="",
        dest_relpath="srv/shares/public/notice.txt",
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


def test_image_free_content_type_observed_via_container_exec_not_volume_probe():
    """No named volume to probe (ADR-048) - read the destination back directly."""
    address, plan, realization = _image_free_content_placement_fixture()
    backend = _Backend(
        containers=("aptl-vm",),
        exec_results={"aptl-vm": [(1, ""), (0, "")]},  # test -d fails, test -f succeeds
    )

    observation = observe_realization(backend, realization, plan)[address]

    assert observation.realized is True
    assert observation.concerns == {("spec", "type"): "file"}


def test_image_free_content_type_directory_observed_via_container_exec():
    address, plan, realization = _image_free_content_placement_fixture()
    backend = _Backend(
        containers=("aptl-vm",),
        exec_results={"aptl-vm": [(0, "")]},  # test -d succeeds; test -f never runs
    )

    observation = observe_realization(backend, realization, plan)[address]

    assert observation.concerns == {("spec", "type"): "directory"}


def test_image_free_content_missing_omits_concern_without_echoing_plan():
    address, plan, realization = _image_free_content_placement_fixture()
    backend = _Backend(
        containers=("aptl-vm",),
        exec_results={"aptl-vm": [(1, ""), (1, "")]},  # neither -d nor -f
    )

    observation = observe_realization(backend, realization, plan)[address]

    assert observation.realized is True
    assert observation.concerns == {}


def test_image_free_content_exec_timeout_fails_closed_not_crash():
    address, plan, realization = _image_free_content_placement_fixture()
    backend = _Backend(containers=("aptl-vm",), exec_raises=True)

    observation = observe_realization(backend, realization, plan)[address]

    assert observation.realized is True
    assert observation.concerns == {}
