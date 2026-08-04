"""Unit tests for backend-observed realization (issue #578).

These pin the observation layer that lets the SEM-218 gate reject a backend that
did not realize what a scenario declared: a resource is recorded only when the
backend can actually be *seen* to have realized it, and an unobservable resource
fails closed (no snapshot entry) rather than being assumed realized.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

from raes_contracts.planning import (
    ChangeAction,
    PlannedResource,
    ProvisioningPlan,
    ProvisionOp,
    RuntimeDomain,
)

from aptl.backends.raes_observation import observe_realization
from aptl.backends.raes_realization_model import (
    AptlRealization,
    NetworkRealization,
    NodeRealization,
    PlacementRealization,
)
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactOutput,
    DeploymentGeneratedArtifactRealization,
    DeploymentImageRealization,
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
        realization_root=None,
        bind_source_types=None,
        bind_probe_raises=False,
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
        self.realization_root = realization_root
        self._bind_source_types = bind_source_types or {}
        self._bind_probe_raises = bind_probe_raises

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

    def observe_bind_source_type(self, source):
        if self._bind_probe_raises:
            raise BackendTimeoutError("bind source probe timed out")
        return self._bind_source_types.get(source)


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


def _node_realization(name="vm", container="aptl-vm", *, imaged=False):
    """Build one realized node.

    ``imaged`` makes it a Compose service. Only a Compose service can carry a
    bind mount, so it is what decides whether a generated artifact reaches this
    node as a mount or as files the generic materializer placed into its
    container (issue #875).
    """

    address = f"provision.node.{name}"
    return NodeRealization(
        address=address,
        name=name,
        aliases=(),
        profiles=(),
        backend_services=(name,),
        container_name=container,
        services=(),
        networks=(),
        static_addresses=(),
        image=(
            DeploymentImageRealization(
                address=address,
                service_name=name,
                source_name=name,
                source_version="1",
                image_ref=f"{name}:1",
                mode="pull",
                policy_rule="declared",
            )
            if imaged
            else None
        ),
    )


def test_running_healthy_node_is_realized_with_concerns(tmp_path):
    address, plan = _node_plan()
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(),),
        networks=(),
        placements=(),
        diagnostics=(),
    )
    obs = observe_realization(
        _Backend(containers=("aptl-vm",)), realization, plan, scenario_root=tmp_path
    )
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


def test_domain_topology_attested_when_live_domain_matches(tmp_path):
    address, plan = _domain_node_plan()
    backend = _Backend(
        containers=("aptl-ad",),
        exec_results={"aptl-ad": (0, _SAMBA_DOMAIN_INFO)},
    )
    obs = observe_realization(
        backend, _domain_realization(), plan, scenario_root=tmp_path
    )
    assert obs[address].realized is True
    assert obs[address].concerns[("domain_topology",)] == _DECLARED_TOPOLOGY


def test_domain_topology_omitted_when_live_domain_differs(tmp_path):
    address, plan = _domain_node_plan()
    backend = _Backend(
        containers=("aptl-ad",),
        exec_results={
            "aptl-ad": (0, _SAMBA_DOMAIN_INFO.replace("TECHVAULT", "OTHERCORP"))
        },
    )
    obs = observe_realization(
        backend, _domain_realization(), plan, scenario_root=tmp_path
    )
    assert obs[address].realized is True
    assert ("domain_topology",) not in obs[address].concerns


def test_domain_topology_probe_failure_fails_closed(tmp_path):
    address, plan = _domain_node_plan()
    backend = _Backend(
        containers=("aptl-ad",),
        exec_results={"aptl-ad": (1, "")},
    )
    obs = observe_realization(
        backend, _domain_realization(), plan, scenario_root=tmp_path
    )
    assert obs[address].realized is True
    assert ("domain_topology",) not in obs[address].concerns


def test_domain_topology_exec_timeout_fails_closed_not_crash(tmp_path):
    address, plan = _domain_node_plan()
    backend = _Backend(containers=("aptl-ad",), exec_raises=True)
    obs = observe_realization(
        backend, _domain_realization(), plan, scenario_root=tmp_path
    )
    assert obs[address].realized is True
    assert ("domain_topology",) not in obs[address].concerns


def test_starting_node_settles_before_judgment(monkeypatch, tmp_path):
    """A transiently 'starting' container is waited out, not failed.

    Wazuh manager/indexer restart themselves once during first boot, so a
    consumer can read health='starting' between the realization health gate
    and observation (issue #677). 'starting' is transitional evidence, not an
    unrealized resource.
    """
    from aptl.backends import _raes_observation_helpers as helpers

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
    obs = observe_realization(backend, realization, plan, scenario_root=tmp_path)
    assert obs[address].realized is True
    assert obs[address].concerns[("node_type",)] == "vm"


def test_settle_deadline_returns_transitional_info_instead_of_hanging(monkeypatch):
    """A container stuck in 'starting' fails closed at the settle budget.

    The deadline is the fail-safe for a genuinely wedged container: settle
    must give up within `_SETTLE_TIMEOUT` and hand back the still-transitional
    info (judged unrealized) rather than loop forever.
    """
    from aptl.backends import _raes_observation_helpers as helpers

    clock = iter(
        [0.0, 1.0, helpers._SETTLE_TIMEOUT + 1.0, helpers._SETTLE_TIMEOUT + 2.0]
    )
    monkeypatch.setattr(helpers.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(helpers.time, "sleep", lambda _s: None)
    backend = _Backend(containers=("aptl-vm",), health="starting")

    info = helpers.settled_inspect(backend, "aptl-vm")

    assert info["State"]["Health"]["Status"] == "starting"
    assert helpers.container_realized(info) is False


def test_stopped_node_fails_immediately_without_settling(monkeypatch, tmp_path):
    from aptl.backends import _raes_observation_helpers as helpers

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
        _Backend(containers=("aptl-vm",), running=False),
        realization,
        plan,
        scenario_root=tmp_path,
    )
    assert obs[address].realized is False


def test_node_without_declared_topology_is_never_probed(tmp_path):
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
    obs = observe_realization(backend, realization, plan, scenario_root=tmp_path)
    assert obs[address].realized is True
    assert obs[address].concerns == {("node_type",): "vm", ("os_family",): "linux"}


def test_non_running_node_is_not_realized(tmp_path):
    address, plan = _node_plan()
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(),),
        networks=(),
        placements=(),
        diagnostics=(),
    )
    backend = _Backend(containers=("aptl-vm",), running=False)
    assert (
        observe_realization(backend, realization, plan, scenario_root=tmp_path)[
            address
        ].realized
        is False
    )


def test_unhealthy_node_is_not_realized(tmp_path):
    address, plan = _node_plan()
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(),),
        networks=(),
        placements=(),
        diagnostics=(),
    )
    backend = _Backend(containers=("aptl-vm",), health="unhealthy")
    assert (
        observe_realization(backend, realization, plan, scenario_root=tmp_path)[
            address
        ].realized
        is False
    )


def test_inspect_timeout_fails_closed_not_crash(tmp_path):
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
    assert (
        observe_realization(backend, realization, plan, scenario_root=tmp_path)[
            address
        ].realized
        is False
    )


def test_same_named_container_from_another_project_is_not_realized(tmp_path):
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

    assert (
        observe_realization(backend, realization, plan, scenario_root=tmp_path)[
            address
        ].realized
        is False
    )


def test_switch_network_realized_under_project_prefixed_name(tmp_path):
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
    obs = observe_realization(backend, realization, plan, scenario_root=tmp_path)
    assert obs[address].realized is True
    assert obs[address].concerns == {("node_type",): "switch"}


def test_network_list_timeout_fails_closed(tmp_path):
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
    assert (
        observe_realization(backend, realization, plan, scenario_root=tmp_path)[
            address
        ].realized
        is False
    )


def test_feature_binding_placement_resolves_via_target_address(tmp_path):
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
        observe_realization(
            _Backend(containers=("aptl-vm",)),
            realization,
            plan,
            scenario_root=tmp_path,
        )[address].realized
        is True
    )


def test_placement_on_down_target_is_not_realized(tmp_path):
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
        observe_realization(
            _Backend(containers=()), realization, plan, scenario_root=tmp_path
        )[address].realized
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
            {
                "name": "root-ca",
                "path": "root-ca.pem",
                "sensitivity": "public",
                "disposition": "consumer_selected",
            }
        ],
        "consumers": [
            {
                "node": "wazuh-indexer",
                "target_address": "provision.node.wazuh-indexer",
                "mount_destination": "/usr/share/wazuh-indexer/certs",
                "access_mode": "read_only",
            }
        ],
        # raes 0.23 carries dependency wiring inside the declared spec;
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
        nodes=(_node_realization("wazuh-indexer", "aptl-wazuh-indexer", imaged=True),),
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
        "aptl.backends._raes_stateful_observation.certificate_bundle_evidence",
        return_value={
            "public_root_sha256": "0" * 64,
            "chain_valid": True,
            "san_valid": True,
        },
    )

    observed = observe_realization(
        backend, realization, plan, scenario_root=tmp_path
    )[address]

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
    assert (
        observe_realization(backend, realization, plan, scenario_root=tmp_path)[
            address
        ].realized
        is False
    )
    backend.authenticated_readiness = {"wazuh.indexer": True}
    certificate_evidence.return_value = None
    assert (
        observe_realization(backend, realization, plan, scenario_root=tmp_path)[
            address
        ].realized
        is False
    )


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
                "disposition": "consumer_selected",
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
        nodes=(_node_realization("wazuh-manager", "aptl-wazuh-manager", imaged=True),),
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
        backend,
        realization,
        ProvisioningPlan(resources={address: resource}),
        scenario_root=tmp_path,
    )[address]

    assert observed.realized is True
    assert (
        observed.evidence["configuration_sha256"]
        == hashlib.sha256(secret_content).hexdigest()
    )
    assert "must-not-enter-evidence" not in str(observed.evidence)


def test_persistent_volume_is_observed_from_project_scoped_mount(tmp_path):
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
        nodes=(_node_realization("wazuh-indexer", "aptl-wazuh-indexer", imaged=True),),
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

    observed = observe_realization(
        backend, realization, plan, scenario_root=tmp_path
    )[address]

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
    assert (
        observe_realization(
            _Backend(containers=()), realization, plan, scenario_root=tmp_path
        )[address].realized
        is False
    )


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


def test_content_type_comes_from_backend_probe_not_declared_payload(tmp_path):
    """A realized directory must not be echoed back as the planned file."""
    address, plan, realization = _content_placement_fixture()
    backend = _Backend(
        containers=("aptl-vm",),
        content_types={address: "directory"},
    )

    observation = observe_realization(
        backend, realization, plan, scenario_root=tmp_path
    )[address]

    assert observation.realized is True
    assert observation.concerns == {("spec", "type"): "directory"}


def test_content_probe_timeout_omits_concern_without_echoing_plan(tmp_path):
    """Unobservable exact content fails closed instead of becoming a file."""
    address, plan, realization = _content_placement_fixture()
    backend = _Backend(containers=("aptl-vm",), content_probe_raises=True)

    observation = observe_realization(
        backend, realization, plan, scenario_root=tmp_path
    )[address]

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


def test_image_free_content_type_observed_via_container_exec_not_volume_probe(tmp_path):
    """No named volume to probe (ADR-048) - read the destination back directly."""
    address, plan, realization = _image_free_content_placement_fixture()
    backend = _Backend(
        containers=("aptl-vm",),
        exec_results={"aptl-vm": [(1, ""), (0, "")]},  # test -d fails, test -f succeeds
    )

    observation = observe_realization(
        backend, realization, plan, scenario_root=tmp_path
    )[address]

    assert observation.realized is True
    assert observation.concerns == {("spec", "type"): "file"}


def test_image_free_content_type_directory_observed_via_container_exec(tmp_path):
    address, plan, realization = _image_free_content_placement_fixture()
    backend = _Backend(
        containers=("aptl-vm",),
        exec_results={"aptl-vm": [(0, "")]},  # test -d succeeds; test -f never runs
    )

    observation = observe_realization(
        backend, realization, plan, scenario_root=tmp_path
    )[address]

    assert observation.concerns == {("spec", "type"): "directory"}


def test_image_free_content_missing_omits_concern_without_echoing_plan(tmp_path):
    address, plan, realization = _image_free_content_placement_fixture()
    backend = _Backend(
        containers=("aptl-vm",),
        exec_results={"aptl-vm": [(1, ""), (1, "")]},  # neither -d nor -f
    )

    observation = observe_realization(
        backend, realization, plan, scenario_root=tmp_path
    )[address]

    assert observation.realized is True
    assert observation.concerns == {}


def test_image_free_content_exec_timeout_fails_closed_not_crash(tmp_path):
    address, plan, realization = _image_free_content_placement_fixture()
    backend = _Backend(containers=("aptl-vm",), exec_raises=True)

    observation = observe_realization(
        backend, realization, plan, scenario_root=tmp_path
    )[address]

    assert observation.realized is True
    assert observation.concerns == {}


_SSH_OUTPUTS = (
    DeploymentGeneratedArtifactOutput(
        name="control-plane-key",
        path="operator/control-plane-key",
        sensitivity="secret",
        disposition="producer_private",
    ),
    DeploymentGeneratedArtifactOutput(
        name="labadmin-key",
        path="labadmin/.ssh/id_ed25519",
        sensitivity="secret",
    ),
    DeploymentGeneratedArtifactOutput(
        name="kali-authorized-keys",
        path="kali/.ssh/authorized_keys",
        sensitivity="public",
    ),
)


def _ssh_bundle_fixture(*, imaged, selected=("labadmin-key",)):
    """One ``ssh_key_bundle`` artifact with a single output-selecting consumer."""

    address = "provision.generated-artifact.techvault-ssh-keys"
    resource = PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="generated-artifact",
        payload={"name": "techvault-ssh-keys", "spec": {}},
    )
    plan = ProvisioningPlan(resources={address: resource})
    consumer = DeploymentStatefulConsumer(
        target_address="provision.node.workstation",
        node_name="workstation",
        service_name="workstation",
        mount_destination="/home",
        access_mode="read_only",
        selected_outputs=tuple(selected),
    )
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(
            _node_realization("workstation", "aptl-workstation", imaged=imaged),
        ),
        networks=(),
        placements=(),
        diagnostics=(),
        generated_artifacts=(
            DeploymentGeneratedArtifactRealization(
                address=address,
                name="techvault-ssh-keys",
                generator="ssh_key_bundle",
                lifecycle="reuse_valid",
                provenance="techvault:ssh-access-profile/v1",
                outputs=_SSH_OUTPUTS,
                consumers=(consumer,),
            ),
        ),
    )
    return address, plan, realization


def _write_ssh_bundle(root):
    """Materialize the bundle's declared outputs under a realization root."""

    bundle = root / ".aptl/realization/ssh-key-bundles/techvault-ssh-keys"
    for output in _SSH_OUTPUTS:
        path = bundle / output.path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("key material fixture")
    return bundle


def test_generated_artifact_is_read_back_from_the_backend_realization_root(tmp_path):
    """The artifact is read back where it was written, not from the pristine pack.

    Generated output is written under the backend's writable realization root
    precisely so a digest-validated staged pack does not gain generated files
    (issue #875). Reading it back out of the bundle root instead found nothing,
    stripped every generated-artifact entry, and made the SEM-218 gate reject an
    apply whose artifacts were all correctly realized.
    """

    address, plan, realization = _ssh_bundle_fixture(imaged=True)
    engine_root = tmp_path / "engine"
    bundle_root = tmp_path / "pack"
    bundle_root.mkdir()
    bundle = _write_ssh_bundle(engine_root)
    backend = _Backend(
        containers=("aptl-workstation",),
        realization_root=engine_root,
        mounts={
            "aptl-workstation": [
                {
                    "Type": "bind",
                    "Source": str(bundle / "labadmin/.ssh/id_ed25519"),
                    "Destination": "/home/labadmin/.ssh/id_ed25519",
                    "RW": False,
                }
            ]
        },
    )

    observed = observe_realization(
        backend, realization, plan, scenario_root=bundle_root
    )[address]

    assert observed.realized is True
    assert ("spec",) in observed.concerns


def test_a_consumer_is_never_expected_to_mount_material_withheld_from_it(tmp_path):
    """Only the consumer's selected, non-private outputs are expected as mounts.

    Realization mounts exactly what a consumer selected and never a
    ``producer_private`` output. Expecting the whole bundle instead demanded
    mounts of material deliberately withheld, so a correctly delivered artifact
    read as unrealized (issue #875).
    """

    address, plan, realization = _ssh_bundle_fixture(imaged=True)
    engine_root = tmp_path / "engine"
    bundle = _write_ssh_bundle(engine_root)
    backend = _Backend(
        containers=("aptl-workstation",),
        realization_root=engine_root,
        mounts={
            "aptl-workstation": [
                {
                    "Type": "bind",
                    "Source": str(bundle / "labadmin/.ssh/id_ed25519"),
                    "Destination": "/home/labadmin/.ssh/id_ed25519",
                    "RW": False,
                }
            ]
        },
    )

    observed = observe_realization(
        backend, realization, plan, scenario_root=engine_root
    )[address]

    assert observed.realized is True
    # The producer-private control-plane key is on disk but must never be
    # expected -- or observed -- in any consumer's mount set.
    assert "control-plane-key" not in str(observed.evidence)


def test_image_free_consumer_artifact_is_observed_from_its_placed_files(tmp_path):
    """An image-free node has no Compose service, so no bind to observe.

    Its selected outputs are placed into the container as files instead
    (issue #875); demanding a bind mount reported every such artifact as
    unrealized.
    """

    address, plan, realization = _ssh_bundle_fixture(imaged=False)
    engine_root = tmp_path / "engine"
    _write_ssh_bundle(engine_root)
    backend = _Backend(
        containers=("aptl-workstation",),
        realization_root=engine_root,
        exec_results={"aptl-workstation": [(0, "")]},
    )

    observed = observe_realization(
        backend, realization, plan, scenario_root=engine_root
    )[address]

    assert observed.realized is True


def test_image_free_consumer_missing_its_placed_output_is_not_realized(tmp_path):
    """An output that never reached the container fails the gate, as it must."""

    address, plan, realization = _ssh_bundle_fixture(imaged=False)
    engine_root = tmp_path / "engine"
    _write_ssh_bundle(engine_root)
    backend = _Backend(
        containers=("aptl-workstation",),
        realization_root=engine_root,
        exec_results={"aptl-workstation": [(1, "")]},
    )

    observed = observe_realization(
        backend, realization, plan, scenario_root=engine_root
    )[address]

    assert observed.realized is False


def test_image_free_consumer_exec_failure_is_not_read_as_delivery(tmp_path):
    address, plan, realization = _ssh_bundle_fixture(imaged=False)
    engine_root = tmp_path / "engine"
    _write_ssh_bundle(engine_root)
    backend = _Backend(
        containers=("aptl-workstation",),
        realization_root=engine_root,
        exec_raises=True,
    )

    observed = observe_realization(
        backend, realization, plan, scenario_root=engine_root
    )[address]

    assert observed.realized is False


def _bind_content_placement_fixture(container="aptl-vm", dest="etc/otelcol/config.yaml"):
    """A content placement delivered to an image node as a read-only bind.

    An image node is a Compose service with a fixed image, so its config is
    delivered by binding the rendered file at the declared destination -- there
    is no named volume to probe and, for a distroless image or an exited
    one-shot, nothing to exec either (issue #875).
    """

    address = "provision.content.collector-config"
    target_address = "provision.node.vm"
    resource = PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="content-placement",
        payload={
            "name": "collector-config",
            "target_address": target_address,
            "spec": {"type": "file", "path": f"/{dest}"},
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
    placement = PlacementRealization(
        address=address,
        resource_type="content-placement",
        name="collector-config",
        target_address=target_address,
        target_node="vm",
        content=DeploymentContentRealization(
            address=address,
            target_address=target_address,
            content_name="collector-config",
            volume_suffix="",
            dest_relpath=dest,
            source_kind="inline-text",
            inline_text="receivers: {}",
        ),
    )
    realization = AptlRealization(
        profiles=frozenset(),
        nodes=(_node_realization(container=container, imaged=True),),
        networks=(),
        placements=(placement,),
        diagnostics=(),
    )
    return address, plan, realization


_BIND_SOURCE = "/engine/.aptl/realization/content/collector-config/config.yaml"


def _content_bind(destination, *, source=_BIND_SOURCE, read_write=False):
    return {
        "Type": "bind",
        "Source": source,
        "Destination": destination,
        "RW": read_write,
    }


def test_bind_delivered_content_type_read_from_the_daemon_not_the_container(tmp_path):
    """A distroless image has no ``test`` binary; the mount is still observable.

    The OTel collector image ships no shell or coreutils, so ``container_exec
    test -f`` exits 127 and the content-type concern went absent -- which the
    SEM-218 gate reads as a silent omission and rejects, even though the config
    is bound at the declared path (issue #875). Container inspection plus a host
    probe of the bind source observes it without running anything in the image.
    """

    address, plan, realization = _bind_content_placement_fixture()
    backend = _Backend(
        containers=("aptl-vm",),
        # No exec_results: the fake asserts if container_exec is called at all.
        mounts={"aptl-vm": [_content_bind("/etc/otelcol/config.yaml")]},
        bind_source_types={_BIND_SOURCE: "file"},
    )

    observation = observe_realization(
        backend, realization, plan, scenario_root=tmp_path
    )[address]

    assert observation.realized is True
    assert observation.concerns == {("spec", "type"): "file"}


def test_bind_delivered_content_type_observed_on_an_exited_one_shot(tmp_path):
    """An exited run-to-completion node cannot be exec'd but is still realized.

    The Cortex index initializer places its script by bind mount and exits 0 by
    design. Exec against a stopped container fails outright, so the only honest
    readback is the daemon's own mount record (issue #875).
    """

    address, plan, realization = _bind_content_placement_fixture(
        container="aptl-cortex-index-init", dest="usr/local/bin/cortex-index-init.sh"
    )
    backend = _Backend(
        containers=("aptl-cortex-index-init",),
        running=False,
        health=None,
        mounts={
            "aptl-cortex-index-init": [
                _content_bind("/usr/local/bin/cortex-index-init.sh")
            ]
        },
        bind_source_types={_BIND_SOURCE: "file"},
    )
    backend.container_inspect = lambda name: {
        "State": {"Running": False, "Status": "exited", "ExitCode": 0},
        "HostConfig": {"RestartPolicy": {"Name": "no"}},
        "Platform": "linux",
        "Mounts": [_content_bind("/usr/local/bin/cortex-index-init.sh")],
    }

    observation = observe_realization(
        backend, realization, plan, scenario_root=tmp_path
    )[address]

    assert observation.realized is True
    assert observation.concerns == {("spec", "type"): "file"}


def test_bind_delivered_directory_content_type_is_reported_as_directory(tmp_path):
    address, plan, realization = _bind_content_placement_fixture()
    backend = _Backend(
        containers=("aptl-vm",),
        mounts={"aptl-vm": [_content_bind("/etc/otelcol/config.yaml")]},
        bind_source_types={_BIND_SOURCE: "directory"},
    )

    observation = observe_realization(
        backend, realization, plan, scenario_root=tmp_path
    )[address]

    assert observation.concerns == {("spec", "type"): "directory"}


def test_writable_bind_at_the_destination_corroborates_nothing(tmp_path):
    """Content is always delivered read-only, so a RW bind is not the placement."""

    address, plan, realization = _bind_content_placement_fixture()
    backend = _Backend(
        containers=("aptl-vm",),
        mounts={
            "aptl-vm": [_content_bind("/etc/otelcol/config.yaml", read_write=True)]
        },
        bind_source_types={_BIND_SOURCE: "file"},
        exec_results={"aptl-vm": [(1, ""), (1, "")]},  # nothing at the destination
    )

    observation = observe_realization(
        backend, realization, plan, scenario_root=tmp_path
    )[address]

    assert observation.realized is True
    assert observation.concerns == {}


def test_bind_source_probe_failure_omits_the_content_type(tmp_path):
    """An unreadable bind source observes nothing rather than assuming a kind."""

    address, plan, realization = _bind_content_placement_fixture()
    backend = _Backend(
        containers=("aptl-vm",),
        mounts={"aptl-vm": [_content_bind("/etc/otelcol/config.yaml")]},
        bind_probe_raises=True,
    )

    observation = observe_realization(
        backend, realization, plan, scenario_root=tmp_path
    )[address]

    assert observation.realized is True
    assert observation.concerns == {}


def test_container_realized_accepts_a_completed_one_shot():
    """A run-to-completion init container is realized, not unrealized (#866).

    The Cortex Elasticsearch index initializer creates its index and exits 0 by
    design. Before this, the RAES realization gate read its exited container as
    an unrealized node and rejected the whole apply for a node-type requirement
    the container actually satisfied -- which forced `aptl lab start` to fail.
    """

    from aptl.backends._raes_observation_helpers import container_realized

    one_shot = {
        "State": {"Running": False, "Status": "exited", "ExitCode": 0},
        "HostConfig": {"RestartPolicy": {"Name": "no"}},
    }
    assert container_realized(one_shot) is True

    # A stay-up service that exited is still a real failure.
    dead_service = {
        "State": {"Running": False, "Status": "exited", "ExitCode": 0},
        "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}},
    }
    assert container_realized(dead_service) is False

    # A one-shot that errored failed its job.
    errored = {
        "State": {"Running": False, "Status": "exited", "ExitCode": 1},
        "HostConfig": {"RestartPolicy": {"Name": "no"}},
    }
    assert container_realized(errored) is False

    # A running healthy service is realized as before.
    running = {"State": {"Running": True}, "HostConfig": {"RestartPolicy": {"Name": "always"}}}
    assert container_realized(running) is True
