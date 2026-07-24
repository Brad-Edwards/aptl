"""Tests for the generic base-substrate decision (ADR-048).

A node runs on a generic base-OS container chosen solely from its declared
`os`/`os_version` (never a per-node or appliance image). A node that declares
service units needs an init-capable substrate so `systemctl` works; a node that
declares none does not. This module encodes that scenario-independent decision;
the concrete init mechanism is backend/host integration validated against real
local Docker.
"""

from __future__ import annotations

import pytest

from aces_sdl.runtime_capabilities import RuntimeCapabilityPolicy
from aces_sdl.runtime_configuration import (
    RuntimeConfiguration,
    ServiceManagerUnit,
)

from aptl.backends.aces_base_substrate import (
    UnauthorizedCapabilityError,
    base_container_spec,
    plan_node,
)
from aptl.backends.aces_materializer import (
    BaseSubstrateOp,
    StartServiceUnitOp,
    UnsupportedOsFamilyError,
)


def _runtime_with_service() -> RuntimeConfiguration:
    return RuntimeConfiguration(
        service_manager_units=[
            ServiceManagerUnit(
                unit_id="svc", unit_name="svc.service", active_state="active"
            )
        ]
    )


class TestBaseContainerSpec:
    def test_image_and_name_derive_from_os_and_address_only(self):
        spec = base_container_spec("techvault.wazuh-manager", os="linux", os_version="", runtime=None)
        assert spec.image_ref == base_container_spec(
            "other.node", os="linux", os_version="", runtime=None
        ).image_ref  # same OS -> same generic base, regardless of node identity
        assert "wazuh-manager" in spec.container_name

    def test_node_with_service_units_needs_init(self):
        spec = base_container_spec(
            "n.node", os="linux", os_version="", runtime=_runtime_with_service()
        )
        assert spec.runs_services is True

    def test_node_without_service_units_needs_no_init(self):
        spec = base_container_spec(
            "n.node", os="linux", os_version="", runtime=RuntimeConfiguration()
        )
        assert spec.runs_services is False
        assert spec.init is None
        spec_none = base_container_spec("n.node", os="linux", os_version="", runtime=None)
        assert spec_none.runs_services is False
        assert spec_none.init is None

    def test_service_node_gets_init_substrate_and_requirements(self):
        spec = base_container_spec(
            "n.node", os="linux", os_version="", runtime=_runtime_with_service()
        )
        # A distinct, init-capable generic substrate (not the minimal base).
        non_service = base_container_spec(
            "n.node", os="linux", os_version="", runtime=None
        )
        assert spec.image_ref != non_service.image_ref
        # The validated systemd run requirements are carried, not fabricated per call.
        assert spec.init is not None
        assert "SYS_ADMIN" in spec.init.capabilities
        assert spec.init.cgroup_host is True
        assert spec.init.seccomp_unconfined is True
        assert ("container", "docker") in spec.init.env
        assert spec.init.stop_signal == "SIGRTMIN+3"
        assert "/run/lock" in spec.init.tmpfs

    def test_unknown_os_fails_closed(self):
        with pytest.raises(UnsupportedOsFamilyError):
            base_container_spec("n.node", os="haiku", os_version="", runtime=None)

    def test_declared_extra_capabilities_extend_the_fixed_init_set(self):
        runtime = RuntimeConfiguration(
            service_manager_units=[
                ServiceManagerUnit(unit_id="svc", unit_name="svc.service", active_state="active")
            ],
            linux_capabilities=RuntimeCapabilityPolicy(add=["CAP_NET_ADMIN"]),
        )
        spec = base_container_spec("n.node", os="linux", os_version="", runtime=runtime)
        assert spec.init is not None
        assert "NET_ADMIN" in spec.init.capabilities
        # The fixed systemd requirements are still present alongside the addition.
        assert "SYS_ADMIN" in spec.init.capabilities

    def test_declared_capability_outside_the_allowlist_is_rejected(self):
        # issue #816: a scenario declaring a host-impacting capability APTL
        # has no verified need for must fail admission, not be granted.
        runtime = RuntimeConfiguration(
            service_manager_units=[
                ServiceManagerUnit(unit_id="svc", unit_name="svc.service", active_state="active")
            ],
            linux_capabilities=RuntimeCapabilityPolicy(add=["CAP_SYS_ADMIN"]),
        )
        with pytest.raises(UnauthorizedCapabilityError, match="CAP_SYS_ADMIN"):
            base_container_spec("n.node", os="linux", os_version="", runtime=runtime)

    def test_no_declared_capabilities_keeps_the_fixed_default_set(self):
        spec = base_container_spec(
            "n.node", os="linux", os_version="", runtime=_runtime_with_service()
        )
        assert spec.init is not None
        assert spec.init.capabilities == ("SYS_ADMIN", "SYS_NICE", "SYS_RESOURCE")

    def test_declared_published_ports_are_lowered(self):
        from aces_sdl.runtime_network import (
            RuntimeNetworkRealization,
            RuntimePublishedPort,
        )

        runtime = RuntimeConfiguration(
            network=RuntimeNetworkRealization(
                published_ports=[
                    RuntimePublishedPort(container_port=8080, host_port=8080),
                    RuntimePublishedPort(
                        container_port=53, protocol="udp", host_ip="127.0.0.1", host_port=5353
                    ),
                ]
            )
        )
        spec = base_container_spec("n.node", os="linux", os_version="", runtime=runtime)
        assert len(spec.published_ports) == 2
        assert spec.published_ports[0].container_port == 8080
        assert spec.published_ports[0].protocol == "tcp"
        assert spec.published_ports[0].host_port == 8080
        # An author who omits host_ip gets loopback, never all interfaces
        # (ADR-034 Host Exposure Amendment).
        assert spec.published_ports[0].host_ip == "127.0.0.1"
        assert spec.published_ports[1].protocol == "udp"
        assert spec.published_ports[1].host_ip == "127.0.0.1"

    def test_no_declared_network_yields_no_published_ports(self):
        spec = base_container_spec("n.node", os="linux", os_version="", runtime=RuntimeConfiguration())
        assert spec.published_ports == ()
        spec_none = base_container_spec("n.node", os="linux", os_version="", runtime=None)
        assert spec_none.published_ports == ()

    def test_declared_volume_mount_is_lowered(self):
        from aces_sdl.runtime_mounts import RuntimeMount

        runtime = RuntimeConfiguration(
            mounts=[
                RuntimeMount(
                    target="/var/lib/suricata/rules/misp",
                    source="suricata_misp_rules",
                    source_kind="volume",
                ),
                RuntimeMount(
                    target="/etc/config",
                    source="/host/config",
                    source_kind="bind",
                ),
            ]
        )
        spec = base_container_spec("n.node", os="linux", os_version="", runtime=runtime)
        assert len(spec.volume_mounts) == 1
        assert spec.volume_mounts[0].source == "suricata_misp_rules"
        assert spec.volume_mounts[0].target == "/var/lib/suricata/rules/misp"
        assert spec.volume_mounts[0].read_only is False

    def test_no_declared_mounts_yields_no_volume_mounts(self):
        spec = base_container_spec("n.node", os="linux", os_version="", runtime=RuntimeConfiguration())
        assert spec.volume_mounts == ()
        spec_none = base_container_spec("n.node", os="linux", os_version="", runtime=None)
        assert spec_none.volume_mounts == ()


class TestPlanNode:
    def test_spec_and_ops_are_coherent(self):
        spec, ops = plan_node(
            "techvault.wazuh-manager",
            os="linux",
            os_version="",
            runtime=_runtime_with_service(),
        )
        # First op stands up the base the spec chose.
        assert ops[0] == BaseSubstrateOp(image_ref=spec.image_ref)
        # A node that declares service units both needs init and gets start ops.
        assert spec.runs_services is True
        assert any(isinstance(op, StartServiceUnitOp) for op in ops)

    def test_no_service_units_means_no_init_and_no_start_ops(self):
        spec, ops = plan_node("n.node", os="linux", os_version="", runtime=None)
        assert spec.runs_services is False
        assert not any(isinstance(op, StartServiceUnitOp) for op in ops)
