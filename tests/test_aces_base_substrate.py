"""Tests for the generic base-substrate decision (ADR-047).

A node runs on a generic base-OS container chosen solely from its declared
`os`/`os_version` (never a per-node or appliance image). A node that declares
service units needs an init-capable substrate so `systemctl` works; a node that
declares none does not. This module encodes that scenario-independent decision;
the concrete init mechanism is backend/host integration validated in AWS.
"""

from __future__ import annotations

import pytest

from aces_sdl.runtime_configuration import (
    RuntimeConfiguration,
    ServiceManagerUnit,
)

from aptl.backends.aces_base_substrate import base_container_spec
from aptl.backends.aces_materializer import UnsupportedOsFamilyError


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
        spec_none = base_container_spec("n.node", os="linux", os_version="", runtime=None)
        assert spec_none.runs_services is False

    def test_unknown_os_fails_closed(self):
        with pytest.raises(UnsupportedOsFamilyError):
            base_container_spec("n.node", os="haiku", os_version="", runtime=None)
