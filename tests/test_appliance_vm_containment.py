"""VM-only seats retain outer admission without claiming inner-zone isolation."""

from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from aptl.appliance.policy import full_techvault_boundary_policy
from aptl.appliance.guest_observation import collect_guest_observation
from aptl.core.appliance_boundary import ApplianceBoundaryPolicy
from aptl.core.appliance_boundary_inventory import qualify_appliance_boundary
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment.realization import DeploymentRealizationSpec
from tests.test_appliance_boundary_inventory import _binding, _guest, _host, _policy
from tests.test_appliance_guest_observation import _Backend


def _vm_policy():
    return full_techvault_boundary_policy().model_copy(
        update={
            "guest_publications": _policy().guest_publications,
            "host_mcp_contract": None,
        }
    )


def _vm_guest():
    return _guest().model_copy(update={"enforcements": (), "probes": ()})


def test_vm_policy_has_no_scenario_zone_selectors():
    policy = full_techvault_boundary_policy()
    assert policy.schema_version == "aptl.appliance-boundary/v2"
    assert not policy.internal_zone_isolation
    assert not policy.default_deny
    assert policy.platform_networks is None
    assert policy.platform_anchors is None
    assert policy.fixed_crossings == policy.egress_authorities == []
    assert policy.egress_proxy_limits is None


def test_vm_startup_does_not_apply_platform_rules_to_lab_networks(tmp_path):
    backend = DockerComposeBackend(tmp_path, project_name="seat")
    backend.configure_appliance_boundary(full_techvault_boundary_policy(), _binding())
    backend.realize_boundary = MagicMock(
        side_effect=AssertionError("no platform rules")
    )
    backend.host_list_lab_networks = MagicMock(
        side_effect=AssertionError("no selectors")
    )
    assert backend._realize_platform_baseline() is None
    assert backend._realize_platform_boundary() is None
    assert (
        backend._start_boundary_anchor_services(
            DeploymentRealizationSpec(profiles=(), nodes=(), networks=()),
            profiles=[],
            build=False,
            compose_files=None,
            excluded_services=(),
            scenario_root=tmp_path,
        )
        is None
    )
    backend._realize_raes_boundary = MagicMock(return_value=None)
    realization = DeploymentRealizationSpec(profiles=(), nodes=(), networks=())
    assert backend._realize_authority_boundaries(realization) is None
    backend._realize_raes_boundary.assert_called_once_with(realization)


def test_vm_admission_needs_no_fabricated_internal_enforcement():
    result = qualify_appliance_boundary(_vm_policy(), _binding(), _host(), _vm_guest())
    assert result.passed, result.findings
    assert result.inventory["policy"]["containment"] == "vm-only"
    assert result.inventory["guest"]["enforcements"] == []


def test_vm_observer_reports_guest_identity_without_synthetic_firewall_probes():
    backend = _Backend()
    backend._run = MagicMock(side_effect=AssertionError("no internal probes"))
    result = collect_guest_observation(
        backend=backend,
        policy=full_techvault_boundary_policy(),
        binding=_binding(),
        boundary_specs={},
        boundary_receipts={},
        realization=DeploymentRealizationSpec(profiles=(), nodes=(), networks=()),
    )
    assert result.observation_complete
    assert result.guest_daemon_id == "daemon-42"
    assert result.enforcements == result.probes == ()


@pytest.mark.parametrize(
    "field,value",
    [
        ("guest_daemon_id", "wrong-daemon"),
        ("boot_id", "old-boot"),
        ("policy_digest", "sha256:" + "9" * 64),
        ("observation_complete", False),
    ],
)
def test_vm_admission_still_rejects_invalid_guest_identity(field, value):
    guest = _vm_guest().model_copy(update={field: value})
    assert not qualify_appliance_boundary(
        _vm_policy(), _binding(), _host(), guest
    ).passed


def test_vm_admission_still_requires_verified_host_observation():
    assert not qualify_appliance_boundary(
        _vm_policy(), _binding(), None, _vm_guest()
    ).passed
    host = _host().model_copy(update={"forbidden_reachability_passed": False})
    assert not qualify_appliance_boundary(
        _vm_policy(), _binding(), host, _vm_guest()
    ).passed


def test_internal_policy_still_requires_real_internal_enforcement():
    assert not qualify_appliance_boundary(
        _policy(), _binding(), _host(), _vm_guest()
    ).passed


@pytest.mark.parametrize("field", ["enforcements", "probes"])
def test_vm_evidence_cannot_claim_internal_platform_isolation(field):
    guest = _vm_guest().model_copy(update={field: getattr(_guest(), field)})
    assert not qualify_appliance_boundary(
        _vm_policy(), _binding(), _host(), guest
    ).passed


def test_signed_policy_versions_cannot_silently_change_containment():
    vm = full_techvault_boundary_policy().model_dump(mode="json")
    with pytest.raises(ValidationError):
        ApplianceBoundaryPolicy.model_validate(
            {**vm, "schema_version": "aptl.appliance-boundary/v1"}
        )
    legacy = _policy().model_dump(mode="json")
    with pytest.raises(ValidationError):
        ApplianceBoundaryPolicy.model_validate(
            {**legacy, "schema_version": "aptl.appliance-boundary/v2"}
        )
