"""Compose binding of trusted appliance policy to observed workload anchors."""

from unittest.mock import MagicMock

from aptl.core.appliance_boundary import (
    ApplianceBoundaryBinding,
    ApplianceBoundaryPolicy,
)
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment.realization import (
    DeploymentImageRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.core.lab_types import LabResult


def _policy() -> ApplianceBoundaryPolicy:
    return ApplianceBoundaryPolicy.model_validate(
        {
            "schema_version": "aptl.appliance-boundary/v1",
            "policy_id": "default",
            "generation": 1,
            "workbench_policy_version": "participant-workbench-profile/v1",
            "default_deny": True,
            "platform_networks": {
                "participant": "org.aptl.network=participant",
                "management": "org.aptl.network=management",
                "egress": "org.aptl.network=egress",
            },
            "platform_anchors": {
                "participant": "org.aptl.zone=participant",
                "management": "org.aptl.zone=management",
                "egress": "org.aptl.zone=egress",
            },
            "fixed_crossings": [
                {
                    "source": "management",
                    "destination": "egress",
                    "protocol": "tcp",
                    "ports": [3128],
                    "purpose": "model-proxy",
                }
            ],
            "egress_authorities": [
                {
                    "source": "egress",
                    "authority": "api.example.test",
                    "protocol": "tcp",
                    "port": 443,
                    "purpose": "model-provider",
                    "resolution": "proxy-resolved-all-global",
                    "failure_disposition": "deny",
                }
            ],
            "egress_proxy_limits": {
                "max_connections": 32,
                "max_header_bytes": 4096,
                "header_timeout_seconds": 5,
                "connect_timeout_seconds": 10,
                "idle_timeout_seconds": 60,
            },
            "guest_publications": [],
            "docker_authority": {
                "allowed_holder_labels": [],
                "require_guest_daemon": True,
            },
        }
    )


def _binding() -> ApplianceBoundaryBinding:
    return ApplianceBoundaryBinding(
        policy_digest="sha256:" + "a" * 64,
        payload_digest="sha256:" + "b" * 64,
        raes_plan_digest="sha256:" + "c" * 64,
        raes_boundary_required=False,
        boundary_helper_image="example.test/aptl-boundary@sha256:" + "d" * 64,
        egress_proxy_image="example.test/aptl-egress@sha256:" + "e" * 64,
        boot_id="boot-1",
        guest_daemon_id="daemon-1",
        host_observation_id="host-1",
    )


def _network(name: str) -> dict[str, object]:
    zone = name.removeprefix("seat_")
    index = {"participant": 1, "management": 2, "egress": 3, "scenario": 4}[zone]
    labels = {"com.docker.compose.project": "seat"}
    if zone != "scenario":
        labels["org.aptl.network"] = zone
    return {
        "name": name,
        "bridge": f"br-seat{zone[:6]}",
        "subnet": f"10.50.{index}.0/24",
        "subnets": [f"10.50.{index}.0/24"],
        "labels": labels,
    }


def _inspect(*placements: tuple[str, str]) -> dict[str, object]:
    return {
        "NetworkSettings": {
            "Networks": {
                f"seat_{zone}": {
                    "IPAddress": address,
                    "GlobalIPv6Address": "",
                }
                for zone, address in placements
            }
        }
    }


def test_platform_policy_binds_exact_labeled_workloads_before_start(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="seat")
    backend.configure_appliance_boundary(_policy(), _binding())
    network_names = [
        "seat_participant",
        "seat_management",
        "seat_egress",
        "seat_scenario",
    ]
    backend.host_list_lab_networks = MagicMock(return_value=network_names)
    backend.host_inspect_network = MagicMock(side_effect=_network)
    backend.host_list_lab_containers = MagicMock(
        return_value=[
            {"name": "aptl-participant", "labels": {"org.aptl.zone": "participant"}},
            {"name": "aptl-management", "labels": {"org.aptl.zone": "management"}},
            {"name": "aptl-egress", "labels": {"org.aptl.zone": "egress"}},
        ]
    )
    placements = {
        "aptl-participant": (("participant", "10.50.1.10"),),
        "aptl-management": (("management", "10.50.2.20"),),
        "aptl-egress": (
            ("management", "10.50.2.30"),
            ("egress", "10.50.3.30"),
        ),
    }
    backend.container_inspect = MagicMock(
        side_effect=lambda name: _inspect(*placements[name]),
    )
    backend.realize_boundary = MagicMock(return_value=LabResult(success=True))

    result = backend._realize_platform_boundary()

    assert result is None
    spec = backend.realize_boundary.call_args.args[0]
    assert spec.authority == "platform"
    assert spec.egress_ports == (443,)
    assert {network.name for network in spec.networks} == {
        "seat_participant",
        "seat_management",
        "seat_egress",
    }
    assert [workload.identity for _zone, workload in spec.anchors] == [
        "aptl-participant",
        "aptl-management",
        "aptl-egress",
    ]


def test_ambiguous_platform_anchor_fails_before_mutation(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="seat")
    backend.configure_appliance_boundary(_policy(), _binding())
    network_names = [
        "seat_participant",
        "seat_management",
        "seat_egress",
    ]
    backend.host_list_lab_networks = MagicMock(return_value=network_names)
    backend.host_inspect_network = MagicMock(side_effect=_network)
    backend.host_list_lab_containers = MagicMock(
        return_value=[
            {"name": "aptl-participant", "labels": {"org.aptl.zone": "participant"}},
            {"name": "aptl-management-a", "labels": {"org.aptl.zone": "management"}},
            {"name": "aptl-management-b", "labels": {"org.aptl.zone": "management"}},
            {"name": "aptl-egress", "labels": {"org.aptl.zone": "egress"}},
        ]
    )
    backend.container_inspect = MagicMock(
        return_value=_inspect(("participant", "10.50.1.10"))
    )
    backend.realize_boundary = MagicMock()

    result = backend._realize_platform_boundary()

    assert result is not None
    assert result.success is False
    backend.realize_boundary.assert_not_called()


def test_appliance_installs_deny_baseline_before_anchor_workloads(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="seat")
    backend.configure_appliance_boundary(_policy(), _binding())
    backend._ensure_realization_networks = MagicMock(return_value=[])
    backend.host_list_lab_networks = MagicMock(
        return_value=["seat_participant", "seat_management", "seat_egress"]
    )
    backend.host_inspect_network = MagicMock(side_effect=_network)
    backend.host_list_lab_containers = MagicMock(return_value=[])
    backend.realize_boundary = MagicMock(return_value=LabResult(success=True))
    backend._realize_raes_boundary = MagicMock(return_value=None)

    result = backend._realize_networks_and_boundaries(
        DeploymentRealizationSpec(profiles=(), nodes=(), networks=())
    )

    assert result is None
    baseline = backend.realize_boundary.call_args.args[0]
    assert baseline.authority == "platform"
    assert baseline.bootstrap is True
    assert baseline.anchors == ()
    assert baseline.crossings == ()
    assert baseline.egress_ports == ()
    backend.host_list_lab_containers.assert_not_called()


def test_full_boundary_precedes_service_index_and_general_start(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="seat")
    backend.configure_appliance_boundary(_policy(), _binding())
    events: list[str] = []
    backend._start_boundary_anchor_services = MagicMock(
        side_effect=lambda *args, **kwargs: events.append("anchors")
    )
    backend._realize_platform_boundary = MagicMock(
        side_effect=lambda: events.append("full")
    )
    backend._materialize_service_index_schemas = MagicMock(
        side_effect=lambda *args, **kwargs: events.append("index")
    )
    backend._start_realized_services = MagicMock(
        side_effect=lambda *args, **kwargs: (
            events.append("general"),
            LabResult(success=True),
        )[1]
    )
    backend._realization_result = MagicMock(
        side_effect=lambda *args: (
            events.append("post"),
            LabResult(success=True),
        )[1]
    )

    result = backend._start_compose_realization(
        DeploymentRealizationSpec(profiles=(), nodes=(), networks=()),
        profiles=[],
        build=False,
        compose_files=None,
        excluded_services=(),
        scenario_root=tmp_path,
        observation_context=MagicMock(),
    )

    assert result.success
    assert events == ["anchors", "full", "index", "general", "post"]


def test_only_image_backed_anchor_starts_under_deny_baseline(tmp_path) -> None:
    policy = _policy().model_dump(mode="json")
    policy["platform_anchors"] = {
        "participant": "aptl.node.address=provision.node.kali",
        "management": "aptl.node.address=provision.node.soc-workstation",
        "egress": "aptl.node.address=provision.node.suricata",
    }
    backend = DockerComposeBackend(tmp_path, project_name="seat")
    backend.configure_appliance_boundary(
        ApplianceBoundaryPolicy.model_validate(policy), _binding()
    )
    backend._start_realized_services = MagicMock(return_value=LabResult(success=True))
    nodes = tuple(
        DeploymentNodeRealization(
            address=f"provision.node.{name}",
            name=name,
            service_name=name,
            container_name=f"aptl-{name}",
            networks=(),
        )
        for name in ("kali", "soc-workstation", "suricata")
    )
    realization = DeploymentRealizationSpec(
        profiles=("soc",),
        nodes=nodes,
        networks=(),
        images=(
            DeploymentImageRealization(
                address="provision.node.suricata",
                service_name="suricata",
                source_name="suricata",
                source_version="1",
                image_ref="suricata:1",
                mode="pull",
                policy_rule="test",
            ),
        ),
    )

    result = backend._start_boundary_anchor_services(
        realization,
        profiles=["soc"],
        build=False,
        compose_files=None,
        excluded_services=(),
        scenario_root=tmp_path,
    )

    assert result is None
    assert backend._start_realized_services.call_args.kwargs["only_services"] == (
        "suricata",
    )


def test_scenario_without_acls_removes_stale_raes_authority(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="seat")
    backend._boundary_receipts["raes"] = {"observed": True}
    backend.realize_boundary = MagicMock(return_value=LabResult(success=True))

    result = backend._realize_raes_boundary(
        DeploymentRealizationSpec(profiles=(), nodes=(), networks=())
    )

    assert result is None
    cleanup = backend.realize_boundary.call_args.args[0]
    assert cleanup.authority == "raes"
    assert cleanup.rules == ()
