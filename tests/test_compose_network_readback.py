"""Network reconciliation must prove declared endpoints, not command success."""

from unittest.mock import MagicMock, patch
from pathlib import Path
from dataclasses import replace

import pytest

from aptl.core.deployment import (
    DeploymentNetworkAttachment,
    DeploymentNetworkRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
    DockerComposeBackend,
)
from aptl.core.deployment._compose_network_conflicts import _network_subnet_conflicts
from aptl.core.lab_types import LabResult


def _spec(*, legacy_names=True):
    return DeploymentRealizationSpec(
        profiles=(),
        nodes=(
            DeploymentNodeRealization(
                address="provision.node.webapp",
                name="webapp",
                service_name="portal",
                container_name="aptl-webapp",
                networks=("dmz-net",) if legacy_names else (),
                network_attachments=(
                    DeploymentNetworkAttachment("dmz-net", "172.20.1.20"),
                ),
            ),
        ),
        networks=(DeploymentNetworkRealization(name="dmz-net"),),
    )


def _info(endpoint=None):
    networks = {"bridge": {"IPAddress": "172.17.0.2"}}
    if endpoint is not None:
        networks["test_aptl-dmz"] = endpoint
    return {"NetworkSettings": {"Networks": networks}}


def _backend(tmp_path, observed):
    backend = DockerComposeBackend(project_dir=tmp_path, project_name="test")
    backend.host_list_lab_networks = MagicMock(return_value=["test_aptl-dmz"])
    backend.container_inspect = MagicMock(side_effect=[_info(), observed])
    backend.connect_container_network = MagicMock(return_value=LabResult(success=True))
    backend.disconnect_container_network = MagicMock(
        return_value=LabResult(success=True)
    )
    return backend


@pytest.mark.parametrize(
    ("observed", "diagnostic"),
    [
        ({}, "not inspectable"),
        (_info(), "missing declared network"),
        (_info({"IPAddress": "", "Aliases": ["portal", "webapp"]}), "IPv4"),
        (_info({"IPAddress": "172.20.1.99", "Aliases": ["portal", "webapp"]}), "IPv4"),
        (_info({"IPAddress": "172.20.1.20", "Aliases": []}), "DNS aliases"),
    ],
)
def test_successful_connect_requires_actual_endpoint_readback(
    tmp_path, observed, diagnostic
):
    backend = _backend(tmp_path, observed)

    failures = backend._reconcile_realization_networks(_spec())

    assert failures
    assert diagnostic in "; ".join(failures)
    assert "webapp" in "; ".join(failures)
    backend.connect_container_network.assert_called_once()
    # Preserve bootstrap connectivity when declared attachment was not proven.
    backend.disconnect_container_network.assert_not_called()


def test_explicit_attachments_are_checked_without_legacy_network_names(tmp_path):
    backend = _backend(tmp_path, _info())

    failures = backend._reconcile_realization_networks(_spec(legacy_names=False))

    assert failures
    backend.connect_container_network.assert_called_once()


@pytest.mark.parametrize("address", [None, "", "missing"])
def test_unpinned_attachment_requires_an_allocated_ipv4_address(tmp_path, address):
    spec = _spec()
    spec = replace(
        spec,
        nodes=(
            replace(
                spec.nodes[0],
                network_attachments=(DeploymentNetworkAttachment("dmz-net"),),
            ),
        ),
    )
    endpoint = {"Aliases": ["portal", "webapp"]}
    if address != "missing":
        endpoint["IPAddress"] = address
    observed = _info(endpoint)
    backend = _backend(tmp_path, observed)
    backend.container_inspect = MagicMock(
        side_effect=[
            _info(),
            observed,
            {"NetworkSettings": {"Networks": {"test_aptl-dmz": endpoint}}},
        ]
    )

    failures = backend._reconcile_realization_networks(spec)

    assert failures
    assert "IPv4" in "; ".join(failures)
    backend.disconnect_container_network.assert_not_called()


def test_unpinned_attachment_accepts_an_allocated_ipv4_address(tmp_path):
    spec = _spec()
    spec = replace(
        spec,
        nodes=(
            replace(
                spec.nodes[0],
                network_attachments=(DeploymentNetworkAttachment("dmz-net"),),
            ),
        ),
    )
    endpoint = {"IPAddress": "172.20.1.99", "Aliases": ["portal", "webapp"]}
    observed = _info(endpoint)
    backend = _backend(tmp_path, observed)
    backend.container_inspect = MagicMock(
        side_effect=[
            _info(),
            observed,
            {"NetworkSettings": {"Networks": {"test_aptl-dmz": endpoint}}},
        ]
    )

    assert backend._reconcile_realization_networks(spec) == []
    backend.connect_container_network.assert_called_once_with(
        "aptl-webapp",
        "test_aptl-dmz",
        ipv4_address=None,
        aliases=("portal", "webapp"),
    )


def test_empty_static_address_is_repaired_even_with_correct_aliases(tmp_path):
    endpoint = {"IPAddress": "", "Aliases": ["portal", "webapp"]}
    backend = _backend(tmp_path, _info(endpoint))
    backend.container_inspect = MagicMock(
        side_effect=[
            _info(endpoint),
            _info({"IPAddress": "172.20.1.20", "Aliases": ["portal", "webapp"]}),
            {
                "NetworkSettings": {
                    "Networks": {
                        "test_aptl-dmz": {
                            "IPAddress": "172.20.1.20",
                            "Aliases": ["portal", "webapp"],
                        }
                    }
                }
            },
        ]
    )

    assert backend._reconcile_realization_networks(_spec()) == []

    backend.connect_container_network.assert_called_once_with(
        "aptl-webapp",
        "test_aptl-dmz",
        ipv4_address="172.20.1.20",
        aliases=("portal", "webapp"),
    )


def test_connect_failure_preserves_default_bridge(tmp_path):
    backend = _backend(tmp_path, _info())
    backend.connect_container_network.return_value = LabResult(
        success=False, error="connect refused"
    )

    assert backend._reconcile_realization_networks(_spec()) == ["connect refused"]

    backend.disconnect_container_network.assert_not_called()


def test_successful_disconnect_must_remove_extra_project_attachment(tmp_path):
    observed = _info({"IPAddress": "172.20.1.20", "Aliases": ["portal", "webapp"]})
    observed["NetworkSettings"]["Networks"]["test_aptl-extra"] = {
        "IPAddress": "172.31.1.2"
    }
    backend = _backend(tmp_path, observed)
    backend.host_list_lab_networks.return_value.append("test_aptl-extra")
    backend.container_inspect = MagicMock(return_value=observed)

    failures = backend._reconcile_realization_networks(_spec())

    assert failures
    assert "extra project network" in "; ".join(failures)
    backend.disconnect_container_network.assert_called_once_with(
        "aptl-webapp", "test_aptl-extra"
    )


def test_successful_disconnect_must_remove_default_bridge(tmp_path):
    observed = _info({"IPAddress": "172.20.1.20", "Aliases": ["portal", "webapp"]})
    backend = _backend(tmp_path, observed)
    backend.container_inspect = MagicMock(return_value=observed)

    failures = backend._reconcile_realization_networks(_spec())

    assert failures
    assert "default bridge" in "; ".join(failures)


@pytest.mark.parametrize("route", ["image-free", "compose"])
def test_every_startup_route_rejects_unobserved_networks(tmp_path, route):
    backend = _backend(tmp_path, _info())
    spec = _spec()
    backend._realize_networks_and_boundaries = MagicMock(return_value=None)
    backend._image_free_generated_artifact_ops = MagicMock(return_value=(None, {}))
    backend._realize_platform_boundary = MagicMock(return_value=None)
    backend._await_realized_service_health = MagicMock(return_value=[])

    with patch(
        "aptl.core.deployment._compose_realization._realize_node_subset",
        return_value=LabResult(success=True),
    ):
        if route == "image-free":
            result = backend._realize_without_compose(spec, tmp_path)
        else:
            from aptl.core.deployment.observation import DeploymentObservationContext

            result = backend._realization_result(
                LabResult(success=True), spec, DeploymentObservationContext()
            )

    assert not result.success
    assert "missing declared network attachment" in result.error
    backend._await_realized_service_health.assert_not_called()
    backend.disconnect_container_network.assert_not_called()


def test_default_bridge_conflict_does_not_recommend_removing_builtin_network():
    failures = _network_subnet_conflicts(
        DeploymentNetworkRealization(name="dmz-net", cidr="172.20.1.0/24"),
        [{"name": "bridge", "subnet": "172.20.0.0/16", "containers": ["other-app"]}],
    )

    assert len(failures) == 1
    assert "docker network rm bridge" not in failures[0]
    assert "built-in" in failures[0]
    assert "bip" in failures[0]
    assert "non-overlapping" in failures[0]
    assert "restart" in failures[0]


@pytest.mark.parametrize(
    "selection",
    [
        "techvault",
        "bounded-participant-agency-techvault",
        "techvault-attacker-target",
        "techvault-defensive-min",
        "techvault-enterprise-web",
    ],
)
def test_authored_scenario_networks_cannot_report_success_on_default_bridge(
    tmp_path, selection
):
    """Use real admission/lowering for every plausible reported variant."""
    from raes import parse_sdl_file
    from raes_runtime.manager import RuntimeManager

    from aptl.backends.raes import create_aptl_runtime_target
    from aptl.backends.raes_realization import interpret_provisioning_plan
    from aptl.backends.scenario_runtime_parameters import resolve_runtime_parameters
    from aptl.core.config import AptlConfig
    from aptl.core.scenario_bundle import env_pack_bundle, project_tree_bundle
    from aptl.core.deployment._compose_realization_networks import (
        _concrete_network_name,
    )
    from aptl.core.deployment._compose_image_free_realization import _needs_compose

    root = Path(__file__).resolve().parents[1]
    bundle = (
        env_pack_bundle(tmp_path / "packs")
        if selection == "techvault"
        else project_tree_bundle(root, root / "scenarios" / f"{selection}.sdl.yaml")
    )
    config = AptlConfig()
    backend = DockerComposeBackend(project_dir=tmp_path, project_name="test")
    target = create_aptl_runtime_target(
        project_dir=tmp_path,
        config=config,
        backend=backend,
        bundle=bundle,
    )
    plan = RuntimeManager(target).plan(
        parse_sdl_file(bundle.sdl_path),
        parameters=resolve_runtime_parameters(bundle),
    )
    lowered = interpret_provisioning_plan(
        plan=plan.provisioning,
        config=config,
        bundle=bundle,
        component_root=root,
    )
    assert not [d.message for d in lowered.diagnostics if d.is_error]
    spec = lowered.deployment_spec([])
    assert _needs_compose(spec) == (selection != "bounded-participant-agency-techvault")
    assert spec.nodes
    assert spec.networks
    assert all(node.network_attachments for node in spec.nodes)

    backend.host_list_lab_networks = MagicMock(
        return_value=[_concrete_network_name(n.name, "test") for n in spec.networks]
    )
    backend.container_inspect = MagicMock(return_value=_info())
    backend.connect_container_network = MagicMock(return_value=LabResult(success=True))
    backend.disconnect_container_network = MagicMock(
        return_value=LabResult(success=True)
    )

    failures = backend._reconcile_realization_networks(spec)

    assert failures
    assert all("missing declared network attachment" in failure for failure in failures)
    assert backend.connect_container_network.call_count == sum(
        len(n.network_attachments) for n in spec.nodes
    )
    backend.disconnect_container_network.assert_not_called()
