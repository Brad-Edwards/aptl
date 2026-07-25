"""Unit tests for mixed-realization node partitioning (ADR-048).

TechVault's real shape is permanently mixed: some nodes convert to the
generic materializer (`runtime:`), others stay on a declared vendor
`source:`. These pure functions decide which nodes materialize directly and
which Compose service names must be scaled to zero so neither side starts,
skips, or double-realizes the other's nodes. See
test_mixed_realization_integration.py for the real-Docker proof.
"""

from __future__ import annotations

from aces_sdl.runtime_configuration import RuntimeConfiguration, ServiceManagerUnit

from aptl.core.deployment._compose_realization import (
    _image_free_node_addresses,
    _image_free_service_names,
    _realize_node_subset,
    _strip_image_free_published_ports,
)
from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentPublishedPort,
    DeploymentRealizationSpec,
)


def _node(
    address: str, *, runtime=None, service_name=None, published_ports=()
) -> DeploymentNodeRealization:
    return DeploymentNodeRealization(
        address=address,
        name=address.rsplit(".", 1)[-1],
        service_name=service_name,
        container_name=None,
        networks=(),
        os="linux",
        runtime=runtime,
        published_ports=published_ports,
    )


def _spec(nodes: tuple[DeploymentNodeRealization, ...]) -> DeploymentRealizationSpec:
    return DeploymentRealizationSpec(profiles=(), nodes=nodes, networks=())


class TestImageFreeNodeAddresses:
    def test_only_runtime_declaring_nodes_are_included(self):
        free = _node("provision.node.free", runtime=RuntimeConfiguration())
        legacy = _node("provision.node.legacy", runtime=None)
        addresses = _image_free_node_addresses(_spec((free, legacy)))
        assert addresses == frozenset({"provision.node.free"})

    def test_empty_when_nothing_declares_runtime(self):
        legacy = _node("provision.node.legacy", runtime=None)
        assert _image_free_node_addresses(_spec((legacy,))) == frozenset()


class TestImageFreeServiceNames:
    def test_returns_service_names_of_image_free_nodes_only(self):
        free = _node(
            "provision.node.free", runtime=RuntimeConfiguration(), service_name="free"
        )
        legacy = _node("provision.node.legacy", runtime=None, service_name="legacy")
        spec = _spec((free, legacy))
        names = _image_free_service_names(spec, _image_free_node_addresses(spec))
        assert names == ("free",)

    def test_image_free_node_without_a_compose_service_is_skipped(self):
        # A brand-new node with no legacy Compose definition at all (e.g. one
        # authored only after the image-free cutover) has nothing to exclude.
        free = _node("provision.node.free", runtime=RuntimeConfiguration(), service_name=None)
        spec = _spec((free,))
        names = _image_free_service_names(spec, _image_free_node_addresses(spec))
        assert names == ()

    def test_names_are_sorted_for_deterministic_argv(self):
        b = _node(
            "provision.node.b", runtime=RuntimeConfiguration(), service_name="b-service"
        )
        a = _node(
            "provision.node.a", runtime=RuntimeConfiguration(), service_name="a-service"
        )
        spec = _spec((b, a))
        names = _image_free_service_names(spec, _image_free_node_addresses(spec))
        assert names == ("a-service", "b-service")


class TestStripImageFreePublishedPorts:
    """An image-free node's declared host ports are already bound by its own
    `docker run -p` during image-free materialization, which runs before the
    legacy Compose pipeline's own published-port conflict check and Compose
    port override. Left alone, those would re-probe the same host port
    their own earlier stage already bound and fail realize() on a false
    conflict with itself (issue #581, caught only by a real local boot)."""

    def test_image_free_node_published_ports_are_cleared(self):
        free = _node(
            "provision.node.webapp",
            runtime=RuntimeConfiguration(),
            service_name="webapp",
            published_ports=(DeploymentPublishedPort(container_port=8080, host_port=8080),),
        )
        spec = _spec((free,))

        result = _strip_image_free_published_ports(spec, frozenset({"provision.node.webapp"}))

        assert result.nodes[0].published_ports == ()

    def test_compose_managed_node_published_ports_are_untouched(self):
        legacy = _node(
            "provision.node.kali-ssh-proxy",
            runtime=None,
            service_name="kali-ssh-proxy",
            published_ports=(DeploymentPublishedPort(container_port=2023, host_port=2023),),
        )
        spec = _spec((legacy,))

        result = _strip_image_free_published_ports(spec, frozenset())

        assert result.nodes[0].published_ports == legacy.published_ports

    def test_other_node_fields_are_preserved(self):
        free = _node(
            "provision.node.webapp",
            runtime=RuntimeConfiguration(),
            service_name="webapp",
            published_ports=(DeploymentPublishedPort(container_port=8080, host_port=8080),),
        )
        spec = _spec((free,))

        result = _strip_image_free_published_ports(spec, frozenset({"provision.node.webapp"}))

        assert result.nodes[0].service_name == "webapp"
        assert result.nodes[0].runtime is free.runtime


class _FakeBaseImageBackend:
    """Minimal backend fake exercising _realize_node_subset's up-front
    image-ensuring loop. container_exec/start_base_container/
    copy_into_container are permissive no-ops that satisfy whatever the
    rest of materialization asks of them (enabling/starting a service
    unit), so a passing build check can observe materialization actually
    proceeding, not just that nothing raised."""

    def __init__(self, build_failures):
        self._build_failures = build_failures
        self.ensure_calls: list[str] = []
        self.container_exec_calls: list[list[str]] = []

    project_dir = None

    def ensure_generic_base_image(self, image_ref: str) -> list[str]:
        self.ensure_calls.append(image_ref)
        return list(self._build_failures.get(image_ref, ()))

    def start_base_container(self, spec) -> None:
        pass

    def copy_into_container(self, container, source_path, dest_path, is_directory) -> None:
        pass

    def container_exec(self, name: str, argv: list[str]):
        import subprocess

        self.container_exec_calls.append(argv)
        stdout = ""
        if argv[:2] == ["systemctl", "is-active"]:
            stdout = "active"
        elif argv[:2] == ["systemctl", "is-enabled"]:
            stdout = "enabled"
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout=stdout, stderr="")


class TestRealizeNodeSubsetEnsuresGenericBaseImages:
    """A fresh machine has none of the locally-built generic base images
    (aptl/generic-systemd-base-debian, aptl/generic-systemd-base) in its
    Docker cache — masked for a long-lived dev machine, but a hard `aptl lab
    start` failure on a genuinely fresh one (issue #581, caught only by a
    real boot on a brand-new VM, not any prior unit test)."""

    def test_needed_images_are_deduped_across_nodes(self):
        service_unit = ServiceManagerUnit(
            unit_id="svc", unit_name="svc.service", active_state="active"
        )
        webapp = _node(
            "provision.node.webapp",
            runtime=RuntimeConfiguration(service_manager_units=[service_unit]),
        )
        dns = _node(
            "provision.node.dns",
            runtime=RuntimeConfiguration(service_manager_units=[service_unit]),
        )
        backend = _FakeBaseImageBackend(build_failures={})

        result = _realize_node_subset(backend, (webapp, dns), ())

        assert result is None
        assert backend.ensure_calls == ["aptl/generic-systemd-base-debian:latest"]

    def test_build_failure_short_circuits_before_any_node_materializes(self):
        service_unit = ServiceManagerUnit(
            unit_id="svc", unit_name="svc.service", active_state="active"
        )
        db = _node(
            "provision.node.db",
            runtime=RuntimeConfiguration(service_manager_units=[service_unit]),
        )
        backend = _FakeBaseImageBackend(
            build_failures={
                "aptl/generic-systemd-base-debian:latest": [
                    "failed to build generic base image aptl/generic-systemd-base-debian:latest"
                ]
            }
        )

        result = _realize_node_subset(backend, (db,), ())

        assert result is not None
        assert result.success is False
        assert "aptl/generic-systemd-base-debian:latest" in result.error
