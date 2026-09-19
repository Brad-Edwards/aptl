"""Tests for the Compose backend's generic base-container mixin (ADR-048).

start_base_container runs a plain `docker run`, never `docker compose up` -
so every project-ownership check that filters containers by the
`com.docker.compose.project` label (container_exists, the host snapshot
listing, observation) would otherwise never see a node the generic
materializer realized directly. Caught by a real local live-gate boot of
the full TechVault range, not by any unit test - this file exists so it
cannot regress silently again.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aptl.backends.raes_base_substrate import (
    BaseContainerSpec,
    InitRequirements,
    PublishedPort,
    VolumeMount,
)
from aptl.core.deployment import (
    DeploymentNetworkAttachment,
    DockerComposeBackend,
)
from aptl.core.deployment.errors import BackendSeedError
from aptl.core.deployment._compose_resource_ownership import ResourceReceipt
from aptl.core.lab_types import LabResult


def _backend(tmp_path: Path) -> DockerComposeBackend:
    backend = DockerComposeBackend(project_dir=tmp_path, project_name="test-proj")
    backend._docker_daemon_id = "test-daemon"
    return backend


# A stand-in for the substrate's image config id — the sha256 domain
# `docker image inspect --format {{.Id}}` reports and `docker run <id>` records
# as the container's ``Config.Image``.
_CONFIG_ID = "sha256:" + "a" * 64
_CONTAINER_ID = "b" * 64


class TestEnsureGenericBaseImage:
    """A fresh machine has none of the locally-built generic base images in
    its Docker cache — a developer's own long-lived cache silently masked
    this gap since ADR-048 shipped, until a real fresh-machine boot (issue
    #581) surfaced it as a hard `aptl lab start` failure on node 'db'."""

    def test_builds_the_image_when_missing(self, tmp_path):
        backend = _backend(tmp_path)

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:3] == ["docker", "image", "inspect"]:
                return MagicMock(returncode=1, stdout="", stderr="No such image")
            return MagicMock(returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr="")

        with patch("subprocess.run", side_effect=fake_run) as mock_run:
            failures = backend.ensure_generic_base_image(
                "aptl/generic-systemd-base-debian:latest"
            )

        assert failures == []
        build_call = next(
            c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "build"]
        )
        argv = build_call.args[0]
        assert argv[:4] == [
            "docker",
            "build",
            "-t",
            "aptl/generic-systemd-base-debian:latest",
        ]
        assert argv[-1] == str(tmp_path)

    def test_rebuilds_even_when_the_tag_already_exists(self, tmp_path):
        """Presence of `aptl/...:latest` is not evidence of freshness.

        Skipping the build when the tag existed pinned every install to the
        substrate it first built, so an advanced base image or a patched layer
        never reached a machine that had already started a lab. Docker's layer
        cache keeps the unchanged case cheap (issue #1006).
        """
        backend = _backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
            )
            failures = backend.ensure_generic_base_image(
                "aptl/generic-systemd-base-debian:latest"
            )

        assert failures == []
        assert any(
            c.args[0][:2] == ["docker", "build"] for c in mock_run.call_args_list
        )

    def test_no_op_for_a_real_registry_image(self, tmp_path):
        # debian:13-slim / rockylinux:9 are real registry references; `docker
        # run` pulls them on demand, so this must never attempt to build them.
        backend = _backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            failures = backend.ensure_generic_base_image("debian:13-slim")

        assert failures == []
        mock_run.assert_not_called()

    def test_build_failure_is_reported_not_raised(self, tmp_path):
        backend = _backend(tmp_path)

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:3] == ["docker", "image", "inspect"]:
                return MagicMock(returncode=1, stdout="", stderr="No such image")
            return MagicMock(returncode=1, stdout="", stderr="Dockerfile not found")

        with patch("subprocess.run", side_effect=fake_run):
            failures = backend.ensure_generic_base_image(
                "aptl/generic-systemd-base-debian:latest"
            )

        assert failures
        assert "aptl/generic-systemd-base-debian:latest" in failures[0]

    def test_builds_backend_selected_node22_systemd_base(self, tmp_path):
        backend = _backend(tmp_path)

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:3] == ["docker", "image", "inspect"]:
                return MagicMock(returncode=1, stdout="", stderr="No such image")
            return MagicMock(returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr="")

        with patch("subprocess.run", side_effect=fake_run) as mock_run:
            failures = backend.ensure_generic_base_image(
                "aptl/generic-systemd-node22-base:latest"
            )

        assert failures == []
        build_call = next(
            call
            for call in mock_run.call_args_list
            if call.args[0][:2] == ["docker", "build"]
        )
        assert build_call.args[0][-1] == str(tmp_path)

    def test_builds_backend_selected_samba_provider_base(self, tmp_path):
        backend = _backend(tmp_path)

        def fake_run(cmd, **kwargs):
            del kwargs
            if cmd[:3] == ["docker", "image", "inspect"]:
                return MagicMock(returncode=1, stdout="", stderr="No such image")
            return MagicMock(returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr="")

        with patch("subprocess.run", side_effect=fake_run) as mock_run:
            failures = backend.ensure_generic_base_image(
                "aptl/generic-samba-ad-base:latest"
            )

        assert failures == []
        build_call = next(
            call
            for call in mock_run.call_args_list
            if call.args[0][:2] == ["docker", "build"]
        )
        assert build_call.args[0][-1] == str(
            tmp_path / "containers" / "generic-samba-ad-base"
        )


def test_start_base_container_carries_the_compose_project_ownership_label(tmp_path):
    backend = _backend(tmp_path)
    spec = BaseContainerSpec(
        node_address="provision.node.victim",
        container_name="aptl-victim",
        image_ref="debian:13-slim",
        runs_services=False,
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
        )
        backend.start_base_container(spec)

    run_call = next(
        c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"]
    )
    argv = run_call.args[0]
    assert "--label" in argv
    assert f"com.docker.compose.project={backend.project_name}" in argv
    # container_exists/host snapshot listing key on this exact label+value -
    # any other project's containers on a shared daemon must not match.
    assert f"com.docker.compose.project={backend.project_name}" in argv


def test_start_base_container_keeps_the_aptl_lifecycle_labels(tmp_path):
    backend = _backend(tmp_path)
    spec = BaseContainerSpec(
        node_address="provision.node.victim",
        container_name="aptl-victim",
        image_ref="debian:13-slim",
        runs_services=False,
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
        )
        backend.start_base_container(spec)

    run_call = next(
        c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"]
    )
    argv = run_call.args[0]
    assert f"aptl.lifecycle.project={backend.project_name}" in argv
    assert "aptl.node.address=provision.node.victim" in argv


def test_start_base_container_can_retain_the_provider_image_command(tmp_path):
    backend = _backend(tmp_path)
    spec = BaseContainerSpec(
        node_address="provision.node.ad",
        container_name="aptl-ad",
        image_ref="aptl/generic-samba-ad-base:latest",
        runs_services=False,
        use_image_command=True,
        backend_run_capabilities=("SYS_ADMIN",),
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
        )
        backend.start_base_container(spec)

    run_call = next(
        c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"]
    )
    argv = run_call.args[0]
    image_index = argv.index("aptl/generic-samba-ad-base:latest")
    assert argv[image_index:] == ["aptl/generic-samba-ad-base:latest"]
    assert argv[image_index - 2 : image_index] == ["--cap-add", "SYS_ADMIN"]


def test_start_base_container_with_init_still_carries_the_label(tmp_path):
    backend = _backend(tmp_path)
    spec = BaseContainerSpec(
        node_address="provision.node.kali",
        container_name="aptl-kali",
        image_ref="aptl/generic-systemd-base-debian:latest",
        runs_services=True,
        init=InitRequirements(),
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
        )
        backend.start_base_container(spec)

    run_call = next(
        c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"]
    )
    argv = run_call.args[0]
    assert f"com.docker.compose.project={backend.project_name}" in argv
    assert "seccomp:unconfined" in argv
    assert "apparmor:unconfined" in argv


def test_declared_network_is_attached_before_image_free_node_starts(tmp_path):
    backend = _backend(tmp_path)
    backend._ensure_resource_ownership(attempt_id="run-a")
    backend._appliance_boundary = (MagicMock(), MagicMock())
    node = MagicMock(
        address="provision.node.kali",
        network_attachments=(
            DeploymentNetworkAttachment(
                network="security",
                ipv4_address="172.31.8.10",
            ),
        ),
    )
    backend.host_list_lab_networks = MagicMock(
        return_value=[f"{backend.project_name}_aptl-security"]
    )
    backend.connect_container_network = MagicMock(return_value=LabResult(success=True))
    backend.configure_base_container_networks((node,))
    spec = BaseContainerSpec(
        node_address=node.address,
        container_name="aptl-kali",
        image_ref="debian:13-slim",
        runs_services=False,
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
        )
        backend.start_base_container(spec)

    create = next(
        call
        for call in mock_run.call_args_list
        if call.args[0][:2] == ["docker", "create"]
    )
    assert "--network" in create.args[0]
    assert f"{backend.project_name}_aptl-security" in create.args[0]
    assert "--ip" in create.args[0]
    assert "172.31.8.10" in create.args[0]
    assert "none" not in create.args[0]
    assert ["docker", "start", _CONTAINER_ID] in [
        call.args[0] for call in mock_run.call_args_list
    ]
    assert not any(
        call.args[0][:2] == ["docker", "run"] for call in mock_run.call_args_list
    )


def test_materialization_is_idempotent_for_an_already_running_node(tmp_path):
    """A retry must not tear down a node that already materialized correctly.

    `aptl lab start` retries a single SOC backend-start failure by re-running the
    whole admitted plan, re-entering node materialization. If it recreated an
    already-good base container, the container would come back on the default
    bridge and lose the project networks the post-start reconcile attached --
    stranding the node (the attacker among them) when the retry then fails before
    its own reconcile runs. So an existing, running container on the expected
    image is left in place.
    """

    backend = _backend(tmp_path)
    spec = BaseContainerSpec(
        node_address="provision.node.kali",
        container_name="aptl-kali",
        image_ref="debian:13-slim",
        runs_services=False,
    )
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    external = ownership.container_name(spec.container_name)
    ownership.record(
        ResourceReceipt(
            kind="container",
            native_id=_CONTAINER_ID,
            external_name=external,
            semantic_name=spec.container_name,
            node_address=spec.node_address,
            workspace_id=ownership.workspace_id,
            project_name=ownership.project_name,
            daemon_id="test-daemon",
            attempt_id="run-a",
        )
    )
    backend._raw_container_inspect = MagicMock(
        return_value={
            "Id": _CONTAINER_ID,
            "Name": f"/{external}",
            "State": {"Running": True},
            "Config": {
                "Image": "debian:13-slim",
                "Labels": {
                    "aptl.workspace.id": ownership.workspace_id,
                    "aptl.lifecycle.project": ownership.project_name,
                },
            },
        }
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
        )
        backend.start_base_container(spec)

    # No teardown, no recreate: the running container keeps its networks.
    assert not any(
        call.args[0][:2] in (["docker", "rm"], ["docker", "run"], ["docker", "create"])
        for call in mock_run.call_args_list
    )


def test_materialization_recreates_a_stopped_or_wrong_image_node(tmp_path):
    """Idempotency is narrow: a stopped or wrong-image container is recreated.

    The skip only applies to a container that is genuinely up on the exact image
    the spec calls for. A crashed node, or one left from a different image, must
    be torn down and rebuilt rather than trusted.
    """

    backend = _backend(tmp_path)
    spec = BaseContainerSpec(
        node_address="provision.node.kali",
        container_name="aptl-kali",
        image_ref="debian:13-slim",
        runs_services=False,
    )
    # Present but not running -> must recreate.
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    external = ownership.container_name(spec.container_name)
    ownership.record(
        ResourceReceipt(
            kind="container",
            native_id=_CONTAINER_ID,
            external_name=external,
            semantic_name=spec.container_name,
            node_address=spec.node_address,
            workspace_id=ownership.workspace_id,
            project_name=ownership.project_name,
            daemon_id="test-daemon",
            attempt_id="run-a",
        )
    )
    backend._raw_container_inspect = MagicMock(
        return_value={
            "Id": _CONTAINER_ID,
            "Name": f"/{external}",
            "State": {"Running": False},
            "Config": {
                "Image": "debian:13-slim",
                "Labels": {
                    "aptl.workspace.id": ownership.workspace_id,
                    "aptl.lifecycle.project": ownership.project_name,
                },
            },
        }
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
        )
        backend.start_base_container(spec)

    assert any(call.args[0][:2] == ["docker", "rm"] for call in mock_run.call_args_list)
    assert any(
        call.args[0][:2] == ["docker", "run"] for call in mock_run.call_args_list
    )


def test_foreign_same_name_container_is_neither_adopted_nor_removed(tmp_path):
    """A name/image match is discovery evidence, never cleanup authority."""

    backend = _backend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    external = ownership.container_name("aptl-victim")
    spec = BaseContainerSpec(
        node_address="provision.node.victim",
        container_name="aptl-victim",
        image_ref="debian:13-slim",
        runs_services=False,
    )
    backend._raw_container_inspect = MagicMock(
        return_value={
            "Id": "f" * 64,
            "Name": f"/{external}",
            "State": {"Running": True},
            "Config": {
                "Image": "debian:13-slim",
                "Labels": {"aptl.workspace.id": "foreign-workspace"},
            },
        }
    )
    backend._run = MagicMock()

    with pytest.raises(BackendSeedError, match="resource ownership conflict"):
        backend.start_base_container(spec)

    backend._run.assert_not_called()


def test_base_container_records_native_id_and_uses_scoped_external_name(tmp_path):
    backend = _backend(tmp_path)
    backend._docker_daemon_id = "daemon-a"
    ownership = backend._ensure_resource_ownership(attempt_id="run-a")
    external = ownership.container_name("aptl-victim")
    spec = BaseContainerSpec(
        node_address="provision.node.victim",
        container_name="aptl-victim",
        image_ref="debian:13-slim",
        runs_services=False,
    )
    backend._raw_container_inspect = MagicMock(return_value={})
    backend._run = MagicMock(
        return_value=MagicMock(
            returncode=0,
            stdout=f"{_CONTAINER_ID}\n",
            stderr="",
        )
    )

    backend.start_base_container(spec)

    argv = backend._run.call_args.args[0]
    assert argv[:2] == ["docker", "run"]
    assert argv[argv.index("--name") + 1] == external
    assert argv[argv.index("--hostname") + 1] == "aptl-victim"
    assert f"aptl.workspace.id={ownership.workspace_id}" in argv
    assert "aptl.attempt.id=run-a" in argv
    assert not any(
        call.args[0][:2] == ["docker", "rm"] for call in backend._run.call_args_list
    )
    receipt = ownership.candidates(
        "aptl-victim", kind="container", daemon_id="daemon-a"
    )
    assert len(receipt) == 1
    assert receipt[0].native_id == _CONTAINER_ID
    assert receipt[0].external_name == external


def test_appliance_image_free_node_without_network_fails_before_create(
    tmp_path,
) -> None:
    backend = _backend(tmp_path)
    backend._appliance_boundary = (MagicMock(), MagicMock())
    node = MagicMock(
        address="provision.node.unbound",
        network_attachments=(),
    )
    backend.host_list_lab_networks = MagicMock(return_value=[])

    with pytest.raises(BackendSeedError, match="no admitted network"):
        backend.configure_base_container_networks((node,))


class TestStartBaseContainerVolumesAndPorts:
    """ADR-048/#581: a node materialized directly (never Compose-started)
    can still need a shared named volume or a host-published port — both
    come from typed SDL fields (``runtime.mounts`` / ``runtime.network.
    published_ports``), lowered onto ``BaseContainerSpec`` and then into
    ``docker run`` flags here."""

    def test_volume_mount_uses_the_project_scoped_volume_name(self, tmp_path):
        backend = _backend(tmp_path)
        backend._ensure_labeled_project_volume = MagicMock()
        spec = BaseContainerSpec(
            node_address="provision.node.misp-suricata-sync",
            container_name="aptl-misp-suricata-sync",
            image_ref="debian:13-slim",
            runs_services=False,
            volume_mounts=(
                VolumeMount(
                    target="/var/lib/suricata/rules/misp", source="suricata_misp_rules"
                ),
            ),
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
            )
            backend.start_base_container(spec)

        run_call = next(
            c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"]
        )
        argv = run_call.args[0]
        assert "-v" in argv
        assert (
            f"{backend.project_name}_suricata_misp_rules:/var/lib/suricata/rules/misp"
            in argv
        )
        backend._ensure_labeled_project_volume.assert_called_once_with(
            "suricata_misp_rules"
        )

    def test_read_only_volume_mount_appends_ro_suffix(self, tmp_path):
        backend = _backend(tmp_path)
        backend._ensure_labeled_project_volume = MagicMock()
        spec = BaseContainerSpec(
            node_address="provision.node.misp-suricata-sync",
            container_name="aptl-misp-suricata-sync",
            image_ref="debian:13-slim",
            runs_services=False,
            volume_mounts=(
                VolumeMount(
                    target="/var/run/suricata",
                    source="suricata_command_socket",
                    read_only=True,
                ),
            ),
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
            )
            backend.start_base_container(spec)

        run_call = next(
            c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"]
        )
        argv = run_call.args[0]
        assert (
            f"{backend.project_name}_suricata_command_socket:/var/run/suricata:ro"
            in argv
        )
        backend._ensure_labeled_project_volume.assert_called_once_with(
            "suricata_command_socket"
        )

    def test_published_port_defaults_host_port_to_container_port(self, tmp_path):
        backend = _backend(tmp_path)
        spec = BaseContainerSpec(
            node_address="provision.node.webapp",
            container_name="aptl-webapp",
            image_ref="debian:13-slim",
            runs_services=False,
            published_ports=(PublishedPort(container_port=8080),),
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
            )
            backend.start_base_container(spec)

        run_call = next(
            c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"]
        )
        argv = run_call.args[0]
        assert "-p" in argv
        assert "8080:8080/tcp" in argv

    def test_published_port_honours_explicit_host_ip_and_host_port(self, tmp_path):
        backend = _backend(tmp_path)
        spec = BaseContainerSpec(
            node_address="provision.node.dns",
            container_name="aptl-dns",
            image_ref="debian:13-slim",
            runs_services=False,
            published_ports=(
                PublishedPort(
                    container_port=53,
                    protocol="udp",
                    host_ip="127.0.0.1",
                    host_port=5353,
                ),
            ),
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
            )
            backend.start_base_container(spec)

        run_call = next(
            c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"]
        )
        argv = run_call.args[0]
        assert "127.0.0.1:5353:53/udp" in argv


class TestDynamicCompositionImmutableStart:
    """ADR-051 route 3 (issue #876): a dynamic-composition node's base container
    starts from the exact config id the AVAILABILITY pass verified for its
    address -- carried in as ``realize()`` apply context -- with ``--pull=never``,
    and NEVER by re-resolving the mutable tag at start (cycle-6 review). Starting
    an immutable config id closes the availability-to-apply gap: a tag that moved
    since cannot substitute other bytes, and a verified id that is gone produces
    no container.
    """

    def _spec(self, **overrides) -> BaseContainerSpec:
        base = dict(
            node_address="provision.node.web",
            container_name="aptl-web",
            image_ref="debian:13-slim",
            runs_services=False,
            dynamic_composition=True,
        )
        base.update(overrides)
        return BaseContainerSpec(**base)

    @staticmethod
    def _with_verified(backend, digest: str = _CONFIG_ID) -> None:
        """Seed the apply context ``realize()`` derives from availability facts."""
        backend._realization_substrate_digests = {"provision.node.web": digest}

    def test_starts_from_the_availability_verified_digest_not_the_tag(self, tmp_path):
        backend = _backend(tmp_path)
        self._with_verified(backend)
        spec = self._spec()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
            )
            backend.start_base_container(spec)

        run_call = next(
            c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"]
        )
        argv = run_call.args[0]
        # Never pulls, and runs the exact availability-verified config id -- the
        # declared tag never appears as the image argument.
        assert "--pull=never" in argv
        assert argv[-3:] == [_CONFIG_ID, "sleep", "infinity"]
        assert "debian:13-slim" not in argv
        # The mutable tag is never resolved at start: no `docker image inspect`.
        assert not any(
            c.args[0][:4] == ["docker", "image", "inspect", "--format"]
            for c in mock_run.call_args_list
        )

    def test_fails_closed_when_availability_did_not_verify_the_substrate(
        self, tmp_path
    ):
        # No verified digest for this address (the substrate was unobtainable at
        # availability, or changed away since): refuse to resolve the tag and
        # start nothing -- ADR-051's "a changed substrate produces no container".
        backend = _backend(tmp_path)
        spec = self._spec()  # apply context deliberately not seeded

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
            )
            with pytest.raises(BackendSeedError, match="not verified by availability"):
                backend.start_base_container(spec)

        assert not any(
            c.args[0][:2] in (["docker", "run"], ["docker", "create"])
            for c in mock_run.call_args_list
        )

    def test_idempotent_against_the_verified_digest_not_the_tag(self, tmp_path):
        backend = _backend(tmp_path)
        self._with_verified(backend)
        spec = self._spec()
        # Already up on the verified config id (what `docker run <id>` records as
        # ``Config.Image``) -- a retry must leave it in place.
        ownership = backend._ensure_resource_ownership(attempt_id="run-a")
        external = ownership.container_name(spec.container_name)
        ownership.record(
            ResourceReceipt(
                kind="container",
                native_id=_CONTAINER_ID,
                external_name=external,
                semantic_name=spec.container_name,
                node_address=spec.node_address,
                workspace_id=ownership.workspace_id,
                project_name=ownership.project_name,
                daemon_id="test-daemon",
                attempt_id="run-a",
            )
        )
        backend._raw_container_inspect = MagicMock(
            return_value={
                "Id": _CONTAINER_ID,
                "Name": f"/{external}",
                "State": {"Running": True},
                "Config": {
                    "Image": _CONFIG_ID,
                    "Labels": {
                        "aptl.workspace.id": ownership.workspace_id,
                        "aptl.lifecycle.project": ownership.project_name,
                    },
                },
            }
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
            )
            backend.start_base_container(spec)

        assert not any(
            call.args[0][:2]
            in (["docker", "rm"], ["docker", "run"], ["docker", "create"])
            for call in mock_run.call_args_list
        )

    def test_ordinary_node_runs_the_tag_and_never_forces_pull_never(self, tmp_path):
        # Contrast: an ordinary (non route-3) node keeps the on-demand pull of its
        # declared tag and consults no verified-digest apply context.
        backend = _backend(tmp_path)
        spec = self._spec(dynamic_composition=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
            )
            backend.start_base_container(spec)

        run_call = next(
            c for c in mock_run.call_args_list if c.args[0][:2] == ["docker", "run"]
        )
        argv = run_call.args[0]
        assert "--pull=never" not in argv
        assert argv[-3:] == ["debian:13-slim", "sleep", "infinity"]


class TestRemoveGenericMaterializerContainers:
    """`docker compose down`/`kill` never touch these - stop/kill must (P7).

    Discovered by a real live-gate boot: stopping the lab left every
    generic-materializer container running, attached to the project's
    networks, which then failed to remove with "network has active
    endpoints" - the whole stop/kill operation failed, not just a warning.
    """

    def test_never_queries_labels_when_no_receipts_exist(self, tmp_path):
        backend = _backend(tmp_path)
        with patch("subprocess.run") as mock_run:
            failures = backend.remove_generic_materializer_containers()

        assert failures == []
        mock_run.assert_not_called()

    def test_no_containers_is_a_clean_noop(self, tmp_path):
        backend = _backend(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=f"{_CONTAINER_ID}\n", stderr=""
            )
            failures = backend.remove_generic_materializer_containers()

        assert failures == []
        # No `docker rm` call at all when there is nothing to remove.
        assert not any(
            c.args[0][:2] == ["docker", "rm"] for c in mock_run.call_args_list
        )

    def test_removal_failure_is_reported_not_raised(self, tmp_path):
        backend = _backend(tmp_path)
        ownership = backend._ensure_resource_ownership(attempt_id="run-a")
        external = ownership.container_name("aptl-victim")
        ownership.record(
            ResourceReceipt(
                kind="container",
                native_id=_CONTAINER_ID,
                external_name=external,
                semantic_name="aptl-victim",
                node_address="provision.node.victim",
                workspace_id=ownership.workspace_id,
                project_name=ownership.project_name,
                daemon_id="test-daemon",
                attempt_id="run-a",
            )
        )
        backend._raw_container_inspect = MagicMock(
            return_value={
                "Id": _CONTAINER_ID,
                "Name": f"/{external}",
                "Config": {
                    "Labels": {
                        "aptl.workspace.id": ownership.workspace_id,
                        "aptl.lifecycle.project": ownership.project_name,
                    }
                },
            }
        )
        backend._run = MagicMock(
            return_value=MagicMock(returncode=1, stdout="", stderr="container in use")
        )

        assert backend.remove_generic_materializer_containers() == [
            "failed to remove receipt-owned container"
        ]

    def test_docker_unavailable_is_reported_not_raised(self, tmp_path):
        # kill_compose_lab's own tests hit this exact path: every subprocess
        # call fails, and the whole operation must still return gracefully.
        backend = _backend(tmp_path)

        ownership = backend._ensure_resource_ownership(attempt_id="run-a")
        external = ownership.container_name("aptl-victim")
        ownership.record(
            ResourceReceipt(
                kind="container",
                native_id=_CONTAINER_ID,
                external_name=external,
                semantic_name="aptl-victim",
                node_address="provision.node.victim",
                workspace_id=ownership.workspace_id,
                project_name=ownership.project_name,
                daemon_id="test-daemon",
                attempt_id="run-a",
            )
        )
        backend._raw_container_inspect = MagicMock(
            return_value={
                "Id": _CONTAINER_ID,
                "Name": f"/{external}",
                "Config": {
                    "Labels": {
                        "aptl.workspace.id": ownership.workspace_id,
                        "aptl.lifecycle.project": ownership.project_name,
                    }
                },
            }
        )
        backend._run = MagicMock(side_effect=FileNotFoundError("docker not found"))

        assert backend.remove_generic_materializer_containers() == [
            "failed to establish container cleanup authority"
        ]
