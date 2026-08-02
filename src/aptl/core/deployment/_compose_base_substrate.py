"""Generic base-container start/copy for image-free node materialization.

Split out of ``docker_compose.py`` (module-length budget) as a mixin so the
deployment backend stays under the size limit. ``ComposeBaseSubstrateMixin``
is mixed into ``DockerComposeBackend``, which supplies ``_run`` and
``_project_name``.

ADR-048: an image-free node is realized onto a generic base-OS container,
never an appliance image. These two operations are the Docker mechanics the
generic materializer needs from a backend: start the base container with the
declared init requirements, and copy checked-in project content into it.
"""

from __future__ import annotations

import os
import stat

from aptl.core.env import load_dotenv

import subprocess
from typing import TYPE_CHECKING

from aptl.core.deployment._compose_realization_networks import (
    _match_managed_network,
)
from aptl.core.deployment.errors import BackendSeedError, BackendTimeoutError
from aptl.core.deployment.realization import DeploymentNetworkAttachment

if TYPE_CHECKING:
    from aptl.backends.raes_base_substrate import BaseContainerSpec, InitRequirements

# Every OS-family/service-manager combination `base_image_for_os`
# (src/aptl/backends/raes_materializer.py) can select for a runs_services
# node, mapped to the checked-in Dockerfile that builds it. These are the
# ONLY generic base images that need a local build: the non-service images
# (debian:12-slim, rockylinux:9) are real registry images `docker run`
# already pulls on demand. Never built anywhere in the codebase before
# issue #581 surfaced it via a fresh-machine boot (a developer's existing
# local image cache had silently masked the gap since ADR-048 shipped).
_GENERIC_BASE_IMAGE_BUILD_CONTEXTS: dict[str, str] = {
    "aptl/generic-systemd-base-debian:latest": "containers/generic-systemd-base-debian",
    "aptl/generic-systemd-base:latest": "containers/generic-systemd-base",
}


def _init_run_flags(init: "InitRequirements") -> list[str]:
    """Build the `docker run` flags a systemd-capable base container needs."""

    flags: list[str] = []
    if init.cgroup_host:
        flags.append("--cgroupns=host")
    if init.cgroupfs_rw_mount:
        flags += ["-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw"]
    for path in init.tmpfs:
        flags += ["--tmpfs", path]
    for capability in init.capabilities:
        flags += ["--cap-add", capability]
    if init.seccomp_unconfined:
        flags += ["--security-opt", "seccomp:unconfined"]
    for env_name, env_value in init.env:
        flags += ["-e", f"{env_name}={env_value}"]
    if init.stop_signal:
        flags += ["--stop-signal", init.stop_signal]
    return flags


class ComposeBaseSubstrateMixin(object):
    """Start a node's generic base container and copy content into it (ADR-048).

    Mixed into ``DockerComposeBackend``, which supplies the ``_run`` subprocess
    runner, the ``_project_name`` attribute, and (for image builds)
    ``_project_dir``.
    """

    def ensure_generic_base_image(self, image_ref: str) -> list[str]:
        """Build a locally-built generic base image if it is not already present.

        A no-op for any image not in ``_GENERIC_BASE_IMAGE_BUILD_CONTEXTS``
        (a real registry reference like ``debian:12-slim`` needs no local
        build; ``docker run`` pulls it on demand).
        """

        build_context = _GENERIC_BASE_IMAGE_BUILD_CONTEXTS.get(image_ref)
        failures: list[str] = []
        if build_context is None and not self._offline_staged:
            return failures
        inspect_result = self._run(
            ["docker", "image", "inspect", image_ref], timeout=30
        )
        if inspect_result.returncode != 0:
            if self._offline_staged:
                failures.append(
                    f"required staged generic base image is missing: {image_ref}"
                )
            elif build_context is not None:
                build_result = self._run(
                    [
                        "docker",
                        "build",
                        "-t",
                        image_ref,
                        str(self._project_dir / build_context),
                    ],
                    timeout=600,
                )
                if build_result.returncode != 0:
                    failures.append(f"failed to build generic base image {image_ref}")
        return failures

    def start_base_container(self, spec: "BaseContainerSpec") -> None:
        """Start a node's generic base container (ADR-048).

        Runs the generic base image with the validated init requirements when the
        node declares service units (host cgroup ns, cgroupfs rw, tmpfs,
        capabilities, unconfined seccomp, systemd as PID 1). A node with no
        service units runs the base with a keepalive so the materializer can exec
        into it. Idempotent: any stale container of the same name is removed
        first. Raises on failure so the materialization engine translates it into
        the RAES `LabResult` envelope.
        """

        network_bindings = getattr(self, "_base_networks_by_address", {}).get(
            spec.node_address
        )
        run_image_ref = self._resolve_base_run_image(spec)
        if self._base_container_already_realized(spec, run_image_ref):
            # Idempotent: a node that already materialized correctly is left in
            # place. `aptl lab start` retries a single SOC backend-start failure
            # by re-running the whole admitted plan, which re-enters node
            # materialization. Tearing the container down and recreating it would
            # drop the project networks the post-start reconcile
            # (_reconcile_realization_networks) attached -- the container is
            # recreated on the default bridge -- and if that retry then fails or
            # times out before its own reconcile runs, the node is left stranded
            # on bridge with no scenario network (the attacker among them). The
            # retry only fires after materialization already succeeded, so the
            # existing container is known-good; the caller's remaining
            # materialization ops run against it idempotently.
            return
        self._run(["docker", "rm", "-f", spec.container_name])
        argv = self._base_container_create_command(spec, network_bindings, run_image_ref)
        result = self._run(argv, timeout=180)
        self._complete_base_container_start(spec, network_bindings, result)

    def _resolve_base_run_image(self, spec: "BaseContainerSpec") -> str:
        """Return the exact image reference a node's base container runs from.

        For an ordinary node that is the declared base image ref: `docker run`
        resolves the tag and pulls it on demand. A dynamic-composition node
        (ADR-051 route 3, issue #876) must instead run the precise config id the
        AVAILABILITY pass already verified for this address, carried in as
        request-scoped apply context (:meth:`realize`'s ``substrate_digests``).
        Starting that immutable config id with ``--pull=never`` closes the
        availability-to-apply gap the cycle-6 review flagged: the tag may have
        moved since, but the bytes are addressed by digest, so the wrong image
        can never start; if that digest is no longer present the start fails
        closed (a changed substrate produces no container) rather than resolving
        the mutable tag a second time.
        """

        if not spec.dynamic_composition:
            return spec.image_ref
        verified = getattr(self, "_realization_substrate_digests", {}).get(
            spec.node_address
        )
        if not verified:
            raise BackendSeedError(
                "dynamic-composition substrate for node "
                f"{spec.node_address} was not verified by availability; refusing "
                "to resolve the mutable tag at start (ADR-051 route 3)"
            )
        return verified

    def _base_container_already_realized(
        self, spec: "BaseContainerSpec", run_image_ref: str
    ) -> bool:
        """Return whether this node's base container is already up on its image.

        True only when a container of the exact name is running the exact image
        the spec calls for — ``run_image_ref``, which for a dynamic-composition
        node is the verified config id (the value ``docker run`` recorded as
        ``Config.Image``), and for an ordinary node is the declared tag. A
        stopped, missing, or wrong-image container returns False so it is
        recreated cleanly. Network attachments are deliberately not part of the
        test: the post-start reconcile owns them, and a preserved container keeps
        whatever it already had.
        """

        try:
            info = self.container_inspect(spec.container_name)
        # inspect shells out; treat any error as the container being absent.
        except Exception:
            return False
        if not isinstance(info, dict):
            return False
        state = info.get("State")
        running = isinstance(state, dict) and bool(state.get("Running"))
        config = info.get("Config")
        image = config.get("Image") if isinstance(config, dict) else None
        return running and image == run_image_ref

    def _base_container_create_command(
        self,
        spec: "BaseContainerSpec",
        network_bindings: (tuple[tuple[str, DeploymentNetworkAttachment], ...] | None),
        run_image_ref: str,
    ) -> list[str]:
        """Build a create/run command with exact declared network identity.

        ``run_image_ref`` is the resolved image the container starts from — the
        declared tag for an ordinary node, the verified config id for a
        dynamic-composition node (ADR-051 route 3, issue #876). A route-3 node
        also carries ``--pull=never`` so Docker runs only the bytes availability
        already verified are local, never a fresh fetch.
        """

        argv = [
            "docker",
            "create" if network_bindings is not None else "run",
            *(
                ["--pull=never"]
                if self._offline_staged or spec.dynamic_composition
                else []
            ),
            "--name",
            spec.container_name,
            "--label",
            f"aptl.lifecycle.project={self._project_name}",
            "--label",
            f"aptl.node.address={spec.node_address}",
            # Every project-ownership check (container_exists, the host
            # snapshot listing, observation) filters on this label - it is
            # Compose's own convention, not Compose-specific knowledge here:
            # a directly-run container is just as project-owned as a
            # Compose-started one, so it carries the same label (ADR-048).
            "--label",
            f"com.docker.compose.project={self._project_name}",
        ]
        if network_bindings is None:
            argv.insert(2, "-d")
        if network_bindings is not None:
            first_network, first_attachment = network_bindings[0]
            argv += ["--network", first_network]
            if first_attachment.ipv4_address:
                argv += ["--ip", first_attachment.ipv4_address]
        self._append_base_mounts(argv, spec)
        self._append_base_ports(argv, spec)
        self._append_base_environment(argv, spec)
        if spec.init is not None:
            argv += _init_run_flags(spec.init)
            # The base image's own CMD runs systemd as init.
            argv.append(run_image_ref)
        else:
            argv += [run_image_ref, "sleep", "infinity"]
        return argv

    def _project_dotenv(self) -> dict[str, str]:
        """Return the project's generated credential bindings, or nothing.

        Reuses the existing dotenv boundary rather than re-parsing the file, so
        quoting, comment, and validation behaviour stay in one place. A missing
        or unreadable file yields no bindings; the caller then omits those
        variables rather than binding them empty.
        """

        try:
            return load_dotenv(self._project_dir / ".env")
        except (OSError, ValueError):
            return {}

    def _append_base_environment(
        self, argv: list[str], spec: "BaseContainerSpec"
    ) -> None:
        """Bind a node's declared environment through a contained env file.

        The SDL declares *which* variables a node requires; their values come
        from the operator environment through the existing secret boundary. The
        binding is written to an owner-only file under the project's generated
        realization directory and passed as ``--env-file``, never as ``-e
        NAME=value``: a value on the command line would put credentials into
        process argv, where any local process can read them, and into anything
        that echoes the command.

        A declared variable absent from the environment is omitted rather than
        bound empty, so the container fails on its own missing-configuration
        path instead of starting with a silently blank credential.
        """

        if not spec.environment_names:
            return
        # Values come from the project's own credential boundary first: APTL
        # keeps them in the generated `.env`, which is never exported into this
        # process. A real process-environment entry still wins, so an operator
        # can override one variable without editing generated credentials.
        # Precedence: an operator's process environment, then the project's
        # generated credentials, then the scenario's authored non-secret
        # default. The author supplies what is safe to write down; the
        # credential boundary supplies what is not.
        available = {
            **dict(spec.environment_defaults),
            **self._project_dotenv(),
            **os.environ,
        }
        bindings = {
            name: available[name]
            for name in spec.environment_names
            if name in available
        }
        if not bindings:
            return
        env_dir = self._project_dir / ".aptl" / "realization" / "env"
        env_dir.mkdir(parents=True, exist_ok=True)
        env_path = env_dir / f"{spec.container_name}.env"
        # Create restricted before writing so the values are never briefly
        # world-readable between creation and chmod.
        descriptor = os.open(
            env_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            for name, value in bindings.items():
                handle.write(f"{name}={value}\n")
        argv.extend(("--env-file", str(env_path)))

    def _append_base_mounts(self, argv: list[str], spec: "BaseContainerSpec") -> None:
        """Append declared named-volume mounts to a base-container command."""

        for mount in spec.volume_mounts:
            source = f"{self._project_name}_{mount.source}"
            suffix = ":ro" if mount.read_only else ""
            argv.extend(("-v", f"{source}:{mount.target}{suffix}"))

    @staticmethod
    def _append_base_ports(argv: list[str], spec: "BaseContainerSpec") -> None:
        """Append exact declared host publications to a base-container command."""

        for port in spec.published_ports:
            host = f"{port.host_ip}:" if port.host_ip else ""
            host_port = (
                port.host_port if port.host_port is not None else port.container_port
            )
            argv.extend(
                ("-p", f"{host}{host_port}:{port.container_port}/{port.protocol}")
            )

    def _complete_base_container_start(
        self,
        spec: "BaseContainerSpec",
        network_bindings: (tuple[tuple[str, DeploymentNetworkAttachment], ...] | None),
        result: subprocess.CompletedProcess,
    ) -> None:
        """Attach remaining admitted networks, start, and clean failed creates."""

        if result.returncode == 0 and network_bindings is not None:
            result = self._attach_and_start_base_container(
                spec.container_name,
                network_bindings[1:],
            )
        if result.returncode != 0:
            if network_bindings is not None:
                self._run(["docker", "rm", "-f", spec.container_name], timeout=30)
            raise BackendSeedError(
                f"failed to start base container for node {spec.node_address}"
            )

    def _attach_and_start_base_container(
        self,
        container_name: str,
        bindings: tuple[tuple[str, DeploymentNetworkAttachment], ...],
    ) -> subprocess.CompletedProcess:
        """Attach only admitted networks to a stopped node, then start it."""

        for concrete, attachment in bindings:
            connected = self.connect_container_network(
                container_name,
                concrete,
                ipv4_address=attachment.ipv4_address,
            )
            if not connected.success:
                return subprocess.CompletedProcess(
                    args=["docker", "network", "connect"],
                    returncode=1,
                )
        return self._run(["docker", "start", container_name], timeout=60)

    def copy_into_container(
        self, container: str, source_path: str, dest_path: str, is_directory: bool
    ) -> None:
        """Copy a checked-in project source into a container (ADR-048).

        For a directory, the source's contents are placed at ``dest_path``;
        for a file, ``dest_path`` is the file. Raises on failure so the
        materialization engine translates it into the RAES envelope.
        """

        source = f"{source_path}/." if is_directory else source_path
        result = self._run(
            ["docker", "cp", source, f"{container}:{dest_path}"], timeout=120
        )
        if result.returncode != 0:
            raise BackendSeedError(
                f"failed to copy project content into container {container}"
            )

    def remove_generic_materializer_containers(self) -> list[str]:
        """Force-remove every container the generic materializer started (ADR-048).

        `docker compose down` only tears down containers Compose itself
        started; a node the generic materializer realized directly (a plain
        `docker run`) is invisible to it, so stopping the lab would otherwise
        leave those containers running - attached to the very networks/
        volumes the rest of cleanup needs to remove, failing that cleanup
        outright. Discovered by ``aptl.lifecycle.project``, the label
        ``start_base_container`` sets on every one of its containers, never
        by name pattern. Returns one failure message per container that
        could not be removed, empty when clean.
        """

        try:
            list_result = self._run(
                [
                    "docker",
                    "ps",
                    "-aq",
                    "--filter",
                    f"label=aptl.lifecycle.project={self._project_name}",
                ],
                timeout=30,
            )
            names = [line for line in list_result.stdout.splitlines() if line.strip()]
            if not names:
                return []
            result = self._run(["docker", "rm", "-f", *names], timeout=60)
        except (BackendTimeoutError, OSError) as exc:
            return [f"failed to remove generic-materializer containers: {exc}"]
        return (
            []
            if result.returncode == 0
            else [
                f"failed to remove generic-materializer containers: {result.stderr.strip()}"
            ]
        )

    def configure_base_container_networks(self, nodes: tuple[object, ...]) -> None:
        """Bind image-free nodes to admitted networks before they are created."""

        strict = getattr(
            self, "_appliance_boundary", None
        ) is not None or "raes" in getattr(self, "_boundary_receipts", {})
        if not strict:
            self._base_networks_by_address = {}
            return
        managed = set(self.host_list_lab_networks(self._project_name))
        bindings: dict[str, tuple[tuple[str, DeploymentNetworkAttachment], ...]] = {}
        for node in nodes:
            attachments = getattr(node, "network_attachments", ())
            resolved: list[tuple[str, DeploymentNetworkAttachment]] = []
            for attachment in attachments:
                concrete = _match_managed_network(
                    attachment.network,
                    managed,
                    self._project_name,
                )
                if concrete is None:
                    raise BackendSeedError(
                        "image-free node network binding was not observed"
                    )
                resolved.append((concrete, attachment))
            if resolved:
                bindings[getattr(node, "address")] = tuple(resolved)
            elif getattr(self, "_appliance_boundary", None) is not None:
                raise BackendSeedError(
                    "appliance image-free node has no admitted network"
                )
        self._base_networks_by_address = bindings
