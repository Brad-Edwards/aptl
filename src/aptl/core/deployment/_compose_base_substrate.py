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

from typing import TYPE_CHECKING

from aptl.core.deployment.errors import BackendSeedError, BackendTimeoutError

if TYPE_CHECKING:
    from aptl.backends.aces_base_substrate import BaseContainerSpec, InitRequirements

# Every OS-family/service-manager combination `base_image_for_os`
# (src/aptl/backends/aces_materializer.py) can select for a runs_services
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
        if build_context is None:
            return []
        inspect_result = self._run(["docker", "image", "inspect", image_ref], timeout=30)
        if inspect_result.returncode == 0:
            return []
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
            return [f"failed to build generic base image {image_ref}"]
        return []

    def start_base_container(self, spec: "BaseContainerSpec") -> None:
        """Start a node's generic base container (ADR-048).

        Runs the generic base image with the validated init requirements when the
        node declares service units (host cgroup ns, cgroupfs rw, tmpfs,
        capabilities, unconfined seccomp, systemd as PID 1). A node with no
        service units runs the base with a keepalive so the materializer can exec
        into it. Idempotent: any stale container of the same name is removed
        first. Raises on failure so the materialization engine translates it into
        the ACES `LabResult` envelope.
        """

        self._run(["docker", "rm", "-f", spec.container_name])
        argv = [
            "docker",
            "run",
            "-d",
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
        for mount in spec.volume_mounts:
            source = f"{self._project_name}_{mount.source}"
            suffix = ":ro" if mount.read_only else ""
            argv += ["-v", f"{source}:{mount.target}{suffix}"]
        for port in spec.published_ports:
            host = f"{port.host_ip}:" if port.host_ip else ""
            host_port = port.host_port if port.host_port is not None else port.container_port
            argv += ["-p", f"{host}{host_port}:{port.container_port}/{port.protocol}"]
        if spec.init is not None:
            argv += _init_run_flags(spec.init)
            # The base image's own CMD runs systemd as init.
            argv.append(spec.image_ref)
        else:
            argv += [spec.image_ref, "sleep", "infinity"]
        result = self._run(argv, timeout=180)
        if result.returncode != 0:
            raise BackendSeedError(
                f"failed to start base container for node {spec.node_address}"
            )

    def copy_into_container(
        self, container: str, source_path: str, dest_path: str, is_directory: bool
    ) -> None:
        """Copy a checked-in project source into a container (ADR-048).

        For a directory, the source's contents are placed at ``dest_path``;
        for a file, ``dest_path`` is the file. Raises on failure so the
        materialization engine translates it into the ACES envelope.
        """

        source = f"{source_path}/." if is_directory else source_path
        result = self._run(["docker", "cp", source, f"{container}:{dest_path}"], timeout=120)
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
        if result.returncode != 0:
            return [f"failed to remove generic-materializer containers: {result.stderr.strip()}"]
        return []
