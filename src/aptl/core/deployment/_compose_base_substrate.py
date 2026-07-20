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

from aptl.core.deployment.errors import BackendSeedError

if TYPE_CHECKING:
    from aptl.backends.aces_base_substrate import BaseContainerSpec, InitRequirements


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
    runner and the ``_project_name`` attribute that the methods below depend on.
    """

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
        ]
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
