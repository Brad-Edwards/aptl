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
from aptl.core.deployment._compose_substrate_gate import (
    WRITABLE_CGROUPS_OPTION,
    require_substrate_daemon_support,
)
from aptl.core.deployment.errors import BackendSeedError
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
    """Build the `docker run` flags a systemd-capable base container needs.

    Issue #955: a private cgroup namespace plus `writable-cgroups=true` gives
    systemd the writable, namespace-scoped cgroup2 it needs without a host
    cgroup namespace, a host cgroupfs bind, an unconfined seccomp profile, or
    any added capability. `--cgroupns=private` is requested explicitly rather
    than relied on as the cgroup v2 default, so the inspected contract is
    deterministic and the start-time attestation has an exact value to compare.
    """

    flags: list[str] = []
    if init.cgroup_private:
        flags.append("--cgroupns=private")
    if init.writable_cgroups:
        flags += ["--security-opt", WRITABLE_CGROUPS_OPTION]
    for path in init.tmpfs:
        flags += ["--tmpfs", path]
    for capability in init.capabilities:
        flags += ["--cap-add", capability]
    for env_name, env_value in init.env:
        flags += ["-e", f"{env_name}={env_value}"]
    if init.stop_signal:
        flags += ["--stop-signal", init.stop_signal]
    return flags


def _host_config(info: dict) -> dict:
    """Return a container's ``HostConfig``, or an empty mapping."""

    host = info.get("HostConfig")
    return host if isinstance(host, dict) else {}


def _normalized_capabilities(values: object) -> frozenset[str]:
    """Normalize a capability list to bare, upper-case names.

    Docker echoes back whatever form the grant was written in, so the same
    capability can read as ``SYS_ADMIN`` or ``CAP_SYS_ADMIN``. Comparing raw
    strings would call an identical grant a drift.
    """

    if not isinstance(values, (list, tuple)):
        return frozenset()
    return frozenset(
        str(value).upper().removeprefix("CAP_") for value in values if value
    )


def _realized_bind_targets(info: dict, host: dict) -> frozenset[str]:
    """Return every host path bind-mounted into the container.

    ``Mounts`` carries binds as structured entries; ``HostConfig.Binds`` carries
    the raw ``source:target[:mode]`` strings. A bind can appear through either,
    so both are read rather than trusting one.

    Binds are read separately from volumes because they are the
    privilege-relevant kind: a generic base container is created with named
    volumes only, so ANY bind on one is state APTL did not put there -- the
    retired ``/sys/fs/cgroup:rw`` bind among them.
    """

    targets: set[str] = set()
    mounts = info.get("Mounts")
    if isinstance(mounts, (list, tuple)):
        for mount in mounts:
            if isinstance(mount, dict) and mount.get("Type") == "bind":
                if mount.get("Destination"):
                    targets.add(str(mount["Destination"]))
    binds = host.get("Binds")
    if isinstance(binds, (list, tuple)):
        for bind in binds:
            parts = str(bind).split(":")
            if len(parts) >= 2 and parts[0].startswith("/"):
                targets.add(parts[1])
    return frozenset(targets)


def _realized_mount_destinations(info: dict) -> frozenset[str]:
    """Return every destination the container has a mount at, of any kind."""

    mounts = info.get("Mounts")
    if not isinstance(mounts, (list, tuple)):
        return frozenset()
    return frozenset(
        str(mount["Destination"])
        for mount in mounts
        if isinstance(mount, dict) and mount.get("Destination")
    )


def _published_ports_match(host: dict, spec: "BaseContainerSpec") -> bool:
    """Whether the container publishes exactly the spec's declared ports."""

    expected = {
        f"{port.container_port}/{port.protocol}" for port in spec.published_ports
    }
    bindings = host.get("PortBindings")
    realized = set()
    if isinstance(bindings, dict):
        realized = {key for key, value in bindings.items() if value}
    return realized == expected


def _init_posture_matches(info: dict, host: dict, init: "InitRequirements") -> bool:
    """Whether a realized systemd node still carries the code-owned posture.

    Compares the four facts that distinguish the current posture from the
    retired privileged recipe: cgroup namespace mode, the writable-cgroups
    security option (and the absence of any unconfined one), the exact added
    capability set, and the tmpfs set. A container failing any of these was
    created by a different substrate policy than the one in force now.
    """

    if init.cgroup_private and str(host.get("CgroupnsMode") or "") != "private":
        return False
    options = host.get("SecurityOpt")
    options = [str(option) for option in options] if isinstance(options, (list, tuple)) else []
    if any("unconfined" in option for option in options):
        return False
    if init.writable_cgroups and WRITABLE_CGROUPS_OPTION not in options:
        return False
    if _normalized_capabilities(host.get("CapAdd")) != _normalized_capabilities(
        init.capabilities
    ):
        return False
    tmpfs = host.get("Tmpfs")
    realized_tmpfs = frozenset(tmpfs) if isinstance(tmpfs, dict) else frozenset()
    return realized_tmpfs == frozenset(init.tmpfs)


def _realized_container_matches_spec(info: dict, spec: "BaseContainerSpec") -> bool:
    """Whether a running container still matches the spec that would create it.

    Deliberately excludes network attachments: the post-start reconcile owns
    them and a preserved container keeps what it had. Deliberately excludes
    declared environment *names* too — those bind through an env file, and a
    variable absent from the operator environment is legitimately omitted, so
    requiring presence would recreate a correct container on every start.
    """

    host = _host_config(info)
    if not _published_ports_match(host, spec):
        return False
    # Binds must be exactly absent: APTL creates generic base containers with
    # named volumes only, so any bind is state it did not put there.
    if _realized_bind_targets(info, host):
        return False
    # Every declared volume must actually be mounted. Deliberately a subset test
    # rather than equality: an image may declare its own VOLUME, which Docker
    # realizes as an anonymous volume the spec never named. That is not drift
    # and not privilege — failing on it would recreate a correct container on
    # every start, breaking the idempotent retry this function exists to
    # protect. A missing declared volume is the real drift, and is caught.
    expected_mounts = {mount.target for mount in spec.volume_mounts}
    if not expected_mounts <= _realized_mount_destinations(info):
        return False
    if spec.init is None:
        return True
    return _init_posture_matches(info, host, spec.init)


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

        if spec.init is not None:
            self._require_substrate_daemon()
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
        argv = self._base_container_create_command(
            spec, network_bindings, run_image_ref
        )
        result = self._run(argv, timeout=180)
        self._complete_base_container_start(spec, network_bindings, result)

    def _require_substrate_daemon(self) -> None:
        """Prove the target daemon can run the substrate posture, once per run.

        Resolved on first use and cached for the process: the answer is a
        property of the daemon, not of the node, and re-probing per node would
        add two subprocess round trips per systemd container for an answer that
        cannot change mid-start. A refusal is re-raised on every subsequent
        node rather than cached as a pass, so one node cannot be admitted
        because another was checked first.

        Called before the image build, network attachment, and stale-container
        removal in ``start_base_container``, so an unsupported host fails
        before any mutation.
        """

        if getattr(self, "_substrate_daemon_verified", False):
            return
        require_substrate_daemon_support(self._run)
        self._substrate_daemon_verified = True

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
        ``Config.Image``), and for an ordinary node is the declared tag —  AND
        still matches the spec that would be created now. A stopped, missing,
        wrong-image, or drifted container returns False so it is recreated
        cleanly. Network attachments are deliberately not part of the test: the
        post-start reconcile owns them, and a preserved container keeps whatever
        it already had.

        The drift comparison exists because image identity is not realization
        identity (issue #955). A container created under the retired privileged
        recipe is byte-identical to a new one on name and image, so on any
        machine carrying a warm lab it would be silently reused and the
        substrate hardening would never apply — while the fresh-directory boot
        gate, which runs on a clean tree, passed. That is the same class of
        cache-masked gap that hid the missing generic base image builds until a
        real fresh-machine boot surfaced it (#581, see
        ``_GENERIC_BASE_IMAGE_BUILD_CONTEXTS``). The same blindness applied to
        every other realized fact — published ports, mounts, environment, tmpfs
        — so the comparison covers those too rather than only the posture that
        prompted it.

        A mismatch returns False and nothing more: the caller's ordinary
        recreate path owns removal, and that path carries the project-ownership
        proof (#964). Posture drift is never licence to force-remove a
        same-named container APTL cannot prove it owns.
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
        if not (running and image == run_image_ref):
            return False
        return _realized_container_matches_spec(info, spec)

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
