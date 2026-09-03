"""Deployment backend protocol.

Defines the abstract interface for lab deployment backends. Each backend
implements lifecycle operations (start, stop, status, kill, pull) and
container interaction (list, logs, shell, exec, inspect) for a specific
deployment target (Docker Compose, SSH remote, Kubernetes, etc.).

Container interaction (CLI-004, ADR-023) lets local and SSH backends present a
uniform surface so the same CLI commands and core helpers (snapshot, flags,
collectors) work whether the daemon is local or remote.

Follows the same Protocol pattern as RunStorageBackend in runstore.py.
"""

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol

from aptl.core.lab_types import LabResult, LabStatus
from aptl.core.deployment.backend_container_ops import ContainerOpsBackend
from aptl.core.deployment.backend_host_inventory import HostInventoryBackend
from aptl.core.deployment.realization import (
    DeploymentAccountRealization,
    DeploymentContentRealization,
    DeploymentNetworkRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.core.deployment.boundary import BoundaryEnforcementSpec
from aptl.core.appliance_boundary import (
    ApplianceBoundaryBinding,
    ApplianceBoundaryPolicy,
)
from aptl.core.seed_spec import NamedVolumeSeed

# Imported from ``aptl.core.lab_types`` (the leaf module) rather than
# ``aptl.core.lab``: a direct lab.py import created a load-order cycle pre-#266
# (lab.py -> snapshot -> deployment.__init__ -> backend.py -> lab.py). The leaf
# has no back-edges, so the names stay resolvable for ``typing.get_type_hints``.


class DeploymentBackend(HostInventoryBackend, ContainerOpsBackend, Protocol):
    """Protocol for lab deployment backends.

    Backends manage the deployment lifecycle (start, stop, status, kill,
    pull) and container interaction (list, logs, shell, exec, inspect). The
    host-inventory operations (``host_versions``, ``host_list_lab_containers``,
    ``host_list_lab_networks``, ``host_list_networks``, ``host_inspect_network``)
    are inherited from :class:`HostInventoryBackend`; the per-container
    operations (``container_list``, ``container_logs``, ``container_exec``,
    ``container_inspect``, ...) from :class:`ContainerOpsBackend`.
    """

    def start(self, profiles: list[str], *, build: bool = True) -> LabResult:
        """Start lab services for the given profiles.

        Args:
            profiles: List of profile names to activate.
            build: If True, rebuild images before starting.

        Returns:
            LabResult indicating success or failure.
        """
        ...

    def realize(
        self,
        realization: DeploymentRealizationSpec,
        *,
        build: bool = True,
        scenario_root: Path,
        substrate_digests: Mapping[str, str] | None = None,
    ) -> LabResult:
        """Realize a typed scenario deployment through the backend.

        Implementations may use profiles as a vehicle for starting existing
        services, but the declared nodes/networks in ``realization`` are the
        topology authority for any follow-on side effects.

        Args:
            realization: Typed deployment realization emitted from RAES plan
                resources.
            build: If True, rebuild images before starting.
            scenario_root: Bundle root every scenario-declared filesystem input
                resolves against; request-scoped, never cached on the backend.
                The operator ``.env`` stays the control-plane ``project_dir``
                boundary (issue #874).
            substrate_digests: Address-scoped immutable substrate identities the
                availability pass verified for dynamic-composition nodes (ADR-051
                route 3, issue #876). A route-3 node's base container starts from
                exactly this config id with ``--pull=never``, so the mutable tag
                is never re-resolved at apply.

        Returns:
            LabResult indicating success or failure.
        """
        ...

    def realize_boundary(self, policy: BoundaryEnforcementSpec) -> LabResult:
        """Apply and read back one project-owned appliance boundary policy."""

        ...

    def configure_appliance_boundary(
        self,
        policy: ApplianceBoundaryPolicy,
        binding: ApplianceBoundaryBinding,
    ) -> None:
        """Bind trusted appliance policy inputs to the next realization."""

        ...

    def stop(self, profiles: list[str], *, remove_volumes: bool = False) -> LabResult:
        """Stop lab services.

        Args:
            profiles: List of profile names to include in the stop.
            remove_volumes: If True, also remove persistent volumes.

        Returns:
            LabResult indicating success or failure.
        """
        ...

    def status(self) -> LabStatus:
        """Query the current deployment status.

        Returns:
            LabStatus with container information.
        """
        ...

    def kill(self, profiles: list[str]) -> tuple[bool, str]:
        """Emergency-stop all lab containers.

        Sends immediate kill signal, then cleans up.

        Args:
            profiles: List of profile names to include.

        Returns:
            Tuple of (success, error_message).
        """
        ...

    def pull_images(self, images: list[str]) -> list[str]:
        """Pre-pull container images.

        Args:
            images: List of image references to pull.

        Returns:
            List of warning messages for images that failed to pull
            (non-fatal).
        """
        ...

    def artifact_available(
        self, image_ref: str, *, allow_remote: bool | None = None
    ) -> bool:
        """Report whether one immutable artifact reference can be obtained.

        Operational fact only: implementations must not pull, build, tag, or
        otherwise mutate state here, and must not decide admission. The result
        feeds the RAES artifact availability context, which the planner uses to
        admit or reject an authored artifact requirement (ADR-051).

        Args:
            image_ref: Digest-pinned artifact reference to check.
            allow_remote: Whether a registry-resolvable reference counts. None
                lets the backend decide from its own staging mode; False means
                only local presence counts (offline/staged appliance).

        Returns:
            True when the reference is obtainable under those rules.
        """
        ...

    def materialize_component_image(
        self, image_ref: str, dockerfile_path: str, context_path: str
    ) -> str | None:
        """Build one component image and return the digest it materialized to.

        Runs during backend preparation and produces a local artifact only. The
        returned digest is what makes a materialized artifact's identity
        knowable, since a built image's digest cannot be predicted.

        Returns None when the build fails or the digest cannot be read.
        """
        ...

    def container_image_digest(self, container_name: str) -> str | None:
        """Return the manifest digest of the image backing one container.

        Read-after-write for exact artifact realization: the satisfaction
        disclosure is built from this observed value, never from the planned
        one. Return None when the digest cannot be determined, so the caller
        refuses the disclosure instead of assuming a match.
        """
        ...

    def substrate_image_identity(self, image_ref: str) -> tuple[str, str] | None:
        """Return the ``(digest, media_type)`` of a locally present image ref.

        The route-3 (dynamic-composition) availability check verifies the
        generic substrate is already on the target daemon: a strict local-lookup
        that never pulls (ADR-051 route 3). The digest is reported in the same
        domain as ``container_image_digest`` so availability and post-realization
        readback compare like with like. Returns None when the reference is not
        locally present or its identity cannot be read.
        """
        ...

    def container_image_config_id(self, container_name: str) -> str | None:
        """Return the config-id digest of the image backing one container.

        The same digest domain as ``substrate_image_identity``, used to read a
        dynamic-composition node's realized substrate back for the runtime gate.
        Returns None when it cannot be read.
        """
        ...

    def create_network(
        self,
        network: DeploymentNetworkRealization,
        ip_range: str | None = None,
    ) -> LabResult:
        """Materialize one scenario-declared network.

        Implementations choose the concrete backend network name, but must keep
        it scoped to this deployment project and honor CIDR, gateway, and
        internal-egress settings when present. ``ip_range`` optionally confines
        dynamic allocation off statically-pinned node addresses (issue #875).
        """
        ...

    def connect_container_network(
        self,
        container_name: str,
        network_name: str,
        *,
        ipv4_address: str | None = None,
        aliases: tuple[str, ...] = (),
    ) -> LabResult:
        """Attach one container to one backend network.

        Args:
            container_name: Concrete backend container name.
            network_name: Concrete backend network name.
            ipv4_address: Optional static IPv4 address for this attachment.
            aliases: Optional DNS aliases to preserve on the attachment.
        """
        ...

    def disconnect_container_network(
        self,
        container_name: str,
        network_name: str,
    ) -> LabResult:
        """Detach one container from one backend network."""
        ...

    def seed_named_volumes(
        self,
        seeds: Sequence[NamedVolumeSeed],
        *,
        seeder_image: str,
    ) -> None:
        """Materialize checked-in source into Compose named volumes (ADR-043).

        For each seed, a root (``--user 0:0``) one-off container copies the
        spec's files from the read-only source bind into the project-scoped
        named volume, overwriting prior content so the operation is idempotent
        regardless of the existing owner. A seed carrying a still-present
        ``legacy_retire_path`` has that one canonical path removed first.
        Implementations route Docker through their own runner -- a narrow typed
        operation, not a generic argv passthrough.

        Args:
            seeds: The volume seed specs to materialize, in order.
            seeder_image: Image used to run the copy/cleanup containers
                (an image already in the lab's supply chain).

        Raises:
            BackendSeedError: if a seed or retire container exits non-zero.
            BackendTimeoutError: if a seed container exceeds its timeout.
        """
        ...

    def realize_content(
        self,
        content: Sequence[DeploymentContentRealization],
        *,
        seeder_image: str,
        scenario_root: Path,
    ) -> None:
        """Materialize typed RAES content placements (issue #689).

        Mirrors :meth:`seed_named_volumes`: each realized content item is lowered
        into a project-scoped named-volume seed (inline text rendered into the
        ignored ``.aptl/content/`` tree first; project-contained sources bound
        read-only from their containment-checked location) and materialized by
        the same root one-off seed mechanism, so it inherits ADR-043 seeding's
        idempotency, project-scoping, and redaction without a second mechanism.

        Args:
            content: The typed content realizations to materialize, in
                order.
            seeder_image: Image used to run the copy containers (an image
                already in the lab's supply chain).

        Raises:
            BackendSeedError: if a seed container exits non-zero.
            BackendTimeoutError: if a seed container exceeds its timeout.
        """
        ...

    def observe_content_type(
        self,
        content: DeploymentContentRealization,
    ) -> str | None:
        """Read back the realized filesystem kind for one content placement.

        Implementations inspect the project-scoped realized destination and
        return only the governed RAES kind (``file`` or ``directory``). Missing,
        ambiguous, or failed observations return ``None``. Content bytes and raw
        probe output must never cross this boundary.
        """
        ...

    def observe_bind_source_type(self, source: str) -> str | None:
        """Read back the filesystem kind of one realized bind-mount source.

        Content delivered to an image node is a read-only bind of a host path,
        so the destination's kind *is* the source's kind. Implementations
        classify the path on the Docker host — never by executing anything from
        the observed container's image, which may be distroless or already
        exited — and return only the governed RAES kind (``file`` or
        ``directory``). A missing, ambiguous, or failed observation returns
        ``None``; bytes and raw probe output never cross this boundary.
        """
        ...

    @property
    def realization_root(self) -> Path:
        """The writable root the backend writes generated realization output to.

        Generated artifacts, rendered content, and generated Compose overrides
        are written here, never into the pristine staged scenario bundle whose
        digest-validated inventory must not gain generated files (issue #875).
        Realization observation reads them back from this same root, so the two
        cannot drift. In-tree it coincides with the bundle root.
        """
        ...

    def realize_accounts(
        self,
        accounts: Sequence[DeploymentAccountRealization],
        nodes: Sequence[DeploymentNodeRealization],
        *,
        timeout: int | None = None,
    ) -> LabResult | None:
        """Realize typed RAES account placements onto their target nodes (#577).

        Ensures declared groups, creates or reconciles each declared user via
        the resolved backend account provider (Samba AD on the ``ad`` node),
        applies supported non-secret attributes, reconciles group memberships,
        and verifies the resulting non-secret state by read-after-write. The
        whole batch is validated before the first mutation; an already-existing
        account is reconciled, not re-created, so its provider-owned credential
        is preserved. No credential ever crosses argv/env/evidence (ADR-029 +
        ADR-046 addendum): user creation delegates password generation to the
        target provider.

        Args:
            accounts: The typed account realizations to materialize.
            nodes: The realized nodes, used to resolve each account's concrete
                target container and account provider.
            timeout: Optional per-command timeout in seconds.

        Returns:
            ``None`` on success (or when there is nothing to realize); a
            fail-closed :class:`LabResult` naming the placement address and a
            stable reason on validation, readiness, or verification failure.

        Raises:
            BackendTimeoutError: if a provider command exceeds its timeout.
        """
        ...
