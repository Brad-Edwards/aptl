"""Docker Compose realization orchestration for typed deployment specs."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from aptl.core.deployment._compose_account_realization import (
    ComposeRealizationAccountMixin,
)
from aptl.core.deployment._compose_observability import ComposeObservabilityMixin
from aptl.core.deployment._compose_capture_apparatus import (
    ComposeCaptureApparatusMixin,
)
from aptl.core.deployment._compose_traffic_mirror import ComposeTrafficMirrorMixin
from aptl.core.deployment._compose_content_realization import (
    ComposeRealizationContentMixin,
)
from aptl.core.deployment._compose_boundary_realization import (
    ComposeBoundaryRealizationMixin,
)
from aptl.core.deployment._compose_model_realization import (
    ComposeRealizationModelMixin,
)
from aptl.core.deployment._compose_mixed_realization import (
    ComposeMixedRealizationMixin,
)
from aptl.core.deployment._compose_post_start import (
    ComposeRealizationPostStartMixin,
)
from aptl.core.deployment._compose_port_realization import published_port_conflicts
from aptl.core.deployment._compose_port_readback import (
    owned_bindings as _owned_bindings,
)
from aptl.core.deployment._compose_service_index_realization import (
    ComposeRealizationServiceIndexMixin,
)
from aptl.core.deployment._compose_stateful_realization import (
    ComposeStatefulRealizationMixin,
)
from aptl.core.deployment._compose_image_realization import (
    ComposeRealizationImageMixin,
)
from aptl.core.deployment._compose_network_realization import (
    ComposeRealizationNetworkMixin,
)
from aptl.core.deployment._compose_image_free_realization import (
    _image_free_node_addresses,
    _image_free_service_names,
    _needs_compose,
    _realize_node_subset,
    _strip_image_free_published_ports,
)
from aptl.core.deployment._compose_realization_networks import (
    _container_networks,
    _network_name_candidates,
    _resolve_realization_networks,
)
from aptl.core.deployment._compose_runtime_orchestration import (
    ComposeRuntimeOrchestrationRouteMixin,
)
from aptl.core.deployment._compose_runtime_materialization import (
    ComposeRuntimeMaterializationMixin,
)
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.deployment.observation import DeploymentObservationContext
from aptl.core.lab_types import LabResult

__all__ = [
    "ComposeRealizationMixin",
    "_container_networks",
    "_image_free_node_addresses",
    "_image_free_service_names",
    "_network_name_candidates",
    "_realize_node_subset",
    "_resolve_realization_networks",
    "_strip_image_free_published_ports",
]


class ComposeRealizationMixin(
    ComposeRuntimeMaterializationMixin,
    ComposeTrafficMirrorMixin,
    ComposeCaptureApparatusMixin,
    ComposeObservabilityMixin,
    ComposeRuntimeOrchestrationRouteMixin,
    ComposeMixedRealizationMixin,
    ComposeBoundaryRealizationMixin,
    ComposeRealizationImageMixin,
    ComposeRealizationNetworkMixin,
    ComposeRealizationContentMixin,
    ComposeRealizationAccountMixin,
    ComposeRealizationModelMixin,
    ComposeRealizationPostStartMixin,
    ComposeRealizationServiceIndexMixin,
    ComposeStatefulRealizationMixin,
):
    """Realize typed scenario specs through Docker Compose."""

    def verify_runtime_orchestration(
        self, realization: DeploymentRealizationSpec
    ) -> LabResult:
        """Re-attest authority holders and current children on the bound daemon.

        This public backend seam is also used after scenario verification, when
        on-demand workers have actually existed. Rebinding first makes that
        delayed observation independent of the process that started the lab.
        """

        failure = self._runtime_orchestration_preflight(realization)
        if failure is not None:
            return failure
        return self._verify_runtime_orchestration(
            realization, require_children=True
        ) or LabResult(success=True)

    def realize(
        self,
        realization: DeploymentRealizationSpec,
        *,
        build: bool = True,
        scenario_root: Path,
        substrate_digests: Mapping[str, str] | None = None,
        observation_context: DeploymentObservationContext | None = None,
    ) -> LabResult:
        """Realize a typed scenario deployment through Docker Compose.

        ``scenario_root`` is the bundle root every scenario-declared filesystem
        input (Compose model, build contexts, generated-artifact locations)
        resolves against. It is required and request-scoped: the backend never
        caches it. The operator ``.env`` stays the control-plane
        ``project_dir/.env``. For an in-tree scenario ``scenario_root`` is the
        project directory, so behaviour is unchanged (issue #874).

        ``substrate_digests`` carries the address-scoped immutable substrate
        identity the availability pass already verified for each
        dynamic-composition node (issue #876 cycle-6 review). It is stored as
        request-scoped apply context and consumed by ``start_base_container`` so a
        route-3 node starts from exactly that config id, never a second
        resolution of the mutable tag.
        """

        failure = self._runtime_materialization_preflight(
            realization, scenario_root=scenario_root
        )
        if failure is not None:
            return failure

        observation_context = observation_context or DeploymentObservationContext()
        attempt_id = observation_context.attempt_id or self._resource_attempt_id
        ownership = self._ensure_resource_ownership()
        self._ensure_resource_ownership(
            attempt_id=attempt_id or ownership.new_attempt_id()
        )
        failure = self._realization_preflight(
            realization, scenario_root, substrate_digests
        )
        if failure is not None:
            result = failure
        elif not _needs_compose(realization):
            result = self._realize_without_compose(realization, scenario_root)
        else:
            result = self._realize_mixed_or_legacy(
                realization,
                build=build,
                scenario_root=scenario_root,
                observation_context=observation_context,
            )
        return result

    def _realization_preflight(
        self,
        realization: DeploymentRealizationSpec,
        scenario_root: Path,
        substrate_digests: Mapping[str, str] | None,
    ) -> LabResult | None:
        """Run ordered backend preflights before any scenario mutation."""

        failure = self._capture_apparatus_preflight(realization, scenario_root)
        if failure is None:
            failure = self._traffic_mirror_preflight(realization)
        if failure is None:
            failure = self._observability_preflight(realization, scenario_root)
        if failure is None:
            # Request-scoped: base start consumes the already-verified identity.
            self._realization_substrate_digests = dict(substrate_digests or {})
            failure = self._runtime_orchestration_preflight(realization)
        if failure is None:
            failure = self._start_backend_observability(realization.profiles)
        return failure

    def _realize_networks_and_boundaries(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Ensure declared networks exist, then realize authority boundaries.

        Fails closed on the first network error rather than continuing into
        boundary realization on a topology that was never brought up. Returns
        ``None`` when both stages succeed, so callers chain on ``is not None``.
        """

        network_failures = self._ensure_realization_networks(realization)
        if network_failures:
            return LabResult(success=False, error="; ".join(network_failures[:5]))
        return self._realize_authority_boundaries(realization)

    def _materialize_image_free_nodes(
        self,
        realization: DeploymentRealizationSpec,
        addresses: frozenset[str],
        scenario_root: Path,
        realization_root: Path | None = None,
    ) -> LabResult | None:
        """Materialize just the runtime:-declared node subset (ADR-048).

        Shares the same node materialization and content-op lowering as the
        fully image-free path, scoped to ``addresses`` so mixed-realization
        content meant for a Compose-managed node is never misinterpreted as
        an image-free placement. Content is read from ``scenario_root`` (the
        pack); generated artifacts are written under ``realization_root`` (the
        writable engine checkout) — issue #875.
        """

        realization_root = realization_root or scenario_root
        substrate_failure = self._realize_networks_and_boundaries(realization)
        if substrate_failure is not None:
            return substrate_failure
        nodes = tuple(n for n in realization.nodes if n.address in addresses)
        content = tuple(
            item for item in realization.content if item.target_address in addresses
        )
        failure, extra_ops = self._image_free_generated_artifact_ops(
            realization, addresses, realization_root
        )
        if failure is not None:
            return failure
        return _realize_node_subset(
            self,
            nodes,
            content,
            scenario_root,
            extra_ops,
            persistent_volumes=realization.persistent_volumes,
        )

    def _image_free_generated_artifact_ops(
        self,
        realization: DeploymentRealizationSpec,
        addresses: frozenset[str],
        realization_root: Path,
    ) -> tuple[LabResult | None, dict[str, tuple[object, ...]]]:
        """Generate and lower each image-free consumer's generated-artifact outputs.

        Compose nodes receive generated artifacts as bind mounts; an image-free
        node has no Compose service to mount into, so its consumer's selected,
        non-producer-private outputs are placed into the container as files
        instead (issue #875). The artifact is generated under ``realization_root``
        (never the pristine pack) once here, before the node is materialized, so
        its outputs exist to place; the generators are idempotent, so a later
        compose-side generation reuses the same material.
        """

        self._image_free_generated_environment = {}
        ops_by_address: dict[str, list[object]] = {}
        generated_environment: dict[str, dict[str, str]] = {}
        for artifact in realization.generated_artifacts:
            consumers = [
                consumer
                for consumer in artifact.consumers
                if consumer.target_address in addresses
            ]
            environment_consumers = [
                consumer
                for consumer in artifact.environment_consumers
                if consumer.target_address in addresses
            ]
            if not consumers and not environment_consumers:
                continue
            failure = self._realize_one_generated_artifact(artifact, realization_root)
            if failure is None:
                failure = _append_image_free_artifact_ops(
                    ops_by_address, artifact, consumers, realization_root
                )
            if failure is None:
                failure = _append_image_free_environment_bindings(
                    generated_environment,
                    artifact,
                    environment_consumers,
                    realization_root,
                )
            if failure is not None:
                return failure, {}
        self._image_free_generated_environment = generated_environment
        return None, {addr: tuple(ops) for addr, ops in ops_by_address.items()}

    def _realize_without_compose(
        self,
        realization: DeploymentRealizationSpec,
        scenario_root: Path,
    ) -> LabResult:
        """Realize a graph in which no node is Compose-managed.

        Every node is materialized from declared state onto a generic base
        substrate, so there is nothing for ``compose up`` to start.

        Networks first, then each node's declared packages/identity/services are
        materialized and verified by read-after-write, then content placements.
        Fails closed on the first unrealized node so a partial range never
        reports success.
        """

        substrate_failure = self._realize_networks_and_boundaries(realization)
        if substrate_failure is not None:
            return substrate_failure
        addresses = frozenset(node.address for node in realization.nodes)
        failure, extra_ops = self._image_free_generated_artifact_ops(
            realization, addresses, self.realization_root
        )
        if failure is not None:
            return failure
        node_result = _realize_node_subset(
            self,
            realization.nodes,
            realization.content,
            scenario_root,
            extra_ops,
            persistent_volumes=realization.persistent_volumes,
        )
        return node_result if node_result is not None else LabResult(success=True)

    def _realize_published_ports(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Refuse to start when a declared exact host binding cannot be published.

        Checked before anything is started so a port conflict fails the run
        cleanly rather than half-realizing the topology. A scenario-declared host
        port is a realization requirement, so it fails closed instead of being
        remapped the way the checked-in stack's convenience ports are.
        """

        # Only ask Docker what we already publish when there is an exact
        # binding whose answer could change, so a realization that declares no
        # host port costs no round-trip.
        declares_exact_binding = any(
            binding.host_port is not None
            for node in realization.nodes
            for binding in node.published_ports
        )
        owned = self._published_host_ports() if declares_exact_binding else frozenset()
        conflicts = published_port_conflicts(realization, owned)
        if not conflicts:
            return None
        return LabResult(success=False, error="; ".join(conflicts[:5]))

    def _published_host_ports(self) -> frozenset[tuple[str, int, str]]:
        """Return the host bindings this project's own containers publish.

        A port probe cannot say who holds a port, and the retry path re-applies
        the plan with the range still up, so without this every declared binding
        looks taken by a stranger on the second pass. Ours are not conflicts:
        Compose reconciles those containers. Unreadable Docker state yields an
        empty set, which only restores the stricter probe-only behavior.
        """

        bindings: frozenset[tuple[str, int, str]] = frozenset()
        try:
            identifiers = self._project_container_ids()
            if identifiers:
                inspected = self._run(
                    [
                        "docker",
                        "inspect",
                        "--format",
                        "{{json .NetworkSettings.Ports}}",
                        *identifiers,
                    ],
                    timeout=60,
                )
                if inspected.returncode == 0:
                    bindings = frozenset(_owned_bindings(inspected.stdout))
        # broad-except: an unreadable daemon must not mask a real port conflict
        # nor crash the start; falling back to the probe alone is the safe side.
        except Exception:
            bindings = frozenset()
        return bindings

    def _project_container_ids(self) -> list[str]:
        """Return the ids of containers labelled for this compose project."""

        listed = self._run(
            [
                "docker",
                "ps",
                "--filter",
                f"label=com.docker.compose.project={self._project_name}",
                "--format",
                "{{.ID}}",
            ],
            timeout=60,
        )
        if listed.returncode != 0:
            return []
        return [line.strip() for line in listed.stdout.splitlines() if line.strip()]


def _append_image_free_artifact_ops(
    ops_by_address: dict[str, list[object]],
    artifact: object,
    consumers: list[object],
    realization_root: Path,
) -> LabResult | None:
    """Lower one artifact's per-consumer outputs into placement ops.

    Each selected, non-producer-private output becomes a file placement under
    the consumer's declared mount destination, with a secret output placed
    owner-only. Returns a fail-closed result when a declared output was not
    produced, so an image-free node never starts missing material it declared.
    """

    from pathlib import PurePosixPath

    from aptl.backends.raes_materializer import PlaceFileOp
    from aptl.core.deployment._compose_stateful_model import (
        _consumer_output_names,
        artifact_source_path,
    )

    source = artifact_source_path(realization_root, artifact)
    by_name = {output.name: output for output in artifact.outputs}
    for consumer in consumers:
        for name in _consumer_output_names(artifact, consumer):
            output = by_name[name]
            try:
                content = (source / output.path).read_text(encoding="utf-8")
            except OSError:
                return LabResult(
                    success=False,
                    error=(
                        "Generated artifact output missing for image-free "
                        f"consumer {consumer.target_address}: {output.path}."
                    ),
                )
            destination = str(PurePosixPath(consumer.mount_destination) / output.path)
            mode = "0600" if output.sensitivity == "secret" else "0644"
            ops_by_address.setdefault(consumer.target_address, []).append(
                PlaceFileOp(path=destination, content=content, mode=mode)
            )
    return None


def _append_image_free_environment_bindings(
    bindings_by_address: dict[str, dict[str, str]],
    artifact: object,
    consumers: list[object],
    realization_root: Path,
) -> LabResult | None:
    """Resolve admitted generated outputs for generic-container env delivery."""

    from aptl.core.deployment._compose_stateful_model import artifact_source_path
    from aptl.core.deployment.realization import valid_environment_variable_name

    source_root = artifact_source_path(realization_root, artifact)
    outputs = {output.name: source_root / output.path for output in artifact.outputs}
    try:
        for consumer in consumers:
            if not valid_environment_variable_name(consumer.environment_variable):
                raise ValueError("invalid generated environment variable name")
            output = outputs.get(consumer.output_name)
            if output is None or not output.is_file():
                raise ValueError("missing generated output")
            value = output.read_text(encoding="utf-8").strip()
            if not value or "\n" in value or "\r" in value:
                raise ValueError("invalid generated environment value")
            node_bindings = bindings_by_address.setdefault(consumer.target_address, {})
            if consumer.environment_variable in node_bindings:
                raise ValueError("duplicate generated environment target")
            node_bindings[consumer.environment_variable] = value
    except (OSError, ValueError):
        return LabResult(
            success=False,
            error=f"Generated artifact {artifact.address} environment delivery failed.",
        )
    return None
