"""Docker Compose ADR-088 service-search-index-schema materialization (issue #889).

Split out of ``_compose_realization.py`` (module-length budget). Runs after the
declared images/networks/content are realized but before the general workload
is started: the target service (and anything its readiness depends on) is
brought up and observed healthy, then each declared portable field schema is
ensured on it through its native interface and proven by a fresh native
readback whose portable projection reproduces the declared digest. Only after
every schema is proven does the caller start the general workload, so a
consumer such as Cortex never races the initial state it needs.
"""

from __future__ import annotations

from pathlib import Path

from aptl.core.deployment._compose_service_health import wait_for_realized_health
from aptl.core.deployment._service_index_materialization import (
    MATERIALIZATION_TIMEOUT,
    materialize_search_index_schema,
)
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.lab_types import LabResult


def _validate_service_index_targets(
    realization: DeploymentRealizationSpec,
) -> tuple[dict[str, str], set[str], LabResult | None]:
    """Resolve each schema's target container + collect target service names.

    Returns ``(target_containers, target_services, None)`` on success, or
    ``({}, set(), failure)`` fail-closed on the first schema whose target isn't
    a realizable node service.
    """

    node_by_address = {node.address: node for node in realization.nodes}
    target_containers: dict[str, str] = {}
    target_services: set[str] = set()
    for schema in realization.service_index_schemas:
        node = node_by_address.get(schema.target_address)
        if node is None or not node.service_name or not node.container_name:
            return (
                {},
                set(),
                LabResult(
                    success=False,
                    error=(
                        "service materialization target "
                        f"'{schema.target_address}' is not a realizable node service"
                    ),
                ),
            )
        target_services.add(node.service_name)
        target_containers[schema.address] = node.container_name
    return target_containers, target_services, None


class ComposeRealizationServiceIndexMixin(object):
    """Materialize and prove ADR-088 search-index schemas before the workload."""

    def _materialize_service_index_schemas(
        self,
        realization: DeploymentRealizationSpec,
        *,
        build: bool,
        compose_files: tuple[Path, ...] | None,
        exclude_services: tuple[str, ...],
        scenario_root: Path,
    ) -> LabResult | None:
        """Materialize and prove ADR-088 search-index schemas before the workload.

        Returns ``None`` when there is nothing to do or every schema materialized
        and read back cleanly; a fail-closed :class:`LabResult` otherwise.
        """

        schemas = realization.service_index_schemas
        if not schemas:
            return None
        return self._run_service_index_materialization(
            realization,
            schemas,
            build=build,
            compose_files=compose_files,
            exclude_services=exclude_services,
            scenario_root=scenario_root,
        )

    def _run_service_index_materialization(
        self,
        realization: DeploymentRealizationSpec,
        schemas: tuple[object, ...],
        *,
        build: bool,
        compose_files: tuple[Path, ...] | None,
        exclude_services: tuple[str, ...],
        scenario_root: Path,
    ) -> LabResult | None:
        """Resolve targets, start + health-check them, then materialize/prove each schema."""

        target_containers, target_services, failure = _validate_service_index_targets(realization)
        if failure is not None:
            return failure

        failure = self._start_and_verify_service_index_health(
            realization,
            target_services,
            target_containers,
            build=build,
            compose_files=compose_files,
            exclude_services=exclude_services,
            scenario_root=scenario_root,
        )
        if failure is not None:
            return failure

        return self._materialize_and_verify_schemas(schemas, target_containers)

    def _start_and_verify_service_index_health(
        self,
        realization: DeploymentRealizationSpec,
        target_services: set[str],
        target_containers: dict[str, str],
        *,
        build: bool,
        compose_files: tuple[Path, ...] | None,
        exclude_services: tuple[str, ...],
        scenario_root: Path,
    ) -> LabResult | None:
        """Start the target services and wait for them to report healthy."""

        start = self._start_realized_services(
            list(realization.profiles),
            build=build,
            compose_files=compose_files,
            exclude_services=exclude_services,
            only_services=tuple(sorted(target_services)),
            scenario_root=scenario_root,
        )
        if not start.success:
            return start
        health = wait_for_realized_health(self, sorted(set(target_containers.values())))
        if health:
            return LabResult(success=False, error="; ".join(health[:5]))
        return None

    def _materialize_and_verify_schemas(
        self,
        schemas: tuple[object, ...],
        target_containers: dict[str, str],
    ) -> LabResult | None:
        """Materialize + prove each declared schema; stash evidence; fail closed on the first bad readback."""

        evidence: dict[str, dict[str, object]] = {}
        for schema in schemas:
            container = target_containers[schema.address]

            def _run_script(script: str, _container: str = container) -> object:
                """Run one ``sh -s`` script inside ``_container``, script on stdin."""

                return self.container_exec_with_input(
                    _container, ["sh", "-s"], script, timeout=MATERIALIZATION_TIMEOUT
                )

            result = materialize_search_index_schema(_run_script, schema)
            if not result.ok:
                return LabResult(
                    success=False,
                    error=(
                        f"service materialization failed for {schema.address} "
                        f"(reason={result.reason})"
                    ),
                )
            evidence[schema.address] = result.evidence()

        # Stash the safe portable readback evidence for observation (SEM-218);
        # never the raw native response.
        self._service_index_materialization_evidence = evidence
        return None
