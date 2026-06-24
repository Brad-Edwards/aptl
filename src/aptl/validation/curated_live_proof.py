"""Model-derived reduced-surface matrix for curated ACES startup variants.

Issue #535 live-proves the small catalog variants from
``docs/sdl/techvault-curated-variants.md`` by booting them through the public
start path and checking the running range matches the variant's *reduced*
ACES-realized surface rather than the full TechVault live surface.

This module owns the model-derived half of that proof: it composes the existing
canonical authorities — the ACES parser/planner, ``interpret_provisioning_plan``,
``select_backend_profiles``, and the ``ComposeProfileIndex`` — into an
``ExpectedMatrix`` (selected profiles, realized node names, expected steady-state
Compose services, expected Compose networks) and compares that matrix against a
captured ``RangeSnapshot`` (``capture_snapshot().to_dict()``). It adds no second
profile map, Compose parser, readiness DTO, or failure taxonomy; the live boot,
snapshot capture, and redaction stay with their existing owners.

The comparison is content-driven and reduced by construction: a curated variant
selects a subset of the enabled Compose profiles, so the booted range must equal
the steady-state services those *selected* profiles activate — no more (a preset
or a name would over-start) and no less (a missing dependency would under-start).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from aces_runtime.manager import RuntimeManager
from aces_sdl import parse_sdl_file

from aptl.backends.aces import create_aptl_runtime_target
from aptl.backends.aces_profiles import (
    load_compose_profile_index,
    normalized_identifier_aliases,
    select_backend_profiles,
    steady_state_service_aliases_for_profiles,
)
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.config import AptlConfig
from aptl.validation._gate_checks import _NoStartBackend


@dataclass(frozen=True)
class ExpectedMatrix(object):
    """The reduced live surface a curated variant should realize.

    ``service_aliases`` / ``network_aliases`` map each expected Compose service
    and network to its normalized alias set, so the comparison can bind a
    snapshot container or network name across the ACES / Compose-key / Compose
    project-prefixed naming spaces without re-parsing ``docker-compose.yml``.
    """

    scenario: str
    selected_profiles: tuple[str, ...]
    realized_nodes: tuple[str, ...]
    expected_services: tuple[str, ...]
    expected_networks: tuple[str, ...]
    service_aliases: Mapping[str, frozenset[str]]
    network_aliases: Mapping[str, frozenset[str]]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view for evidence artifacts."""
        return {
            "scenario": self.scenario,
            "selected_profiles": list(self.selected_profiles),
            "realized_nodes": list(self.realized_nodes),
            "expected_services": list(self.expected_services),
            "expected_networks": list(self.expected_networks),
        }


def expected_reduced_matrix(
    project_dir: Path,
    config: AptlConfig,
    scenario_path: Path,
) -> ExpectedMatrix:
    """Compute a variant's reduced live surface from ACES realization.

    Mirrors ``selected_profiles_for_scenario``'s no-start selection path
    (parse -> plan -> interpret -> ``select_backend_profiles``) and then keys the
    expected steady-state Compose services and networks to that selected profile
    set through the shared ``ComposeProfileIndex``. No Docker is started.
    """
    scenario = parse_sdl_file(scenario_path)
    target = create_aptl_runtime_target(
        project_dir=project_dir, config=config, backend=_NoStartBackend()
    )
    execution_plan = RuntimeManager(target).plan(scenario)
    realization = interpret_provisioning_plan(
        plan=execution_plan.provisioning, project_dir=project_dir, config=config
    )
    selected_profiles = select_backend_profiles(config, realization.profiles)

    details = realization.details()
    realized_nodes = tuple(
        sorted(
            str(node.get("name"))
            for node in details.get("nodes", [])
            if node.get("name")
        )
    )

    service_aliases = steady_state_service_aliases_for_profiles(
        project_dir, selected_profiles
    )
    index = load_compose_profile_index(project_dir)
    network_aliases: dict[str, frozenset[str]] = {}
    for service_name in service_aliases:
        service = index.services.get(service_name)
        if service is None:
            continue
        for network in service.networks:
            network_aliases.setdefault(
                network, frozenset(normalized_identifier_aliases(network))
            )

    return ExpectedMatrix(
        scenario=scenario_path.name,
        selected_profiles=tuple(selected_profiles),
        realized_nodes=realized_nodes,
        expected_services=tuple(sorted(service_aliases)),
        expected_networks=tuple(sorted(network_aliases)),
        service_aliases={
            name: frozenset(aliases) for name, aliases in service_aliases.items()
        },
        network_aliases=network_aliases,
    )


def _running_container_names(snapshot: Mapping[str, object]) -> list[str]:
    """Return steady-state (running) container names from a range snapshot.

    Skips containers that are not ``Up`` so a one-shot or seed task that has
    already exited is never counted as a steady-state proof container.
    """
    names: list[str] = []
    for container in _as_sequence(snapshot.get("containers")):
        if not isinstance(container, Mapping):
            continue
        name = container.get("name")
        status = str(container.get("status", ""))
        if isinstance(name, str) and name and status.startswith("Up"):
            names.append(name)
    return names


def summarize_snapshot(snapshot: Mapping[str, object]) -> dict[str, object]:
    """Return an evidence-sized view of a range snapshot.

    Keeps the operationally meaningful container and network fields (identity,
    health, attachments, published ports) and drops the verbose Compose label
    block, so a committed proof artifact stays reviewable. The source snapshot is
    already redacted by ``capture_snapshot`` (ADR-029); this only trims noise.
    """
    containers = [
        {
            "name": container.get("name"),
            "image": container.get("image"),
            "status": container.get("status"),
            "health": container.get("health"),
            "networks": container.get("networks"),
            "ports": container.get("ports"),
        }
        for container in _as_sequence(snapshot.get("containers"))
        if isinstance(container, Mapping)
    ]
    networks = [
        {
            "name": network.get("name"),
            "subnet": network.get("subnet"),
            "gateway": network.get("gateway"),
            "containers": network.get("containers"),
        }
        for network in _as_sequence(snapshot.get("networks"))
        if isinstance(network, Mapping)
    ]
    return {
        "timestamp": snapshot.get("timestamp"),
        "containers": containers,
        "networks": networks,
    }


def _snapshot_network_names(snapshot: Mapping[str, object]) -> list[str]:
    """Return network names from a range snapshot."""
    names: list[str] = []
    for network in _as_sequence(snapshot.get("networks")):
        if isinstance(network, Mapping):
            name = network.get("name")
            if isinstance(name, str) and name:
                names.append(name)
    return names


def _as_sequence(value: object) -> Sequence[object]:
    """Return a list/tuple value as a sequence, or an empty tuple otherwise."""
    if isinstance(value, list | tuple):
        return value
    return ()


def _bind(actual: str, expected_aliases: Mapping[str, frozenset[str]]) -> str | None:
    """Return the expected key whose alias set an actual name binds to."""
    actual_aliases = normalized_identifier_aliases(actual)
    for key, aliases in expected_aliases.items():
        if actual_aliases & aliases:
            return key
    return None


def compare_to_snapshot(
    matrix: ExpectedMatrix,
    snapshot: Mapping[str, object],
) -> tuple[bool, list[str]]:
    """Compare a captured range snapshot to the expected reduced matrix.

    Passing means the running steady-state containers and the networks match the
    ACES-realized selected profile surface exactly: every expected service has a
    live container, no unexpected steady-state container is running, and the
    network set matches. Returns ``(ok, diagnostics)`` with one structured,
    layer-named diagnostic per gap (never raw Docker / CLI text).
    """
    diagnostics: list[str] = []

    running = _running_container_names(snapshot)
    bound_services = {name: _bind(name, matrix.service_aliases) for name in running}
    matched_services = {svc for svc in bound_services.values() if svc is not None}

    for service in matrix.expected_services:
        if service not in matched_services:
            diagnostics.append(
                f"defensive_stack_readiness: expected service '{service}' "
                f"(profiles {list(matrix.selected_profiles)}) has no running container"
            )
    for name, service in bound_services.items():
        if service is None:
            diagnostics.append(
                f"backend_interpretation: unexpected steady-state container "
                f"'{name}' is not in the selected reduced surface "
                f"{list(matrix.selected_profiles)}"
            )

    snapshot_networks = _snapshot_network_names(snapshot)
    bound_networks = {
        name: _bind(name, matrix.network_aliases) for name in snapshot_networks
    }
    matched_networks = {net for net in bound_networks.values() if net is not None}
    for network in matrix.expected_networks:
        if network not in matched_networks:
            diagnostics.append(
                f"defensive_stack_readiness: expected network '{network}' "
                "is absent from the booted range"
            )
    for name, network in bound_networks.items():
        if network is None:
            diagnostics.append(
                f"backend_interpretation: unexpected network '{name}' "
                f"is not in the selected reduced surface {list(matrix.selected_profiles)}"
            )

    return (not diagnostics, diagnostics)
