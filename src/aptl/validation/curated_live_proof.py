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

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from aces_contracts.participant_behavior import (
    iter_participant_behavior_snapshot_violations,
)
from aces_contracts.participant_episode import (
    iter_participant_episode_snapshot_violations,
)
from aces_contracts.runtime_state import OperationState
from aces_runtime.control_plane import RuntimeControlPlane
from aces_runtime.manager import RuntimeManager
from aces_sdl import parse_sdl_file

from aptl.backends.aces import create_aptl_runtime_target
from aptl.backends.aces_participant_runtime import PARTICIPANT_ACTION_ADDRESS
from aptl.backends.aces_profiles import (
    load_compose_profile_index,
    normalized_identifier_aliases,
    select_backend_profiles,
    steady_state_service_aliases_for_profiles,
)
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.config import AptlConfig
from aptl.core.deployment import get_backend
from aptl.core.snapshot import capture_snapshot
from aptl.utils.redaction import redact
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


def _diff_surface(
    actual_names: list[str],
    expected_keys: tuple[str, ...],
    expected_aliases: Mapping[str, frozenset[str]],
    missing_diag: Callable[[str], str],
    unexpected_diag: Callable[[str], str],
) -> list[str]:
    """Diagnose one surface (containers or networks) against the expected set.

    Binds each actual name to an expected key by normalized alias, then reports
    every expected key with no live match (``missing_diag``) and every actual
    name that binds to nothing expected (``unexpected_diag``).
    """
    bound = {name: _bind(name, expected_aliases) for name in actual_names}
    matched = {key for key in bound.values() if key is not None}
    diagnostics = [missing_diag(key) for key in expected_keys if key not in matched]
    diagnostics.extend(
        unexpected_diag(name) for name, key in bound.items() if key is None
    )
    return diagnostics


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
    profiles = list(matrix.selected_profiles)
    diagnostics = _diff_surface(
        _running_container_names(snapshot),
        matrix.expected_services,
        matrix.service_aliases,
        lambda service: (
            f"defensive_stack_readiness: expected service '{service}' "
            f"(profiles {profiles}) has no running container"
        ),
        lambda name: (
            f"backend_interpretation: unexpected steady-state container '{name}' "
            f"is not in the selected reduced surface {profiles}"
        ),
    )
    diagnostics.extend(
        _diff_surface(
            _snapshot_network_names(snapshot),
            matrix.expected_networks,
            matrix.network_aliases,
            lambda network: (
                f"defensive_stack_readiness: expected network '{network}' "
                "is absent from the booted range"
            ),
            lambda name: (
                f"backend_interpretation: unexpected network '{name}' "
                f"is not in the selected reduced surface {profiles}"
            ),
        )
    )
    return (not diagnostics, diagnostics)


def run_participant_action_proof(
    project_dir: Path,
    config: AptlConfig,
    participant_address: str = PARTICIPANT_ACTION_ADDRESS,
) -> dict[str, object]:
    """Drive a participant action through the ACES control plane.

    The lab must already be realized by the public start path. This proof uses
    the configured deployment backend, calls
    ``RuntimeControlPlane.initialize_participant_episode()``, validates the
    participant episode/behavior snapshot surfaces, captures a post-action range
    snapshot, and returns a JSON-serializable evidence object.
    """

    backend = get_backend(config, project_dir)
    target = create_aptl_runtime_target(
        project_dir=project_dir,
        config=config,
        backend=backend,
    )
    control_plane = RuntimeControlPlane(target)
    receipt = control_plane.initialize_participant_episode(participant_address)
    status = control_plane.get_operation(receipt.operation_id)
    snapshot = control_plane.snapshot

    episode_violations = list(
        iter_participant_episode_snapshot_violations(
            snapshot.participant_episode_results,
            snapshot.participant_episode_history,
        )
    )
    behavior_violations = list(
        iter_participant_behavior_snapshot_violations(
            snapshot.participant_behavior_history,
            participant_episode_results=snapshot.participant_episode_results,
            participant_episode_history=snapshot.participant_episode_history,
            metadata=snapshot.metadata,
        )
    )
    capture_diagnostics: list[str] = []
    range_snapshot_summary: dict[str, object] | None = None
    try:
        range_snapshot_summary = summarize_snapshot(
            capture_snapshot(config_dir=project_dir, backend=backend).to_dict()
        )
    except Exception as exc:  # noqa: BLE001 - evidence-capture failure -> proof diagnostic.
        capture_diagnostics.append(
            redact(f"post-action range snapshot capture failed: {exc}")
        )

    operation_succeeded = (
        status is not None and status.state == OperationState.SUCCEEDED
    )
    has_episode = participant_address in snapshot.participant_episode_results
    has_episode_history = bool(
        snapshot.participant_episode_history.get(participant_address)
    )
    has_behavior_history = bool(
        snapshot.participant_behavior_history.get(participant_address)
    )
    passed = (
        operation_succeeded
        and has_episode
        and has_episode_history
        and has_behavior_history
        and not episode_violations
        and not behavior_violations
        and not capture_diagnostics
    )

    proof = {
        "schema": "aptl.participant-action-proof/v1",
        "participant_address": participant_address,
        "operation_receipt_contract": "operation-receipt-v1",
        "operation_status_contract": "operation-status-v1",
        "runtime_snapshot_contract": "runtime-snapshot-v1",
        "operation_receipt": {
            "operation_id": receipt.operation_id,
            "domain": receipt.domain.value,
            "accepted": receipt.accepted,
            "submitted_at": receipt.submitted_at,
            "diagnostics": _diagnostics_to_dicts(receipt.diagnostics),
        },
        "operation_status": (
            None
            if status is None
            else {
                "operation_id": status.operation_id,
                "domain": status.domain.value,
                "state": status.state.value,
                "submitted_at": status.submitted_at,
                "updated_at": status.updated_at,
                "diagnostics": _diagnostics_to_dicts(status.diagnostics),
                "changed_addresses": list(status.changed_addresses),
            }
        ),
        "participant_runtime_status": target.participant_runtime.status()
        if target.participant_runtime is not None
        else None,
        "participant_episode_results": dict(snapshot.participant_episode_results),
        "participant_episode_history": {
            address: list(events)
            for address, events in snapshot.participant_episode_history.items()
        },
        "participant_behavior_history": {
            address: list(events)
            for address, events in snapshot.participant_behavior_history.items()
        },
        "participant_snapshot_entries": {
            address: {
                "domain": entry.domain.value,
                "resource_type": entry.resource_type,
                "status": entry.status,
                "payload": dict(entry.payload),
            }
            for address, entry in snapshot.entries.items()
            if entry.domain.value == "participant"
        },
        "post_action_range_snapshot": range_snapshot_summary,
        "validation": {
            "episode_violations": [
                {"path": path, "message": message}
                for path, message in episode_violations
            ],
            "behavior_violations": [
                {"path": path, "message": message}
                for path, message in behavior_violations
            ],
            "capture_diagnostics": capture_diagnostics,
        },
        "verdict": "PASS" if passed else "FAIL",
    }
    return _redact_volatile_proof_identifiers(proof, participant_address)


def _diagnostics_to_dicts(diagnostics: Sequence[object]) -> list[dict[str, object]]:
    """Return ACES diagnostics as JSON-serializable redacted dictionaries."""

    result: list[dict[str, object]] = []
    for diagnostic in diagnostics:
        severity = getattr(diagnostic, "severity", "")
        result.append(
            {
                "code": getattr(diagnostic, "code", ""),
                "domain": getattr(diagnostic, "domain", ""),
                "address": getattr(diagnostic, "address", ""),
                "severity": getattr(severity, "value", severity),
                "message": redact(str(getattr(diagnostic, "message", ""))),
            }
        )
    return result


def _redact_volatile_proof_identifiers(
    proof: dict[str, object],
    participant_address: str,
) -> dict[str, object]:
    """Normalize per-run IDs before evidence is committed.

    Operation ids, episode ids, action-instance ids, and output digests prove
    nothing by their raw value and look like secrets to external scanners. Keep
    the references internally consistent while removing the high-entropy values.
    """

    replacements: dict[str, str] = {}
    receipt = proof.get("operation_receipt")
    if isinstance(receipt, Mapping):
        operation_id = receipt.get("operation_id")
        if isinstance(operation_id, str) and operation_id:
            replacements[operation_id] = "operation-id-redacted"

    results = proof.get("participant_episode_results")
    if isinstance(results, Mapping):
        for result in results.values():
            if isinstance(result, Mapping):
                episode_id = result.get("episode_id")
                if isinstance(episode_id, str) and episode_id:
                    replacements[episode_id] = "episode-id-redacted"

    behavior_history = proof.get("participant_behavior_history")
    if isinstance(behavior_history, Mapping):
        for events in behavior_history.values():
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, Mapping):
                    action_instance_id = event.get("action_instance_id")
                    if isinstance(action_instance_id, str) and action_instance_id:
                        replacements[action_instance_id] = (
                            f"{participant_address}.action-instance-redacted"
                        )

    return _replace_proof_strings(proof, replacements)


def _replace_proof_strings(value: object, replacements: Mapping[str, str]) -> object:
    if isinstance(value, str):
        if value.startswith("sha256:") and len(value) > len("sha256:") + 16:
            return "sha256:redacted-proof-digest"
        result = value
        for old, new in replacements.items():
            result = result.replace(old, new)
        return result
    if isinstance(value, list):
        return [_replace_proof_strings(item, replacements) for item in value]
    if isinstance(value, dict):
        return {
            str(_replace_proof_strings(key, replacements)): _replace_proof_strings(
                item, replacements
            )
            for key, item in value.items()
        }
    return value
