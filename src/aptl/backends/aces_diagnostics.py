"""Diagnostics and runtime-state helpers for the APTL ACES backend."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy

from aces_contracts.diagnostics import Diagnostic, Severity
from aces_contracts.planning import ChangeAction, ProvisioningPlan, RuntimeDomain
from aces_contracts.runtime_state import RuntimeSnapshot, SnapshotEntry
from aces_processor.semantics.realization import CONCERN_PAYLOAD_PATH

from aptl.backends.aces_observation import ObservedResource
from aptl.utils.redaction import redact

PROVISIONING_ADDRESS = "runtime.apply.provisioning"
SUPPORTED_RESOURCE_TYPES = frozenset(
    {
        "network",
        "node",
        "feature-binding",
        "content-placement",
        "account-placement",
    }
)


def diagnostic(code: str, address: str, message: str) -> Diagnostic:
    """Build a redacted ACES error diagnostic."""
    return Diagnostic(
        code=code,
        domain=RuntimeDomain.PROVISIONING.value,
        address=address,
        message=redact(message),
        severity=Severity.ERROR,
    )


def has_error(diagnostics: list[Diagnostic]) -> bool:
    """Return whether any diagnostic is error severity."""
    return any(item.is_error for item in diagnostics)


def render_aces_diagnostics(diagnostics: list[Diagnostic]) -> str:
    """Render ACES diagnostics into the APTL ``LabResult`` error surface."""
    if not diagnostics:
        return "ACES runtime handoff failed."
    rendered = [_format_diagnostic(item) for item in diagnostics if item.is_error]
    if not rendered:
        rendered = [_format_diagnostic(item) for item in diagnostics]
    return redact("ACES runtime handoff failed: " + "; ".join(rendered[:5]))


def unsupported_resource_diagnostics(
    plan: ProvisioningPlan,
) -> list[Diagnostic]:
    """Return diagnostics for ACES resources APTL cannot realize."""
    diagnostics: list[Diagnostic] = []
    seen: set[tuple[str, str]] = set()
    for resource in [*plan.resources.values(), *plan.operations]:
        resource_type = resource.resource_type
        key = (resource.address, resource_type)
        if resource_type in SUPPORTED_RESOURCE_TYPES or key in seen:
            continue
        seen.add(key)
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.unsupported-resource-type",
                resource.address,
                (
                    "APTL provisioning target does not support ACES "
                    f"resource type '{resource_type}'."
                ),
            )
        )
    return diagnostics


def snapshot_after_apply(
    plan: ProvisioningPlan,
    snapshot: RuntimeSnapshot,
    observations: Mapping[str, ObservedResource],
) -> RuntimeSnapshot:
    """Return a snapshot of what the backend was observed to have realized.

    Each entry's payload carries the concern values the backend actually
    realized (:mod:`aptl.backends.aces_observation`), not the planned ones. A
    resource the backend did not realize gets no entry: the SEM-218 gate treats
    an absent EXACT concern as a silent approximation and rejects it, which is
    the point — echoing the plan back made the gate compare the plan against
    itself and pass unconditionally (issue #578).
    """
    entries = dict(snapshot.entries)
    for op in plan.operations:
        if op.action == ChangeAction.DELETE:
            entries.pop(op.address, None)
    for address, resource in plan.resources.items():
        observed = observations.get(address)
        if observed is None or not observed.realized:
            entries.pop(address, None)
            continue
        entries[address] = SnapshotEntry(
            address=address,
            domain=RuntimeDomain.PROVISIONING,
            resource_type=resource.resource_type,
            payload=_observed_payload(resource.payload, observed),
            ordering_dependencies=resource.ordering_dependencies,
            refresh_dependencies=resource.refresh_dependencies,
            status="ready",
        )
    return snapshot.with_entries(entries)


def realized_changed_addresses(
    plan: ProvisioningPlan,
    snapshot: RuntimeSnapshot,
) -> list[str]:
    """Return changed addresses that the resulting snapshot actually carries.

    ACES rejects a backend that reports a changed address outside its snapshot
    transition, and an unrealized resource now has no entry — so a planned
    change the backend did not realize must not be claimed as changed.
    """

    return [
        op.address
        for op in plan.operations
        if op.action != ChangeAction.UNCHANGED and op.address in snapshot.entries
    ]


def _observed_payload(
    planned_payload: Mapping[str, object],
    observed: ObservedResource,
) -> dict[str, object]:
    """Return the planned payload with realization concerns replaced by reality.

    Non-concern fields (names, specs, addresses) are descriptive identity the
    backend does not realize a value for, so they are carried through. The
    concern fields the gate compares are overwritten with what was observed, and
    a concern the backend could not be seen to realize is removed entirely
    rather than left echoing the plan.
    """

    payload = deepcopy(dict(planned_payload))
    for path in CONCERN_PAYLOAD_PATH.values():
        if path in observed.concerns:
            _set_path(payload, path, observed.concerns[path])
        else:
            _pop_path(payload, path)
    return payload


def _set_path(
    payload: dict[str, object], path: tuple[str, ...], value: object
) -> None:
    """Set a nested concern value, building intermediate mappings as needed."""

    current = payload
    for key in path[:-1]:
        nested = current.get(key)
        if not isinstance(nested, dict):
            nested = {}
            current[key] = nested
        current = nested
    current[path[-1]] = value


def _pop_path(payload: dict[str, object], path: tuple[str, ...]) -> None:
    """Remove a nested concern value, leaving other payload fields intact."""

    current: object = payload
    for key in path[:-1]:
        if not isinstance(current, dict) or key not in current:
            return
        current = current[key]
    if isinstance(current, dict):
        current.pop(path[-1], None)


def _format_diagnostic(item: Diagnostic) -> str:
    """Format one diagnostic line for operator-facing output."""
    return f"{item.code} at {item.address}: {item.message}"
