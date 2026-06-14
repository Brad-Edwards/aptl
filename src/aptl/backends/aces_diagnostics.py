"""Diagnostics and runtime-state helpers for the APTL ACES backend."""

from __future__ import annotations

from aces_contracts.diagnostics import Diagnostic, Severity
from aces_contracts.planning import ChangeAction, ProvisioningPlan, RuntimeDomain
from aces_contracts.runtime_state import RuntimeSnapshot, SnapshotEntry

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
) -> RuntimeSnapshot:
    """Return a snapshot with applied provisioning resources marked ready."""
    entries = dict(snapshot.entries)
    for op in plan.operations:
        if op.action == ChangeAction.DELETE:
            entries.pop(op.address, None)
    for address, resource in plan.resources.items():
        entries[address] = SnapshotEntry(
            address=address,
            domain=RuntimeDomain.PROVISIONING,
            resource_type=resource.resource_type,
            payload=resource.payload,
            ordering_dependencies=resource.ordering_dependencies,
            refresh_dependencies=resource.refresh_dependencies,
            status="ready",
        )
    return snapshot.with_entries(entries)


def _format_diagnostic(item: Diagnostic) -> str:
    """Format one diagnostic line for operator-facing output."""
    return f"{item.code} at {item.address}: {item.message}"
