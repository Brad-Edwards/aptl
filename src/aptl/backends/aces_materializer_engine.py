"""Generic node materialization engine (ADR-047).

Executes a node's planned generic operations (from
:func:`aptl.backends.aces_materializer.plan_node_materialization`) against a
backend materialization surface, then verifies the result by read-after-write.

The engine is product-agnostic: it dispatches purely on operation type, never on
any node or product name. Per ADR-046 (as amended for ADR-047), an internal or
backend failure is translated at this admission boundary into the existing ACES
`LabResult` envelope; it never escapes as a new public exception hierarchy, and
the raw failure detail never crosses into the envelope. A fact that cannot be
observed and verified is a failure, not a realized fact: "container running" is
never accepted as proof.
"""

from __future__ import annotations

from typing import Protocol

from aptl.backends.aces_diagnostics import diagnostic, render_aces_diagnostics
from aptl.backends.aces_materializer import (
    BaseSubstrateOp,
    EnableServiceUnitOp,
    EnsureGroupOp,
    EnsureUserOp,
    InstallPackagesOp,
    MaterializationOp,
    StartServiceUnitOp,
)
from aptl.core.lab_types import LabResult


class MaterializationExecutor(Protocol):
    """Typed generic materialization surface a deployment backend provides.

    Mutations materialize declared state onto a node; observers read it back for
    verification. No method is product-specific; the concrete backend owns the
    OS mechanics (package manager, identity tools, service manager).
    """

    def ensure_base_substrate(self, node_address: str, image_ref: str) -> None: ...
    def install_packages(self, node_address: str, manager: str, packages: tuple[str, ...]) -> None: ...
    def ensure_group(self, node_address: str, name: str, gid: int | str | None) -> None: ...
    def ensure_user(self, node_address: str, op: EnsureUserOp) -> None: ...
    def enable_service_unit(self, node_address: str, unit_name: str) -> None: ...
    def start_service_unit(self, node_address: str, unit_name: str) -> None: ...
    def observe_installed_packages(self, node_address: str, manager: str) -> frozenset[str]: ...
    def observe_local_group(self, node_address: str, name: str) -> bool: ...
    def observe_local_user(self, node_address: str, username: str) -> bool: ...
    def observe_service_unit_enabled(self, node_address: str, unit_name: str) -> bool: ...
    def observe_service_unit_active(self, node_address: str, unit_name: str) -> bool: ...


def _execute_op(
    op: MaterializationOp, node_address: str, executor: MaterializationExecutor
) -> None:
    if isinstance(op, BaseSubstrateOp):
        executor.ensure_base_substrate(node_address, op.image_ref)
    elif isinstance(op, InstallPackagesOp):
        executor.install_packages(node_address, op.manager, op.packages)
    elif isinstance(op, EnsureGroupOp):
        executor.ensure_group(node_address, op.name, op.gid)
    elif isinstance(op, EnsureUserOp):
        executor.ensure_user(node_address, op)
    elif isinstance(op, EnableServiceUnitOp):
        executor.enable_service_unit(node_address, op.unit_name)
    elif isinstance(op, StartServiceUnitOp):
        executor.start_service_unit(node_address, op.unit_name)


def _verify_op(
    op: MaterializationOp, node_address: str, executor: MaterializationExecutor
) -> str | None:
    """Return a read-after-write failure reason for one op, or None if verified.

    ``BaseSubstrateOp`` has no separate verification: a running container is not
    proof, so the substrate is proved transitively by the state materialized
    onto it.
    """

    if isinstance(op, InstallPackagesOp):
        observed = executor.observe_installed_packages(node_address, op.manager)
        missing = tuple(name for name in op.packages if name not in observed)
        if missing:
            return f"packages not installed via {op.manager}: {', '.join(missing)}"
    elif isinstance(op, EnsureGroupOp):
        if not executor.observe_local_group(node_address, op.name):
            return f"local group not present: {op.name}"
    elif isinstance(op, EnsureUserOp):
        if not executor.observe_local_user(node_address, op.username):
            return f"local user not present: {op.username}"
    elif isinstance(op, EnableServiceUnitOp):
        if not executor.observe_service_unit_enabled(node_address, op.unit_name):
            return f"service unit not enabled: {op.unit_name}"
    elif isinstance(op, StartServiceUnitOp):
        if not executor.observe_service_unit_active(node_address, op.unit_name):
            return f"service unit not active: {op.unit_name}"
    return None


def materialize_node(
    node_address: str,
    operations: tuple[MaterializationOp, ...],
    executor: MaterializationExecutor,
) -> LabResult | None:
    """Materialize one node's declared state, then verify by read-after-write.

    Returns ``None`` on fully-verified success, or a fail-closed
    :class:`LabResult` naming the node and the unmet contract. Any internal or
    backend error is translated into the same envelope, never raised.
    """

    for op in operations:
        try:
            _execute_op(op, node_address, executor)
        except Exception:  # noqa: BLE001 - admission boundary: translate every
            # internal/backend failure into the ACES LabResult envelope; the raw
            # detail is deliberately not echoed (redaction + no verbatim message).
            return LabResult(
                success=False,
                error=render_aces_diagnostics(
                    [
                        diagnostic(
                            "aptl.materializer.operation-failed",
                            node_address,
                            f"materialization step {type(op).__name__} failed on "
                            f"node {node_address}.",
                        )
                    ]
                ),
            )

    diagnostics = []
    for op in operations:
        reason = _verify_op(op, node_address, executor)
        if reason is not None:
            diagnostics.append(
                diagnostic(
                    "aptl.materializer.verification-failed",
                    node_address,
                    f"declared runtime state not verified on node "
                    f"{node_address}: {reason}",
                )
            )
    if diagnostics:
        return LabResult(success=False, error=render_aces_diagnostics(diagnostics))
    return None
