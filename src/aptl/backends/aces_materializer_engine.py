"""Generic node materialization engine (ADR-048).

Executes a node's planned generic operations (from
:func:`aptl.backends.aces_materializer.plan_node_materialization`) against a
backend materialization surface, then verifies the result by read-after-write.

The engine is product-agnostic: it dispatches purely on operation type, never on
any node or product name. Per ADR-046 (as amended for ADR-048), an internal or
backend failure is translated at this admission boundary into the existing ACES
`LabResult` envelope; it never escapes as a new public exception hierarchy, and
the raw failure detail never crosses into the envelope. A fact that cannot be
observed and verified is a failure, not a realized fact: "container running" is
never accepted as proof.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from aptl.backends.aces_diagnostics import diagnostic, render_aces_diagnostics
from aptl.backends.aces_materializer import (
    BaseSubstrateOp,
    EnableServiceUnitOp,
    EnsureDirectoryOp,
    EnsureGroupOp,
    EnsureUserOp,
    InstallDependencyManifestOp,
    InstallPackagesOp,
    MaterializationOp,
    PlaceFileOp,
    PlaceProjectContentOp,
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
    def ensure_directory(self, node_address: str, op: EnsureDirectoryOp) -> None: ...
    def place_file(self, node_address: str, path: str, content: str, mode: str) -> None: ...
    def place_project_content(self, node_address: str, op: PlaceProjectContentOp) -> None: ...
    def install_dependency_manifest(
        self, node_address: str, op: InstallDependencyManifestOp
    ) -> None: ...
    def enable_service_unit(self, node_address: str, unit_name: str) -> None: ...
    def start_service_unit(self, node_address: str, unit_name: str) -> None: ...
    def observe_installed_packages(
        self, node_address: str, manager: str, packages: tuple[str, ...]
    ) -> frozenset[str]: ...
    def observe_local_group(self, node_address: str, name: str) -> bool: ...
    def observe_local_user(self, node_address: str, username: str) -> bool: ...
    def observe_directory(self, node_address: str, path: str) -> bool: ...
    def observe_file(self, node_address: str, path: str) -> bool: ...
    def observe_dependency_manifest_installed(
        self, node_address: str, op: InstallDependencyManifestOp
    ) -> bool: ...
    def observe_service_unit_enabled(self, node_address: str, unit_name: str) -> bool: ...
    def observe_service_unit_active(self, node_address: str, unit_name: str) -> bool: ...


_Execute = Callable[[MaterializationOp, str, MaterializationExecutor], None]

# Dispatch on op type, not a branch chain: each op type materializes through
# exactly one typed executor method, and the table is the single place that
# grows as new generic operations are added.
_EXECUTORS: dict[type, _Execute] = {
    BaseSubstrateOp: lambda op, addr, ex: ex.ensure_base_substrate(addr, op.image_ref),
    InstallPackagesOp: lambda op, addr, ex: ex.install_packages(addr, op.manager, op.packages),
    EnsureGroupOp: lambda op, addr, ex: ex.ensure_group(addr, op.name, op.gid),
    EnsureUserOp: lambda op, addr, ex: ex.ensure_user(addr, op),
    EnsureDirectoryOp: lambda op, addr, ex: ex.ensure_directory(addr, op),
    PlaceFileOp: lambda op, addr, ex: ex.place_file(addr, op.path, op.content, op.mode),
    PlaceProjectContentOp: lambda op, addr, ex: ex.place_project_content(addr, op),
    InstallDependencyManifestOp: lambda op, addr, ex: ex.install_dependency_manifest(addr, op),
    EnableServiceUnitOp: lambda op, addr, ex: ex.enable_service_unit(addr, op.unit_name),
    StartServiceUnitOp: lambda op, addr, ex: ex.start_service_unit(addr, op.unit_name),
}


def _execute_op(
    op: MaterializationOp, node_address: str, executor: MaterializationExecutor
) -> None:
    """Dispatch one op to its typed executor method via the op-type table."""

    handler = _EXECUTORS.get(type(op))
    if handler is not None:
        handler(op, node_address, executor)


_Verify = Callable[[MaterializationOp, str, MaterializationExecutor], "str | None"]


def _verify_install_packages(op: InstallPackagesOp, addr: str, ex: MaterializationExecutor) -> str | None:
    """Verify every declared package is observed installed."""

    observed = ex.observe_installed_packages(addr, op.manager, op.packages)
    missing = tuple(name for name in op.packages if name not in observed)
    return f"packages not installed via {op.manager}: {', '.join(missing)}" if missing else None


def _verify_ensure_group(op: EnsureGroupOp, addr: str, ex: MaterializationExecutor) -> str | None:
    """Verify the declared local group is observed present."""

    return None if ex.observe_local_group(addr, op.name) else f"local group not present: {op.name}"


def _verify_ensure_user(op: EnsureUserOp, addr: str, ex: MaterializationExecutor) -> str | None:
    """Verify the declared local user is observed present."""

    return None if ex.observe_local_user(addr, op.username) else f"local user not present: {op.username}"


def _verify_ensure_directory(op: EnsureDirectoryOp, addr: str, ex: MaterializationExecutor) -> str | None:
    """Verify the declared directory is observed present."""

    return None if ex.observe_directory(addr, op.path) else f"directory not present: {op.path}"


def _verify_place_file(op: PlaceFileOp, addr: str, ex: MaterializationExecutor) -> str | None:
    """Verify the placed config file is observed present."""

    return None if ex.observe_file(addr, op.path) else f"config file not present: {op.path}"


def _verify_place_project_content(
    op: PlaceProjectContentOp, addr: str, ex: MaterializationExecutor
) -> str | None:
    """Verify the copied project-sourced content is observed present."""

    return None if ex.observe_file(addr, op.dest_path) else f"content not present: {op.dest_path}"


def _verify_install_dependency_manifest(
    op: InstallDependencyManifestOp, addr: str, ex: MaterializationExecutor
) -> str | None:
    """Verify the manifest's declared package is observed installed."""

    if ex.observe_dependency_manifest_installed(addr, op):
        return None
    return f"dependency manifest not installed: {op.path}"


def _verify_enable_service_unit(op: EnableServiceUnitOp, addr: str, ex: MaterializationExecutor) -> str | None:
    """Verify the declared service unit is observed enabled."""

    if ex.observe_service_unit_enabled(addr, op.unit_name):
        return None
    return f"service unit not enabled: {op.unit_name}"


def _verify_start_service_unit(op: StartServiceUnitOp, addr: str, ex: MaterializationExecutor) -> str | None:
    """Verify the declared service unit is observed active."""

    if ex.observe_service_unit_active(addr, op.unit_name):
        return None
    return f"service unit not active: {op.unit_name}"


# BaseSubstrateOp has no entry: a running container is not proof, so the
# substrate is proved transitively by the state materialized onto it.
_VERIFIERS: dict[type, _Verify] = {
    InstallPackagesOp: _verify_install_packages,
    EnsureGroupOp: _verify_ensure_group,
    EnsureUserOp: _verify_ensure_user,
    EnsureDirectoryOp: _verify_ensure_directory,
    PlaceFileOp: _verify_place_file,
    PlaceProjectContentOp: _verify_place_project_content,
    InstallDependencyManifestOp: _verify_install_dependency_manifest,
    EnableServiceUnitOp: _verify_enable_service_unit,
    StartServiceUnitOp: _verify_start_service_unit,
}


def _verify_op(
    op: MaterializationOp, node_address: str, executor: MaterializationExecutor
) -> str | None:
    """Return a read-after-write failure reason for one op, or None if verified."""

    verifier = _VERIFIERS.get(type(op))
    return verifier(op, node_address, executor) if verifier is not None else None


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
        except Exception:
            # Admission boundary: translate every internal/backend failure into
            # the ACES LabResult envelope; the raw detail is deliberately not
            # echoed (redaction + no verbatim message).
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
