"""Concrete Docker materialization executor (ADR-047).

Implements the generic :class:`~aptl.backends.aces_materializer_engine.MaterializationExecutor`
surface by running generic OS commands inside a node's base-OS container: a
package manager for packages, `groupadd`/`useradd`/`getent`/`id` for identity,
and `systemctl` for service units. Dispatch is product-agnostic; the same code
paths materialize any node from its declared state.

Commands run as an argv list through an injected exec callable (the deployment
backend's `container_exec`), never a shell string, so no scenario value is ever
interpolated into a shell. A non-zero mutation exit raises
:class:`MaterializationCommandError`, which the materialization engine catches at
the admission boundary and translates into the ACES `LabResult` envelope.
"""

from __future__ import annotations

import base64
import shlex
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Protocol

from aptl.backends.aces_materializer import EnsureUserOp, PlaceProjectContentOp
from aptl.backends.aces_package_managers import (
    install_argv,
    parse_installed,
    query_installed_argv,
    refresh_argv,
)


class MaterializationCommandError(RuntimeError):
    """A generic materialization command exited non-zero inside a node container.

    Internal to the backend: the engine catches it and renders an ACES
    diagnostic. It carries no raw command output, so nothing sensitive escapes.
    """


class _ExecOutcome(Protocol):
    returncode: int
    stdout: str


ExecFn = Callable[[str, list[str]], _ExecOutcome]


class DockerMaterializationExecutor:
    """Run generic materialization operations inside per-node base containers."""

    def __init__(
        self,
        *,
        run: ExecFn,
        container_for: Callable[[str], str],
        start_base: Callable[[str, str], None],
        copy_in: Callable[[str, str, str, bool], None] | None = None,
        project_dir: Path | None = None,
    ) -> None:
        self._run = run
        self._container_for = container_for
        self._start_base = start_base
        self._copy_in = copy_in
        self._project_dir = project_dir

    # -- mutations -------------------------------------------------------

    def ensure_base_substrate(self, node_address: str, image_ref: str) -> None:
        self._start_base(node_address, image_ref)

    def install_packages(
        self, node_address: str, manager: str, packages: tuple[str, ...]
    ) -> None:
        refresh = refresh_argv(manager)
        if refresh is not None:
            self._require_ok(node_address, refresh, "refresh package index")
        self._require_ok(node_address, install_argv(manager, packages), "install packages")

    def ensure_group(self, node_address: str, name: str, gid: int | str | None) -> None:
        argv = ["groupadd", "-f"]
        if gid is not None:
            argv += ["-g", str(gid)]
        argv.append(name)
        self._require_ok(node_address, argv, "ensure group")

    def ensure_user(self, node_address: str, op: EnsureUserOp) -> None:
        if self.observe_local_user(node_address, op.username):
            return  # reconcile-not-recreate: a present user is left in place
        self._require_ok(node_address, _useradd_argv(op), "ensure user")

    def place_file(self, node_address: str, path: str, content: str, mode: str = "") -> None:
        # base64-encode the content so no authored value is interpreted by the
        # shell; the path is quoted. Creates parent dirs, then chmods if asked.
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        quoted_path = shlex.quote(path)
        parent = shlex.quote(str(PurePosixPath(path).parent))
        script = f"mkdir -p {parent} && printf %s {shlex.quote(encoded)} | base64 -d > {quoted_path}"
        if mode:
            script += f" && chmod {shlex.quote(mode)} {quoted_path}"
        self._require_ok(node_address, ["sh", "-c", script], "place file")

    def place_project_content(
        self, node_address: str, op: PlaceProjectContentOp
    ) -> None:
        if self._project_dir is None or self._copy_in is None:
            raise MaterializationCommandError(
                f"project content placement needs a project dir on {node_address}"
            )
        root = self._project_dir.resolve()
        source = (self._project_dir / op.source_relpath).resolve()
        if source != root and root not in source.parents:
            raise MaterializationCommandError(
                f"project content source escapes the project root on {node_address}"
            )
        if not source.exists():
            raise MaterializationCommandError(
                f"project content source missing on {node_address}: {op.source_relpath}"
            )
        container = self._container_for(node_address)
        parent = str(PurePosixPath(op.dest_path).parent)
        self._require_ok(node_address, ["mkdir", "-p", parent], "prep content dir")
        self._copy_in(container, str(source), op.dest_path, op.is_directory)

    def enable_service_unit(self, node_address: str, unit_name: str) -> None:
        self._require_ok(node_address, ["systemctl", "enable", unit_name], "enable unit")

    def start_service_unit(self, node_address: str, unit_name: str) -> None:
        self._require_ok(node_address, ["systemctl", "start", unit_name], "start unit")

    # -- observations (read-after-write) ---------------------------------

    def observe_installed_packages(
        self, node_address: str, manager: str, packages: tuple[str, ...]
    ) -> frozenset[str]:
        outcome = self._exec(node_address, query_installed_argv(manager, packages))
        return parse_installed(manager, outcome.stdout)

    def observe_local_group(self, node_address: str, name: str) -> bool:
        return self._exec(node_address, ["getent", "group", name]).returncode == 0

    def observe_local_user(self, node_address: str, username: str) -> bool:
        return self._exec(node_address, ["id", "-u", username]).returncode == 0

    def observe_file(self, node_address: str, path: str) -> bool:
        return self._exec(node_address, ["test", "-e", path]).returncode == 0

    def observe_service_unit_enabled(self, node_address: str, unit_name: str) -> bool:
        outcome = self._exec(node_address, ["systemctl", "is-enabled", unit_name])
        return outcome.stdout.strip() == "enabled"

    def observe_service_unit_active(self, node_address: str, unit_name: str) -> bool:
        outcome = self._exec(node_address, ["systemctl", "is-active", unit_name])
        return outcome.stdout.strip() == "active"

    # -- internals -------------------------------------------------------

    def _exec(self, node_address: str, argv: list[str]) -> _ExecOutcome:
        return self._run(self._container_for(node_address), argv)

    def _require_ok(self, node_address: str, argv: list[str], what: str) -> None:
        if self._exec(node_address, argv).returncode != 0:
            raise MaterializationCommandError(
                f"generic materialization step '{what}' failed on {node_address}"
            )


def _useradd_argv(op: EnsureUserOp) -> list[str]:
    argv = ["useradd", "--create-home"]
    if op.uid is not None:
        argv += ["-u", str(op.uid)]
    if op.primary_group:
        argv += ["-g", op.primary_group]
    if op.supplemental_groups:
        argv += ["-G", ",".join(op.supplemental_groups)]
    if op.shell:
        argv += ["-s", op.shell]
    if op.home:
        argv += ["-d", op.home]
    argv.append(op.username)
    return argv
