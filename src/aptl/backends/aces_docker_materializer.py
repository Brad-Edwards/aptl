"""Concrete Docker materialization executor (ADR-048).

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
import time
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Protocol

from aptl.backends.aces_materializer import (
    EnsureDirectoryOp,
    EnsureUserOp,
    InstallDependencyManifestOp,
    PlaceProjectContentOp,
)
from aptl.backends.aces_package_managers import (
    install_argv,
    manifest_install_argv,
    manifest_query_argv,
    parse_installed,
    query_installed_argv,
    refresh_argv,
)

# A just-started container's network interface is not always immediately ready
# for outbound traffic: a fresh-VM reproduction (issue #581) showed a node's
# very first package-index refresh failing with a corrupted-download GPG
# signature error on 4 of 5 attempts run immediately after `docker run`, and
# 0 of 5 after a 1s delay. The refresh command is idempotent, so retrying it
# handles this general Docker-boot timing characteristic without a blind
# fixed delay that would be wrong for both slower and faster hosts.
_PACKAGE_INDEX_REFRESH_RETRY_DELAYS_SECONDS: tuple[float, ...] = (1.0, 2.0, 4.0, 8.0)


class MaterializationCommandError(RuntimeError):
    """A generic materialization command exited non-zero inside a node container.

    Internal to the backend: the engine catches it and renders an ACES
    diagnostic. It carries no raw command output, so nothing sensitive escapes.
    """


class _ExecOutcome(Protocol):
    """The result shape a backend's exec callable returns."""

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
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._run = run
        self._container_for = container_for
        self._start_base = start_base
        self._copy_in = copy_in
        self._project_dir = project_dir
        self._sleep = sleep

    # -- mutations -------------------------------------------------------

    def ensure_base_substrate(self, node_address: str, image_ref: str) -> None:
        self._start_base(node_address, image_ref)

    def install_packages(
        self, node_address: str, manager: str, packages: tuple[str, ...]
    ) -> None:
        refresh = refresh_argv(manager)
        if refresh is not None:
            self._require_ok_with_retry(
                node_address,
                refresh,
                "refresh package index",
                _PACKAGE_INDEX_REFRESH_RETRY_DELAYS_SECONDS,
            )
        self._require_ok(node_address, install_argv(manager, packages), "install packages")

    def ensure_group(self, node_address: str, name: str, gid: int | str | None) -> None:
        argv = ["groupadd", "-f"]
        if gid is not None:
            argv += ["-g", str(gid)]
        argv.append(name)
        self._require_ok(node_address, argv, "ensure group")

    def ensure_user(self, node_address: str, op: EnsureUserOp) -> None:
        if self.observe_local_user(node_address, op.username):
            # reconcile-not-recreate: a present user is left in place
            return
        self._require_ok(node_address, _useradd_argv(op), "ensure user")

    def ensure_directory(self, node_address: str, op: EnsureDirectoryOp) -> None:
        self._require_ok(node_address, ["mkdir", "-p", op.path], "ensure directory")
        if op.owner or op.group:
            owner_spec = op.owner + (f":{op.group}" if op.group else "")
            self._require_ok(node_address, ["chown", owner_spec, op.path], "chown directory")
        if op.mode:
            self._require_ok(node_address, ["chmod", op.mode, op.path], "chmod directory")

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

    def install_dependency_manifest(
        self, node_address: str, op: InstallDependencyManifestOp
    ) -> None:
        directory = str(PurePosixPath(op.path).parent)
        self._require_ok(
            node_address,
            manifest_install_argv(op.ecosystem, directory),
            "install dependency manifest",
        )

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

    def observe_directory(self, node_address: str, path: str) -> bool:
        return self._exec(node_address, ["test", "-d", path]).returncode == 0

    def observe_file(self, node_address: str, path: str) -> bool:
        return self._exec(node_address, ["test", "-e", path]).returncode == 0

    def observe_dependency_manifest_installed(
        self, node_address: str, op: InstallDependencyManifestOp
    ) -> bool:
        # A manifest with no declared package name has nothing a query tool
        # can check by name; the manifest file existing is not proof the
        # install succeeded, so this fails closed rather than accepting a
        # weaker check.
        if not op.name:
            return False
        return self._exec(node_address, manifest_query_argv(op.ecosystem, op.name)).returncode == 0

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

    def _require_ok_with_retry(
        self,
        node_address: str,
        argv: list[str],
        what: str,
        delays: tuple[float, ...],
    ) -> None:
        outcome = self._exec(node_address, argv)
        for delay in delays:
            if outcome.returncode == 0:
                return
            self._sleep(delay)
            outcome = self._exec(node_address, argv)
        if outcome.returncode != 0:
            raise MaterializationCommandError(
                f"generic materialization step '{what}' failed on {node_address}"
            )


def _useradd_argv(op: EnsureUserOp) -> list[str]:
    """Build the `useradd` argv for one declared user's non-secret attributes."""

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
