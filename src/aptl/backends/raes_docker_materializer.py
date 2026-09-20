"""Concrete Docker materialization executor (ADR-048).

Implements the generic :class:`~aptl.backends.raes_materializer_engine.MaterializationExecutor`
surface by running generic OS commands inside a node's base-OS container: a
package manager for packages, `groupadd`/`useradd`/`getent`/`id` for identity,
and `systemctl` for service units. Dispatch is product-agnostic; the same code
paths materialize any node from its declared state.

Commands run through an injected exec callable (the deployment backend's
`container_exec`). Sensitive file bodies use stdin, never process argv. A
non-zero mutation exit raises
:class:`MaterializationCommandError`, which the materialization engine catches at
the admission boundary and translates into the RAES `LabResult` envelope.
"""

from __future__ import annotations

import io
import hashlib
import shlex
import tarfile
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from aptl.backends.raes_materializer import (
    EnsureDirectoryOp,
    EnsureUserOp,
    InstallDependencyManifestOp,
    InstallSoftwareComponentOp,
    PlacePackArtifactOp,
    PlaceProjectContentOp,
    ProvisionDomainAuthorityOp,
    SetFilesystemMetadataOp,
)
from aptl.backends._raes_docker_materializer_observations import (
    DockerMaterializationObservationMixin,
    _ExecOutcome,
    _normalized_mode,
)
from aptl.backends.raes_package_managers import (
    install_argv,
    manifest_install_argv,
    refresh_argv,
)
from aptl.core.deployment.errors import BackendSeedError, BackendTimeoutError

# A just-started container's network interface is not always immediately ready
# for outbound traffic: a fresh-VM reproduction (issue #581) showed a node's
# very first package-index refresh failing with a corrupted-download GPG
# signature error on 4 of 5 attempts run immediately after `docker run`, and
# 0 of 5 after a 1s delay. The refresh command is idempotent, so retrying it
# handles this general Docker-boot timing characteristic without a blind
# fixed delay that would be wrong for both slower and faster hosts.
_PACKAGE_INDEX_REFRESH_RETRY_DELAYS_SECONDS: tuple[float, ...] = (1.0, 2.0, 4.0, 8.0)
_IDEMPOTENT_MUTATION_RETRY_DELAYS_SECONDS: tuple[float, ...] = (0.25, 0.5, 1.0, 2.0)


class MaterializationCommandError(RuntimeError):
    """A generic materialization command exited non-zero inside a node container.

    Internal to the backend: the engine catches it and renders a RAES
    diagnostic. It carries no raw command output, so nothing sensitive escapes.
    """


ExecFn = Callable[[str, list[str]], _ExecOutcome]
ExecWithInputFn = Callable[[str, list[str], str], _ExecOutcome]


@dataclass(frozen=True)
class DockerMaterializationSettings:
    """Optional execution context for Docker node materialization."""

    scenario_root: Path | None = None
    sleep: Callable[[float], None] = time.sleep
    offline_staged: bool = False


class DockerMaterializationExecutor(DockerMaterializationObservationMixin):
    """Run generic materialization operations inside per-node base containers."""

    def __init__(
        self,
        *,
        run: ExecFn,
        run_with_input: ExecWithInputFn | None = None,
        container_for: Callable[[str], str],
        start_base: Callable[[str, str], None],
        copy_in: Callable[[str, str, str, bool], None] | None = None,
        settings: DockerMaterializationSettings | None = None,
    ) -> None:
        configured = settings or DockerMaterializationSettings()
        self._run = run
        self._run_with_input = run_with_input
        self._container_for = container_for
        self._start_base = start_base
        self._copy_in = copy_in
        self._scenario_root = configured.scenario_root
        self._sleep = configured.sleep
        self._offline_staged = configured.offline_staged

    # -- mutations -------------------------------------------------------

    def ensure_base_substrate(self, node_address: str, image_ref: str) -> None:
        self._start_base(node_address, image_ref)

    def install_packages(
        self, node_address: str, manager: str, packages: tuple[str, ...]
    ) -> None:
        installed = self.observe_installed_packages(node_address, manager, packages)
        missing = tuple(package for package in packages if package not in installed)
        if not missing:
            return
        if self._offline_staged:
            raise MaterializationCommandError(
                f"offline image is missing declared {manager} packages on "
                f"{node_address}: {', '.join(missing)}"
            )
        refresh = refresh_argv(manager)
        if refresh is not None:
            self._require_ok_with_retry(
                node_address,
                refresh,
                "refresh package index",
                _PACKAGE_INDEX_REFRESH_RETRY_DELAYS_SECONDS,
            )
        self._require_ok(
            node_address, install_argv(manager, missing), "install packages"
        )

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
        argv = _useradd_argv(op)
        outcome = self._exec(node_address, argv)
        if outcome.returncode == 0:
            return
        # A Docker exec can report failure after useradd committed (or while
        # the guest's account database was briefly busy). Re-read before any
        # repeat mutation, then retry only the idempotent ensure operation.
        self._retry_ensure_user(node_address, op.username, argv)

    def _retry_ensure_user(
        self, node_address: str, username: str, argv: list[str]
    ) -> None:
        """Retry an ambiguous user creation only after checking guest state."""

        for delay in _IDEMPOTENT_MUTATION_RETRY_DELAYS_SECONDS:
            self._sleep(delay)
            if self.observe_local_user(node_address, username):
                return
            outcome = self._exec(node_address, argv)
            if outcome.returncode == 0 or self.observe_local_user(
                node_address, username
            ):
                return
        raise MaterializationCommandError(
            f"generic materialization step 'ensure user' failed on {node_address}"
        )

    def ensure_directory(self, node_address: str, op: EnsureDirectoryOp) -> None:
        self._require_ok(node_address, ["mkdir", "-p", op.path], "ensure directory")
        if op.owner or op.group:
            owner_spec = op.owner + (f":{op.group}" if op.group else "")
            self._require_ok(
                node_address, ["chown", owner_spec, op.path], "chown directory"
            )
        if op.mode:
            self._require_ok(
                node_address, ["chmod", op.mode, op.path], "chmod directory"
            )

    def set_filesystem_metadata(
        self, node_address: str, op: SetFilesystemMetadataOp
    ) -> None:
        """Apply exact authored ownership and mode to an existing path."""

        owner = op.owner or (str(op.uid) if op.uid is not None else "")
        group = op.group or (str(op.gid) if op.gid is not None else "")
        if owner or group:
            owner_spec = owner + (f":{group}" if group else "")
            self._require_ok(
                node_address, ["chown", owner_spec, op.path], "chown filesystem entry"
            )
        if op.mode:
            self._require_ok(
                node_address,
                ["chmod", _normalized_mode(op.mode), op.path],
                "chmod filesystem entry",
            )

    def place_file(
        self, node_address: str, path: str, content: str, mode: str = ""
    ) -> None:
        if self._run_with_input is None:
            raise MaterializationCommandError(
                f"file placement needs stdin delivery on {node_address}"
            )
        # Never put an authored body, even reversibly encoded, in docker exec's
        # argv. Stage it in the destination directory and atomically replace the
        # file. A cryptographic readback makes an ambiguous exec outcome
        # safe to retry and avoids treating a truncated file as realized.
        quoted_path = shlex.quote(path)
        parent = shlex.quote(str(PurePosixPath(path).parent))
        script = (
            "set -eu; "
            f"mkdir -p {parent}; "
            f"tmp=$(mktemp {shlex.quote(path + '.aptl.XXXXXX')}); "
            "trap 'rm -f \"$tmp\"' EXIT; "
            'cat > "$tmp"; '
        )
        if mode:
            script += f'chmod {shlex.quote(mode)} "$tmp"; '
        script += f'mv -f "$tmp" {quoted_path}'
        container = self._container_for(node_address)
        expected_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        for attempt in range(len(_IDEMPOTENT_MUTATION_RETRY_DELAYS_SECONDS) + 1):
            self._run_with_input(container, ["sh", "-c", script], content)
            readback = self._exec(node_address, ["sha256sum", path])
            actual_digest = (
                readback.stdout.split(maxsplit=1)[0]
                if readback.returncode == 0 and readback.stdout.strip()
                else ""
            )
            if actual_digest == expected_digest:
                # The exact bytes are present, even if the provider lost the
                # successful mutation result. No second write is needed.
                return
            if attempt < len(_IDEMPOTENT_MUTATION_RETRY_DELAYS_SECONDS):
                self._sleep(_IDEMPOTENT_MUTATION_RETRY_DELAYS_SECONDS[attempt])
        raise MaterializationCommandError(
            f"generic materialization step 'place file' failed on {node_address}"
        )

    def place_project_content(
        self, node_address: str, op: PlaceProjectContentOp
    ) -> None:
        if self._scenario_root is None or self._copy_in is None:
            raise MaterializationCommandError(
                f"project content placement needs a project dir on {node_address}"
            )
        root = self._scenario_root.resolve()
        source = (self._scenario_root / op.source_relpath).resolve()
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
        self._require_ok_with_retry(
            node_address,
            ["mkdir", "-p", parent],
            "prep content dir",
            _IDEMPOTENT_MUTATION_RETRY_DELAYS_SECONDS,
        )
        self._copy_in(container, str(source), op.dest_path, op.is_directory)

    def place_pack_artifact(self, node_address: str, op: PlacePackArtifactOp) -> None:
        if self._scenario_root is None or self._copy_in is None:
            raise MaterializationCommandError(
                f"pack content placement needs a staged pack root on {node_address}"
            )
        from raes_env_packs import resolve_pack_artifact

        resolved = resolve_pack_artifact(str(self._scenario_root), op.artifact_id)
        if getattr(resolved.identity, "digest", None) != op.artifact_digest:
            raise MaterializationCommandError(
                f"pack content digest mismatch on {node_address}: {op.artifact_id}"
            )
        container = self._container_for(node_address)
        parent = str(PurePosixPath(op.dest_path).parent)
        self._require_ok_with_retry(
            node_address,
            ["mkdir", "-p", parent],
            "prep content dir",
            _IDEMPOTENT_MUTATION_RETRY_DELAYS_SECONDS,
        )
        with tempfile.TemporaryDirectory() as staging:
            if op.is_directory:
                staged = Path(staging) / "tree"
                staged.mkdir()
                with tarfile.open(
                    fileobj=io.BytesIO(resolved.data), mode="r:*"
                ) as archive:
                    archive.extractall(staged, filter="data")
            else:
                staged = Path(staging) / PurePosixPath(op.dest_path).name
                staged.write_bytes(resolved.data)
            for path in (
                staged,
                *(sorted(staged.rglob("*")) if op.is_directory else ()),
            ):
                if path.is_symlink():
                    raise MaterializationCommandError(
                        "pack content contains a symbolic link"
                    )
                executable = (
                    path.is_dir()
                    or bool(path.stat().st_mode & 0o111)
                    or (not op.is_directory and op.executable)
                )
                path.chmod(
                    (0o700 if executable else 0o600)
                    if op.sensitive
                    else (0o755 if executable else 0o644)
                )
            for attempt in range(len(_IDEMPOTENT_MUTATION_RETRY_DELAYS_SECONDS) + 1):
                try:
                    self._copy_in(container, str(staged), op.dest_path, op.is_directory)
                    break
                except (BackendSeedError, BackendTimeoutError, OSError):
                    if attempt == len(_IDEMPOTENT_MUTATION_RETRY_DELAYS_SECONDS):
                        raise MaterializationCommandError(
                            f"pack content copy failed on {node_address}"
                        ) from None
                    self._sleep(_IDEMPOTENT_MUTATION_RETRY_DELAYS_SECONDS[attempt])

    def install_dependency_manifest(
        self, node_address: str, op: InstallDependencyManifestOp
    ) -> None:
        directory = str(PurePosixPath(op.path).parent)
        self._require_ok(
            node_address,
            manifest_install_argv(
                op.ecosystem, directory, offline=self._offline_staged
            ),
            "install dependency manifest",
        )

    def install_software_component(
        self, node_address: str, op: InstallSoftwareComponentOp
    ) -> None:
        """Install an exact npm lockfile and run its declared build script."""

        if op.ecosystem != "npm":
            raise MaterializationCommandError(
                f"unsupported software component ecosystem on {node_address}"
            )
        directory = str(PurePosixPath(op.manifest_path).parent)
        install_argv = ["npm", "--prefix", directory, "ci", "--include=dev"]
        if self._offline_staged:
            install_argv.append("--offline")
        self._require_ok(node_address, install_argv, "install software component")
        self._require_ok(
            node_address,
            ["npm", "--prefix", directory, "run", "build", "--if-present"],
            "build software component",
        )

    def provision_domain_authority(
        self, node_address: str, op: ProvisionDomainAuthorityOp
    ) -> None:
        """Bootstrap the selected Samba provider from authored domain facts."""

        if not op.domain or not op.realm:
            raise MaterializationCommandError(
                f"incomplete domain authority parameters on {node_address}"
            )
        self._require_ok(
            node_address,
            ["aptl-provision-samba-domain", op.domain, op.realm],
            "provision domain authority",
        )
        self._require_ok_with_retry(
            node_address,
            ["samba-tool", "domain", "info", "127.0.0.1"],
            "wait for domain authority",
            (0.25, 0.5, 1.0, 2.0, 4.0, 8.0),
        )

    def enable_service_unit(self, node_address: str, unit_name: str) -> None:
        self._require_ok(
            node_address, ["systemctl", "enable", unit_name], "enable unit"
        )

    def start_service_unit(self, node_address: str, unit_name: str) -> None:
        # A preinstalled package can auto-start with its default configuration
        # before authored content is placed. Plain start preserves that stale
        # process, and reload is insufficient for startup-only settings (BIND
        # query logging is one example). Restart applies the complete authored
        # state and also starts an inactive unit.
        self._require_ok(
            node_address, ["systemctl", "restart", unit_name], "start unit"
        )

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
