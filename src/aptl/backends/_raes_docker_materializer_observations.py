"""Read-after-write guest observations for the Docker materialization executor."""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Protocol

from aptl.backends._raes_docker_observation_values import (
    metadata_dimension_matches as _metadata_dimension_matches,
    npm_entrypoint_paths as _npm_entrypoint_paths,
    samba_domain_info as _samba_domain_info,
)
from aptl.backends.raes_materializer import (
    InstallDependencyManifestOp,
    InstallSoftwareComponentOp,
    ProvisionDomainAuthorityOp,
    SetFilesystemMetadataOp,
)
from aptl.backends.raes_package_managers import (
    manifest_query_argv,
    parse_installed,
    query_installed_argv,
)


class _ExecOutcome(Protocol):
    """The result shape a backend's exec callable returns."""

    returncode: int
    stdout: str


class DockerMaterializationObservationMixin:
    """Observe exact guest state after generic materialization mutations."""

    def _exec(self, node_address: str, argv: list[str]) -> _ExecOutcome:
        raise NotImplementedError

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

    def observe_filesystem_metadata(
        self, node_address: str, op: SetFilesystemMetadataOp
    ) -> bool:
        """Read owner/group/id/mode with one bounded GNU stat invocation."""

        outcome = self._exec(
            node_address,
            ["stat", "-c", "%U:%G:%u:%g:%a", op.path],
        )
        fields = outcome.stdout.strip().split(":") if outcome.returncode == 0 else []
        if len(fields) != 5:
            return False
        owner, group, uid, gid, mode = fields
        return all(
            _metadata_dimension_matches(actual, expected)
            for actual, expected in (
                (owner, op.owner),
                (group, op.group),
                (uid, op.uid),
                (gid, op.gid),
                (mode.zfill(4), _normalized_mode(op.mode) if op.mode else ""),
            )
        )

    def observe_dependency_manifest_installed(
        self, node_address: str, op: InstallDependencyManifestOp
    ) -> bool:
        # A manifest with no declared package name has nothing a query tool
        # can check by name; the manifest file existing is not proof the
        # install succeeded, so this fails closed rather than accepting a
        # weaker check.
        if not op.name:
            return False
        return (
            self._exec(
                node_address, manifest_query_argv(op.ecosystem, op.name)
            ).returncode
            == 0
        )

    def observe_software_component(
        self, node_address: str, op: InstallSoftwareComponentOp
    ) -> bool:
        """Read npm package identity and verify its main/bin output exists."""

        package = self._observed_npm_package(node_address, op)
        directory = str(PurePosixPath(op.manifest_path).parent)
        outputs = _npm_entrypoint_paths(package or {})
        return bool(
            package
            and package.get("name") == op.package_name
            and package.get("version") == op.version
            and outputs
            and all(
                self._exec(
                    node_address, ["test", "-f", f"{directory}/{path}"]
                ).returncode
                == 0
                for path in outputs
            )
        )

    def _observed_npm_package(
        self, node_address: str, op: InstallSoftwareComponentOp
    ) -> dict[str, object] | None:
        """Read the selected npm package metadata, failing closed on bad output."""

        if op.ecosystem != "npm":
            return None
        directory = str(PurePosixPath(op.manifest_path).parent)
        outcome = self._exec(
            node_address,
            [
                "npm",
                "--prefix",
                directory,
                "pkg",
                "get",
                "name",
                "version",
                "main",
                "bin",
            ],
        )
        package: object = None
        if outcome.returncode == 0:
            try:
                package = json.loads(outcome.stdout)
            except (TypeError, ValueError):
                pass
        return package if isinstance(package, dict) else None

    def observe_domain_authority(
        self, node_address: str, op: ProvisionDomainAuthorityOp
    ) -> bool:
        """Read Samba's served DNS and NetBIOS identities back exactly."""

        outcome = self._exec(
            node_address, ["samba-tool", "domain", "info", "127.0.0.1"]
        )
        if outcome.returncode != 0:
            return False
        observed = _samba_domain_info(outcome.stdout)
        return (
            observed.get("forest", "").casefold() == op.realm.casefold()
            and observed.get("domain", "").casefold() == op.realm.casefold()
            and observed.get("netbios domain", "").casefold() == op.domain.casefold()
        )

    def observe_service_unit_enabled(self, node_address: str, unit_name: str) -> bool:
        outcome = self._exec(node_address, ["systemctl", "is-enabled", unit_name])
        return outcome.stdout.strip() == "enabled"

    def observe_service_unit_active(self, node_address: str, unit_name: str) -> bool:
        outcome = self._exec(node_address, ["systemctl", "is-active", unit_name])
        return outcome.stdout.strip() == "active"


def _normalized_mode(mode: str) -> str:
    """Return an SDL octal mode in the four-digit form used by chmod/stat."""

    value = mode[2:] if mode.startswith("0o") else mode
    return value.zfill(4)
