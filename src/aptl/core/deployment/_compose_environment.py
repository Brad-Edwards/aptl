"""Environment bindings for the Compose backend: preflight and delivery (#965).

The binding rules live in :mod:`aptl.core.deployment._environment_bindings`.
This module applies them to the Compose backend:

- the preflight binds every base-container node and every Compose service APTL
  generates, before any mutation;
- a Compose service receives each out-of-band value through its own owner-only
  env file, never through ``${NAME}`` interpolation, which every service and
  APTL's own Compose files share;
- a ``docker compose`` process keeps only the client's own variables and
  APTL's settings, so no Compose file can interpolate anything else from
  APTL's environment.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from aptl.core.config import EnvironmentGrant
from aptl.core.deployment._environment_bindings import (
    EnvironmentBinding,
    EnvironmentBindingContext,
    EnvironmentBindingError,
    binding_context,
    declared_environment,
    describe_bindings,
    out_of_band_binding,
    sourced_names,
    unbound_environment_error,
    warn_unused_grants,
)
from aptl.core.deployment._realization_primitives import (
    EnvironmentDeliveryRefused,
    environment_file_line,
)
from aptl.core.lab_types import LabResult
from aptl.utils.logging import get_logger
from aptl.utils.pathsafe import (
    REASON_NOT_FOUND,
    PathContainmentError,
    listdir_contained_nofollow,
    remove_contained_nofollow,
    replace_private_nofollow,
)

if TYPE_CHECKING:
    from aptl.core.deployment.realization import (
        DeploymentNodeRealization,
        DeploymentRealizationSpec,
    )

log = get_logger("deployment.compose_environment")

#: Owner-only directory holding each service's env file and the override that
#: attaches them. The override names paths only, never a value.
SOURCED_ENVIRONMENT_DIR = ".aptl/realization/sourced-environment"
SOURCED_ENVIRONMENT_OVERRIDE = f"{SOURCED_ENVIRONMENT_DIR}/compose.override.yml"

#: Variables the ``docker compose`` client itself reads: toolchain, locale, TLS
#: trust and temporary paths, credential-helper locations, the Windows plugin
#: directory (``%ProgramFiles%\Docker\cli-plugins``), Docker client transport,
#: Compose behaviour, and proxies. None of them is a scenario value.
#: ``COMPOSE_FILE``, ``COMPOSE_PROFILES`` and ``COMPOSE_PROJECT_NAME`` stay out:
#: APTL selects the model itself.
COMPOSE_CLIENT_VARIABLES = frozenset(
    (
        "PATH HOME USER LOGNAME SHELL TERM LANG LC_ALL LC_CTYPE TZ TMPDIR TEMP TMP "
        "XDG_CONFIG_HOME XDG_RUNTIME_DIR XDG_CACHE_HOME XDG_DATA_HOME SSH_AUTH_SOCK "
        "SSL_CERT_FILE SSL_CERT_DIR DBUS_SESSION_BUS_ADDRESS GNUPGHOME "
        "PASSWORD_STORE_DIR "
        "USERPROFILE HOMEDRIVE HOMEPATH APPDATA LOCALAPPDATA PROGRAMDATA PROGRAMFILES "
        "SYSTEMROOT WINDIR COMSPEC PATHEXT "
        "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS "
        "DOCKER_TLS_VERIFY DOCKER_API_VERSION DOCKER_SSH_IDENTITY "
        "DOCKER_DEFAULT_PLATFORM DOCKER_BUILDKIT DOCKER_CLI_HINTS "
        "DOCKER_CLI_EXPERIMENTAL "
        "COMPOSE_HTTP_TIMEOUT COMPOSE_PARALLEL_LIMIT COMPOSE_BAKE COMPOSE_ANSI "
        "COMPOSE_STATUS_STDOUT COMPOSE_MENU COMPOSE_PROGRESS COMPOSE_EXPERIMENTAL "
        "HTTP_PROXY HTTPS_PROXY NO_PROXY ALL_PROXY "
        "http_proxy https_proxy no_proxy all_proxy"
    ).split()
)
#: Prefixes kept as well: APTL's own settings, such as the ``APTL_HP_*``
#: host-port pins and the remaps ``aptl lab start`` exports, and build tuning.
_COMPOSE_CLIENT_PREFIXES = ("APTL_", "BUILDKIT_", "BUILDX_")


def compose_process_environment(inherited: Mapping[str, str]) -> dict[str, str]:
    """Return the environment one ``docker compose`` process may see.

    Compose reads ``${NAME}`` interpolation, and bare ``environment`` and
    ``build.args`` entries, from its own process environment before the
    explicitly bound project ``.env``. Only the client's own variables and
    APTL's settings pass, so nothing else in APTL's environment can reach a
    Compose file. No bound value is added here.
    """

    return {
        name: value
        for name, value in inherited.items()
        if name in COMPOSE_CLIENT_VARIABLES or name.startswith(_COMPOSE_CLIENT_PREFIXES)
    }


@dataclass(frozen=True)
class ComposeEnvironment:
    """Each Compose service's out-of-band bindings, delivered by its env file."""

    sourced: Mapping[str, tuple[EnvironmentBinding, ...]] = field(
        default_factory=dict, repr=False
    )


def compose_nodes(
    realization: "DeploymentRealizationSpec",
) -> list["DeploymentNodeRealization"]:
    """Return the nodes the generated Compose model renders as services."""

    imaged = {image.address for image in realization.images}
    return [
        node
        for node in realization.nodes
        if node.service_name and node.address in imaged
    ]


def compose_environment(
    context: EnvironmentBindingContext, realization: "DeploymentRealizationSpec"
) -> ComposeEnvironment:
    """Bind every generated Compose service's out-of-band variables, or refuse.

    Each value must also fit the single-quoted Compose env-file line that will
    carry it, so a refusal comes before any mutation.
    """

    sourced: dict[str, tuple[EnvironmentBinding, ...]] = {}
    for node in compose_nodes(realization):
        declared = declared_environment(node.runtime)
        names = [n for n in dict.fromkeys(declared.names) if n in declared.sourced]
        if names:
            sourced[str(node.service_name)] = tuple(
                _compose_binding(context, node.name, name) for name in names
            )
    return ComposeEnvironment(sourced=sourced)


def _compose_binding(
    context: EnvironmentBindingContext, node: str, name: str
) -> EnvironmentBinding:
    """Bind one out-of-band Compose variable, naming the node in a refusal."""

    try:
        binding = out_of_band_binding(context, node, name)
        environment_file_line(name, binding.value, compose=True)
    except (EnvironmentBindingError, EnvironmentDeliveryRefused) as exc:
        raise EnvironmentBindingError(
            f"Environment binding refused for node {node}: {exc}."
        ) from exc
    return binding


def sourced_environment_file(service_name: str) -> str:
    """Return the project-relative env file that carries one service's values."""

    key = hashlib.sha256(service_name.encode()).hexdigest()[:20]
    return f"{SOURCED_ENVIRONMENT_DIR}/{key}.env"


def write_sourced_environment(
    root: Path, environment: ComposeEnvironment
) -> Path | None:
    """Write each service's env file and the override that attaches it.

    Every file is replaced without following links and kept owner-only. Files
    this request does not use are removed, so a value no longer bound does not
    stay on disk. Returns the override, or ``None`` when no service needs one.
    """

    payloads = {
        sourced_environment_file(service): "".join(
            environment_file_line(b.name, b.value, compose=True) for b in bindings
        ).encode()
        for service, bindings in environment.sourced.items()
    }
    if payloads:
        services = {
            service: {"env_file": [str(root / sourced_environment_file(service))]}
            for service in environment.sourced
        }
        payloads[SOURCED_ENVIRONMENT_OVERRIDE] = yaml.safe_dump(
            {"services": services}, sort_keys=True
        ).encode()
    for relative, payload in payloads.items():
        replace_private_nofollow(root, relative, payload)
    _remove_unused_files(root, set(payloads))
    for service, bindings in environment.sourced.items():
        log.info(
            "Compose service %s environment: %s", service, describe_bindings(bindings)
        )
    return root / SOURCED_ENVIRONMENT_OVERRIDE if payloads else None


def _remove_unused_files(root: Path, used: set[str]) -> None:
    """Remove each file in the sourced directory that this request does not use."""

    try:
        names = listdir_contained_nofollow(root, SOURCED_ENVIRONMENT_DIR)
    except PathContainmentError as exc:
        if exc.reason != REASON_NOT_FOUND:
            raise
        names = []
    for name in names:
        relative = f"{SOURCED_ENVIRONMENT_DIR}/{name}"
        if relative not in used:
            remove_contained_nofollow(root, relative)


class ComposeEnvironmentBindingMixin:
    """Check every declared variable has an explicit source before mutation."""

    _project_dir: Path
    _environment_grants: tuple[EnvironmentGrant, ...] = ()
    _compose_environment: ComposeEnvironment | None = None

    def use_environment_grants(self, grants: Sequence[EnvironmentGrant]) -> None:
        """Adopt the operator's environment grants from ``aptl.json``."""

        self._environment_grants = tuple(grants)

    def _environment_binding_preflight(
        self,
        realization: "DeploymentRealizationSpec",
        scenario_root: Path | None = None,
    ) -> LabResult | None:
        """Bind the request's declared environment, or refuse it.

        Runs with the other backend preflights, before any scenario mutation.
        The bindings it records are what each node and service later receives,
        so a grant or adapter value that is missing now never becomes a
        silently omitted variable after containers have changed. Compose
        services are bound only when APTL generates their model; a project-tree
        scenario's own ``docker-compose.yml`` carries its own references. The
        file's presence alone can decide this because ``env_pack_bundle()``
        refuses a pack that ships one at its root.
        """

        from aptl.core.deployment._compose_base_container_realization import (
            _base_container_node_addresses,
        )
        from aptl.core.deployment._compose_node_generation import (
            STATIC_COMPOSE_FILENAME,
        )

        # Nothing from an earlier request reaches this one's Compose services.
        self._compose_environment = ComposeEnvironment()
        context = binding_context(
            realization, self._environment_grants, self._project_dir
        )
        self._environment_binding_context = context
        self._environment_consumers = {
            node.address: node.name for node in realization.nodes
        }
        addresses = _base_container_node_addresses(realization)
        error = unbound_environment_error(context, realization, addresses)
        static = scenario_root is not None and (
            (scenario_root / STATIC_COMPOSE_FILENAME).exists()
        )
        if error is None and not static:
            try:
                self._compose_environment = compose_environment(context, realization)
            except EnvironmentBindingError as exc:
                error = str(exc)
            addresses |= {node.address for node in compose_nodes(realization)}
        if error is None:
            warn_unused_grants(context, sourced_names(realization, addresses))
        return LabResult(success=False, error=error) if error is not None else None

    def _write_sourced_environment_override(
        self, realization: "DeploymentRealizationSpec", root: Path
    ) -> Path | None:
        """Write this request's per-service env files and their override.

        Raises :class:`EnvironmentBindingError`, which names the refusal reason
        and never a value, when the files cannot be written safely or when the
        bindings were never checked for this request.
        """

        environment = self._compose_environment
        if environment is None:
            if sourced_names(
                realization, frozenset(n.address for n in compose_nodes(realization))
            ):
                raise EnvironmentBindingError(
                    "the environment grants were not checked before this start"
                )
            environment = ComposeEnvironment()
        try:
            return write_sourced_environment(root, environment)
        except PathContainmentError as exc:
            raise EnvironmentBindingError(
                f"unsafe Compose environment file ({exc.reason})"
            ) from exc
        except OSError as exc:
            raise EnvironmentBindingError(
                f"Compose environment file could not be written ({type(exc).__name__})"
            ) from exc

    @staticmethod
    def _compose_command_environment(inherited: Mapping[str, str]) -> dict[str, str]:
        """Return the process environment for one ``docker compose`` command."""

        return compose_process_environment(inherited)
