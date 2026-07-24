"""Generic package-manager mechanism registry (ADR-048).

Encodes how to drive a package manager (build an install command, query what is
installed, parse the result) as OS-mechanism knowledge, parameterized entirely
by the declared manager name and package names. It contains no product
knowledge: installing `wazuh-manager` and installing `curl` go through the same
generic apt path. An unknown manager fails closed rather than guessing.

Argv is always a list (no shell). Package names are sorted for deterministic,
reproducible commands.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


class UnsupportedPackageManagerError(ValueError):
    """Raised when APTL has no generic mechanism for a declared package manager.

    Fail closed: an unknown manager is an admission error translated into an ACES
    diagnostic at the engine boundary, never a guessed command.
    """


@dataclass(frozen=True)
class _Manager:
    """One package manager's install/query/parse mechanism."""

    install: Callable[[tuple[str, ...]], list[str]]
    query: Callable[[tuple[str, ...]], list[str]]
    parse: Callable[[str], frozenset[str]]
    # Optional index-refresh run before install (apt needs it on a slim base
    # image whose package lists were stripped). None when the manager refreshes
    # implicitly at install time.
    refresh: tuple[str, ...] | None = None


def _apt_install(packages: tuple[str, ...]) -> list[str]:
    """Build the non-interactive `apt-get install` argv for declared packages."""

    return [
        "env",
        "DEBIAN_FRONTEND=noninteractive",
        "apt-get",
        "install",
        "-y",
        "--no-install-recommends",
        *sorted(packages),
    ]


def _apt_query(packages: tuple[str, ...]) -> list[str]:
    """Build the `dpkg-query` argv that reports which declared packages are installed."""

    return ["dpkg-query", "-W", "-f=${Package}\n", *sorted(packages)]


def _lines_to_set(stdout: str) -> frozenset[str]:
    """Parse one-package-name-per-line query output into a set of names."""

    return frozenset(line.strip() for line in stdout.splitlines() if line.strip())


def _dnf_install(packages: tuple[str, ...]) -> list[str]:
    """Build the `dnf install` argv for declared packages."""

    return ["dnf", "install", "-y", *sorted(packages)]


def _dnf_query(packages: tuple[str, ...]) -> list[str]:
    """Build the `rpm -q` argv that reports which declared packages are installed."""

    return ["rpm", "-q", "--qf", "%{NAME}\n", *sorted(packages)]


def _pip_install(packages: tuple[str, ...]) -> list[str]:
    """Build the `pip install` argv for declared packages.

    ``--break-system-packages`` is required on a PEP 668-protected system pip
    (Debian's own python3-pip package, which the generic base installs) -
    without it every install fails closed with "externally-managed-
    environment" before anything is materialized. There is no venv here to
    scope the install to instead: the generic base substrate has no other
    Python consumer to conflict with.
    """

    return ["pip", "install", "--break-system-packages", *sorted(packages)]


def _pip_query(packages: tuple[str, ...]) -> list[str]:
    """Build the `pip freeze` argv that reports all installed packages."""

    return ["pip", "freeze"]


def _pip_parse(stdout: str) -> frozenset[str]:
    """Parse `pip freeze` output into a set of installed package names."""

    names: set[str] = set()
    for line in stdout.splitlines():
        token = line.strip()
        if not token:
            continue
        # `name==version`, `name @ url`, or bare name.
        for sep in ("==", " @ ", ">=", "<=", "~="):
            if sep in token:
                token = token.split(sep, 1)[0]
                break
        names.add(token.strip())
    return frozenset(names)


_MANAGERS: dict[str, _Manager] = {
    "apt": _Manager(
        install=_apt_install,
        query=_apt_query,
        parse=_lines_to_set,
        refresh=("env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update"),
    ),
    "dnf": _Manager(install=_dnf_install, query=_dnf_query, parse=_lines_to_set),
    "pip": _Manager(install=_pip_install, query=_pip_query, parse=_pip_parse),
}


def _manager(name: str) -> _Manager:
    """Look up a declared package manager's mechanism, or fail closed."""

    manager = _MANAGERS.get(name)
    if manager is None:
        raise UnsupportedPackageManagerError(
            f"no generic mechanism for package manager {name!r}"
        )
    return manager


def refresh_argv(manager: str) -> list[str] | None:
    """Return the index-refresh argv to run before install, or None.

    apt needs `apt-get update` on a slim base image whose package lists were
    stripped; dnf/pip refresh implicitly and return None.
    """
    refresh = _manager(manager).refresh
    return list(refresh) if refresh is not None else None


def install_argv(manager: str, packages: tuple[str, ...]) -> list[str]:
    """Return the argv that installs the declared packages via the manager."""
    return _manager(manager).install(packages)


def query_installed_argv(manager: str, packages: tuple[str, ...]) -> list[str]:
    """Return the argv that reports which of the declared packages are installed."""
    return _manager(manager).query(packages)


def parse_installed(manager: str, stdout: str) -> frozenset[str]:
    """Parse the query output into the set of installed package names."""
    return _manager(manager).parse(stdout)


class UnsupportedDependencyEcosystemError(ValueError):
    """Raised when APTL has no generic mechanism for a declared dependency ecosystem.

    Fail closed: an unknown ecosystem is an admission error, never a guessed
    command.
    """


# Manifest-driven install: a project's own manifest (e.g. pyproject.toml)
# declares its dependencies; the generic mechanism is "install from this
# manifest's directory", parameterized only by ecosystem. No knowledge of
# what any specific manifest declares.
_MANIFEST_INSTALLERS: dict[str, Callable[[str], list[str]]] = {
    "pip": lambda directory: ["pip", "install", "--break-system-packages", directory],
}

_MANIFEST_QUERIES: dict[str, Callable[[str], list[str]]] = {
    "pip": lambda name: ["pip", "show", name],
}


def manifest_install_argv(ecosystem: str, directory: str) -> list[str]:
    """Return the argv that installs a project from its manifest's directory."""

    builder = _MANIFEST_INSTALLERS.get(ecosystem)
    if builder is None:
        raise UnsupportedDependencyEcosystemError(
            f"no generic mechanism for dependency ecosystem {ecosystem!r}"
        )
    return builder(directory)


def manifest_query_argv(ecosystem: str, name: str) -> list[str]:
    """Return the argv that reports whether the manifest's declared package is installed."""

    builder = _MANIFEST_QUERIES.get(ecosystem)
    if builder is None:
        raise UnsupportedDependencyEcosystemError(
            f"no generic mechanism for dependency ecosystem {ecosystem!r}"
        )
    return builder(name)
