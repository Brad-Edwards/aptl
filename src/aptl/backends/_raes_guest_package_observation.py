"""Bounded package-manager readback for RAES runtime concerns."""

from __future__ import annotations

from typing import TYPE_CHECKING

from raes.runtime_configuration import RuntimeConfiguration

from aptl.backends._runtime_concern_disclosure import _disclose

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend


def observe_packages(
    backend: DeploymentBackend,
    container_name: str,
    runtime: RuntimeConfiguration,
) -> object | None:
    """Corroborate declared package identity, version, and architecture."""

    packages = tuple(runtime.packages)
    if not packages or any(
        package.source or package.purl or package.repository is not None
        for package in packages
    ):
        return None
    observed = _observed_packages(backend, container_name, packages)
    if observed is None or not all(
        _package_matches(package, observed) for package in packages
    ):
        return None
    return _disclose(
        "runtime-packages",
        [package.model_dump(mode="json", by_alias=True) for package in packages],
    )


def _observed_packages(
    backend: DeploymentBackend,
    container_name: str,
    packages: tuple[object, ...],
) -> dict[tuple[str, str], tuple[str, str]] | None:
    """Query declared packages in manager batches, failing as one unit."""

    by_manager: dict[str, list[object]] = {}
    for package in packages:
        by_manager.setdefault(package.manager, []).append(package)
    observed: dict[tuple[str, str], tuple[str, str]] = {}
    for manager, selected in sorted(by_manager.items()):
        rows = _query_packages(
            backend,
            container_name,
            manager,
            tuple(sorted(package.name for package in selected)),
        )
        if rows is None:
            return None
        observed.update({(manager, name): value for name, value in rows.items()})
    return observed


def _package_matches(
    package: object,
    observed: dict[tuple[str, str], tuple[str, str]],
) -> bool:
    """Return whether one installed package matches its exact declaration."""

    installed = observed.get((package.manager, package.name))
    if installed is None:
        return False
    version, architecture = installed
    return bool(
        (package.version == "*" or package.version == version)
        and (
            not package.architecture
            or _architecture_matches(package.architecture, architecture)
        )
    )


def _query_packages(
    backend: DeploymentBackend,
    container_name: str,
    manager: str,
    names: tuple[str, ...],
) -> dict[str, tuple[str, str]] | None:
    """Query one supported package manager without invoking a shell."""

    if manager == "apt":
        command = [
            "dpkg-query",
            "-W",
            "-f=${Package}\\t${Version}\\t${Architecture}\\n",
            *names,
        ]
        result = backend.container_exec(container_name, command, timeout=30)
        rows = _tabular_packages(result, fields=3)
        if rows is None or not all(name in rows for name in names):
            rows = _apt_rows_with_providers(backend, container_name, names, rows)
    elif manager in {"dnf", "yum"}:
        command = [
            "rpm",
            "-q",
            "--qf",
            "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n",
            *names,
        ]
        result = backend.container_exec(container_name, command, timeout=30)
        rows = _tabular_packages(result, fields=3)
    elif manager == "pip":
        result = backend.container_exec(container_name, ["pip", "freeze"], timeout=30)
        rows = _pip_packages(result)
    else:
        rows = None
    return rows


def _apt_rows_with_providers(
    backend: DeploymentBackend,
    container_name: str,
    names: tuple[str, ...],
    rows: dict[str, tuple[str, str]] | None,
) -> dict[str, tuple[str, str]] | None:
    """Resolve declared names that a distribution ships as virtual packages.

    Debian renames real packages into virtual ones across releases — `dnsutils`
    is `bind9-dnsutils` from trixie on — so `dpkg-query <name>` reports the
    declared name as absent even though the declared software is installed and
    `apt-get install <name>` is what installed it. Corroborating through the
    installed package that Provides the name keeps the readback honest: it
    still proves something real is installed for the declaration, rather than
    assuming a missing name is fine (issue #1006).
    """

    command = [
        "dpkg-query",
        "-W",
        "-f=${Package}\\t${Version}\\t${Architecture}\\t${Provides}\\n",
    ]
    result = backend.container_exec(container_name, command, timeout=30)
    installed = _provider_rows(result)
    if installed is None:
        return rows
    resolved = dict(rows or {})
    for name in names:
        if name in resolved:
            continue
        provider = installed.get(name)
        if provider is not None:
            resolved[name] = provider
    return resolved if all(name in resolved for name in names) else rows


def _provider_rows(result: object) -> dict[str, tuple[str, str]] | None:
    """Map each provided virtual name to its installed provider's identity."""

    if getattr(result, "returncode", 1) != 0:
        return None
    provided: dict[str, tuple[str, str]] = {}
    for line in _stdout(result).splitlines():
        columns = line.split("\t")
        if len(columns) != 4:
            continue
        package, version, architecture, provides = columns
        if not package or not version or not architecture:
            continue
        # The batch query fails as a unit, so this listing has to answer for
        # every declared name: the installed packages themselves as well as the
        # virtual names they provide.
        provided.setdefault(package, (version, architecture))
        for entry in provides.split(","):
            # `Provides` entries may carry a version, e.g. `name (= 1.2)`.
            virtual = entry.split("(", 1)[0].strip()
            if virtual:
                provided.setdefault(virtual, (version, architecture))
    return provided


def _pip_packages(result: object) -> dict[str, tuple[str, str]] | None:
    """Parse a successful bounded pip-freeze result into package rows."""

    rows = None
    if getattr(result, "returncode", 1) == 0:
        rows = {}
        for line in _stdout(result).splitlines():
            name, separator, version = line.strip().partition("==")
            if separator and name and version:
                rows[name] = (version, "")
    return rows


def _tabular_packages(
    result: object, *, fields: int
) -> dict[str, tuple[str, str]] | None:
    """Parse an exact tab-delimited package-manager result."""

    if getattr(result, "returncode", 1) != 0:
        return None
    rows: dict[str, tuple[str, str]] = {}
    valid = True
    for line in _stdout(result).splitlines():
        columns = line.split("\t")
        if len(columns) != fields or not all(columns):
            valid = False
            break
        name, version, architecture = columns
        rows[name] = (version, architecture)
    return rows if valid else None


def _architecture_matches(declared: object, observed: str) -> bool:
    """Compare package architectures after normalizing common aliases."""

    aliases = {
        "amd64": "x86_64",
        "x86-64": "x86_64",
        "aarch64": "arm64",
    }
    declared_text = str(getattr(declared, "value", declared)).casefold()
    observed_text = observed.casefold()
    return aliases.get(declared_text, declared_text) == aliases.get(
        observed_text, observed_text
    )


def _stdout(result: object) -> str:
    """Decode a package command's strict UTF-8 stdout."""

    value = getattr(result, "stdout", "")
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="strict")
    return value if isinstance(value, str) else ""


__all__ = ("observe_packages",)
