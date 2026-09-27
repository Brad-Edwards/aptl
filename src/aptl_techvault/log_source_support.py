"""TechVault-local source selection and bounded native log readback helpers.

Only the content-qualified adapter imports these helpers. They select exact
SDL-declared source/producer combinations, transform supported native configs,
and corroborate guest activity; they never invent a source or append fabricated
log content.
"""

from __future__ import annotations

import time
import re
from pathlib import PurePosixPath
from typing import Protocol


class LogSourceBackend(Protocol):
    """Container execution capabilities needed for native log realization."""

    def container_exec(
        self, name: str, cmd: list[str], *, timeout: int | None = None
    ) -> object: ...

    def container_exec_with_input(
        self, name: str, cmd: list[str], payload: str, *, timeout: int | None = None
    ) -> object: ...


SAMBA_AUDIT_LOG = "/var/log/samba/log.samba"
SAMBA_MAIN_LOG = "/var/log/samba/log.smbd"
SMBD_SERVICE = "smbd.service"
_SAFE_CLUSTER = re.compile(r"[A-Za-z0-9_.-]+")


def _value(value: object) -> str:
    """Normalize RAES enum-like values before comparing declarations."""

    return str(getattr(value, "value", value) or "")


def _declared_tailed_files(runtime: object) -> frozenset[str]:
    """Find paths both inventoried as files and tailed by Wazuh agents."""

    inventory = {
        str(entry.path)
        for entry in getattr(runtime, "filesystem_inventory", ())
        if _value(getattr(entry, "entry_type", "")) == "file"
        and _value(getattr(entry, "presence", "")) == "present"
    }
    tailed = {
        str(source.location)
        for agent in getattr(runtime, "forwarding_agents", ())
        if _value(getattr(agent, "implementation", "")) == "wazuh_agent"
        for source in getattr(agent, "sources", ())
        if _value(getattr(source, "kind", "")) == "tailed_path"
    }
    return frozenset(inventory & tailed)


def _has_unit(runtime: object, unit_name: str) -> bool:
    """Check whether the SDL declares a systemd unit by name."""

    return any(
        getattr(unit, "unit_name", "") == unit_name
        for unit in getattr(runtime, "service_manager_units", ())
    )


def _postgres_candidate(runtime: object, sources: frozenset[str]) -> bool:
    """Select a declared PostgreSQL producer with an inventoried log path."""

    return bool(
        _has_unit(runtime, "postgresql.service")
        and any(
            _value(getattr(service, "engine", "")) == "postgresql"
            for service in getattr(runtime, "database_services", ())
        )
        and any(path.startswith("/var/log/postgresql/") for path in sources)
    )


def _rocky_syslog_candidate(runtime: object, sources: frozenset[str]) -> bool:
    """Select the Rocky syslog producer only for its declared log paths."""

    return bool(
        {"/var/log/secure", "/var/log/messages"} <= sources
        and _has_unit(runtime, "sshd.service")
        and any(
            getattr(package, "manager", "") in {"dnf", "yum"}
            for package in getattr(runtime, "packages", ())
        )
    )


def _samba_candidate(runtime: object, sources: frozenset[str]) -> bool:
    """Select standalone Samba only when its native logs are declared."""

    return bool(
        {SAMBA_MAIN_LOG, SAMBA_AUDIT_LOG} <= sources
        and _has_unit(runtime, SMBD_SERVICE)
        and any(
            _value(getattr(service, "protocol", "")) == "smb"
            for service in getattr(runtime, "file_services", ())
        )
    )


def _samba_ad_candidate(runtime: object, sources: frozenset[str]) -> bool:
    """Select the domain provider only when its Samba sources are declared."""

    return bool(
        {SAMBA_AUDIT_LOG, SAMBA_MAIN_LOG} <= sources
        and any(
            _value(getattr(authority, "kind", "")) == "domain"
            for authority in getattr(runtime, "identity_authorities", ())
        )
    )


def _exec(
    backend: LogSourceBackend, container: str, command: list[str], timeout: int = 30
) -> object:
    """Run a bounded command in a realized container."""

    return backend.container_exec(container, command, timeout=timeout)


def _ok(
    backend: LogSourceBackend, container: str, command: list[str], timeout: int = 30
) -> bool:
    """Return whether the bounded container command succeeded."""

    return getattr(_exec(backend, container, command, timeout), "returncode", 1) == 0


def _stdout(
    backend: LogSourceBackend, container: str, command: list[str], timeout: int = 30
) -> str | None:
    """Read trimmed output only from a successful container command."""

    result = _exec(backend, container, command, timeout)
    if getattr(result, "returncode", 1) != 0:
        return None
    return str(getattr(result, "stdout", "") or "").strip()


def _read_file(backend: LogSourceBackend, container: str, path: str) -> str | None:
    """Read a guest file without mistaking a failed cat for empty content."""

    result = _exec(backend, container, ["cat", path])
    if getattr(result, "returncode", 1) != 0:
        return None
    return str(getattr(result, "stdout", "") or "")


def _await_nonempty_file(backend: LogSourceBackend, container: str, path: str) -> bool:
    """Wait briefly for a native producer to write a nonempty file."""

    for attempt in range(20):
        if _ok(backend, container, ["test", "-s", path]):
            return True
        if attempt < 19:
            time.sleep(0.25)
    return False


def _await_active_unit(backend: LogSourceBackend, container: str, unit: str) -> bool:
    """Read the settled systemd state after an asynchronous service job."""

    for attempt in range(40):
        if _ok(backend, container, ["systemctl", "is-active", "--quiet", unit]):
            return True
        if attempt < 39:
            time.sleep(0.25)
    return False


def _file_size(backend: LogSourceBackend, container: str, path: str) -> int:
    """Read a guest file's size, treating a missing file as empty."""

    output = _stdout(backend, container, ["stat", "-c", "%s", path])
    try:
        return max(0, int(output or "0"))
    except ValueError:
        return 0


def _await_file_growth(
    backend: LogSourceBackend, container: str, path: str, before: int
) -> bool:
    """Confirm a fresh producer event increased the guest file size."""

    for attempt in range(40):
        if _file_size(backend, container, path) > before:
            return True
        if attempt < 39:
            time.sleep(0.25)
    return False


def _await_log_event(
    backend: LogSourceBackend, container: str, path: str, marker: str
) -> bool:
    """Wait for an exact probe marker in a native guest log."""

    command = ["grep", "-Fq", marker, path]
    for attempt in range(40):
        if _ok(backend, container, command):
            return True
        if attempt < 39:
            time.sleep(0.25)
    return False


def _postgres_settings(
    backend: LogSourceBackend, container: str
) -> tuple[str, str, str] | None:
    """Read PostgreSQL's effective logging directory, file, and collector."""

    result = _stdout(
        backend,
        container,
        [
            "runuser",
            "-u",
            "postgres",
            "--",
            "psql",
            "-Atqc",
            "SHOW log_directory; SHOW log_filename; SHOW logging_collector;",
        ],
    )
    values = result.splitlines() if result is not None else []
    return tuple(values) if len(values) == 3 else None


def _postgres_log_path(
    sources: frozenset[str],
) -> tuple[PurePosixPath | None, str | None]:
    """Require one declared PostgreSQL log directly under its native parent."""

    selected = [
        path
        for path in sources
        if path.startswith("/var/log/postgresql/") and path.endswith(".log")
    ]
    if len(selected) != 1:
        return None, "PostgreSQL log path is ambiguous"
    path = PurePosixPath(selected[0])
    if path.parent != PurePosixPath("/var/log/postgresql"):
        return None, "PostgreSQL log path is invalid"
    return path, None


def _postgres_cluster(
    backend: LogSourceBackend, container: str
) -> tuple[str, str] | None:
    """Select one safely named native PostgreSQL cluster."""

    rows = _stdout(backend, container, ["pg_lsclusters", "--no-header"])
    clusters = [line.split()[:2] for line in rows.splitlines()] if rows else []
    if (
        len(clusters) != 1
        or len(clusters[0]) != 2
        or not all(_SAFE_CLUSTER.fullmatch(value) for value in clusters[0])
    ):
        return None
    return clusters[0][0], clusters[0][1]


def _apply_postgres_log_settings(
    backend: LogSourceBackend,
    container: str,
    version: str,
    cluster: str,
    path: PurePosixPath,
) -> bool:
    """Set only the three declared native PostgreSQL logging dimensions."""

    for key, value in (
        ("log_directory", str(path.parent)),
        ("log_filename", path.name),
        ("logging_collector", "on"),
    ):
        if not _ok(
            backend, container, ["pg_conftool", version, cluster, "set", key, value]
        ):
            return False
    return True


def _rocky_rsyslog_config(original: str) -> str | None:
    """Use the systemd syslog socket while retaining the distro's output rules."""

    if (
        'module(load="imuxsock" SysSock.Use="on")' in original
        and 'module(load="imjournal"' not in original
    ):
        return original
    lines = original.splitlines(keepends=True)
    bounds = _rsyslog_module_bounds(lines)
    if bounds is None or not all(
        path in original
        for path in ('file="/var/log/secure"', 'file="/var/log/messages"')
    ):
        return None
    imux, journal_end = bounds
    return "".join(
        lines[:imux]
        + ['module(load="imuxsock" SysSock.Use="on")\n']
        + lines[journal_end + 1 :]
    )


def _rsyslog_module_bounds(lines: list[str]) -> tuple[int, int] | None:
    """Recognize only the supported adjacent distro input-module blocks."""

    imux = _first_prefixed_line(lines, 'module(load="imuxsock"')
    imjournal = _first_prefixed_line(lines, 'module(load="imjournal"')
    if imux is None or imjournal is None or imjournal <= imux:
        return None
    imux_end = _module_end(lines, imux, 5, 'SysSock.Use="off")')
    journal_end = _module_end(lines, imjournal, 7, 'StateFile="imjournal.state")')
    if imux_end is None or journal_end is None or imjournal - imux_end > 3:
        return None
    return imux, journal_end


def _first_prefixed_line(lines: list[str], prefix: str) -> int | None:
    """Find one distro module declaration by its exact line prefix."""

    return next((i for i, line in enumerate(lines) if line.startswith(prefix)), None)


def _module_end(lines: list[str], start: int, width: int, marker: str) -> int | None:
    """Bound how far a supported multiline module declaration may extend."""

    return next(
        (i for i in range(start, min(start + width, len(lines))) if marker in lines[i]),
        None,
    )


def _samba_ad_config(original: str) -> str | None:
    """Add native audit logging without replacing the provisioned AD config."""

    lines = original.splitlines(keepends=True)
    bounds = _samba_global_bounds(lines)
    configured = None
    if bounds is not None:
        start, end = bounds
        expected = {
            "log file": SAMBA_AUDIT_LOG,
            "log level": "1 auth_audit:5",
        }
        present = _samba_logging_present(lines, start, end, expected)
        if present is not None and all(
            present.get(key, value) == value for key, value in expected.items()
        ):
            if len(present) == len(expected):
                configured = original
            else:
                additions = [
                    f"\t{key} = {value}\n"
                    for key, value in expected.items()
                    if key not in present
                ]
                configured = "".join(
                    lines[: start + 1] + additions + lines[start + 1 :]
                )
    return configured


def _samba_global_bounds(lines: list[str]) -> tuple[int, int] | None:
    """Locate exactly one Samba global section without widening its scope."""

    global_headers = [
        index for index, line in enumerate(lines) if line.strip() == "[global]"
    ]
    if len(global_headers) != 1:
        return None
    start = global_headers[0]
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index].startswith("[")
        ),
        len(lines),
    )
    return start, end


def _samba_logging_present(
    lines: list[str], start: int, end: int, expected: dict[str, str]
) -> dict[str, str] | None:
    """Reject duplicate controlled keys before adding missing log settings."""

    present: dict[str, str] = {}
    for line in lines[start + 1 : end]:
        key, separator, value = line.partition("=")
        key = key.strip().lower()
        if separator and key in expected:
            if key in present:
                return None
            present[key] = value.strip()
    return present
