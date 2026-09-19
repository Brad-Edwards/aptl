"""Realize the released pack's declared log sources as live producer output.

This belongs to the content-qualified scenario adapter. The SDL declares the
paths and forwarding agents; the selected Debian/Rocky/Samba implementations
need native configuration before those paths can honestly be observed. No file
is fabricated merely to satisfy a presence check.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import time
from pathlib import PurePosixPath
from typing import Protocol


class LogSourceBackend(Protocol):
    def container_exec(
        self, name: str, cmd: list[str], *, timeout: int | None = None
    ) -> object: ...

    def container_exec_with_input(
        self, name: str, cmd: list[str], payload: str, *, timeout: int | None = None
    ) -> object: ...


_SAFE_CLUSTER = re.compile(r"[A-Za-z0-9_.-]+")
_SAMBA_DROPIN = "/etc/systemd/system/smbd.service.d/60-aptl-log-sources.conf"
_CHECK_MARKER = "aptl-log-source-readback"
_RSYSLOG_CONFIG = "/etc/rsyslog.conf"
_RSYSLOG_STAGING = "/tmp/aptl-rsyslog.conf"
_JOURNALD_DROPIN = "/etc/systemd/journald.conf.d/60-aptl-forward.conf"
_JOURNALD_PAYLOAD = "[Journal]\nForwardToSyslog=yes\n"
_SYSLOG_ALIAS = "/etc/systemd/system/syslog.service"
_RSYSLOG_UNIT = "/usr/lib/systemd/system/rsyslog.service"


def realize_log_sources(
    backend: LogSourceBackend, nodes: tuple[object, ...]
) -> list[str]:
    """Configure only exact source/producer combinations the pack declares."""

    failures: list[str] = []
    smb_clients = [
        str(getattr(node, "container_name", "") or "")
        for node in nodes
        if any(
            getattr(package, "name", "") == "smbclient"
            for package in getattr(getattr(node, "runtime", None), "packages", ())
        )
    ]
    for node in nodes:
        container = str(getattr(node, "container_name", "") or "")
        runtime = getattr(node, "runtime", None)
        if not container or runtime is None:
            continue
        sources = _declared_tailed_files(runtime)
        if not sources:
            continue
        reason = None
        if _postgres_candidate(runtime, sources):
            reason = _realize_postgres_log(backend, container, sources)
        elif _rocky_syslog_candidate(runtime, sources):
            reason = _realize_rocky_syslog(backend, container)
        elif _samba_ad_candidate(runtime, sources):
            reason = _realize_samba_ad_logs(
                backend, container, smb_clients[0] if len(smb_clients) == 1 else ""
            )
        elif _samba_candidate(runtime, sources):
            reason = _realize_samba_logs(
                backend, container, smb_clients[0] if len(smb_clients) == 1 else ""
            )
        if reason is not None:
            failures.append(f"declared log source failed for {container}: {reason}")
    return failures


def _value(value: object) -> str:
    return str(getattr(value, "value", value) or "")


def _declared_tailed_files(runtime: object) -> frozenset[str]:
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
    return any(
        getattr(unit, "unit_name", "") == unit_name
        for unit in getattr(runtime, "service_manager_units", ())
    )


def _postgres_candidate(runtime: object, sources: frozenset[str]) -> bool:
    return bool(
        _has_unit(runtime, "postgresql.service")
        and any(
            _value(getattr(service, "engine", "")) == "postgresql"
            for service in getattr(runtime, "database_services", ())
        )
        and any(path.startswith("/var/log/postgresql/") for path in sources)
    )


def _rocky_syslog_candidate(runtime: object, sources: frozenset[str]) -> bool:
    return bool(
        {"/var/log/secure", "/var/log/messages"} <= sources
        and _has_unit(runtime, "sshd.service")
        and any(
            getattr(package, "manager", "") in {"dnf", "yum"}
            for package in getattr(runtime, "packages", ())
        )
    )


def _samba_candidate(runtime: object, sources: frozenset[str]) -> bool:
    return bool(
        {"/var/log/samba/log.smbd", "/var/log/samba/log.samba"} <= sources
        and _has_unit(runtime, "smbd.service")
        and any(
            _value(getattr(service, "protocol", "")) == "smb"
            for service in getattr(runtime, "file_services", ())
        )
    )


def _samba_ad_candidate(runtime: object, sources: frozenset[str]) -> bool:
    """Select the domain provider only when its Samba sources are declared."""

    return bool(
        {"/var/log/samba/log.samba", "/var/log/samba/log.smbd"} <= sources
        and any(
            _value(getattr(authority, "kind", "")) == "domain"
            for authority in getattr(runtime, "identity_authorities", ())
        )
    )


def _exec(
    backend: LogSourceBackend, container: str, command: list[str], timeout: int = 30
) -> object:
    return backend.container_exec(container, command, timeout=timeout)


def _ok(
    backend: LogSourceBackend, container: str, command: list[str], timeout: int = 30
) -> bool:
    return getattr(_exec(backend, container, command, timeout), "returncode", 1) == 0


def _stdout(
    backend: LogSourceBackend, container: str, command: list[str], timeout: int = 30
) -> str | None:
    result = _exec(backend, container, command, timeout)
    if getattr(result, "returncode", 1) != 0:
        return None
    return str(getattr(result, "stdout", "") or "").strip()


def _read_file(backend: LogSourceBackend, container: str, path: str) -> str | None:
    result = _exec(backend, container, ["cat", path])
    if getattr(result, "returncode", 1) != 0:
        return None
    return str(getattr(result, "stdout", "") or "")


def _await_nonempty_file(backend: LogSourceBackend, container: str, path: str) -> bool:
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
    output = _stdout(backend, container, ["stat", "-c", "%s", path])
    try:
        return max(0, int(output or "0"))
    except ValueError:
        return 0


def _await_file_growth(
    backend: LogSourceBackend, container: str, path: str, before: int
) -> bool:
    for attempt in range(40):
        if _file_size(backend, container, path) > before:
            return True
        if attempt < 39:
            time.sleep(0.25)
    return False


def _await_log_event(
    backend: LogSourceBackend, container: str, path: str, marker: str
) -> bool:
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


def _realize_postgres_log(
    backend: LogSourceBackend, container: str, sources: frozenset[str]
) -> str | None:
    selected = [
        path
        for path in sources
        if path.startswith("/var/log/postgresql/") and path.endswith(".log")
    ]
    if len(selected) != 1:
        return "PostgreSQL log path is ambiguous"
    path = PurePosixPath(selected[0])
    if path.parent != PurePosixPath("/var/log/postgresql"):
        return "PostgreSQL log path is invalid"
    expected = (str(path.parent), path.name, "on")
    if _postgres_settings(backend, container) == expected and _ok(
        backend, container, ["test", "-s", str(path)]
    ):
        return None
    rows = _stdout(backend, container, ["pg_lsclusters", "--no-header"])
    clusters = [line.split()[:2] for line in rows.splitlines()] if rows else []
    if (
        len(clusters) != 1
        or len(clusters[0]) != 2
        or not all(_SAFE_CLUSTER.fullmatch(value) for value in clusters[0])
    ):
        return "PostgreSQL cluster selection is ambiguous"
    version, cluster = clusters[0]
    for key, value in (
        ("log_directory", str(path.parent)),
        ("log_filename", path.name),
        ("logging_collector", "on"),
    ):
        if not _ok(
            backend, container, ["pg_conftool", version, cluster, "set", key, value]
        ):
            return "PostgreSQL log configuration failed"
    if not _ok(backend, container, ["pg_ctlcluster", version, cluster, "restart"], 120):
        return "PostgreSQL cluster restart failed"
    if _postgres_settings(backend, container) != expected or not _await_nonempty_file(
        backend, container, str(path)
    ):
        return "PostgreSQL log producer did not verify"
    return None


def _rocky_rsyslog_config(original: str) -> str | None:
    """Use the systemd syslog socket while retaining the distro's output rules."""

    if (
        'module(load="imuxsock" SysSock.Use="on")' in original
        and 'module(load="imjournal"' not in original
    ):
        return original
    lines = original.splitlines(keepends=True)
    imux = next(
        (
            i
            for i, line in enumerate(lines)
            if line.startswith('module(load="imuxsock"')
        ),
        None,
    )
    imjournal = next(
        (
            i
            for i, line in enumerate(lines)
            if line.startswith('module(load="imjournal"')
        ),
        None,
    )
    if imux is None or imjournal is None or imjournal <= imux:
        return None
    imux_end = next(
        (
            i
            for i in range(imux, min(imux + 5, len(lines)))
            if 'SysSock.Use="off")' in lines[i]
        ),
        None,
    )
    journal_end = next(
        (
            i
            for i in range(imjournal, min(imjournal + 7, len(lines)))
            if 'StateFile="imjournal.state")' in lines[i]
        ),
        None,
    )
    if imux_end is None or journal_end is None or imjournal - imux_end > 3:
        return None
    if not all(
        path in original
        for path in ('file="/var/log/secure"', 'file="/var/log/messages"')
    ):
        return None
    return "".join(
        lines[:imux]
        + ['module(load="imuxsock" SysSock.Use="on")\n']
        + lines[journal_end + 1 :]
    )


def _write_container_file(
    backend: LogSourceBackend, container: str, path: str, payload: str
) -> bool:
    parent = str(PurePosixPath(path).parent)
    if not _ok(backend, container, ["mkdir", "-p", parent]):
        return False
    result = backend.container_exec_with_input(
        container,
        ["sh", "-ec", f"umask 022; tee {path} >/dev/null"],
        payload,
        timeout=30,
    )
    return getattr(result, "returncode", 1) == 0


def _configure_rsyslog_file(backend: LogSourceBackend, container: str) -> str | None:
    """Validate the native socket input before replacing the package config."""

    original = _read_file(backend, container, _RSYSLOG_CONFIG)
    configured = _rocky_rsyslog_config(original or "")
    if configured is None:
        return "rsyslog input configuration is unsupported"
    if configured == original:
        return None
    if not _write_container_file(backend, container, _RSYSLOG_STAGING, configured):
        return "rsyslog configuration staging failed"
    if not _ok(backend, container, ["rsyslogd", "-N1", "-f", _RSYSLOG_STAGING]):
        return "rsyslog configuration validation failed"
    if not _ok(
        backend,
        container,
        [
            "install",
            "-m",
            "0644",
            "-o",
            "root",
            "-g",
            "root",
            _RSYSLOG_STAGING,
            _RSYSLOG_CONFIG,
        ],
    ):
        return "rsyslog configuration installation failed"
    return None


def _configure_syslog_bridge(backend: LogSourceBackend, container: str) -> str | None:
    """Connect journald to rsyslog through systemd's socket activation."""

    if not _write_container_file(
        backend, container, _JOURNALD_DROPIN, _JOURNALD_PAYLOAD
    ):
        return "journald syslog-forwarding configuration failed"
    if _ok(backend, container, ["test", "-L", _SYSLOG_ALIAS]):
        if (
            _stdout(backend, container, ["readlink", "-f", _SYSLOG_ALIAS])
            != _RSYSLOG_UNIT
        ):
            return "syslog socket service alias is unexpected"
    elif not _ok(backend, container, ["ln", "-s", _RSYSLOG_UNIT, _SYSLOG_ALIAS]):
        return "syslog socket service alias failed"
    if not _ok(backend, container, ["systemctl", "daemon-reload"], 120):
        return "syslog service reload failed"
    stopped = _ok(backend, container, ["systemctl", "stop", "rsyslog.service"], 120)
    if not stopped and _ok(
        backend, container, ["systemctl", "is-active", "--quiet", "rsyslog.service"]
    ):
        return "rsyslog service stop failed"
    _ok(backend, container, ["systemctl", "start", "syslog.socket"], 120)
    if not _await_active_unit(backend, container, "syslog.socket"):
        return "syslog socket failed"
    enabled = _ok(backend, container, ["systemctl", "enable", "rsyslog.service"], 120)
    if not enabled and not _ok(
        backend, container, ["systemctl", "is-enabled", "--quiet", "rsyslog.service"]
    ):
        return "rsyslog service could not be enabled"
    _ok(backend, container, ["systemctl", "start", "rsyslog.service"], 120)
    if not _await_active_unit(backend, container, "rsyslog.service"):
        return "rsyslog service did not start"
    _ok(backend, container, ["systemctl", "restart", "systemd-journald.service"], 120)
    if not _await_active_unit(backend, container, "systemd-journald.service"):
        return "journald restart failed"
    return None


def _verify_syslog_paths(backend: LogSourceBackend, container: str) -> str | None:
    """Prove both declared paths receive fresh events, not empty files."""

    marker = f"{_CHECK_MARKER}-{secrets.token_hex(8)}"
    for facility in ("authpriv.notice", "user.notice"):
        if not _ok(backend, container, ["logger", "-p", facility, marker]):
            return "syslog probe emission failed"
    for path in ("/var/log/secure", "/var/log/messages"):
        if not _await_log_event(backend, container, path, marker):
            return "declared syslog path did not receive an event"
    return None


def _realize_rocky_syslog(backend: LogSourceBackend, container: str) -> str | None:
    if not _ok(backend, container, ["test", "-x", "/usr/sbin/rsyslogd"]):
        return "rsyslog is absent from the selected base image"
    for step in (
        _configure_rsyslog_file,
        _configure_syslog_bridge,
        _verify_syslog_paths,
    ):
        reason = step(backend, container)
        if reason is not None:
            return reason
    return None


def _samba_dropin() -> str:
    """Keep the pack's exact smb.conf intact; select native runtime log args."""

    return (
        "[Service]\n"
        "ExecStart=\n"
        "ExecStart=/usr/sbin/smbd --foreground --no-process-group $SMBDOPTIONS "
        '"--option=log file=/var/log/samba/log.smbd" '
        '"--option=log level=1 auth_audit:5@/var/log/samba/log.samba" '
        '"--option=debug syslog format=yes"\n'
    )


def _realize_samba_logs(
    backend: LogSourceBackend, container: str, smb_client_container: str
) -> str | None:
    payload = _samba_dropin()
    expected = hashlib.sha256(payload.encode()).hexdigest()
    digest = _stdout(backend, container, ["sha256sum", _SAMBA_DROPIN])
    if not digest or digest.split(maxsplit=1)[0] != expected:
        parent = str(PurePosixPath(_SAMBA_DROPIN).parent)
        if not _ok(backend, container, ["mkdir", "-p", parent]):
            return "Samba service override directory could not be created"
        result = backend.container_exec_with_input(
            container,
            ["sh", "-ec", f"umask 022; tee {_SAMBA_DROPIN} >/dev/null"],
            payload,
            timeout=30,
        )
        if getattr(result, "returncode", 1) != 0 or not _ok(
            backend, container, ["systemctl", "daemon-reload"]
        ):
            return "Samba service override failed"
        if not _ok(backend, container, ["systemctl", "restart", "smbd.service"], 120):
            return "Samba service restart failed"
    if not _ok(
        backend, container, ["systemctl", "is-active", "--quiet", "smbd.service"]
    ):
        return "Samba service is inactive"
    if not _await_nonempty_file(backend, container, "/var/log/samba/log.smbd"):
        return "Samba main log is empty"
    if not smb_client_container:
        return "declared SMB probe client is unavailable"
    audit_path = "/var/log/samba/log.samba"
    before = _file_size(backend, container, audit_path)
    if not _ok(
        backend,
        smb_client_container,
        ["smbclient", "-N", "//fileshare/Public", "-c", "quit"],
        60,
    ):
        return "Samba guest-share probe failed"
    if not _await_file_growth(backend, container, audit_path, before):
        return "Samba audit log did not receive an authentication event"
    return None


def _samba_ad_config(original: str) -> str | None:
    """Add native audit logging without replacing the provisioned AD config."""

    lines = original.splitlines(keepends=True)
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
    expected = {
        "log file": "/var/log/samba/log.samba",
        "log level": "1 auth_audit:5",
    }
    present: dict[str, str] = {}
    for line in lines[start + 1 : end]:
        key, separator, value = line.partition("=")
        key = key.strip().lower()
        if separator and key in expected:
            if key in present:
                return None
            present[key] = value.strip()
    if any(present.get(key, value) != value for key, value in expected.items()):
        return None
    if len(present) == len(expected):
        return original
    additions = [
        f"\t{key} = {value}\n" for key, value in expected.items() if key not in present
    ]
    return "".join(lines[: start + 1] + additions + lines[start + 1 :])


def _realize_samba_ad_logs(
    backend: LogSourceBackend, container: str, smb_client_container: str
) -> str | None:
    """Make the domain provider's declared audit path receive real SMB events."""

    config_paths = (
        "/var/lib/samba/smb.conf.provisioned",
        "/etc/samba/smb.conf",
    )
    for path in config_paths:
        original = _read_file(backend, container, path)
        configured = _samba_ad_config(original) if original is not None else None
        if configured is None:
            return "domain Samba configuration is unsupported"
        if configured != original and not _write_container_file(
            backend, container, path, configured
        ):
            return "domain Samba audit configuration failed"
    if not _ok(backend, container, ["smbcontrol", "all", "reload-config"]):
        return "domain Samba configuration reload failed"
    if not smb_client_container:
        return "declared SMB probe client is unavailable"
    audit_path = "/var/log/samba/log.samba"
    before = _file_size(backend, container, audit_path)
    marker = f"aptl-readiness-{secrets.token_hex(8)}"
    # Guest authorization is expected to fail on the domain controller. The
    # native audit record, not smbclient's exit status, proves the producer.
    _exec(
        backend,
        smb_client_container,
        ["smbclient", "-N", "-U", marker, "//ad/sysvol", "-c", "quit"],
        60,
    )
    if not _await_file_growth(backend, container, audit_path, before):
        return "domain Samba audit log did not receive an authentication event"
    return None


__all__ = ("realize_log_sources",)
