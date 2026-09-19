"""Realize the released pack's declared log sources as live producer output.

This belongs to the content-qualified scenario adapter. The SDL declares the
paths and forwarding agents; the selected Debian/Rocky/Samba implementations
need native configuration before those paths can honestly be observed. No file
is fabricated merely to satisfy a presence check.
"""

from __future__ import annotations

import hashlib
import secrets
from pathlib import PurePosixPath

from aptl_techvault.log_source_support import (
    SAMBA_AUDIT_LOG as _SAMBA_AUDIT_LOG,
    SAMBA_MAIN_LOG as _SAMBA_MAIN_LOG,
    SMBD_SERVICE as _SMBD_SERVICE,
    LogSourceBackend,
    _await_active_unit,
    _await_file_growth,
    _await_log_event,
    _await_nonempty_file,
    _declared_tailed_files,
    _exec,
    _file_size,
    _ok,
    _apply_postgres_log_settings,
    _postgres_cluster,
    _postgres_candidate,
    _postgres_log_path,
    _postgres_settings,
    _read_file,
    _rocky_rsyslog_config,
    _rocky_syslog_candidate,
    _samba_ad_config,
    _samba_ad_candidate,
    _samba_candidate,
    _stdout,
)


_SAMBA_DROPIN = "/etc/systemd/system/smbd.service.d/60-aptl-log-sources.conf"
_CHECK_MARKER = "aptl-log-source-readback"
_RSYSLOG_CONFIG = "/etc/rsyslog.conf"
# Stage under a root-owned parent, not the guest's publicly writable /tmp.
_RSYSLOG_STAGING = "/run/aptl/rsyslog.conf"
_JOURNALD_DROPIN = "/etc/systemd/journald.conf.d/60-aptl-forward.conf"
_JOURNALD_PAYLOAD = "[Journal]\nForwardToSyslog=yes\n"
_SYSLOG_ALIAS = "/etc/systemd/system/syslog.service"
_RSYSLOG_UNIT = "/usr/lib/systemd/system/rsyslog.service"
_RSYSLOG_SERVICE = "rsyslog.service"


def realize_log_sources(
    backend: LogSourceBackend, nodes: tuple[object, ...]
) -> list[str]:
    """Configure only exact source/producer combinations the pack declares."""

    failures: list[str] = []
    smb_client = _single_smb_probe_client(nodes)
    for node in nodes:
        container = str(getattr(node, "container_name", "") or "")
        runtime = getattr(node, "runtime", None)
        if not container or runtime is None:
            continue
        sources = _declared_tailed_files(runtime)
        if not sources:
            continue
        reason = _realize_declared_source(
            backend, container, runtime, sources, smb_client
        )
        if reason is not None:
            failures.append(f"declared log source failed for {container}: {reason}")
    return failures


def _single_smb_probe_client(nodes: tuple[object, ...]) -> str:
    """Use a guest SMB client only when the admitted nodes identify one."""

    clients = [
        str(getattr(node, "container_name", "") or "")
        for node in nodes
        if any(
            getattr(package, "name", "") == "smbclient"
            for package in getattr(getattr(node, "runtime", None), "packages", ())
        )
    ]
    return clients[0] if len(clients) == 1 else ""


def _realize_declared_source(
    backend: LogSourceBackend,
    container: str,
    runtime: object,
    sources: frozenset[str],
    smb_client: str,
) -> str | None:
    """Select the first exact producer supported by this pack adapter."""

    reason = None
    if _postgres_candidate(runtime, sources):
        reason = _realize_postgres_log(backend, container, sources)
    elif _rocky_syslog_candidate(runtime, sources):
        reason = _realize_rocky_syslog(backend, container)
    elif _samba_ad_candidate(runtime, sources):
        reason = _realize_samba_ad_logs(backend, container, smb_client)
    elif _samba_candidate(runtime, sources):
        reason = _realize_samba_logs(backend, container, smb_client)
    return reason


def _realize_postgres_log(
    backend: LogSourceBackend, container: str, sources: frozenset[str]
) -> str | None:
    """Configure and corroborate the one declared PostgreSQL log producer."""

    path, reason = _postgres_log_path(sources)
    if reason is not None or path is None:
        return reason or "PostgreSQL log path is invalid"
    expected = (str(path.parent), path.name, "on")
    if _postgres_settings(backend, container) == expected and _ok(
        backend, container, ["test", "-s", str(path)]
    ):
        return None
    cluster = _postgres_cluster(backend, container)
    if cluster is None:
        reason = "PostgreSQL cluster selection is ambiguous"
    elif not _apply_postgres_log_settings(backend, container, *cluster, path):
        reason = "PostgreSQL log configuration failed"
    elif not _ok(backend, container, ["pg_ctlcluster", *cluster, "restart"], 120):
        reason = "PostgreSQL cluster restart failed"
    elif _postgres_settings(backend, container) != expected or not _await_nonempty_file(
        backend, container, str(path)
    ):
        reason = "PostgreSQL log producer did not verify"
    return reason


def _write_container_file(
    backend: LogSourceBackend, container: str, path: str, payload: str
) -> bool:
    """Write a root-owned guest config under an explicit parent directory."""

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
    return _install_rsyslog_config(backend, container, configured)


def _install_rsyslog_config(
    backend: LogSourceBackend, container: str, configured: str
) -> str | None:
    """Validate staged config before installing it over the package file."""

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
    for step in (
        _ensure_syslog_alias,
        _activate_syslog_socket,
        _enable_syslog_services,
    ):
        reason = step(backend, container)
        if reason is not None:
            return reason
    return None


def _ensure_syslog_alias(backend: LogSourceBackend, container: str) -> str | None:
    """Use only the expected systemd service alias for syslog.socket."""

    if _ok(backend, container, ["test", "-L", _SYSLOG_ALIAS]):
        if (
            _stdout(backend, container, ["readlink", "-f", _SYSLOG_ALIAS])
            != _RSYSLOG_UNIT
        ):
            return "syslog socket service alias is unexpected"
    elif not _ok(backend, container, ["ln", "-s", _RSYSLOG_UNIT, _SYSLOG_ALIAS]):
        return "syslog socket service alias failed"
    return None


def _activate_syslog_socket(backend: LogSourceBackend, container: str) -> str | None:
    """Reload units and establish a settled active socket state."""

    if not _ok(backend, container, ["systemctl", "daemon-reload"], 120):
        return "syslog service reload failed"
    stopped = _ok(backend, container, ["systemctl", "stop", _RSYSLOG_SERVICE], 120)
    if not stopped and _ok(
        backend, container, ["systemctl", "is-active", "--quiet", _RSYSLOG_SERVICE]
    ):
        return "rsyslog service stop failed"
    _ok(backend, container, ["systemctl", "start", "syslog.socket"], 120)
    if not _await_active_unit(backend, container, "syslog.socket"):
        return "syslog socket failed"
    return None


def _enable_syslog_services(backend: LogSourceBackend, container: str) -> str | None:
    """Enable rsyslog and verify both it and journald have settled."""

    enabled = _ok(backend, container, ["systemctl", "enable", _RSYSLOG_SERVICE], 120)
    if not enabled and not _ok(
        backend, container, ["systemctl", "is-enabled", "--quiet", _RSYSLOG_SERVICE]
    ):
        return "rsyslog service could not be enabled"
    _ok(backend, container, ["systemctl", "start", _RSYSLOG_SERVICE], 120)
    if not _await_active_unit(backend, container, _RSYSLOG_SERVICE):
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
    """Configure Rocky's native syslog path and verify fresh events."""

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
        f'"--option=log file={_SAMBA_MAIN_LOG}" '
        f'"--option=log level=1 auth_audit:5@{_SAMBA_AUDIT_LOG}" '
        '"--option=debug syslog format=yes"\n'
    )


def _realize_samba_logs(
    backend: LogSourceBackend, container: str, smb_client_container: str
) -> str | None:
    """Enable standalone Samba audit output and verify a guest SMB event."""

    for step in (_ensure_samba_dropin, _verify_samba_service):
        reason = step(backend, container)
        if reason is not None:
            return reason
    return _probe_samba_audit(backend, container, smb_client_container)


def _ensure_samba_dropin(backend: LogSourceBackend, container: str) -> str | None:
    """Install the exact service override only when its digest differs."""

    payload = _samba_dropin()
    expected = hashlib.sha256(payload.encode()).hexdigest()
    digest = _stdout(backend, container, ["sha256sum", _SAMBA_DROPIN])
    if digest and digest.split(maxsplit=1)[0] == expected:
        return None
    return _install_samba_dropin(backend, container, payload)


def _install_samba_dropin(
    backend: LogSourceBackend, container: str, payload: str
) -> str | None:
    """Reload and restart only after an exact root-owned override write."""

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
    if not _ok(backend, container, ["systemctl", "restart", _SMBD_SERVICE], 120):
        return "Samba service restart failed"
    return None


def _verify_samba_service(backend: LogSourceBackend, container: str) -> str | None:
    """Corroborate the active service and its first native log."""

    if not _ok(
        backend, container, ["systemctl", "is-active", "--quiet", _SMBD_SERVICE]
    ):
        return "Samba service is inactive"
    if not _await_nonempty_file(backend, container, _SAMBA_MAIN_LOG):
        return "Samba main log is empty"
    return None


def _probe_samba_audit(
    backend: LogSourceBackend, container: str, smb_client_container: str
) -> str | None:
    """Require a guest SMB probe to grow the declared authentication log."""

    if not smb_client_container:
        return "declared SMB probe client is unavailable"
    audit_path = _SAMBA_AUDIT_LOG
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


def _realize_samba_ad_logs(
    backend: LogSourceBackend, container: str, smb_client_container: str
) -> str | None:
    """Make the domain provider's declared audit path receive real SMB events."""

    reason = _configure_domain_samba(backend, container)
    if reason is not None:
        return reason
    if not _ok(backend, container, ["smbcontrol", "all", "reload-config"]):
        return "domain Samba configuration reload failed"
    return _probe_domain_samba_audit(backend, container, smb_client_container)


def _configure_domain_samba(backend: LogSourceBackend, container: str) -> str | None:
    """Update only the two provisioned domain config locations."""

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
    return None


def _probe_domain_samba_audit(
    backend: LogSourceBackend, container: str, smb_client_container: str
) -> str | None:
    """Demand one real guest-authentication attempt and native log growth."""

    if not smb_client_container:
        return "declared SMB probe client is unavailable"
    audit_path = _SAMBA_AUDIT_LOG
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
