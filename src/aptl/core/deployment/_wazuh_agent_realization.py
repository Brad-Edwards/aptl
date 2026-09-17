"""Install, configure, and verify a declared Wazuh forwarding agent."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Protocol

from aptl.core.deployment._wazuh_agent_configuration import (
    _single_target,
    wazuh_config,
)

_WAZUH_VERSION = "4.12.0-1"
_WAZUH_CONFIG = "/var/ossec/etc/ossec.conf"
_WAZUH_CONTROL = "/var/ossec/bin/wazuh-control"
_WAZUH_BOOTSTRAP_DIR = "/var/lib/aptl-bootstrap"
_WAZUH_KEY_DOWNLOAD = f"{_WAZUH_BOOTSTRAP_DIR}/wazuh.gpg"
_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


class WazuhAgentBackend(Protocol):
    """Narrow container surface used by Wazuh realization."""

    def container_exec(
        self, name: str, cmd: list[str], *, timeout: int | None = None
    ) -> object: ...

    def container_exec_with_input(
        self,
        name: str,
        cmd: list[str],
        payload: str,
        *,
        timeout: int | None = None,
    ) -> object: ...


def realize_wazuh_agent(
    backend: WazuhAgentBackend, container: str, agent: object
) -> str | None:
    """Install and verify one Wazuh agent, returning a bounded failure."""

    host = _manager_host(agent)
    if host is None:
        return "invalid manager target"
    checks = (
        lambda: _ensure_wazuh_installed(backend, container, host),
        lambda: ensure_active_response_assets(backend, container),
        lambda: _write_wazuh_configuration(backend, container, agent),
        lambda: _configured_reason(backend, container, agent),
        lambda: _start_reason(backend, container),
        lambda: _ready_reason(backend, container),
    )
    return next((reason for check in checks if (reason := check()) is not None), None)


def _manager_host(agent: object) -> str | None:
    """Return the validated manager host from the sole ship target."""

    target = _single_target(agent)
    host = str(getattr(target, "target_node_ref", "") or "") if target else ""
    return host if _SAFE_HOST.fullmatch(host) else None


def _ensure_wazuh_installed(
    backend: WazuhAgentBackend, container: str, host: str
) -> str | None:
    """Install the agent only when its control executable is absent."""

    present = _exec_ok(backend, container, ["test", "-x", _WAZUH_CONTROL])
    return None if present else install_wazuh_agent(backend, container, host)


# The active-response contract every realized agent carries, whatever put the
# agent there (issue #249, ADR-021). Agent images stage it at build time through
# containers/_wazuh-agent/install-active-response.sh; an agent installed at
# realization time gets the same files here. Both used to be optional, and the
# RHEL image path and this runtime path both shipped agents without them
# (issue #1006).
ACTIVE_RESPONSE_ASSETS: tuple[tuple[str, str, str], ...] = (
    (
        "containers/_wazuh-agent/aptl-firewall-drop.sh",
        "/var/ossec/active-response/bin/aptl-firewall-drop",
        "0755",
    ),
    (
        "config/wazuh_cluster/etc/lists/active-response-whitelist",
        "/var/ossec/etc/lists/active-response-whitelist",
        "0640",
    ),
)


def ensure_active_response_assets(
    backend: WazuhAgentBackend, container: str
) -> str | None:
    """Place and verify the active-response wrapper and whitelist on an agent."""

    project_dir = getattr(backend, "_project_dir", None)
    if project_dir is None:
        return "active-response assets are unavailable"
    for asset in ACTIVE_RESPONSE_ASSETS:
        reason = _place_active_response_asset(
            backend, container, Path(project_dir), asset
        )
        if reason is not None:
            return reason
    return None


def _place_active_response_asset(
    backend: WazuhAgentBackend,
    container: str,
    project_dir: Path,
    asset: tuple[str, str, str],
) -> str | None:
    """Write one asset when the agent's copy differs, then verify what landed."""

    source, destination, mode = asset
    try:
        payload = (project_dir / source).read_text(encoding="utf-8")
    except OSError:
        return "active-response assets are unavailable"
    if _file_digest_matches(backend, container, destination, payload):
        return None
    written = _write_file(
        backend, container, destination, payload, mode, owner="root:wazuh"
    )
    verified = written and _file_digest_matches(
        backend, container, destination, payload
    )
    return None if verified else "active-response assets did not verify"


def _write_wazuh_configuration(
    backend: WazuhAgentBackend, container: str, agent: object
) -> str | None:
    """Write the exact rendered Wazuh configuration."""

    payload = wazuh_config(agent)
    written = bool(
        payload is not None
        and _write_file(
            backend, container, _WAZUH_CONFIG, payload, "0640", owner="root:wazuh"
        )
    )
    return None if written else "could not write Wazuh configuration"


def _configured_reason(
    backend: WazuhAgentBackend, container: str, agent: object
) -> str | None:
    """Return a failure when exact configuration readback does not verify."""

    return (
        None
        if wazuh_agent_configured(backend, container, agent)
        else "Wazuh configuration did not verify"
    )


def _start_reason(backend: WazuhAgentBackend, container: str) -> str | None:
    """Start the agent and return a bounded failure on non-zero exit."""

    started = _exec_ok(backend, container, [_WAZUH_CONTROL, "start"], timeout=120)
    return None if started else "Wazuh agent did not start"


def _ready_reason(backend: WazuhAgentBackend, container: str) -> str | None:
    """Return a failure unless both required Wazuh processes are running."""

    return (
        None
        if wazuh_agent_running(backend, container)
        else "Wazuh agent did not become ready"
    )


def wazuh_agent_running(backend: WazuhAgentBackend, container: str) -> bool:
    """Read back the two processes required for declared log delivery."""

    status = backend.container_exec(container, [_WAZUH_CONTROL, "status"], timeout=30)
    output = str(getattr(status, "stdout", "") or "")
    return bool(
        getattr(status, "returncode", 1) == 0
        and "wazuh-agentd is running" in output
        and "wazuh-logcollector is running" in output
    )


def install_wazuh_agent(
    backend: WazuhAgentBackend, container: str, manager: str
) -> str | None:
    """Install the pinned Wazuh package with the available package manager."""

    if _exec_ok(backend, container, ["test", "-x", "/usr/bin/apt-get"]):
        return _install_apt_agent(backend, container, manager)
    if _exec_ok(backend, container, ["test", "-x", "/usr/bin/dnf"]):
        return _install_rpm_agent(backend, container, manager)
    return "no supported package manager"


def _install_apt_agent(
    backend: WazuhAgentBackend, container: str, manager: str
) -> str | None:
    """Install Wazuh through its pinned Debian repository."""

    prerequisites = (
        ["apt-get", "update"],
        [
            "env",
            "DEBIAN_FRONTEND=noninteractive",
            "apt-get",
            "install",
            "-y",
            "--no-install-recommends",
            "curl",
            "gnupg",
            "ca-certificates",
            "procps",
        ],
        ["install", "-d", "-m", "0700", _WAZUH_BOOTSTRAP_DIR],
        [
            "curl",
            "-fsSL",
            "-o",
            _WAZUH_KEY_DOWNLOAD,
            "https://packages.wazuh.com/key/GPG-KEY-WAZUH",
        ],
        [
            "gpg",
            "--batch",
            "--yes",
            "--dearmor",
            "--output",
            "/usr/share/keyrings/wazuh.gpg",
            _WAZUH_KEY_DOWNLOAD,
        ],
    )
    if not _commands_ok(backend, container, prerequisites):
        return "Wazuh apt prerequisites failed"
    repository = (
        "deb [signed-by=/usr/share/keyrings/wazuh.gpg] "
        "https://packages.wazuh.com/4.x/apt/ stable main\n"
    )
    if not _write_file(
        backend,
        container,
        "/etc/apt/sources.list.d/wazuh.list",
        repository,
        "0644",
    ):
        return "Wazuh apt repository configuration failed"
    install = (
        ["apt-get", "update"],
        [
            "env",
            f"WAZUH_MANAGER={manager}",
            "DEBIAN_FRONTEND=noninteractive",
            "apt-get",
            "install",
            "-y",
            f"wazuh-agent={_WAZUH_VERSION}",
        ],
    )
    return (
        None
        if _commands_ok(backend, container, install)
        else "Wazuh agent package installation failed"
    )


def _install_rpm_agent(
    backend: WazuhAgentBackend, container: str, manager: str
) -> str | None:
    """Install Wazuh through its pinned RPM repository."""

    reason = None
    if not _exec_ok(
        backend,
        container,
        ["dnf", "install", "-y", "curl", "ca-certificates", "procps-ng"],
        timeout=600,
    ):
        reason = "Wazuh rpm prerequisites failed"
    if reason is None and not _exec_ok(
        backend,
        container,
        ["rpm", "--import", "https://packages.wazuh.com/key/GPG-KEY-WAZUH"],
        timeout=120,
    ):
        reason = "Wazuh rpm key import failed"
    repository = """[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
"""
    if reason is None and not _write_file(
        backend, container, "/etc/yum.repos.d/wazuh.repo", repository, "0644"
    ):
        reason = "Wazuh rpm repository configuration failed"
    install = (
        [
            "env",
            f"WAZUH_MANAGER={manager}",
            "dnf",
            "install",
            "-y",
            f"wazuh-agent-{_WAZUH_VERSION}",
        ],
    )
    if reason is None and not _commands_ok(backend, container, install):
        reason = "Wazuh agent package installation failed"
    return reason


def _commands_ok(
    backend: WazuhAgentBackend,
    container: str,
    commands: tuple[list[str], ...],
) -> bool:
    """Run a bounded package command sequence and require every command."""

    return all(
        _exec_ok(backend, container, command, timeout=600) for command in commands
    )


def wazuh_agent_configured(
    backend: WazuhAgentBackend, container: str, agent: object
) -> bool:
    """Verify the Wazuh executable and exact configuration digest."""

    payload = wazuh_config(agent)
    return bool(
        payload is not None
        and _exec_ok(backend, container, ["test", "-x", _WAZUH_CONTROL])
        and _file_digest_matches(backend, container, _WAZUH_CONFIG, payload)
    )


def _write_file(
    backend: WazuhAgentBackend,
    container: str,
    path: str,
    payload: str,
    mode: str,
    *,
    owner: str = "root:root",
) -> bool:
    """Write one root-owned configuration file and apply exact metadata."""

    parent = path.rpartition("/")[0] or "/"
    if not _exec_ok(backend, container, ["mkdir", "-p", parent]):
        return False
    result = backend.container_exec_with_input(
        container, ["sh", "-c", f"cat > {path}"], payload, timeout=30
    )
    return bool(
        getattr(result, "returncode", 1) == 0
        and _exec_ok(backend, container, ["chown", owner, path])
        and _exec_ok(backend, container, ["chmod", mode, path])
    )


def _file_digest_matches(
    backend: WazuhAgentBackend, container: str, path: str, payload: str
) -> bool:
    """Compare the native file digest with the exact rendered payload."""

    expected = hashlib.sha256(payload.encode()).hexdigest()
    result = backend.container_exec(container, ["sha256sum", path], timeout=30)
    stdout = str(getattr(result, "stdout", "") or "")
    return (
        getattr(result, "returncode", 1) == 0
        and stdout.split(maxsplit=1)[0] == expected
    )


def _exec_ok(
    backend: WazuhAgentBackend,
    container: str,
    command: list[str],
    *,
    timeout: int = 30,
) -> bool:
    """Run one bounded container command and require a zero exit status."""

    return (
        getattr(
            backend.container_exec(container, command, timeout=timeout), "returncode", 1
        )
        == 0
    )


__all__ = (
    "ensure_active_response_assets",
    "install_wazuh_agent",
    "realize_wazuh_agent",
    "wazuh_agent_configured",
    "wazuh_agent_running",
    "wazuh_config",
)
