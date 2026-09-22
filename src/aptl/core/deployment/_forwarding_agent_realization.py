"""Materialize and verify authored runtime forwarding-agent configuration.

Forwarding agents are scenario state, not optional observability apparatus.  A
mount that happens to contain one of their inputs does not prove an agent is
installed, configured, or running.  This module realizes the declared
implementation in the target node and verifies the exact configuration bytes
and required delivery processes in-world.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Protocol

from raes.runtime_configuration import RuntimeConfiguration

from aptl.core.deployment import _wazuh_agent_realization

_WAZUH_BOOTSTRAP_DIR = _wazuh_agent_realization._WAZUH_BOOTSTRAP_DIR
_WAZUH_CONFIG = _wazuh_agent_realization._WAZUH_CONFIG
_WAZUH_KEY_DOWNLOAD = _wazuh_agent_realization._WAZUH_KEY_DOWNLOAD
_install_wazuh_agent = _wazuh_agent_realization.install_wazuh_agent
_realize_wazuh_agent = _wazuh_agent_realization.realize_wazuh_agent
_wazuh_agent_configured = _wazuh_agent_realization.wazuh_agent_configured
_wazuh_agent_running = _wazuh_agent_realization.wazuh_agent_running
_wazuh_config = _wazuh_agent_realization.wazuh_config

_MAX_WORKERS = 8
_RSYSLOG_CONFIG = "/etc/rsyslog.d/60-aptl-forwarding.conf"
_MISP_SYNC_CONFIG = "/etc/aptl/misp-suricata-sync.env"
_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


class ForwardingAgentBackend(Protocol):
    """Narrow container surface used by forwarding-agent realization."""

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


def realize_forwarding_agents(
    backend: ForwardingAgentBackend, nodes: Iterable[object]
) -> list[str]:
    """Realize every declared agent concurrently and return bounded failures."""

    work = [
        (str(getattr(node, "container_name", "") or ""), node.runtime)
        for node in nodes
        if getattr(node, "container_name", None)
        and getattr(node, "runtime", None) is not None
        and getattr(node.runtime, "forwarding_agents", ())
    ]
    if not work:
        return []
    failures: list[str] = []
    with ThreadPoolExecutor(max_workers=min(len(work), _MAX_WORKERS)) as pool:
        futures = {
            pool.submit(_realize_node_agents, backend, container, runtime): container
            for container, runtime in work
        }
        for future, container in futures.items():
            reason = future.result()
            if reason is not None:
                failures.append(
                    f"forwarding-agent configuration failed for {container}: {reason}"
                )
    return failures


def forwarding_agents_configured(
    backend: ForwardingAgentBackend,
    container_name: str,
    runtime: RuntimeConfiguration,
) -> bool:
    """Return whether every declared implementation and config is present."""

    return bool(runtime.forwarding_agents) and all(
        _agent_configured(backend, container_name, agent)
        for agent in runtime.forwarding_agents
    )


def _realize_node_agents(
    backend: ForwardingAgentBackend,
    container: str,
    runtime: RuntimeConfiguration,
) -> str | None:
    """Install, configure, and verify all agents declared on one node."""

    for agent in runtime.forwarding_agents:
        implementation = _value(agent.implementation)
        if implementation == "wazuh_agent":
            reason = _realize_wazuh_agent(backend, container, agent)
        elif implementation == "rsyslog":
            reason = _realize_rsyslog(backend, container, agent)
        elif implementation == "misp_suricata_sync":
            reason = _realize_misp_sync(backend, container, agent)
        else:
            reason = "unsupported declared implementation"
        if reason is not None:
            return reason
    return None


def _realize_rsyslog(
    backend: ForwardingAgentBackend, container: str, agent: object
) -> str | None:
    """Install and verify one declared rsyslog forwarding agent."""

    reason = _install_rsyslog(backend, container)
    payload = _rsyslog_config(agent) if reason is None else None
    if reason is None and (
        payload is None
        or not _write_file(backend, container, _RSYSLOG_CONFIG, payload, "0644")
    ):
        reason = "could not write rsyslog configuration"
    if reason is None and not _agent_configured(backend, container, agent):
        reason = "rsyslog configuration did not verify"
    return reason


def _install_rsyslog(backend: ForwardingAgentBackend, container: str) -> str | None:
    """Install rsyslog when absent using the available package manager."""

    if _exec_ok(backend, container, ["test", "-x", "/usr/sbin/rsyslogd"]):
        return None
    command = None
    if _exec_ok(backend, container, ["test", "-x", "/usr/bin/apt-get"]):
        command = ["apt-get", "install", "-y", "rsyslog"]
    elif _exec_ok(backend, container, ["test", "-x", "/usr/bin/dnf"]):
        command = ["dnf", "install", "-y", "rsyslog"]
    if command is None:
        return "no supported rsyslog package manager"
    return (
        None
        if _exec_ok(backend, container, command, timeout=600)
        else "rsyslog package installation failed"
    )


def _realize_misp_sync(
    backend: ForwardingAgentBackend, container: str, agent: object
) -> str | None:
    """Write and verify the declared MISP-to-Suricata sync configuration."""

    payload = _misp_sync_config(agent)
    if payload is None or not _write_file(
        backend, container, _MISP_SYNC_CONFIG, payload, "0600"
    ):
        return "could not write MISP sync configuration"
    return (
        None
        if _agent_configured(backend, container, agent)
        else "MISP sync configuration did not verify"
    )


def _agent_configured(
    backend: ForwardingAgentBackend, container: str, agent: object
) -> bool:
    """Return whether one agent's executable and exact config are present."""

    implementation = _value(getattr(agent, "implementation", ""))
    if implementation == "wazuh_agent":
        return _wazuh_agent_configured(backend, container, agent)
    configurations = {
        "rsyslog": (
            ["test", "-x", "/usr/sbin/rsyslogd"],
            _RSYSLOG_CONFIG,
            _rsyslog_config,
        ),
        "misp_suricata_sync": (
            ["sh", "-c", 'test -x "$(command -v aptl-misp-suricata-sync)"'],
            _MISP_SYNC_CONFIG,
            _misp_sync_config,
        ),
    }
    selected = configurations.get(implementation)
    if selected is None:
        return False
    executable_probe, path, render = selected
    payload = render(agent)
    return bool(
        payload is not None
        and _exec_ok(backend, container, executable_probe)
        and _file_digest_matches(backend, container, path, payload)
    )


def _rsyslog_config(agent: object) -> str | None:
    """Render the exact rsyslog forwarding directive for one target."""

    target = _single_target(agent)
    if target is None:
        return None
    host = str(getattr(target, "target_node_ref", "") or "")
    port = getattr(target, "ingestion_port", None)
    protocol = _value(getattr(target, "protocol", "udp"))
    if not _SAFE_HOST.fullmatch(host) or port is None or protocol not in {"tcp", "udp"}:
        return None
    selector = next(
        (
            str(getattr(source, "selector", "") or "")
            for source in getattr(agent, "sources", ())
            if getattr(source, "selector", "")
        ),
        "*.*",
    )
    prefix = "@@" if protocol == "tcp" else "@"
    return f"{selector} {prefix}{host}:{int(port)}\n"


def _misp_sync_config(agent: object) -> str | None:
    """Render sorted MISP sync environment settings from portable semantics."""

    sources = tuple(getattr(agent, "sources", ()))
    transforms = tuple(getattr(agent, "transforms", ()))
    source = sources[0] if len(sources) == 1 else None
    if source is None or not str(getattr(source, "location", "")).startswith(
        "https://"
    ):
        return None
    values = {
        "MISP_URL": str(source.location),
        "IOC_TAG_FILTER": str(getattr(source, "selector", "") or "aptl:enforce"),
        "MISP_VERIFY_SSL": "true",
    }
    if transforms and getattr(transforms[0], "sid_namespace", ""):
        values["SID_BASE"] = str(transforms[0].sid_namespace)
    for setting in getattr(agent, "settings", ()):
        if getattr(setting, "setting_id", "") == "misp-ca-trust-anchor" and getattr(
            setting, "value", ""
        ):
            values["MISP_CA_CERT_PATH"] = str(setting.value)
    values["RULES_OUT_PATH"] = "/var/lib/suricata/rules/misp/misp-iocs.rules"
    values["SURICATA_SOCKET_PATH"] = "/var/run/suricata/suricata-command.socket"
    return "".join(f"{key}={values[key]}\n" for key in sorted(values))


def _single_target(agent: object) -> object | None:
    """Return the sole ship target, rejecting ambiguous target sets."""

    targets = tuple(getattr(agent, "ship_targets", ()))
    return targets[0] if len(targets) == 1 else None


def _write_file(
    backend: ForwardingAgentBackend,
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
    backend: ForwardingAgentBackend, container: str, path: str, payload: str
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
    backend: ForwardingAgentBackend,
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


def _value(value: object) -> str:
    """Read enum-like values without coupling to their concrete enum type."""

    return str(getattr(value, "value", value) or "")


__all__ = ("forwarding_agents_configured", "realize_forwarding_agents")
