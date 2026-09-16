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
from html import escape
from typing import Protocol

from raes.runtime_configuration import RuntimeConfiguration

_MAX_WORKERS = 8
_WAZUH_VERSION = "4.12.0-1"
_WAZUH_CONFIG = "/var/ossec/etc/ossec.conf"
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


def _realize_wazuh_agent(
    backend: ForwardingAgentBackend, container: str, agent: object
) -> str | None:
    target = _single_target(agent)
    host = str(getattr(target, "target_node_ref", "") or "") if target else ""
    if not _SAFE_HOST.fullmatch(host):
        return "invalid manager target"
    if not _exec_ok(backend, container, ["test", "-x", "/var/ossec/bin/wazuh-control"]):
        reason = _install_wazuh_agent(backend, container, host)
        if reason is not None:
            return reason
    payload = _wazuh_config(agent)
    if payload is None or not _write_file(
        backend, container, _WAZUH_CONFIG, payload, "0640", owner="root:wazuh"
    ):
        return "could not write Wazuh configuration"
    if not _agent_configured(backend, container, agent):
        return "Wazuh configuration did not verify"
    if not _exec_ok(
        backend, container, ["/var/ossec/bin/wazuh-control", "start"], timeout=120
    ):
        return "Wazuh agent did not start"
    return (
        None
        if _wazuh_agent_running(backend, container)
        else "Wazuh agent did not become ready"
    )


def _wazuh_agent_running(backend: ForwardingAgentBackend, container: str) -> bool:
    """Read back the two processes required for declared log delivery."""

    status = backend.container_exec(
        container, ["/var/ossec/bin/wazuh-control", "status"], timeout=30
    )
    output = str(getattr(status, "stdout", "") or "")
    return bool(
        getattr(status, "returncode", 1) == 0
        and "wazuh-agentd is running" in output
        and "wazuh-logcollector is running" in output
    )


def _install_wazuh_agent(
    backend: ForwardingAgentBackend, container: str, manager: str
) -> str | None:
    if _exec_ok(backend, container, ["test", "-x", "/usr/bin/apt-get"]):
        commands = (
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
            [
                "curl",
                "-fsSL",
                "-o",
                "/tmp/aptl-wazuh.gpg",
                "https://packages.wazuh.com/key/GPG-KEY-WAZUH",
            ],
            [
                "gpg",
                "--batch",
                "--yes",
                "--dearmor",
                "--output",
                "/usr/share/keyrings/wazuh.gpg",
                "/tmp/aptl-wazuh.gpg",
            ],
        )
        if not all(
            _exec_ok(backend, container, command, timeout=600) for command in commands
        ):
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
    elif _exec_ok(backend, container, ["test", "-x", "/usr/bin/dnf"]):
        if not _exec_ok(
            backend,
            container,
            ["dnf", "install", "-y", "curl", "ca-certificates", "procps-ng"],
            timeout=600,
        ):
            return "Wazuh rpm prerequisites failed"
        if not _exec_ok(
            backend,
            container,
            ["rpm", "--import", "https://packages.wazuh.com/key/GPG-KEY-WAZUH"],
            timeout=120,
        ):
            return "Wazuh rpm key import failed"
        repository = """[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
"""
        if not _write_file(
            backend, container, "/etc/yum.repos.d/wazuh.repo", repository, "0644"
        ):
            return "Wazuh rpm repository configuration failed"
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
    else:
        return "no supported package manager"
    if not all(
        _exec_ok(backend, container, command, timeout=600) for command in install
    ):
        return "Wazuh agent package installation failed"
    return None


def _realize_rsyslog(
    backend: ForwardingAgentBackend, container: str, agent: object
) -> str | None:
    if not _exec_ok(backend, container, ["test", "-x", "/usr/sbin/rsyslogd"]):
        if _exec_ok(backend, container, ["test", "-x", "/usr/bin/apt-get"]):
            command = ["apt-get", "install", "-y", "rsyslog"]
        elif _exec_ok(backend, container, ["test", "-x", "/usr/bin/dnf"]):
            command = ["dnf", "install", "-y", "rsyslog"]
        else:
            return "no supported rsyslog package manager"
        if not _exec_ok(backend, container, command, timeout=600):
            return "rsyslog package installation failed"
    payload = _rsyslog_config(agent)
    if payload is None or not _write_file(
        backend, container, _RSYSLOG_CONFIG, payload, "0644"
    ):
        return "could not write rsyslog configuration"
    return (
        None
        if _agent_configured(backend, container, agent)
        else "rsyslog configuration did not verify"
    )


def _realize_misp_sync(
    backend: ForwardingAgentBackend, container: str, agent: object
) -> str | None:
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
    implementation = _value(getattr(agent, "implementation", ""))
    if implementation == "wazuh_agent":
        executable = "/var/ossec/bin/wazuh-control"
        path = _WAZUH_CONFIG
        payload = _wazuh_config(agent)
    elif implementation == "rsyslog":
        executable = "/usr/sbin/rsyslogd"
        path = _RSYSLOG_CONFIG
        payload = _rsyslog_config(agent)
    elif implementation == "misp_suricata_sync":
        executable = "/usr/local/bin/aptl-misp-suricata-sync"
        path = _MISP_SYNC_CONFIG
        payload = _misp_sync_config(agent)
    else:
        return False
    return bool(
        payload is not None
        and _exec_ok(backend, container, ["test", "-x", executable])
        and _file_digest_matches(backend, container, path, payload)
    )


def _wazuh_config(agent: object) -> str | None:
    target = _single_target(agent)
    if target is None:
        return None
    host = str(getattr(target, "target_node_ref", "") or "")
    if not _SAFE_HOST.fullmatch(host):
        return None
    ingestion = getattr(target, "ingestion_port", None)
    protocol = _value(getattr(target, "protocol", "tcp")) or "tcp"
    enrollment = getattr(target, "enrollment_port", None)
    if ingestion is None:
        return None
    name = str(getattr(agent, "name", "") or getattr(agent, "forwarding_agent_id", ""))
    crypto = _value(getattr(getattr(agent, "buffer_policy", None), "crypto", "aes"))
    lines = [
        "<ossec_config>",
        "  <client>",
        "    <server>",
        f"      <address>{escape(host)}</address>",
        f"      <port>{int(ingestion)}</port>",
        f"      <protocol>{escape(protocol)}</protocol>",
        "    </server>",
        f"    <config-profile>{escape(name)}</config-profile>",
        "    <notify_time>10</notify_time>",
        "    <time-reconnect>60</time-reconnect>",
        # The manager's first shared-config acknowledgement is not a semantic
        # change to this backend-owned config.  Letting it auto-restart here can
        # strand a container without an init supervisor in wazuh-control's
        # minute-per-process stale-PID shutdown loop.
        "    <auto_restart>no</auto_restart>",
        f"    <crypto_method>{escape(crypto or 'aes')}</crypto_method>",
    ]
    if enrollment is not None:
        lines.extend(
            (
                "    <enrollment>",
                "      <enabled>yes</enabled>",
                f"      <manager_address>{escape(host)}</manager_address>",
                f"      <port>{int(enrollment)}</port>",
                "    </enrollment>",
            )
        )
    lines.extend(
        (
            "  </client>",
            "  <client_buffer>",
            "    <disabled>no</disabled>",
            "    <queue_size>5000</queue_size>",
            "    <events_per_second>500</events_per_second>",
            "  </client_buffer>",
        )
    )
    for source in getattr(agent, "sources", ()):
        location = str(getattr(source, "location", "") or "")
        if not location.startswith("/"):
            return None
        lines.extend(
            (
                "  <localfile>",
                f"    <log_format>{escape(_wazuh_log_format(source.parse_format))}</log_format>",
                f"    <location>{escape(location)}</location>",
                "  </localfile>",
            )
        )
    lines.extend(
        (
            "  <logging>",
            "    <log_format>plain</log_format>",
            "  </logging>",
            "</ossec_config>",
        )
    )
    return "\n".join(lines) + "\n"


def _wazuh_log_format(value: object) -> str:
    """Map portable source formats onto Wazuh logcollector formats."""

    selected = _value(value)
    return "json" if selected == "eve_json" else selected


def _rsyslog_config(agent: object) -> str | None:
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
    return (
        getattr(
            backend.container_exec(container, command, timeout=timeout), "returncode", 1
        )
        == 0
    )


def _value(value: object) -> str:
    return str(getattr(value, "value", value) or "")


__all__ = ("forwarding_agents_configured", "realize_forwarding_agents")
