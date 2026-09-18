"""Render a declared forwarding agent's Wazuh configuration.

The scenario declares where an agent ships and under what name; this renders
exactly that into ``ossec.conf``. Nothing here touches a container: the caller
writes the payload and reads it back, because a written file is not a
configured agent until the agent agrees.

Split out of ``_wazuh_agent_realization`` so installing/verifying an agent and
rendering its configuration each stay inside a file a reader can hold in their
head.
"""

from __future__ import annotations

import re
from html import escape

_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


def _value(value: object) -> str:
    """Return a declared scalar as the plain string the configuration carries."""

    return str(getattr(value, "value", value) or "")


def wazuh_config(agent: object) -> str | None:
    """Render the exact Wazuh configuration for one valid forwarding agent."""

    target = _valid_target(agent)
    if target is None:
        return None
    host, ingestion, protocol, enrollment = target
    name = str(getattr(agent, "name", "") or getattr(agent, "forwarding_agent_id", ""))
    crypto = _value(getattr(getattr(agent, "buffer_policy", None), "crypto", "aes"))
    lines = _wazuh_header(host, ingestion, protocol, name, crypto)
    lines.extend(_enrollment_lines(host, enrollment, name))
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
    source_lines = _source_lines(agent)
    if source_lines is None:
        return None
    lines.extend(source_lines)
    lines.extend(
        (
            "  <logging>",
            "    <log_format>plain</log_format>",
            "  </logging>",
            "</ossec_config>",
        )
    )
    return "\n".join(lines) + "\n"


def _valid_target(agent: object) -> tuple[str, int, str, object] | None:
    """Validate and return the single Wazuh manager target."""

    target = _single_target(agent)
    host = str(getattr(target, "target_node_ref", "") or "") if target else ""
    ingestion = getattr(target, "ingestion_port", None)
    protocol = _value(getattr(target, "protocol", "tcp")) or "tcp"
    if not _SAFE_HOST.fullmatch(host) or ingestion is None:
        return None
    return host, int(ingestion), protocol, getattr(target, "enrollment_port", None)


def _wazuh_header(
    host: str, ingestion: int, protocol: str, name: str, crypto: str
) -> list[str]:
    """Return the fixed Wazuh client header lines."""

    return [
        "<ossec_config>",
        "  <client>",
        "    <server>",
        f"      <address>{escape(host)}</address>",
        f"      <port>{ingestion}</port>",
        f"      <protocol>{escape(protocol)}</protocol>",
        "    </server>",
        f"    <config-profile>{escape(name)}</config-profile>",
        "    <notify_time>10</notify_time>",
        "    <time-reconnect>60</time-reconnect>",
        "    <auto_restart>no</auto_restart>",
        f"    <crypto_method>{escape(crypto or 'aes')}</crypto_method>",
    ]


def _enrollment_lines(host: str, enrollment: object, name: str) -> list[str]:
    """Return enrollment lines only when the author selected an enrollment port."""

    if enrollment is None:
        return []
    lines = [
        "    <enrollment>",
        "      <enabled>yes</enabled>",
        f"      <manager_address>{escape(host)}</manager_address>",
        f"      <port>{int(enrollment)}</port>",
    ]
    # The scenario names each forwarding agent, and that name is how the agent
    # is identified on the manager. Without <agent_name> the agent enrolls
    # under its container hostname, so the SIEM shows an opaque container id
    # instead of the declared agent (issue #1006).
    if name:
        lines.append(f"      <agent_name>{escape(name)}</agent_name>")
    lines.append("    </enrollment>")
    return lines


def _source_lines(agent: object) -> list[str] | None:
    """Render exact log sources, failing closed on non-absolute locations."""

    lines: list[str] = []
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
    return lines


def _wazuh_log_format(value: object) -> str:
    """Map portable source formats onto Wazuh logcollector formats."""

    selected = _value(value)
    return "json" if selected == "eve_json" else selected


def _single_target(agent: object) -> object | None:
    """Return the sole ship target, rejecting ambiguous target sets."""

    targets = tuple(getattr(agent, "ship_targets", ()))
    return targets[0] if len(targets) == 1 else None
