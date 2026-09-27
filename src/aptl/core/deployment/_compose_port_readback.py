"""Parse project-owned Docker port bindings from inspect output."""

from __future__ import annotations

import json


def _port_maps(payload: str) -> list[dict[str, object]]:
    """Return each parsable port map from JSON-lines inspect output."""

    maps: list[dict[str, object]] = []
    for line in payload.splitlines():
        try:
            ports = json.loads(line.strip()) if line.strip() else None
        except ValueError:
            ports = None
        if isinstance(ports, dict):
            maps.append(ports)
    return maps


def _binding_addresses(host_ip: str) -> list[str]:
    """Return the host addresses one published binding satisfies."""

    if host_ip in ("", "0.0.0.0"):
        return [host_ip, "127.0.0.1"]
    return [host_ip]


def _entry_bindings(entries: object, protocol: str) -> list[tuple[str, int, str]]:
    """Return the binding triples one container port's entries publish."""

    bindings: list[tuple[str, int, str]] = []
    for entry in entries or ():
        raw_port = str(entry.get("HostPort") or "")
        if raw_port.isdigit():
            bindings.extend(
                (address, int(raw_port), protocol)
                for address in _binding_addresses(str(entry.get("HostIp") or ""))
            )
    return bindings


def owned_bindings(payload: str) -> list[tuple[str, int, str]]:
    """Parse Docker inspect port maps into host binding triples."""

    return [
        binding
        for ports in _port_maps(payload)
        for container_port, entries in ports.items()
        for binding in _entry_bindings(
            entries, str(container_port).rpartition("/")[2] or "tcp"
        )
    ]


__all__ = ("owned_bindings",)
