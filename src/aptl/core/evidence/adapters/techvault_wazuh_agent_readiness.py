"""Native endpoint-agent readiness evidence for the TechVault scenario.

The released pack's ``wazuh-agent-readiness`` requirement is per host, not per
fleet. For each node that declares a forwarding agent it asks for exactly one
active manager member correlated by stable enrollment name and node reference,
readable declared log sources, and fresh telemetry attributed to that identity.

Three ways of appearing ready are explicitly rejected by the pack's own scope
and therefore by this source:

* a duplicate or stale identity -- two members answering to one host means the
  attribution of any event to that host is ambiguous;
* another source standing in -- Suricata EVE, generic syslog and manager health
  each prove something, but none of them prove a given host's endpoint agent;
* enrollment that did not survive recreation -- an agent whose identity is
  regenerated on restart silently breaks historical attribution.

Only bounded identity, status and correlation results leave this boundary.
Enrollment keys, credentials and raw event bodies never do.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence

from aptl.core.evidence.adapters.sources import SourceResult
from aptl.core.evidence.outcomes import CollectorStatus

_MAX_READINESS_BYTES = 512 * 1024

#: Per-host facts and the type each must carry.
_REQUIRED_HOST_FIELDS: Mapping[str, type | tuple[type, ...]] = {
    "node_ref": str,
    "enrollment_name": str,
    "agent_id": str,
    "status": str,
    "sources_readable": bool,
    "telemetry_fresh": bool,
    "telemetry_event_count": int,
    "enrollment_preserved": bool,
}
_REQUIRED_HOST_TRUE = ("sources_readable", "telemetry_fresh", "enrollment_preserved")
_ACTIVE_STATUS = "active"


class WazuhAgentReadinessSource:
    """Project one bounded per-host endpoint-agent readiness observation."""

    def __init__(
        self,
        query: Callable[[str, str], Mapping[str, object] | None],
        expected_nodes: Sequence[str],
    ) -> None:
        """Bind the trusted query owner and the nodes the pack declares.

        ``expected_nodes`` comes from the admitted realization's declared
        forwarding agents, so a host that silently stops being observed is a
        missing required identity rather than a smaller passing fleet.
        """

        self._query = query
        self._expected_nodes = tuple(sorted(set(expected_nodes)))

    def fetch(self, start_iso: str, end_iso: str) -> SourceResult:
        payload = self._query(start_iso, end_iso)
        if payload is None:
            return _failure(CollectorStatus.SOURCE_UNAVAILABLE)
        hosts = payload.get("hosts")
        if not isinstance(hosts, Sequence) or isinstance(hosts, (str, bytes)):
            return _failure()
        rows = [host for host in hosts if isinstance(host, Mapping)]
        if len(rows) != len(hosts) or not _hosts_are_ready(rows, self._expected_nodes):
            return _failure()
        document = {
            "wazuh_agent_ready": True,
            "hosts": sorted(
                (
                    {name: row[name] for name in sorted(_REQUIRED_HOST_FIELDS)}
                    for row in rows
                ),
                key=lambda row: str(row["node_ref"]),
            ),
        }
        raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        if len(raw) > _MAX_READINESS_BYTES:
            return _failure()
        return SourceResult(
            status=CollectorStatus.OK,
            chunks=(raw,),
            media_type="application/json",
            source_pipeline={
                "source_refs": [
                    {
                        "ref_kind": "other",
                        "ref_id": (
                            f"nodes.{node}.runtime.forwarding_agents"
                            if node != "wazuh-manager"
                            else "nodes.wazuh-manager.runtime."
                            "security_monitoring_managers.wazuh-manager"
                        ),
                    }
                    for node in ("wazuh-manager", *self._expected_nodes)
                ]
            },
        )


def _hosts_are_ready(
    rows: Sequence[Mapping[str, object]], expected_nodes: Sequence[str]
) -> bool:
    """Return whether every declared host has exactly one ready identity."""

    if not expected_nodes:
        return False
    for row in rows:
        if not _host_row_is_ready(row):
            return False
    node_refs = [str(row["node_ref"]) for row in rows]
    agent_ids = [str(row["agent_id"]) for row in rows]
    enrollment_names = [str(row["enrollment_name"]) for row in rows]
    # One member per host, and no member claimed by two hosts: either direction
    # makes per-host attribution ambiguous.
    if len(set(node_refs)) != len(node_refs):
        return False
    if len(set(agent_ids)) != len(agent_ids):
        return False
    if len(set(enrollment_names)) != len(enrollment_names):
        return False
    return set(node_refs) == set(expected_nodes)


def _host_row_is_ready(row: Mapping[str, object]) -> bool:
    """Return whether one host row is complete, typed, active and affirmative."""

    for name, expected in _REQUIRED_HOST_FIELDS.items():
        value = row.get(name)
        # bool is a subclass of int, so a count field must not accept True.
        if not isinstance(value, expected) or (
            expected is int and isinstance(value, bool)
        ):
            return False
    # The freshness flag has to agree with the count it summarises; a row that
    # claims fresh telemetry while reporting none observed is contradictory.
    if bool(row["telemetry_fresh"]) != (int(row["telemetry_event_count"]) > 0):
        return False
    if any(not str(row[name]).strip() for name in ("node_ref", "enrollment_name", "agent_id")):
        return False
    if str(row["status"]) != _ACTIVE_STATUS:
        return False
    return all(row[name] is True for name in _REQUIRED_HOST_TRUE)


def _failure(status: CollectorStatus = CollectorStatus.MID_RUN_LOSS) -> SourceResult:
    """Return one bounded, secret-free failure with no partial evidence."""

    return SourceResult(status=status, chunks=(), media_type="application/json")


__all__ = ("WazuhAgentReadinessSource",)
