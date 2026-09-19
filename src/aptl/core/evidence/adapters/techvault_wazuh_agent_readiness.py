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
        raw = _readiness_document(payload, self._expected_nodes)
        if raw is None:
            status = (
                CollectorStatus.SOURCE_UNAVAILABLE
                if payload is None
                else CollectorStatus.MID_RUN_LOSS
            )
            return _failure(status)
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


def _readiness_document(
    payload: Mapping[str, object] | None, expected_nodes: Sequence[str]
) -> bytes | None:
    """Encode a complete per-host readiness payload within its bound."""

    if payload is None:
        return None
    hosts = payload.get("hosts")
    if not isinstance(hosts, Sequence) or isinstance(hosts, (str, bytes)):
        return None
    rows = [host for host in hosts if isinstance(host, Mapping)]
    if len(rows) != len(hosts) or not _hosts_are_ready(rows, expected_nodes):
        return None
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
    return raw if len(raw) <= _MAX_READINESS_BYTES else None


def _hosts_are_ready(
    rows: Sequence[Mapping[str, object]], expected_nodes: Sequence[str]
) -> bool:
    """Return whether every declared host has exactly one ready identity."""

    if not expected_nodes:
        return False
    if any(not _host_row_is_ready(row) for row in rows):
        return False
    node_refs = [str(row["node_ref"]) for row in rows]
    agent_ids = [str(row["agent_id"]) for row in rows]
    enrollment_names = [str(row["enrollment_name"]) for row in rows]
    # One member per host, and no member claimed by two hosts: either direction
    # makes per-host attribution ambiguous.
    identities_are_unique = all(
        len(set(values)) == len(values)
        for values in (node_refs, agent_ids, enrollment_names)
    )
    return identities_are_unique and set(node_refs) == set(expected_nodes)


def _host_row_is_ready(row: Mapping[str, object]) -> bool:
    """Return whether one host row is complete, typed, active and affirmative."""

    if not _host_row_has_valid_types(row):
        return False
    freshness_agrees = bool(row["telemetry_fresh"]) == (
        int(row["telemetry_event_count"]) > 0
    )
    identities_present = all(
        str(row[name]).strip() for name in ("node_ref", "enrollment_name", "agent_id")
    )
    return bool(
        freshness_agrees
        and identities_present
        and str(row["status"]) == _ACTIVE_STATUS
        and all(row[name] is True for name in _REQUIRED_HOST_TRUE)
    )


def _host_row_has_valid_types(row: Mapping[str, object]) -> bool:
    """Return whether every required field has its exact admitted type."""

    for name, expected in _REQUIRED_HOST_FIELDS.items():
        value = row.get(name)
        # bool is a subclass of int, so a count field must not accept True.
        if not isinstance(value, expected) or (
            expected is int and isinstance(value, bool)
        ):
            return False
    return True


def _failure(status: CollectorStatus = CollectorStatus.MID_RUN_LOSS) -> SourceResult:
    """Return one bounded, secret-free failure with no partial evidence."""

    return SourceResult(status=status, chunks=(), media_type="application/json")


__all__ = ("WazuhAgentReadinessSource",)
