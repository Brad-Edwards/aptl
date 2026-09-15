"""Exact native sources for the released TechVault evidence demands."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from aptl.core.evidence.adapters.sources import SourceResult
from aptl.core.evidence.outcomes import CollectorStatus

CORTEX_ANALYZER_ID = "TechVaultScenarioContext_1_0"
CORTEX_OBSERVABLE = "172.20.1.30"
SURICATA_SQLI_SID = 1000010
WAZUH_SQLI_RULE_ID = "303020"
TECHVAULT_LOCAL_SIDS = frozenset(
    {
        1000001,
        1000002,
        1000010,
        1000011,
        1000012,
        1000020,
        1000030,
        1000031,
        1000040,
        1000050,
        1000060,
        1000061,
        1000070,
        1000080,
        1000090,
        1000091,
    }
)
_MAX_NATIVE_JSON_BYTES = 2 * 1024 * 1024


def _bounded_json(value: object) -> bytes | None:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    except (TypeError, ValueError, RecursionError):
        return None
    return raw if len(raw) <= _MAX_NATIVE_JSON_BYTES else None


def _failure(status: CollectorStatus = CollectorStatus.MID_RUN_LOSS) -> SourceResult:
    return SourceResult(status=status)


class CortexEnrichmentSource:
    """Validate one fresh Cortex/TheHive native readback as exact JSON."""

    def __init__(
        self,
        query: Callable[[str, str], Mapping[str, object] | None],
    ) -> None:
        self._query = query

    def fetch(self, start_iso: str, end_iso: str) -> SourceResult:
        payload = self._query(start_iso, end_iso)
        if payload is None:
            return _failure(CollectorStatus.SOURCE_UNAVAILABLE)
        if not _valid_cortex_payload(payload, start_iso, end_iso):
            return _failure()
        safe = {
            "enabled_analyzers": sorted(
                str(item["id"])
                for item in payload["analyzers"]  # type: ignore[index]
                if item.get("enabled") is True  # type: ignore[union-attr]
            ),
            "report": {
                key: payload["report"][key]  # type: ignore[index]
                for key in (
                    "analyzer_id",
                    "observable",
                    "status",
                    "started_at",
                    "finished_at",
                    "scenario_role",
                )
                if key in payload["report"]  # type: ignore[operator]
            },
            "thehive_connector": {
                "name": payload["connector"]["name"],  # type: ignore[index]
                "status": payload["connector"]["status"],  # type: ignore[index]
            },
        }
        raw = _bounded_json(safe)
        if raw is None:
            return _failure(CollectorStatus.TRUNCATION)
        return SourceResult(
            status=CollectorStatus.OK,
            records=[safe],
            source_min_time=str(payload["report"]["started_at"]),  # type: ignore[index]
            source_max_time=str(payload["report"]["finished_at"]),  # type: ignore[index]
            source_pipeline={
                "source_refs": [
                    {
                        "ref_kind": "other",
                        "ref_id": "nodes.cortex.runtime.platform_applications.cortex-enrichment",
                    },
                    {
                        "ref_kind": "other",
                        "ref_id": "nodes.thehive.runtime.platform_applications.thehive-case-management",
                    },
                ]
            },
        )


def _valid_cortex_payload(
    payload: Mapping[str, object], start_iso: str, end_iso: str
) -> bool:
    analyzers = payload.get("analyzers")
    report = payload.get("report")
    connector = payload.get("connector")
    if (
        not isinstance(analyzers, Sequence)
        or isinstance(analyzers, str | bytes)
        or not isinstance(report, Mapping)
        or not isinstance(connector, Mapping)
    ):
        return False
    required = [
        item
        for item in analyzers
        if isinstance(item, Mapping) and item.get("id") == CORTEX_ANALYZER_ID
    ]
    return (
        len(required) == 1
        and required[0].get("enabled") is True
        and report.get("analyzer_id") == CORTEX_ANALYZER_ID
        and report.get("observable") == CORTEX_OBSERVABLE
        and str(report.get("status", "")).lower() in {"success", "succeeded"}
        and _inside_window(report.get("started_at"), start_iso, end_iso)
        and _inside_window(report.get("finished_at"), start_iso, end_iso)
        and connector.get("status") == "OK"
        and bool(connector.get("name"))
        and _bounded_json(payload) is not None
    )


class SuricataRuleReadinessSource:
    """Validate native Suricata configuration and emit path-free readiness text."""

    def __init__(
        self, query: Callable[[str, str], Mapping[str, object] | None]
    ) -> None:
        self._query = query

    def fetch(self, start_iso: str, end_iso: str) -> SourceResult:
        payload = self._query(start_iso, end_iso)
        if payload is None:
            return _failure(CollectorStatus.SOURCE_UNAVAILABLE)
        if not _valid_readiness_payload(payload):
            return _failure()
        digests = payload["realized_byte_digests"]
        identities = payload["content_identities"]
        lines = [
            f"image_ref={payload['image_ref']}",
            f"image_digest={payload['image_digest']}",
            "native_configuration=ok",
            "source=suricata-builtin",
            "source=techvault-local",
            *(
                f"content_identity.{key}={identities[key]}"
                for key in sorted(identities)
            ),
            *(f"content_digest.{key}={digests[key]}" for key in sorted(digests)),  # type: ignore[index]
            *(f"local_sid={sid}" for sid in sorted(TECHVAULT_LOCAL_SIDS)),
            f"local_rule_count={len(TECHVAULT_LOCAL_SIDS)}",
        ]
        return SourceResult(
            status=CollectorStatus.OK,
            chunks=(("\n".join(lines) + "\n").encode(),),
            media_type="text/plain",
            source_pipeline={
                "source_refs": [
                    {
                        "ref_kind": "other",
                        "ref_id": "nodes.suricata.runtime.network_detection_engines.suricata-engine.rule_sources.suricata-builtin",
                    },
                    {
                        "ref_kind": "other",
                        "ref_id": "nodes.suricata.runtime.network_detection_engines.suricata-engine.rule_sources.techvault-local",
                    },
                ]
            },
        )


def _valid_readiness_payload(payload: Mapping[str, object]) -> bool:
    digests = payload.get("realized_byte_digests")
    identities = payload.get("content_identities")
    sources = payload.get("selected_sources")
    sids = payload.get("local_sids")
    image_ref = payload.get("image_ref")
    image_digest = payload.get("image_digest")
    return (
        payload.get("native_configuration_ok") is True
        and isinstance(image_ref, str)
        and _sha256(image_digest)
        and image_ref.endswith(f"@{image_digest}")
        and isinstance(digests, Mapping)
        and set(digests) == {"suricata-config", "suricata-local-rules"}
        and all(_sha256(value) for value in digests.values())
        and isinstance(identities, Mapping)
        and set(identities) == {"suricata-config", "suricata-local-rules"}
        and all(
            isinstance(value, str)
            and "@sha256:" in value
            and value.rsplit("@", 1)[-1] == digests.get(key)
            for key, value in identities.items()
        )
        and isinstance(sources, Sequence)
        and not isinstance(sources, str | bytes)
        and set(sources) == {"suricata-builtin", "techvault-local"}
        and isinstance(sids, Sequence)
        and not isinstance(sids, str | bytes)
        and len(sids) == len(TECHVAULT_LOCAL_SIDS)
        and {int(value) for value in sids if isinstance(value, int | str)}
        == TECHVAULT_LOCAL_SIDS
    )


class SuricataWazuhSqliSource:
    """Generate a fresh fixed probe and require exact flow-lineage correlation."""

    def __init__(
        self,
        trigger: Callable[[], Mapping[str, object] | None],
        query_suricata: Callable[[str, str], Sequence[Mapping[str, object]] | None],
        query_wazuh: Callable[[str, str], Sequence[Mapping[str, object]] | None],
        *,
        poll_attempts: int = 1,
        poll_interval_seconds: float = 0.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._trigger = trigger
        self._query_suricata = query_suricata
        self._query_wazuh = query_wazuh
        self._poll_attempts = max(1, poll_attempts)
        self._poll_interval_seconds = max(0.0, poll_interval_seconds)
        self._sleep = sleep

    def fetch(self, start_iso: str, end_iso: str) -> SourceResult:
        trigger = self._trigger()
        if trigger is None or not _valid_trigger(trigger, start_iso, end_iso):
            return _failure(CollectorStatus.SOURCE_UNAVAILABLE)
        pair = None
        unavailable = False
        for attempt in range(self._poll_attempts):
            suricata = self._query_suricata(str(trigger["triggered_at"]), end_iso)
            wazuh = self._query_wazuh(str(trigger["triggered_at"]), end_iso)
            if suricata is None or wazuh is None:
                unavailable = True
            else:
                pair = _exact_correlated_pair(trigger, suricata, wazuh, end_iso)
            if pair is not None:
                break
            if attempt + 1 < self._poll_attempts and self._poll_interval_seconds:
                self._sleep(self._poll_interval_seconds)
        if pair is None:
            return _failure(
                CollectorStatus.SOURCE_UNAVAILABLE
                if unavailable
                else CollectorStatus.MID_RUN_LOSS
            )
        suricata_event, wazuh_event = pair
        rows = (
            _sqli_projection("suricata", trigger, suricata_event),
            _sqli_projection("wazuh", trigger, wazuh_event),
        )
        chunks = tuple(
            json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            for row in rows
        )
        return SourceResult(
            status=CollectorStatus.OK,
            records=list(rows),
            chunks=chunks,
            media_type="application/x-ndjson",
            source_min_time=str(suricata_event["timestamp"]),
            source_max_time=str(wazuh_event["timestamp"]),
            observer_effect="one fixed POST /login containing UNION SELECT",
            source_pipeline={
                "source_refs": [
                    {
                        "ref_kind": "other",
                        "ref_id": "nodes.suricata.runtime.network_detection_engines.suricata-engine.output_streams.eve-json",
                    },
                    {
                        "ref_kind": "other",
                        "ref_id": "nodes.wazuh-manager.runtime.security_monitoring_managers.wazuh-manager.content_sets.suricata-rules",
                    },
                ],
                "correlation": "shared-suricata-flow-id",
            },
        )


def _valid_trigger(trigger: Mapping[str, object], start_iso: str, end_iso: str) -> bool:
    return (
        bool(trigger.get("trigger_id"))
        and trigger.get("method") == "POST"
        and trigger.get("path") == "/login"
        and trigger.get("source_ip") == "172.20.1.30"
        and bool(trigger.get("destination_ip"))
        and trigger.get("contains_union_select") is True
        and _inside_window(trigger.get("triggered_at"), start_iso, end_iso)
    )


def _exact_correlated_pair(
    trigger: Mapping[str, object],
    suricata: Sequence[Mapping[str, object]],
    wazuh: Sequence[Mapping[str, object]],
    end_iso: str,
) -> tuple[Mapping[str, object], Mapping[str, object]] | None:
    start_iso = str(trigger["triggered_at"])
    sensor = [
        event
        for event in suricata
        if _suricata_sid(event) == SURICATA_SQLI_SID
        and _event_matches_trigger(event, trigger, start_iso, end_iso)
    ]
    manager = [
        event
        for event in wazuh
        if _wazuh_rule_id(event) == WAZUH_SQLI_RULE_ID
        and _embedded_suricata_sid(event) == SURICATA_SQLI_SID
        and _event_matches_trigger(event, trigger, start_iso, end_iso)
    ]
    pairs = [
        (left, right)
        for left in sensor
        for right in manager
        if str(left.get("flow_id", ""))
        and str(left.get("flow_id")) == str(_nested(right, "data", "flow_id"))
    ]
    return pairs[0] if len(pairs) == 1 else None


def _event_matches_trigger(
    event: Mapping[str, object],
    trigger: Mapping[str, object],
    start_iso: str,
    end_iso: str,
) -> bool:
    source = event.get("src_ip", _nested(event, "data", "src_ip"))
    destination = event.get("dest_ip", _nested(event, "data", "dest_ip"))
    return (
        source == trigger["source_ip"]
        and destination == trigger["destination_ip"]
        and _inside_window(event.get("timestamp"), start_iso, end_iso)
    )


def _sqli_projection(
    source: str,
    trigger: Mapping[str, object],
    event: Mapping[str, object],
) -> dict[str, object]:
    flow_id = event.get("flow_id", _nested(event, "data", "flow_id"))
    return {
        "source": source,
        "trigger_id": trigger["trigger_id"],
        "timestamp": event["timestamp"],
        "flow_id": str(flow_id),
        "source_ip": trigger["source_ip"],
        "destination_ip": trigger["destination_ip"],
        "suricata_signature_id": SURICATA_SQLI_SID,
        "wazuh_rule_id": WAZUH_SQLI_RULE_ID,
    }


@dataclass(frozen=True)
class TranscriptFrame:
    sequence: int
    timestamp: str
    direction: str
    data: bytes


@dataclass(frozen=True)
class TranscriptSession:
    session_id: str
    started_at: str
    finished_at: str
    close_reason: str
    frames: tuple[TranscriptFrame, ...]
    final_chain_digest: str
    loss_count: int = 0


class RedteamSessionTranscriptSource:
    """Require complete sidecar-owned custody for every admitted session."""

    def __init__(
        self,
        expected_session_ids: Callable[[], Sequence[str] | None],
        read_sessions: Callable[[], Sequence[TranscriptSession] | None],
    ) -> None:
        self._expected_session_ids = expected_session_ids
        self._read_sessions = read_sessions

    def fetch(self, start_iso: str, end_iso: str) -> SourceResult:
        expected = self._expected_session_ids()
        sessions = self._read_sessions()
        if expected is None or sessions is None:
            return _failure(CollectorStatus.SOURCE_UNAVAILABLE)
        if len(expected) != len(set(expected)) or len(sessions) != len(
            {session.session_id for session in sessions}
        ):
            return _failure()
        if set(expected) != {session.session_id for session in sessions}:
            return _failure()
        if any(
            not _valid_transcript_session(session, start_iso, end_iso)
            for session in sessions
        ):
            return _failure()
        chunks: list[bytes] = []
        frame_count = 0
        for session in sorted(
            sessions, key=lambda item: (item.started_at, item.session_id)
        ):
            chunks.append(f"=== session {session.session_id} start ===\n".encode())
            for frame in session.frames:
                chunks.append(
                    f"[{frame.sequence}:{frame.direction}:{frame.timestamp}] ".encode()
                    + frame.data
                    + b"\n"
                )
                frame_count += 1
            chunks.append(
                f"=== session {session.session_id} end close={session.close_reason} chain={session.final_chain_digest} ===\n".encode()
            )
        return SourceResult(
            status=CollectorStatus.OK if sessions else CollectorStatus.EMPTY_OK,
            chunks=tuple(chunks),
            media_type="text/plain",
            source_min_time=min(
                (item.started_at for item in sessions), default=start_iso
            ),
            source_max_time=max(
                (item.finished_at for item in sessions), default=end_iso
            ),
            source_pipeline={
                "source_refs": [
                    {
                        "ref_kind": "apparatus-context",
                        "ref_id": "apparatus.capture.kali-session-capture",
                    }
                ],
                "custody": "sidecar-owned-pty-master-sha256-chain",
                "session_count": len(sessions),
                "frame_count": frame_count,
            },
        )


def _valid_transcript_session(
    session: TranscriptSession, start_iso: str, end_iso: str
) -> bool:
    if (
        not session.session_id
        or session.loss_count
        or session.close_reason
        not in {"clean-exit", "remote-eof", "signal", "forced-teardown"}
        or not _inside_window(session.started_at, start_iso, end_iso)
        or not _inside_window(session.finished_at, start_iso, end_iso)
        or any(frame.sequence != index for index, frame in enumerate(session.frames, 1))
        or any(frame.direction not in {"input", "output"} for frame in session.frames)
        or any(
            not _inside_window(frame.timestamp, session.started_at, session.finished_at)
            for frame in session.frames
        )
    ):
        return False
    try:
        for frame in session.frames:
            frame.data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return _transcript_chain(session.frames) == session.final_chain_digest


def _transcript_chain(frames: Sequence[TranscriptFrame]) -> str:
    chain = bytes(32)
    for frame in frames:
        header = f"{frame.sequence}\0{frame.timestamp}\0{frame.direction}\0".encode()
        chain = hashlib.sha256(chain + header + frame.data).digest()
    return "sha256:" + chain.hex()


def transcript_chain_digest(frames: Sequence[TranscriptFrame]) -> str:
    """Return the custody-chain digest used by the sidecar and source verifier."""

    return _transcript_chain(frames)


def _sha256(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    tail = value.removeprefix("sha256:")
    return len(tail) == 64 and all(char in "0123456789abcdef" for char in tail)


def _nested(value: Mapping[str, object], *keys: str) -> object:
    current: object = value
    for key in keys:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _suricata_sid(event: Mapping[str, object]) -> int | None:
    value = _nested(event, "alert", "signature_id")
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _embedded_suricata_sid(event: Mapping[str, object]) -> int | None:
    value = _nested(event, "data", "alert", "signature_id")
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _wazuh_rule_id(event: Mapping[str, object]) -> str:
    return str(_nested(event, "rule", "id") or "")


def _inside_window(value: object, start_iso: str, end_iso: str) -> bool:
    try:
        instant = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        start = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        end = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return False
    return start <= instant <= end


__all__ = (
    "CORTEX_ANALYZER_ID",
    "CORTEX_OBSERVABLE",
    "CortexEnrichmentSource",
    "RedteamSessionTranscriptSource",
    "SuricataRuleReadinessSource",
    "SuricataWazuhSqliSource",
    "TECHVAULT_LOCAL_SIDS",
    "TranscriptFrame",
    "TranscriptSession",
    "transcript_chain_digest",
)
