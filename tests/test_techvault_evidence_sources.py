"""Exact validation for the four released TechVault evidence sources."""

import json

from aptl_techvault.evidence.techvault import (
    CortexEnrichmentSource,
    RedteamSessionTranscriptSource,
    SuricataRuleReadinessSource,
    SuricataWazuhSqliSource,
    TECHVAULT_LOCAL_SIDS,
    TranscriptFrame,
    TranscriptSession,
    transcript_chain_digest,
)
from aptl.core.evidence.outcomes import CollectorStatus

_START = "2026-09-14T10:00:00Z"
_TRIGGERED = "2026-09-14T10:00:05Z"
_FINISHED = "2026-09-14T10:00:10Z"
_END = "2026-09-14T10:01:00Z"
_DIGEST = "sha256:" + "a" * 64


def _cortex_payload():
    return {
        "analyzers": [
            {"id": "Other_1_0", "enabled": False},
            {"id": "TechVaultScenarioContext_1_0", "enabled": True},
        ],
        "report": {
            "analyzer_id": "TechVaultScenarioContext_1_0",
            "observable": "172.20.1.30",
            "status": "Success",
            "started_at": _TRIGGERED,
            "finished_at": _FINISHED,
            "scenario_role": "attacker",
            "summary": {"taxonomies": []},
        },
        "connector": {"name": "techvault-cortex", "status": "OK"},
    }


def test_cortex_source_requires_exact_fresh_analyzer_report_and_connector():
    source = CortexEnrichmentSource(lambda _start, _end: _cortex_payload())

    result = source.fetch(_START, _END)

    assert result.status is CollectorStatus.OK
    assert result.records[0]["enabled_analyzers"] == ["TechVaultScenarioContext_1_0"]
    assert "summary" not in result.records[0]["report"]
    assert "source_refs" in result.source_pipeline


def test_cortex_source_rejects_stale_or_partial_readback():
    payload = _cortex_payload()
    payload["connector"] = {"name": "techvault-cortex", "status": "ERROR"}
    source = CortexEnrichmentSource(lambda _start, _end: payload)

    assert source.fetch(_START, _END).status is CollectorStatus.MID_RUN_LOSS


def _readiness_payload():
    return {
        "image_ref": "jasonish/suricata@" + _DIGEST,
        "image_digest": _DIGEST,
        "content_identities": {
            "suricata-config": "techvault-suricata-config@" + _DIGEST,
            "suricata-local-rules": (
                "techvault-suricata-local-rules@sha256:" + "b" * 64
            ),
        },
        "realized_byte_digests": {
            "suricata-config": _DIGEST,
            "suricata-local-rules": "sha256:" + "b" * 64,
        },
        "native_configuration_ok": True,
        "selected_sources": ["suricata-builtin", "techvault-local"],
        "local_sids": sorted(TECHVAULT_LOCAL_SIDS),
    }


def test_suricata_readiness_emits_exact_sids_and_no_paths_or_rule_bodies():
    source = SuricataRuleReadinessSource(lambda _start, _end: _readiness_payload())

    result = source.fetch(_START, _END)
    text = b"".join(result.chunks).decode()

    assert result.status is CollectorStatus.OK
    assert result.media_type == "text/plain"
    assert text.count("local_sid=") == 16
    assert "alert http" not in text
    assert "/etc/" not in text


def test_suricata_readiness_rejects_missing_or_extra_sid():
    payload = _readiness_payload()
    payload["local_sids"] = sorted(TECHVAULT_LOCAL_SIDS - {1000010})

    result = SuricataRuleReadinessSource(lambda _start, _end: payload).fetch(
        _START, _END
    )

    assert result.status is CollectorStatus.MID_RUN_LOSS


def _trigger():
    return {
        "trigger_id": "probe-1",
        "method": "POST",
        "path": "/login",
        "source_ip": "172.20.1.30",
        "destination_ip": "172.20.1.20",
        "contains_union_select": True,
        "triggered_at": _TRIGGERED,
    }


def _suricata_event():
    return {
        "timestamp": _FINISHED,
        "flow_id": 4242,
        "src_ip": "172.20.1.30",
        "dest_ip": "172.20.1.20",
        "alert": {"signature_id": 1000010},
    }


def _wazuh_event():
    return {
        "timestamp": _FINISHED,
        "rule": {"id": "303020"},
        "data": {
            "flow_id": "4242",
            "src_ip": "172.20.1.30",
            "dest_ip": "172.20.1.20",
            "alert": {"signature_id": 1000010},
        },
    }


def test_sqli_source_requires_exact_correlated_suricata_and_wazuh_pair():
    source = SuricataWazuhSqliSource(
        _trigger,
        lambda _start, _end: [_suricata_event()],
        lambda _start, _end: [_wazuh_event()],
    )

    result = source.fetch(_START, _END)
    rows = [json.loads(line) for line in b"".join(result.chunks).splitlines()]

    assert result.status is CollectorStatus.OK
    assert result.media_type == "application/x-ndjson"
    assert [row["source"] for row in rows] == ["suricata", "wazuh"]
    assert {row["flow_id"] for row in rows} == {"4242"}
    assert result.observer_effect == "one fixed POST /login containing UNION SELECT"


def test_sqli_source_rejects_legacy_or_uncorrelated_alerts():
    wazuh = _wazuh_event()
    wazuh["rule"] = {"id": "302010"}

    result = SuricataWazuhSqliSource(
        _trigger,
        lambda _start, _end: [_suricata_event()],
        lambda _start, _end: [wazuh],
    ).fetch(_START, _END)

    assert result.status is CollectorStatus.MID_RUN_LOSS


def _session(session_id="session-1"):
    frames = (
        TranscriptFrame(1, _TRIGGERED, "input", b"whoami"),
        TranscriptFrame(2, _FINISHED, "output", b"kali"),
    )
    return TranscriptSession(
        session_id=session_id,
        started_at=_TRIGGERED,
        finished_at=_FINISHED,
        close_reason="clean-exit",
        frames=frames,
        final_chain_digest=transcript_chain_digest(frames),
    )


def test_transcript_source_requires_every_ledger_session_and_valid_chain():
    source = RedteamSessionTranscriptSource(lambda: ["session-1"], lambda: [_session()])

    result = source.fetch(_START, _END)
    text = b"".join(result.chunks).decode()

    assert result.status is CollectorStatus.OK
    assert "[1:input:" in text
    assert "[2:output:" in text
    assert result.source_pipeline["session_count"] == 1


def test_transcript_source_rejects_bypass_or_forged_chain():
    forged = _session()
    forged = TranscriptSession(
        **{
            **forged.__dict__,
            "final_chain_digest": "sha256:" + "0" * 64,
        }
    )
    bypass = RedteamSessionTranscriptSource(
        lambda: ["session-1", "direct-exec"], lambda: [_session()]
    )
    tampered = RedteamSessionTranscriptSource(lambda: ["session-1"], lambda: [forged])

    assert bypass.fetch(_START, _END).status is CollectorStatus.MID_RUN_LOSS
    assert tampered.fetch(_START, _END).status is CollectorStatus.MID_RUN_LOSS
