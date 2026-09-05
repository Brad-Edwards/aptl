"""Scenario-neutral evidence polling for installed verification plugins."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import time
from typing import TYPE_CHECKING

from aptl.core.deployment import get_backend
from aptl.core.env import env_vars_from_dict, find_placeholder_env_values, load_dotenv
from aptl.validation._live_gate_probes import (
    EvidencePollRequest,
    _collect_until_evidence,
    _event_type_tally,
    _is_traffic_event,
    _matched_alert_summary,
    _now_iso,
)

if TYPE_CHECKING:
    from aptl.core.config import AptlConfig
    from aptl.validation.techvault_live_gate import LiveGateState


@dataclass(frozen=True)
class EvidenceCollectionRequest(object):
    """Plugin callbacks and bounds for one evidence collection attempt."""

    trigger: Callable[[], None]
    alert_matches: Callable[[object], bool]
    deadline_monotonic: float
    poll_interval_seconds: float
    env_loader: Callable[[Path], dict[str, str]] | None = None
    monotonic_fn: Callable[[], float] = time.monotonic


@dataclass(frozen=True)
class _IndexerSettings(object):
    url: str
    auth: tuple[str, str]


def _indexer_settings(
    project_dir: Path,
    env_loader: Callable[[Path], dict[str, str]] | None,
) -> _IndexerSettings:
    raw_env = (env_loader or load_dotenv)(project_dir / ".env")
    if find_placeholder_env_values(raw_env):
        raise ValueError("placeholder credentials")
    env = env_vars_from_dict(raw_env)
    indexer_port = int(raw_env.get("APTL_HP_WAZUH_INDEXER_9200", "9200"))
    if not 1 <= indexer_port <= 65535:
        raise ValueError("invalid indexer port")
    return _IndexerSettings(
        url=f"https://localhost:{indexer_port}",
        auth=(env.indexer_username, env.indexer_password),
    )


def _record_summary(
    state: "LiveGateState",
    start_iso: str,
    eve: list[dict],
    alerts: list[dict],
    alert_matches: Callable[[object], bool],
) -> list[dict]:
    end_iso = _now_iso()
    traffic_eve = [event for event in eve if _is_traffic_event(event)]
    correlated_alerts = [alert for alert in alerts if alert_matches(alert)]
    summary = {
        "window": [start_iso, end_iso],
        "suricata_event_types": _event_type_tally(eve),
        "suricata_traffic_event_count": len(traffic_eve),
        "wazuh_alert_count": len(alerts),
        "wazuh_correlated_alert_count": len(correlated_alerts),
    }
    if correlated_alerts:
        summary["matched_alert"] = _matched_alert_summary(correlated_alerts[0])
    state.evidence = {**(state.evidence or {}), "telemetry": summary}
    return correlated_alerts


def collect_evidence_diagnostics(
    config: "AptlConfig",
    project_dir: Path,
    state: "LiveGateState",
    request: EvidenceCollectionRequest,
) -> list[str]:
    """Poll core-owned sources for one plugin-defined, correlated observation."""

    backend = get_backend(config, project_dir)
    diagnostics: list[str] = []
    try:
        settings = _indexer_settings(project_dir, request.env_loader)
    except (OSError, ValueError):
        diagnostics.append("Wazuh collector credentials or endpoint are unavailable.")
    if not diagnostics:
        start_iso = _now_iso()
        if request.monotonic_fn() >= request.deadline_monotonic:
            diagnostics.append("verification deadline elapsed before evidence trigger")
        else:
            request.trigger()
            if request.monotonic_fn() >= request.deadline_monotonic:
                diagnostics.append("verification deadline elapsed during evidence trigger")
            else:
                eve, alerts = _collect_until_evidence(
                    EvidencePollRequest(
                        backend=backend,
                        start_iso=start_iso,
                        deadline_monotonic=request.deadline_monotonic,
                        poll_interval_seconds=request.poll_interval_seconds,
                        indexer_url=settings.url,
                        indexer_auth=settings.auth,
                        alert_matches=request.alert_matches,
                        regenerate=request.trigger,
                        monotonic_fn=request.monotonic_fn,
                    )
                )
                correlated = _record_summary(
                    state, start_iso, eve, alerts, request.alert_matches
                )
                if not correlated:
                    diagnostics.append(
                        "no plugin-correlated alert was observed in the bounded "
                        "evidence window"
                    )
    return diagnostics


__all__ = ["EvidenceCollectionRequest", "collect_evidence_diagnostics"]
