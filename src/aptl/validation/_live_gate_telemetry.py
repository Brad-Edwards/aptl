"""Scenario-neutral evidence polling for installed verification plugins."""

from collections.abc import Callable
from pathlib import Path
import time
from typing import TYPE_CHECKING

from aptl.core.deployment import get_backend
from aptl.core.env import env_vars_from_dict, find_placeholder_env_values, load_dotenv
from aptl.validation._live_gate_probes import (
    _collect_until_evidence,
    _event_type_tally,
    _is_traffic_event,
    _matched_alert_summary,
    _now_iso,
)

if TYPE_CHECKING:
    from aptl.core.config import AptlConfig
    from aptl.validation.techvault_live_gate import LiveGateState


def collect_evidence_diagnostics(
    config: "AptlConfig",
    project_dir: Path,
    state: "LiveGateState",
    *,
    trigger: Callable[[], None],
    alert_matches: Callable[[object], bool],
    deadline_monotonic: float,
    poll_interval_seconds: float,
    env_loader: Callable[[Path], dict[str, str]] | None = None,
    monotonic_fn: Callable[[], float] = time.monotonic,
) -> list[str]:
    """Poll core-owned sources for one plugin-defined, correlated observation."""

    backend = get_backend(config, project_dir)
    try:
        raw_env = (env_loader or load_dotenv)(project_dir / ".env")
        if find_placeholder_env_values(raw_env):
            raise ValueError("placeholder credentials")
        env = env_vars_from_dict(raw_env)
        indexer_port = int(raw_env.get("APTL_HP_WAZUH_INDEXER_9200", "9200"))
        if not 1 <= indexer_port <= 65535:
            raise ValueError("invalid indexer port")
    except (OSError, ValueError):
        return ["Wazuh collector credentials or endpoint are unavailable."]
    start_iso = _now_iso()
    if monotonic_fn() >= deadline_monotonic:
        return ["verification deadline elapsed before evidence trigger"]
    trigger()
    if monotonic_fn() >= deadline_monotonic:
        return ["verification deadline elapsed during evidence trigger"]
    eve, alerts = _collect_until_evidence(
        backend,
        start_iso,
        deadline_monotonic=deadline_monotonic,
        poll_interval_seconds=poll_interval_seconds,
        indexer_url=f"https://localhost:{indexer_port}",
        indexer_auth=(env.indexer_username, env.indexer_password),
        alert_matches=alert_matches,
        regenerate=trigger,
        monotonic_fn=monotonic_fn,
    )
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

    if not correlated_alerts:
        return [
            "no plugin-correlated alert was observed in the bounded evidence window"
        ]
    return []


__all__ = ["collect_evidence_diagnostics"]
