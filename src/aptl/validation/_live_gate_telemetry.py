"""Telemetry evidence collection for the ACES live validation gate."""

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from aptl.core.deployment import get_backend
from aptl.core.env import env_vars_from_dict, find_placeholder_env_values, load_dotenv
from aptl.validation._live_gate_probes import (
    _collect_until_evidence,
    _event_type_tally,
    _generate_event,
    _is_correlated_wazuh_alert,
    _is_traffic_event,
    _now_iso,
    _wazuh_correlation_summary,
)

if TYPE_CHECKING:
    from aptl.core.config import AptlConfig
    from aptl.validation.techvault_live_gate import LiveGateOptions, LiveGateState


def telemetry_diagnostics(
    targets: list[tuple[str, str]],
    config: "AptlConfig",
    project_dir: Path,
    options: "LiveGateOptions",
    state: "LiveGateState",
    *,
    env_loader: Callable[[Path], dict[str, str]] | None = None,
) -> list[str]:
    """Generate an event, collect evidence, record the summary, and grade it."""

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
    _generate_event(backend, targets)
    eve, alerts = _collect_until_evidence(
        backend,
        start_iso,
        options.event_window_seconds,
        indexer_url=f"https://localhost:{indexer_port}",
        indexer_auth=(env.indexer_username, env.indexer_password),
    )
    end_iso = _now_iso()

    traffic_eve = [event for event in eve if _is_traffic_event(event)]
    correlated_alerts = [alert for alert in alerts if _is_correlated_wazuh_alert(alert)]
    summary = {
        "generator": "kali nmap + failed-ssh-auth against reachable targets",
        "window": [start_iso, end_iso],
        "suricata_event_types": _event_type_tally(eve),
        "suricata_traffic_event_count": len(traffic_eve),
        "wazuh_alert_count": len(alerts),
        "wazuh_correlated_alert_count": len(correlated_alerts),
    }
    if correlated_alerts:
        summary["wazuh_correlation"] = _wazuh_correlation_summary(correlated_alerts[0])
    state.evidence = {**(state.evidence or {}), "telemetry": summary}

    if not correlated_alerts:
        return [
            "no correlated post-trigger Wazuh alert traversed the realized defensive "
            "stack in the bounded window (unrelated, Suricata-only, or stats-only "
            "events do not count)"
        ]
    return []
