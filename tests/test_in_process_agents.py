"""Verify Wazuh agents run in-process on the four target containers (issue #248).

Pre-#248 the agents lived in sidecar containers (`wazuh-sidecar-{webapp,fileshare,
ad,dns}`) whose iptables operated on the sidecar's own network namespace, not
the target's. Active-response could install a `firewall-drop` rule but the
target's traffic transited a different namespace — the rule had no effect.

After #248, the agent runs **in the target's namespace**: AR-issued iptables
drops execute against the same veth that carries the target's traffic. The
sidecar containers for these four services are removed from compose; only
`wazuh-sidecar-db` (deferred per the issue body's postgres carve-out) and
`wazuh-sidecar-suricata` (out of scope) remain.

These are integration tests that require a healthy lab. Set `APTL_SMOKE=1`
to run them. CI without the lab skips the file cleanly so it doesn't break
the no-lab pipelines.
"""

from __future__ import annotations

import datetime as _dt
import json

import pytest

from tests.helpers import (
    API_PASS,
    API_USER,
    LIVE_LAB,
    docker_exec,
    run_cmd,
)

# Map of in-process agent name → set of acceptable target IPs (multi-homed
# containers can register from any of their interfaces). The agent must NOT
# report a sidecar IP (172.20.0.31..34, the previous sidecar block).
EXPECTED_AGENTS: dict[str, set[str]] = {
    "aptl-webapp-agent": {"172.20.1.20", "172.20.2.25"},
    "aptl-fileshare-agent": {"172.20.2.12"},
    "aptl-ad-agent": {"172.20.2.10"},
    "aptl-dns-agent": {"172.20.1.22", "172.20.2.27", "172.20.0.25"},
}

# Containers whose iptables we exec-and-check for NET_ADMIN.
IN_PROCESS_TARGETS: list[str] = [
    "aptl-webapp",
    "aptl-fileshare",
    "aptl-ad",
    "aptl-dns",
]

# Sidecar container names that MUST be gone from `docker ps` after #248
# (the docker-compose entries are deleted; the running containers should
# not exist on a fresh `aptl lab start`).
REMOVED_SIDECARS: list[str] = [
    "aptl-wazuh-sidecar-webapp",
    "aptl-wazuh-sidecar-fileshare",
    "aptl-wazuh-sidecar-ad",
    "aptl-wazuh-sidecar-dns",
]

# Sidecars that legitimately stay (db carve-out, suricata out of scope).
RETAINED_SIDECARS: list[str] = [
    "aptl-wazuh-sidecar-db",
    "aptl-wazuh-sidecar-suricata",
]

WAZUH_API = "https://localhost:55000"


def _wazuh_token() -> str:
    """Authenticate to the Wazuh manager API and return a JWT.

    Skips the test if the manager is not reachable — so this file is safe
    in CI without the lab.
    """
    cmd = [
        "curl",
        "-sk",
        "--max-time",
        "10",
        "-u",
        f"{API_USER}:{API_PASS}",
        "-X",
        "POST",
        f"{WAZUH_API}/security/user/authenticate?raw=true",
    ]
    result = run_cmd(cmd, timeout=15)
    if result.returncode != 0 or not result.stdout.strip():
        pytest.skip(
            f"Wazuh manager API not reachable at {WAZUH_API}: "
            f"rc={result.returncode}, stderr={result.stderr[:200]}",
        )
    return result.stdout.strip()


def _list_agents(token: str) -> list[dict]:
    """Fetch all registered agents from the manager.

    The manager surfaces the `agent-000` placeholder (the manager itself);
    we filter it out.
    """
    cmd = [
        "curl",
        "-sk",
        "--max-time",
        "10",
        "-H",
        f"Authorization: Bearer {token}",
        f"{WAZUH_API}/agents?limit=500",
    ]
    result = run_cmd(cmd, timeout=15)
    assert result.returncode == 0, f"GET /agents failed: {result.stderr}"
    data = json.loads(result.stdout)
    items = data.get("data", {}).get("affected_items", [])
    return [a for a in items if a.get("id") != "000"]


@LIVE_LAB
class TestInProcessAgents:
    """Integration suite: in-process Wazuh agent placement on 4 target containers."""

    def test_four_in_process_agents_active(self) -> None:
        """The four expected in-process agents are registered, Active, and
        report from a target-container IP — not the previous sidecar block."""
        token = _wazuh_token()
        agents = _list_agents(token)
        by_name = {a["name"]: a for a in agents}

        missing = [name for name in EXPECTED_AGENTS if name not in by_name]
        assert not missing, (
            f"Missing in-process agents (expected to be present after #248): "
            f"{missing}. Found agents: {sorted(by_name)}"
        )

        for agent_name, allowed_ips in EXPECTED_AGENTS.items():
            agent = by_name[agent_name]
            status = agent.get("status", "")
            assert status.lower() == "active", (
                f"{agent_name} status is {status!r}; expected 'active'. "
                f"Agent record: {agent}"
            )
            ip = agent.get("ip", "")
            assert ip in allowed_ips, (
                f"{agent_name} reports IP {ip!r}; expected one of {allowed_ips}. "
                f"This usually means the agent is still running in the sidecar "
                f"namespace (172.20.0.3X) instead of the target's namespace."
            )

    def test_iptables_works_inside_each_in_process_target(self) -> None:
        """`iptables -L` must succeed inside each in-process target — the
        proxy assertion that NET_ADMIN is granted to the container. Without
        NET_ADMIN, `iptables` fails with 'Permission denied' even for read,
        and active-response's `firewall-drop` cannot insert rules."""
        for target in IN_PROCESS_TARGETS:
            result = docker_exec(target, "iptables -L >/dev/null")
            assert result.returncode == 0, (
                f"{target}: `iptables -L` failed (rc={result.returncode}). "
                f"NET_ADMIN cap likely missing from compose. "
                f"stderr: {result.stderr[:300]}"
            )

    def test_sidecars_for_in_process_targets_are_removed(self) -> None:
        """The four sidecar containers we replaced must not be running."""
        result = run_cmd(
            ["docker", "ps", "--format", "{{.Names}}"],
            timeout=15,
        )
        assert result.returncode == 0, f"docker ps failed: {result.stderr}"
        running = set(result.stdout.split())

        still_running = [n for n in REMOVED_SIDECARS if n in running]
        assert not still_running, (
            f"Sidecars that should have been removed by #248 are still "
            f"running: {still_running}. Check docker-compose.yml — these "
            f"service entries should be deleted."
        )

        # Sanity: the carve-out sidecars MUST still be running.
        retained_missing = [n for n in RETAINED_SIDECARS if n not in running]
        assert not retained_missing, (
            f"Carve-out sidecars are not running but should be: "
            f"{retained_missing}. db keeps its sidecar (deferred postgres "
            f"in-process work); suricata keeps its sidecar (out of scope, "
            f"covered by ADR-019)."
        )

    def test_in_process_agents_have_recent_keepalive(self) -> None:
        """Each in-process agent must have shipped a keepalive to the
        manager in the last 5 minutes. Keepalive is a necessary condition
        for log shipping — without it, the agent-manager channel is dead
        — but not sufficient. The next test rounds out the AC#5 picture
        by querying logcollector stats, which advance on every shipped
        localfile event."""
        token = _wazuh_token()
        agents = _list_agents(token)
        by_name = {a["name"]: a for a in agents}

        now_utc = _dt.datetime.now(_dt.timezone.utc)
        max_age = _dt.timedelta(minutes=5)
        stale: list[str] = []
        for agent_name in EXPECTED_AGENTS:
            agent = by_name.get(agent_name)
            if agent is None:
                stale.append(f"{agent_name} (missing)")
                continue
            keepalive_str = agent.get("lastKeepAlive", "")
            if not keepalive_str or keepalive_str.startswith("9999"):
                # 9999-12-31 sentinel = "never connected"
                stale.append(f"{agent_name} (lastKeepAlive={keepalive_str!r})")
                continue
            # ISO 8601 with optional trailing Z; normalize to aware UTC.
            normalized = keepalive_str.rstrip("Z")
            try:
                ts = _dt.datetime.fromisoformat(normalized).replace(
                    tzinfo=_dt.timezone.utc,
                )
            except ValueError:
                stale.append(f"{agent_name} (unparseable lastKeepAlive: {keepalive_str!r})")
                continue
            age = now_utc - ts
            if age > max_age:
                stale.append(
                    f"{agent_name} (last keepalive {age.total_seconds():.0f}s ago)",
                )
        assert not stale, (
            f"In-process agents have stale or missing keepalives — log "
            f"shipping is broken: {stale}"
        )

    def test_in_process_agents_daemons_running(self) -> None:
        """Each in-process target's `wazuh-control status` must report
        all four expected agent daemons running (`wazuh-modulesd`,
        `wazuh-logcollector`, `wazuh-syscheckd`, `wazuh-agentd`).
        `lastKeepAlive` only proves agent-manager connectivity; this
        assertion catches the case where the agent connected but the
        logcollector daemon is dead — that would fail to ship local
        log files even though keepalives are flowing."""
        target_for: dict[str, str] = {
            "aptl-webapp-agent": "aptl-webapp",
            "aptl-fileshare-agent": "aptl-fileshare",
            "aptl-ad-agent": "aptl-ad",
            "aptl-dns-agent": "aptl-dns",
        }
        broken: list[str] = []
        for agent_name, container in target_for.items():
            result = docker_exec(container, "/var/ossec/bin/wazuh-control status")
            if result.returncode != 0:
                broken.append(
                    f"{agent_name} ({container}: wazuh-control rc={result.returncode}, "
                    f"stderr={result.stderr[:200]})",
                )
                continue
            stdout = result.stdout
            for daemon in (
                "wazuh-agentd",
                "wazuh-logcollector",
                "wazuh-modulesd",
                "wazuh-syscheckd",
            ):
                # `wazuh-control status` lines look like
                #   "wazuh-agentd is running..."
                # or
                #   "wazuh-logcollector not running..."
                if f"{daemon} is running" not in stdout:
                    broken.append(f"{agent_name} ({container}: {daemon} not running)")
        assert not broken, (
            f"Agent daemons missing in one or more in-process targets — "
            f"log shipping is broken even if keepalives flow: {broken}"
        )
