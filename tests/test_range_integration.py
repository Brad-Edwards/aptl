"""Cross-system integration tests for the full APTL range.

Exercise actual tool interactions across the complete lab: attack execution,
detection pipelines, SOC tool workflows, and scenario harness — treating the
entire range as a single system that must all be running.

Requires:
    - Full lab running with all profiles (wazuh, victim, kali, enterprise, soc)
    - MISP seeded: ./scripts/seed-misp.sh
    - Shuffle seeded: ./scripts/seed-shuffle.sh
    - Env vars: MISP_API_KEY, THEHIVE_API_KEY

    APTL_SMOKE=1 pytest tests/test_range_integration.py -v
"""

import json
import os
import time

import pytest

from tests.helpers import (
    AD_IP,
    API_PASS,
    API_USER,
    DB_IP,
    FILESHARE_IP,
    KALI_DMZ_IP,
    LAB_CA_PATH,
    LIVE_LAB,
    MISP_API_KEY,
    MISP_URL,
    SHUFFLE_API_KEY,
    SHUFFLE_URL,
    THEHIVE_API_KEY,
    THEHIVE_URL,
    VICTIM_IP,
    WEBAPP_IP_DMZ,
    WS_IP,
    container_running,
    curl_json,
    docker_exec,
    kali_exec,
    mcp_call_tool,
    mcp_jsonrpc,
    mcp_server_cmd,
    mcp_tool_text,
    mcp_tools_list,
    run_cmd,
    wait_for_alert,
    workstation_exec,
)


# -------------------------------------------------------------------
# Section 1: Precondition gate
# -------------------------------------------------------------------

ALL_CONTAINERS = [
    "aptl-wazuh-manager",
    "aptl-wazuh-indexer",
    "aptl-wazuh-dashboard",
    "aptl-victim",
    "aptl-kali",
    "aptl-webapp",
    "aptl-ad",
    "aptl-db",
    "aptl-workstation",
    "aptl-fileshare",
    "aptl-misp",
    "aptl-thehive",
    "aptl-shuffle-backend",
    "aptl-suricata",
]


@LIVE_LAB
class TestPreconditions:
    """All expected containers must be running."""

    @pytest.mark.parametrize("name", ALL_CONTAINERS)
    def test_container_running(self, name):
        assert container_running(name), (
            f"{name} is not running"
        )


# -------------------------------------------------------------------
# Section 2: Detection pipeline
# -------------------------------------------------------------------


@LIVE_LAB
class TestDetectionPipeline:
    """Log flow from containers through Wazuh to the Indexer."""

    def test_kali_can_ssh_to_victim(self):
        result = docker_exec(
            "aptl-kali",
            # SEC #417: kali pivots with the dedicated scenario pivot key, not
            # the operator/MCP control-plane key (which kali no longer holds).
            # Run as the unprivileged `kali` login user against the entrypoint's
            # kali-owned copy of the key, which is the real operator path (the
            # 0600 host bind is not readable by the kali user).
            "ssh -i /home/kali/.ssh/kali_pivot_key "
            "-o StrictHostKeyChecking=no -o BatchMode=yes "
            "labadmin@172.20.2.20 echo OK",
            user="kali",
            timeout=30,
        )
        assert result.returncode == 0, (
            f"SSH failed: {result.stderr}"
        )
        assert "OK" in result.stdout

    def test_victim_log_reaches_manager(self):
        """Unique log on victim reaches Wazuh archives."""
        tag = f"APTL_INTEG_VICTIM_{int(time.time())}"
        docker_exec(
            "aptl-victim", ["logger", "-t", "integtest", tag],
        )

        time.sleep(20)  # Let rsyslog establish connection
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            time.sleep(5)
            result = docker_exec(
                "aptl-wazuh-manager",
                [
                    "grep", "-c", tag,
                    "/var/ossec/logs/archives/archives.log",
                ],
            )
            if (
                result.returncode == 0
                and result.stdout.strip() != "0"
            ):
                return
        pytest.fail(
            f"Log '{tag}' not in Wazuh archives within 240s"
        )

    def test_kali_redteam_log_reaches_manager(self):
        """Red-team log on Kali reaches Wazuh archives."""
        tag = f"APTL_INTEG_KALI_{int(time.time())}"
        kali_exec(
            "logger -t kali_redteam "
            f'"RedTeamActivity: command={tag} '
            'target=172.20.2.20"'
        )

        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            time.sleep(5)
            result = docker_exec(
                "aptl-wazuh-manager",
                [
                    "grep", "-c", tag,
                    "/var/ossec/logs/archives/archives.log",
                ],
            )
            if (
                result.returncode == 0
                and result.stdout.strip() != "0"
            ):
                return
        pytest.fail(
            f"Log '{tag}' not in Wazuh archives within 180s"
        )

    def test_wazuh_agents_registered(self):
        """Wazuh Manager API shows registered agents."""
        result = docker_exec(
            "aptl-wazuh-manager",
            f'curl -ks -u {API_USER}:"{API_PASS}" '
            "https://localhost:55000/security/user/authenticate",
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Auth failed: {result.stderr}"
        )
        token_data = json.loads(result.stdout)
        token = token_data.get("data", {}).get("token", "")
        assert token, "Failed to get auth token"

        result = docker_exec(
            "aptl-wazuh-manager",
            f'curl -ks -H "Authorization: Bearer {token}" '
            "https://localhost:55000/agents?limit=50",
            timeout=30,
        )
        assert result.returncode == 0
        agents_data = json.loads(result.stdout)
        agents = agents_data.get(
            "data", {},
        ).get("affected_items", [])
        assert len(agents) >= 1, (
            f"Expected agents, got: "
            f"{[a.get('name', '') for a in agents]}"
        )


# -------------------------------------------------------------------
# Section 3: Attack -> Detection
# -------------------------------------------------------------------


@LIVE_LAB
class TestAttackDetection:
    """Attacks from Kali generate expected Wazuh alerts."""

    def test_webapp_reachable_from_kali(self):
        result = kali_exec(
            "curl -sf http://172.20.1.20:8080/", timeout=30,
        )
        assert result.returncode == 0, (
            f"Webapp unreachable: {result.stderr}"
        )
        out = result.stdout.lower()
        assert "<html" in out or "techvault" in out

    def test_sqli_generates_alert(self):
        """SQL injection from Kali triggers rule 302010."""
        kali_exec(
            "curl -sf 'http://172.20.1.20:8080/login"
            "?username=admin%27%20UNION%20SELECT%201,2,3--"
            "&password=x'",
            timeout=30,
        )

        hit = wait_for_alert(
            {
                "bool": {
                    "must": [
                        {"match": {"rule.id": "302010"}},
                        {"range": {
                            "timestamp": {"gte": "now-5m"},
                        }},
                    ]
                }
            },
            timeout=240,
        )
        assert hit.get("rule", {}).get("id") == "302010"

    def test_xss_generates_alert(self):
        """XSS from Kali triggers rule 302020."""
        kali_exec(
            "curl -sf 'http://172.20.1.20:8080/search"
            "?q=%3Cscript%3Ealert(1)%3C/script%3E'",
            timeout=30,
        )

        hit = wait_for_alert(
            {
                "bool": {
                    "must": [
                        {"match": {"rule.id": "302020"}},
                        {"range": {
                            "timestamp": {"gte": "now-5m"},
                        }},
                    ]
                }
            },
            timeout=240,
        )
        assert hit.get("rule", {}).get("id") == "302020"

    def test_cmdinj_generates_alert(self):
        """Command injection from Kali triggers rule 302030."""
        kali_exec(
            "curl -sf 'http://172.20.1.20:8080/tools/ping"
            "?host=127.0.0.1%3Bls'",
            timeout=30,
        )

        hit = wait_for_alert(
            {
                "bool": {
                    "must": [
                        {"match": {"rule.id": "302030"}},
                        {"range": {
                            "timestamp": {"gte": "now-5m"},
                        }},
                    ]
                }
            },
            timeout=240,
        )
        assert hit.get("rule", {}).get("id") == "302030"

    def test_ad_reachable_from_kali(self):
        """Kali can reach AD domain controller via LDAP."""
        result = kali_exec(
            "nmap -p 389 -Pn --open 172.20.2.10 -oG -",
            timeout=30,
        )
        assert result.returncode == 0, (
            f"nmap failed: {result.stderr}"
        )
        assert "389/open" in result.stdout, (
            f"LDAP port not open on AD: {result.stdout}"
        )


# -------------------------------------------------------------------
# Section 4: SOC tools (require seeded data)
# -------------------------------------------------------------------


def _require_misp_key():
    if not MISP_API_KEY:
        pytest.fail(
            "MISP_API_KEY not set -- retrieve from MISP UI"
        )


def _require_thehive_key():
    if not THEHIVE_API_KEY:
        pytest.fail(
            "THEHIVE_API_KEY not set -- retrieve from "
            "TheHive UI"
        )


def _shuffle_action_result(execution: dict, label: str) -> dict:
    """Return one action's nested app result from a Shuffle execution."""
    for item in execution.get("results", []):
        action = item.get("action", {})
        if action.get("label") != label:
            continue
        result = item.get("result", {})
        return json.loads(result) if isinstance(result, str) else result
    return {}


@LIVE_LAB
class TestSOCTools:
    """SOC tool integration -- require seed scripts."""

    def test_misp_has_seeded_data(self):
        """MISP contains seeded Kali DMZ IP IOC."""
        _require_misp_key()
        data = curl_json(
            f"{MISP_URL}/attributes/restSearch",
            auth_header=MISP_API_KEY,
            method="POST",
            body={
                "value": KALI_DMZ_IP,
                "type": "ip-src",
            },
            ca_cert_path=LAB_CA_PATH,
        )
        attrs = data.get("response", {}).get("Attribute", [])
        assert len(attrs) > 0, (
            f"Kali IP {KALI_DMZ_IP} not found in MISP -- "
            "run ./scripts/seed-misp.sh"
        )

    def test_misp_correlate_attacker_ip(self):
        """MISP search for Kali IP returns correlation."""
        _require_misp_key()
        data = curl_json(
            f"{MISP_URL}/attributes/restSearch",
            auth_header=MISP_API_KEY,
            method="POST",
            body={
                "value": KALI_DMZ_IP,
                "type": "ip-src",
                "includeCorrelations": True,
            },
            ca_cert_path=LAB_CA_PATH,
        )
        attrs = data.get("response", {}).get("Attribute", [])
        assert len(attrs) > 0, (
            "MISP correlation search returned no results"
        )
        assert attrs[0].get("Event") or attrs[0].get("event_id")

    def test_thehive_case_lifecycle(self):
        """Create case, add observable, verify it exists."""
        _require_thehive_key()

        ts = int(time.time())
        case_title = f"APTL Integration Test Case {ts}"

        case = curl_json(
            f"{THEHIVE_URL}/api/v1/case",
            auth_header=f"Bearer {THEHIVE_API_KEY}",
            method="POST",
            body={
                "title": case_title,
                "description": "Automated integration test",
                "severity": 2,
            },
        )
        case_id = case.get("_id")
        assert case_id, f"Case creation failed: {case}"

        obs = curl_json(
            f"{THEHIVE_URL}/api/v1/case/{case_id}/observable",
            auth_header=f"Bearer {THEHIVE_API_KEY}",
            method="POST",
            body={
                "dataType": "ip",
                "data": KALI_DMZ_IP,
                "message": "Kali red team IP",
                "tlp": 3,
                "ioc": True,
            },
        )
        if isinstance(obs, list):
            obs = obs[0] if obs else {}
        assert obs.get("_id") or obs.get("data"), (
            f"Observable creation failed: {obs}"
        )

        fetched = curl_json(
            f"{THEHIVE_URL}/api/v1/case/{case_id}",
            auth_header=f"Bearer {THEHIVE_API_KEY}",
        )
        assert fetched.get("title") == case_title

    def test_shuffle_has_workflow(self):
        """Shuffle contains seeded alert-to-case workflow."""
        data = curl_json(
            f"{SHUFFLE_URL}/api/v1/workflows",
            auth_header=f"Bearer {SHUFFLE_API_KEY}",
        )
        workflows = (
            data if isinstance(data, list)
            else data.get("data", [])
        )
        names = [w.get("name", "") for w in workflows]
        assert any("APTL" in n for n in names), (
            "Seeded workflow not found -- "
            "run ./scripts/seed-shuffle.sh. "
            f"Found: {names}"
        )

    def test_shuffle_execute_workflow(self):
        """Trigger workflow and verify execution completes."""
        _require_thehive_key()

        data = curl_json(
            f"{SHUFFLE_URL}/api/v1/workflows",
            auth_header=f"Bearer {SHUFFLE_API_KEY}",
        )
        workflows = (
            data if isinstance(data, list)
            else data.get("data", [])
        )
        aptl_wf = next(
            (w for w in workflows if "APTL" in w.get("name", "")),
            None,
        )
        assert aptl_wf, "Seeded APTL workflow not found"
        wf_id = aptl_wf["id"]

        exec_result = curl_json(
            f"{SHUFFLE_URL}/api/v1/workflows/{wf_id}/execute",
            auth_header=f"Bearer {SHUFFLE_API_KEY}",
            method="POST",
            body={
                "execution_argument": json.dumps({
                    "rule": {
                        "id": "302010",
                        "description": "APTL integration test alert",
                        "level": 10,
                    },
                    "data": {"srcip": KALI_DMZ_IP},
                    "agent": {"name": "aptl-integration-test"},
                    "timestamp": str(int(time.time())),
                }),
            },
        )
        exec_id = (
            exec_result.get("execution_id")
            or exec_result.get("id")
        )
        assert exec_id, (
            f"Workflow execution failed: {exec_result}"
        )

        deadline = time.monotonic() + 180
        final_status = "EXECUTING"
        while time.monotonic() < deadline:
            time.sleep(5)
            try:
                status_data = curl_json(
                    f"{SHUFFLE_URL}/api/v1/streams/results",
                    auth_header=f"Bearer {SHUFFLE_API_KEY}",
                    method="POST",
                    body={"execution_id": exec_id},
                )
                final_status = status_data.get(
                    "status", "EXECUTING",
                )
                if final_status in (
                    "FINISHED", "ABORTED", "FAILURE",
                ):
                    break
            except (AssertionError, json.JSONDecodeError):
                pass

        assert final_status == "FINISHED", (
            "Workflow execution must complete: "
            f"status={final_status}"
        )
        case_result = _shuffle_action_result(
            status_data, "create_thehive_case"
        )
        assert case_result.get("success") is True, (
            "Shuffle finished but TheHive case creation failed: "
            f"{case_result.get('reason', 'missing action result')}"
        )


# -------------------------------------------------------------------
# Section 5: Full loop — attack to SOC pipeline
# -------------------------------------------------------------------


@LIVE_LAB
class TestFullLoop:
    """Kali -> Webapp -> Wazuh -> MISP -> Shuffle -> TheHive."""

    def test_attack_to_soc_pipeline(self):
        """Full SOC pipeline: SQLi -> alert -> MISP -> case."""
        _require_misp_key()
        _require_thehive_key()

        # Capture the test start time so step 7 can filter TheHive
        # cases to those created during THIS run, not pre-existing
        # ones from earlier test invocations (test-quality review
        # cycle 1 finding-5: previously a pre-existing case would
        # satisfy `len(case_list) > 0` even when the workflow
        # ABORTed).
        from datetime import datetime, timezone
        test_started_at_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

        # 1. SQLi from Kali to webapp
        kali_exec(
            "curl -sf 'http://172.20.1.20:8080/login"
            "?username=admin%27%20UNION%20SELECT%20*"
            "%20FROM%20users--&password=x'",
            timeout=30,
        )

        # 2. Wait for Wazuh alert
        alert = wait_for_alert(
            {
                "bool": {
                    "must": [
                        {"match": {"rule.id": "302010"}},
                        {"range": {
                            "timestamp": {"gte": "now-5m"},
                        }},
                    ]
                }
            },
            timeout=240,
        )
        assert alert.get("rule", {}).get("id") == "302010"

        # 3. Extract attacker IP from alert
        src_ip = (
            alert.get("data", {}).get("srcip")
            or alert.get("srcip")
            or KALI_DMZ_IP
        )

        # 4. Look up attacker IP in MISP
        misp_data = curl_json(
            f"{MISP_URL}/attributes/restSearch",
            auth_header=MISP_API_KEY,
            method="POST",
            body={"value": src_ip, "type": "ip-src"},
            ca_cert_path=LAB_CA_PATH,
        )
        misp_attrs = misp_data.get(
            "response", {},
        ).get("Attribute", [])
        assert len(misp_attrs) > 0, (
            f"Attacker IP {src_ip} not in MISP threat intel"
        )

        # 5. Trigger Shuffle workflow
        wf_data = curl_json(
            f"{SHUFFLE_URL}/api/v1/workflows",
            auth_header=f"Bearer {SHUFFLE_API_KEY}",
        )
        workflows = (
            wf_data if isinstance(wf_data, list)
            else wf_data.get("data", [])
        )
        aptl_wf = next(
            (w for w in workflows if "APTL" in w.get("name", "")),
            None,
        )
        assert aptl_wf, "APTL workflow not found in Shuffle"

        ts = int(time.time())
        exec_result = curl_json(
            f"{SHUFFLE_URL}/api/v1/workflows/"
            f"{aptl_wf['id']}/execute",
            auth_header=f"Bearer {SHUFFLE_API_KEY}",
            method="POST",
            body={
                "execution_argument": json.dumps({
                    "rule": {
                        "id": "302010",
                        "description": "SQL injection attempt detected",
                        "level": 10,
                    },
                    "data": {"srcip": src_ip},
                    "agent": {"name": "aptl-integration-test"},
                    "timestamp": str(ts),
                }),
            },
        )
        exec_id = (
            exec_result.get("execution_id")
            or exec_result.get("id")
        )
        assert exec_id, (
            f"Workflow execution failed: {exec_result}"
        )

        # 6. Poll Shuffle for completion
        deadline = time.monotonic() + 120
        status_data: dict = {}
        while time.monotonic() < deadline:
            time.sleep(5)
            try:
                status_data = curl_json(
                    f"{SHUFFLE_URL}/api/v1/streams/results",
                    auth_header=f"Bearer {SHUFFLE_API_KEY}",
                    method="POST",
                    body={"execution_id": exec_id},
                )
                if status_data.get("status") in (
                    "FINISHED", "ABORTED", "FAILURE",
                ):
                    break
            except (AssertionError, json.JSONDecodeError):
                pass
        # Workflow MUST complete successfully — without this
        # assertion an ABORTED/FAILED workflow could still satisfy
        # step 7 if pre-existing TheHive cases were around
        # (test-quality review cycle 1 finding-5).
        assert status_data.get("status") == "FINISHED", (
            f"Shuffle workflow must reach FINISHED before TheHive check; "
            f"got: {status_data.get('status')!r}"
        )

        # 7. Verify TheHive has a case CREATED BY THIS RUN. Filter
        # by createdAt > test_started_at_ms so stale cases from
        # prior runs cannot satisfy the assertion (cycle 1 finding-5).
        cases = curl_json(
            f"{THEHIVE_URL}/api/v1/query",
            auth_header=f"Bearer {THEHIVE_API_KEY}",
            method="POST",
            body={
                "query": [
                    {"_name": "listCase"},
                    {"_name": "sort", "_fields": [
                        {"_createdAt": "desc"},
                    ]},
                    {"_name": "page", "from": 0, "to": 20},
                ],
            },
        )
        case_list = (
            cases if isinstance(cases, list)
            else cases.get("data", [])
        )
        fresh_cases = [
            c for c in case_list
            if isinstance(c, dict)
            and c.get("_createdAt", 0) >= test_started_at_ms
        ]
        assert len(fresh_cases) > 0, (
            f"No TheHive cases created during this run "
            f"(since {test_started_at_ms}); total recent={len(case_list)}"
        )

    def test_wazuh_webhook_triggers_shuffle(self):
        """Wazuh level-10 alert auto-triggers Shuffle via webhook.

        This proves the automatic path: attack -> Wazuh alert ->
        integration script -> Shuffle webhook -> workflow execution.
        No manual API trigger — the webhook must fire on its own.
        """
        _require_thehive_key()

        # 1. Get current execution count
        wf_data = curl_json(
            f"{SHUFFLE_URL}/api/v1/workflows",
            auth_header=f"Bearer {SHUFFLE_API_KEY}",
        )
        workflows = (
            wf_data if isinstance(wf_data, list)
            else wf_data.get("data", [])
        )
        aptl_wf = next(
            (w for w in workflows if "APTL" in w.get("name", "")),
            None,
        )
        assert aptl_wf, "APTL workflow not found"
        wf_id = aptl_wf["id"]

        exec_data = curl_json(
            f"{SHUFFLE_URL}/api/v1/workflows/{wf_id}/executions",
            auth_header=f"Bearer {SHUFFLE_API_KEY}",
        )
        before = exec_data if isinstance(exec_data, list) else exec_data.get("data", [])
        before_count = len(before)

        # 2. Fire a SQLi attack (triggers rule 302010, level 10)
        ts = int(time.time())
        kali_exec(
            f"curl -sf 'http://172.20.1.20:8080/login"
            f"?username=webhook_test_{ts}%27%20UNION%20SELECT%201--"
            f"&password=x'",
            timeout=30,
        )

        # 3. Wait for new webhook-triggered execution (up to 240s)
        deadline = time.monotonic() + 240
        new_exec = None
        while time.monotonic() < deadline:
            time.sleep(10)
            exec_data = curl_json(
                f"{SHUFFLE_URL}/api/v1/workflows/{wf_id}/executions",
                auth_header=f"Bearer {SHUFFLE_API_KEY}",
            )
            after = exec_data if isinstance(exec_data, list) else exec_data.get("data", [])
            if len(after) > before_count:
                # Find the newest webhook-triggered execution
                for e in after:
                    if e.get("execution_source") == "webhook":
                        started = e.get("started_at", 0)
                        if isinstance(started, (int, float)) and started >= ts:
                            new_exec = e
                            break
                if new_exec:
                    break

        assert new_exec is not None, (
            f"No webhook-triggered execution within 240s "
            f"(before={before_count}, after={len(after)})"
        )
        assert new_exec["execution_source"] == "webhook", (
            f"Execution source is '{new_exec['execution_source']}', "
            "expected 'webhook'"
        )


# -------------------------------------------------------------------
# Section 6: Scenario harness — live detection with CLI
# -------------------------------------------------------------------


@LIVE_LAB
class TestScenarioHarness:
    """Exercise the scenario system against live infrastructure."""

    def test_scenario_list_discovers_all(self):
        result = run_cmd(
            ["aptl", "scenario", "list"], timeout=60,
        )
        assert result.returncode == 0, (
            f"scenario list failed: {result.stderr}"
        )
        for name in [
            "recon-nmap-scan",
            "detect-brute-force",
            "webapp-compromise",
            "ad-domain-compromise",
            "lateral-movement-data-theft",
            "prime-enterprise",
        ]:
            assert name in result.stdout, (
                f"Scenario '{name}' not in list output"
            )

    def test_scenario_lifecycle_with_live_detection(
        self, tmp_path,
    ):
        """Full lifecycle: start -> attack -> stop -> run assembled."""
        project_dir = str(tmp_path)
        scenarios_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "scenarios",
        )

        def _aptl(*args):
            return run_cmd(
                [
                    "aptl", "scenario", *args,
                    "--project-dir", project_dir,
                    "--scenarios-dir", scenarios_dir,
                ],
                timeout=60,
            )

        # 1. Start the scenario
        result = _aptl("start", "detect-brute-force")
        assert result.returncode == 0, (
            f"start failed: {result.stderr}"
        )
        assert "Started scenario" in result.stdout

        from pathlib import Path
        session_path = (
            Path(project_dir) / ".aptl" / "session.json"
        )
        assert session_path.exists(), (
            "session.json not created"
        )
        session = json.loads(session_path.read_text())
        assert session["state"] == "active"

        # 2. Generate failed SSH attempts from Kali
        for _ in range(7):
            docker_exec(
                "aptl-kali",
                "sshpass -p wrongpassword ssh "
                "-o StrictHostKeyChecking=no "
                "-o ConnectTimeout=3 "
                "labadmin@172.20.2.20 echo fail "
                "2>/dev/null || true",
                timeout=20,
            )
            time.sleep(1)

        # 3. Wait for the brute-force detection to fire. Test-quality
        # review cycle 1 T-005: previously the test slept 60s then
        # moved straight to stop/cleanup with no assertion that the
        # 'live detection' the test name advertises actually fired.
        # A broken Wazuh rule / decoder / log-forwarding gap would
        # leave the scenario lifecycle green here while detection was
        # silently dead. Pin the contract by querying for rule 5763
        # (SSH brute force) — the same rule the active-response test
        # asserts is wired into ossec.conf.
        hit = wait_for_alert(
            {
                "bool": {
                    "must": [
                        {"match": {"rule.id": "5763"}},
                        {"range": {
                            "timestamp": {"gte": "now-3m"},
                        }},
                    ]
                }
            },
            timeout=180,
        )
        assert hit.get("rule", {}).get("id") == "5763", (
            f"Expected SSH brute-force alert (rule 5763), got: {hit.get('rule')}"
        )

        # 4. Stop and verify run was assembled
        result = _aptl("stop")
        assert result.returncode == 0, (
            f"stop failed: {result.stderr}"
        )
        assert "Scenario stopped" in result.stdout

        # Session file is removed after stop (clear())
        assert not session_path.exists(), (
            "session.json should be removed after stop"
        )


# -------------------------------------------------------------------
# Section 7: MCP protocol — JSON-RPC tools/list
# -------------------------------------------------------------------

# Maps .mcp.json server name -> one expected tool name.
# For published MCPs we verify at least one tool is advertised.
MCP_SERVERS = {
    # Custom Node.js servers (known tool names)
    "kali-ssh": "kali_info",
    "reverse-sandbox-ssh": "reverse_info",
    "shuffle": "soar_list_workflows",
    "indexer": "indexer_query",
    # Published servers (verify they start and list tools)
    "wazuh": None,
    "misp": None,
    "thehive": None,
}


def _server_available(name: str) -> bool:
    """Check if an MCP server's binary/build exists."""
    try:
        cmd, _ = mcp_server_cmd(name)
        return os.path.isfile(cmd[0])
    except (ValueError, IndexError):
        return False


@LIVE_LAB
class TestMCPProtocol:
    """MCP servers respond to JSON-RPC with expected tools."""

    @pytest.mark.parametrize(
        "server,expected_tool",
        list(MCP_SERVERS.items()),
        ids=list(MCP_SERVERS.keys()),
    )
    def test_mcp_server_responds(self, server, expected_tool):
        if not _server_available(server):
            pytest.skip(
                f"{server} binary/build not found"
            )

        tools = mcp_tools_list(server)
        assert len(tools) > 0, (
            f"{server} returned no tools"
        )

        if expected_tool is not None:
            assert expected_tool in tools, (
                f"Expected '{expected_tool}' not in "
                f"{server} tools: {tools}"
            )


# -------------------------------------------------------------------
# Section 8: MCP tool calls — real invocations against live lab
# -------------------------------------------------------------------


@LIVE_LAB
class TestMCPToolCalls:
    """MCP tools return real data from the live lab."""

    # -- Red Team (Kali) --

    def test_kali_info(self):
        """kali_info returns Kali system information."""
        result = mcp_call_tool(
            "kali-ssh", "kali_info", {},
        )
        text = mcp_tool_text(result)
        assert "kali" in text.lower(), (
            f"Expected Kali info, got: {text[:200]}"
        )

    def test_kali_run_command(self):
        """kali_run_command executes a real command."""
        result = mcp_call_tool(
            "kali-ssh", "kali_run_command",
            {"command": "whoami"},
            timeout=120,
        )
        text = mcp_tool_text(result)
        assert "kali" in text, (
            f"Expected 'kali' from whoami, got: {text}"
        )

    # -- Indexer (raw ES DSL) --

    def test_indexer_query(self):
        """indexer_query returns alert data from ES."""
        result = mcp_call_tool(
            "indexer", "indexer_query",
            {"body": {
                "query": {"match_all": {}},
                "size": 1,
            }},
        )
        text = mcp_tool_text(result)
        data = json.loads(text)
        # aptl-mcp-common wraps response: actual ES
        # result is in data["data"]
        es_data = data.get("data", data)
        hits = es_data.get("hits", {}).get("hits", [])
        assert len(hits) > 0, (
            "Expected at least one indexed document"
        )

    # -- SOAR (Shuffle) --

    def test_soar_list_workflows(self):
        """soar_list_workflows returns the APTL workflow."""
        result = mcp_call_tool(
            "shuffle", "soar_list_workflows", {},
        )
        text = mcp_tool_text(result)
        data = json.loads(text)
        # aptl-mcp-common wraps response: workflows
        # are in data["data"] if wrapped
        workflows = (
            data.get("data", data)
            if isinstance(data, dict) else data
        )
        assert isinstance(workflows, list), (
            f"Expected workflow list, got: {type(data)}"
        )
        names = [wf.get("name", "") for wf in workflows]
        assert any("APTL" in n for n in names), (
            f"Expected APTL workflow, found: {names}"
        )


# -------------------------------------------------------------------
# Section 9: Attack path validation (prime scenario)
# -------------------------------------------------------------------


@LIVE_LAB
class TestAttackPaths:
    """Validate all three prime scenario attack paths are functional."""

    # -- Path A: Webapp -> DB --

    def test_webapp_reachable_from_kali_dmz(self):
        result = kali_exec(
            f"curl -sf http://{WEBAPP_IP_DMZ}:8080/",
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Webapp unreachable: {result.stderr}"
        )

    def test_db_reachable_from_kali(self):
        result = kali_exec(
            f"nmap -p 5432 -Pn --open {DB_IP} -oG -",
            timeout=30,
        )
        assert "5432/open" in result.stdout, (
            f"DB port not open: {result.stdout}"
        )

    # -- Path B: AD enumeration --

    def test_ad_ldap_reachable_from_kali(self):
        result = kali_exec(
            f"nmap -p 389 -Pn --open {AD_IP} -oG -",
            timeout=30,
        )
        assert "389/open" in result.stdout, (
            f"LDAP not open on AD: {result.stdout}"
        )

    # -- Path C: Fileshare -> lateral movement --

    def test_fileshare_reachable_from_kali(self):
        result = kali_exec(
            f"nmap -p 445 -Pn --open {FILESHARE_IP} -oG -",
            timeout=30,
        )
        assert "445/open" in result.stdout, (
            f"SMB not open on fileshare: {result.stdout}"
        )

    def test_workstation_reachable_from_kali(self):
        result = kali_exec(
            f"nmap -p 22 -Pn --open {WS_IP} -oG -",
            timeout=30,
        )
        assert "22/open" in result.stdout, (
            f"SSH not open on workstation: {result.stdout}"
        )

    def test_victim_reachable_from_workstation(self):
        """Lateral movement path: workstation -> victim via SSH."""
        result = workstation_exec(
            f"ssh -o StrictHostKeyChecking=no -o BatchMode=yes "
            f"-o ConnectTimeout=5 -i /home/dev-user/.ssh/id_rsa "
            f"labadmin@{VICTIM_IP} echo OK",
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Lateral movement path broken: {result.stderr}"
        )
        assert "OK" in result.stdout

    def test_workstation_pgpass_connects_to_db(self):
        """Credential path: workstation .pgpass -> DB access."""
        result = workstation_exec(
            f"PGPASSFILE=/home/dev-user/.pgpass "
            f"psql -h {DB_IP} -U techvault -d techvault "
            f"-c 'SELECT count(*) FROM customers' -t -A",
            timeout=30,
        )
        assert result.returncode == 0, (
            f"DB connection via .pgpass failed: {result.stderr}"
        )
        count = result.stdout.strip()
        assert int(count) > 0, "No customer records found"


# -------------------------------------------------------------------
# Section 10: Defensive stack configuration
# -------------------------------------------------------------------


# Wazuh custom rule files that MUST be loaded for the prime scenario.
# `kali_redteam_rules.xml` was removed under ADR-033 (OBS-003 non-
# contamination): red-team activity must not bleed into the blue
# defensive stack's awareness via the SIEM. See ADR-027 amendment.
REQUIRED_WAZUH_RULES = [
    "webapp_rules.xml",
    "ad_rules.xml",
    "database_rules.xml",
    "suricata_rules.xml",
    "falco_rules.xml",
]

# Key Wazuh rule IDs that map to prime scenario attack steps
REQUIRED_RULE_IDS = {
    "302010": "SQL injection detection",
    "302020": "XSS detection",
    "302030": "Command injection / RCE detection",
    "302040": "Information disclosure detection",
    "301010": "TGS request (Kerberoasting)",
    "301020": "LDAP search event",
    "301021": "LDAP enumeration detection",
    "304010": "Database connection from red team IP",
    "304030": "Large data export (exfiltration)",
}

# Key Suricata SIDs that cover prime scenario attack types
REQUIRED_SURICATA_SIDS = [
    "1000001",   # nmap SYN scan
    "1000010",   # SQLi in HTTP
    "1000030",   # command injection in HTTP
    "1000040",   # Kerberoasting TGS request
    "1000050",   # SMB brute force
    "1000060",   # DNS tunneling (exfil)
    "1000070",   # lateral movement SSH DMZ->internal
    "1000080",   # LDAP enumeration
]


@LIVE_LAB
class TestDefensiveStack:
    """Defensive detection stack is correctly configured for prime scenario."""

    @pytest.mark.parametrize("rule_file", REQUIRED_WAZUH_RULES)
    def test_wazuh_rule_file_mounted(self, rule_file):
        """Custom Wazuh rule file is present in the manager."""
        result = docker_exec(
            "aptl-wazuh-manager",
            f"test -f /var/ossec/etc/rules/{rule_file} && echo OK",
        )
        assert "OK" in result.stdout, (
            f"Rule file not mounted: {rule_file}"
        )

    def test_wazuh_rules_included_in_config(self):
        """ossec.conf references all custom rule files."""
        result = docker_exec(
            "aptl-wazuh-manager",
            "cat /var/ossec/etc/ossec.conf",
        )
        for rule_file in REQUIRED_WAZUH_RULES:
            assert rule_file in result.stdout, (
                f"Rule file {rule_file} not included in ossec.conf"
            )

    def test_wazuh_no_rule_parse_errors(self):
        """Manager loaded rules without parse errors."""
        result = docker_exec(
            "aptl-wazuh-manager",
            "grep -i 'error.*rule' "
            "/var/ossec/logs/ossec.log 2>/dev/null || echo CLEAN",
        )
        lines = [
            line for line in result.stdout.strip().splitlines()
            if "error" in line.lower()
            and "rule" in line.lower()
            and "no such file" not in line.lower()
            and "sca:" not in line.lower()
        ]
        assert len(lines) == 0, (
            f"Rule loading errors found:\n"
            + "\n".join(lines[:5])
        )

    @pytest.mark.parametrize(
        "rule_id,desc",
        list(REQUIRED_RULE_IDS.items()),
        ids=list(REQUIRED_RULE_IDS.keys()),
    )
    def test_wazuh_rule_id_defined(self, rule_id, desc):
        """Key detection rule ID exists in mounted rule files."""
        result = docker_exec(
            "aptl-wazuh-manager",
            f'grep -r \'id="{rule_id}"\' /var/ossec/etc/rules/',
        )
        assert result.returncode == 0, (
            f"Rule {rule_id} ({desc}) not found in any rule file"
        )

    def test_suricata_local_rules_loaded(self):
        """Suricata has custom local.rules file."""
        result = docker_exec(
            "aptl-suricata",
            "test -f /etc/suricata/rules/local.rules && echo OK",
        )
        assert "OK" in result.stdout, (
            "local.rules not found in Suricata container"
        )

    @pytest.mark.parametrize("sid", REQUIRED_SURICATA_SIDS)
    def test_suricata_sid_present(self, sid):
        """Key Suricata SID is defined in local.rules."""
        result = docker_exec(
            "aptl-suricata",
            f"grep -c 'sid:{sid}' /etc/suricata/rules/local.rules",
        )
        assert (
            result.returncode == 0
            and result.stdout.strip() != "0"
        ), f"SID {sid} not found in Suricata local.rules"

    def test_suricata_eve_log_exists(self):
        """Suricata is generating eve.json events."""
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            result = docker_exec(
                "aptl-suricata",
                "test -f /var/log/suricata/eve.json && echo OK",
            )
            if "OK" in result.stdout:
                return
            time.sleep(10)
        pytest.fail("eve.json not being generated within 120s")

    def test_ad_lockout_configured(self):
        """AD account lockout threshold is set to 10."""
        result = docker_exec(
            "aptl-ad",
            "samba-tool domain passwordsettings show",
        )
        assert result.returncode == 0, (
            f"passwordsettings show failed: {result.stderr}"
        )
        assert "Account lockout threshold (attempts): 10" in result.stdout, (
            f"Lockout threshold not 10:\n{result.stdout}"
        )

    def test_wazuh_active_response_configured(self):
        """Wazuh active response is enabled (not commented out)."""
        result = docker_exec(
            "aptl-wazuh-manager",
            "grep -c '<active-response>' /var/ossec/etc/ossec.conf",
        )
        assert result.returncode == 0, (
            "No <active-response> found in ossec.conf"
        )
        count = int(result.stdout.strip())
        assert count >= 1, (
            "active-response block not found in ossec.conf"
        )

    def test_wazuh_active_response_ssh_brute_force(self):
        """Active response references SSH brute force rule 5763."""
        result = docker_exec(
            "aptl-wazuh-manager",
            "grep '5763' /var/ossec/etc/ossec.conf",
        )
        assert result.returncode == 0, (
            "Rule 5763 (SSH brute force) not in active-response config"
        )
        assert "5763" in result.stdout

    def test_wazuh_shuffle_integration_configured(self):
        """ossec.conf has custom-shuffle integration for level 10+."""
        result = docker_exec(
            "aptl-wazuh-manager",
            "grep -A5 'custom-shuffle' /var/ossec/etc/ossec.conf",
        )
        assert result.returncode == 0, (
            "custom-shuffle integration not found in ossec.conf"
        )
        assert "custom-shuffle" in result.stdout
        assert "<level>10</level>" in result.stdout, (
            "Integration level threshold not set to 10"
        )

    def test_shuffle_integration_script_exists(self):
        """custom-shuffle script exists and is executable in manager."""
        result = docker_exec(
            "aptl-wazuh-manager",
            "test -x /var/ossec/integrations/custom-shuffle && echo OK",
        )
        assert "OK" in result.stdout, (
            "custom-shuffle not found or not executable in "
            "/var/ossec/integrations/"
        )

    def test_shuffle_workflow_has_misp_enrichment(self):
        """Shuffle APTL workflow contains MISP lookup and case creation."""
        data = curl_json(
            f"{SHUFFLE_URL}/api/v1/workflows",
            auth_header=f"Bearer {SHUFFLE_API_KEY}",
        )
        workflows = (
            data if isinstance(data, list)
            else data.get("data", [])
        )
        aptl_wf = next(
            (w for w in workflows if "APTL" in w.get("name", "")),
            None,
        )
        assert aptl_wf, (
            "APTL workflow not found -- run ./scripts/seed-shuffle.sh"
        )

        actions = aptl_wf.get("actions", [])
        labels = [a.get("label", "") for a in actions]
        assert "misp_ip_lookup" in labels, (
            f"misp_ip_lookup action not found in workflow. "
            f"Labels: {labels}"
        )
        assert "create_thehive_case" in labels, (
            f"create_thehive_case action not found in workflow. "
            f"Labels: {labels}"
        )

    def test_wazuh_decoders_for_enterprise(self):
        """Custom decoders are mounted for enterprise log sources.

        ``kali_decoders.xml`` was removed under ADR-033 (OBS-003 non-
        contamination): red activity must not be ingested by the
        defensive stack.
        """
        result = docker_exec(
            "aptl-wazuh-manager",
            "ls /var/ossec/etc/decoders/",
        )
        for decoder in ["postgresql_decoders.xml",
                        "samba_decoders.xml"]:
            assert decoder in result.stdout, (
                f"Decoder {decoder} not mounted"
            )


# -------------------------------------------------------------------
# Section 11: CTF flags and signed tokens
# -------------------------------------------------------------------


@LIVE_LAB
class TestCTFFlags:
    """CTF flags are generated on every container start."""

    def test_victim_user_flag(self):
        result = docker_exec(
            "aptl-victim",
            ["su", "-s", "/bin/bash", "-c",
             "cat /home/labadmin/user.txt", "labadmin"],
        )
        assert result.returncode == 0, (
            f"Cannot read victim user flag: {result.stderr}"
        )
        assert "APTL{user_victim_" in result.stdout

    def test_victim_root_flag(self):
        result = docker_exec(
            "aptl-victim", "cat /root/root.txt",
        )
        assert result.returncode == 0, (
            f"Cannot read victim root flag: {result.stderr}"
        )
        assert "APTL{root_victim_" in result.stdout

    def test_workstation_user_flag(self):
        result = docker_exec(
            "aptl-workstation",
            "cat /home/dev-user/user.txt",
        )
        assert result.returncode == 0, (
            f"Cannot read workstation user flag: "
            f"{result.stderr}"
        )
        assert "APTL{user_workstation_" in result.stdout

    def test_webapp_user_flag(self):
        result = docker_exec(
            "aptl-webapp", "cat /app/user.txt",
        )
        assert result.returncode == 0, (
            f"Cannot read webapp user flag: {result.stderr}"
        )
        assert "APTL{user_webapp_" in result.stdout

    def test_ad_user_flag(self):
        result = docker_exec(
            "aptl-ad", "cat /opt/flags/user.txt",
        )
        assert result.returncode == 0, (
            f"Cannot read AD user flag: {result.stderr}"
        )
        assert "APTL{user_ad_" in result.stdout

    def test_fileshare_user_flag(self):
        result = docker_exec(
            "aptl-fileshare",
            "cat /srv/shares/shared/user-flag.txt",
        )
        assert result.returncode == 0, (
            f"Cannot read fileshare user flag: "
            f"{result.stderr}"
        )
        assert "APTL{user_fileshare_" in result.stdout

    def test_flags_contain_signed_tokens(self):
        """Flag files include aptl:v1: signed tokens."""
        checks = [
            ("aptl-victim",
             ["cat", "/home/labadmin/user.txt"]),
            ("aptl-workstation",
             ["cat", "/home/dev-user/user.txt"]),
            ("aptl-webapp",
             ["cat", "/app/user.txt"]),
            ("aptl-ad",
             ["cat", "/opt/flags/user.txt"]),
            ("aptl-fileshare",
             ["cat", "/srv/shares/shared/user-flag.txt"]),
        ]
        for container, cmd in checks:
            result = docker_exec(container, cmd)
            assert "aptl:v1:" in result.stdout, (
                f"No signed token in {container} user flag"
            )

    def test_root_flags_not_world_readable(self):
        """Root flag files have 600 permissions."""
        containers = [
            "aptl-victim",
            "aptl-workstation",
            "aptl-webapp",
            "aptl-ad",
            "aptl-fileshare",
        ]
        for container in containers:
            result = docker_exec(
                container,
                ["stat", "-c", "%a", "/root/root.txt"],
            )
            assert result.returncode == 0, (
                f"stat failed on {container}: {result.stderr}"
            )
            perms = result.stdout.strip()
            assert perms == "600", (
                f"{container} root.txt has perms {perms}, "
                f"expected 600"
            )


# -------------------------------------------------------------------
# Section 12: MCP harvest race window (#304)
# -------------------------------------------------------------------


@LIVE_LAB
class TestMCPSessionHarvest:
    """Per-session harvest is complete and not truncated.

    #304 acceptance: after `PersistentSession.close()` awaits the remote
    SSH channel close, the kali-side `script(1)` typescript that the
    wrapper's EXIT trap flushes must be fully present in the host-side
    harvest. We mark the end of the session with a known terminator and
    assert it appears intact in the harvested typescript.

    The whole flow runs through ONE MCP-server process so the harvest is
    invoked by the real `close_session` handler — `mcp_call_tool` spawns
    per call and would tear the server down between create and close.
    """

    def test_typescript_ends_with_terminator(self, tmp_path):
        import json as _json
        import secrets

        # Unique per-run id satisfying SESSION_ID_SCHEMA
        # ('^[A-Za-z0-9_][A-Za-z0-9._-]*$'). The previous fixed id used `#`,
        # which the schema rejects — the wrapper would reroute to anon-* and
        # the test would assert against the wrong path. Unique-per-run also
        # avoids matching stale captures from prior failed runs.
        unique = secrets.token_hex(6)
        session_id = f"harvest_304_test_{unique}"
        terminator = f"APTL_HARVEST_TERMINATOR_{unique}"

        # Bring up the lab's MCP server, open an interactive session,
        # run a command that emits the terminator, then close. The
        # close handler triggers harvest from the kali container's
        # capture volume into .aptl/runs/<run>/kali-side/<session>/.
        init = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "aptl-test", "version": "1.0.0"},
            },
        }
        initialized = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        open_session = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "kali_interactive_session",
                "arguments": {
                    "session_id": session_id,
                    "timeout_ms": 60000,
                },
            },
        }
        emit_terminator = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "kali_session_command",
                "arguments": {
                    "session_id": session_id,
                    "command": f"echo {terminator}",
                    "timeout": 10000,
                },
            },
        }
        close = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "kali_close_session",
                "arguments": {"session_id": session_id},
            },
        }

        responses = mcp_jsonrpc(
            "kali-ssh",
            [init, initialized, open_session, emit_terminator, close],
            timeout=90,
        )

        # Sanity check JSON-RPC transport AND the inner success envelope —
        # these MCP handlers report operational failures inside the text
        # body as `success: false` rather than as JSON-RPC errors. A
        # transport-clean response with `success: false` would otherwise
        # produce false confidence about the harvest race fix.
        by_id = {r.get("id"): r for r in responses if "id" in r}
        for call_id in (2, 3, 4):
            resp = by_id.get(call_id)
            assert resp is not None, f"missing response for id={call_id}"
            assert "error" not in resp, (
                f"MCP transport error on id={call_id}: {resp.get('error')}"
            )
            content = resp.get("result", {}).get("content", [])
            assert content, f"empty content for id={call_id}"
            body = _json.loads(content[0]["text"])
            assert body.get("success") is True, (
                f"tool id={call_id} body reports failure: {body}"
            )

        # Locate the harvested typescript. The harvest lands under
        # .aptl/runs/<run_id>/kali-side/<session_id>/. The unique-per-run
        # session_id guarantees we match only captures from this run.
        import glob
        from pathlib import Path

        repo_root = Path(__file__).resolve().parent.parent
        candidates = glob.glob(
            str(
                repo_root / ".aptl" / "runs" / "*" / "kali-side"
                / session_id / "**" / "typescript*"
            ),
            recursive=True,
        )
        assert candidates, (
            "No harvested typescript for the test session — harvest "
            "may have run before remote close, or the kali capture "
            "wrapper did not produce a typescript."
        )

        # Read every candidate (PTY + raw typescript variants) and
        # assert at least one contains the unique terminator intact.
        found_in_any = False
        for path in candidates:
            try:
                contents = Path(path).read_bytes()
            except OSError:
                continue
            if terminator.encode() in contents:
                found_in_any = True
                break
        assert found_in_any, (
            f"Terminator '{terminator}' not found in any harvested "
            f"typescript — capture was truncated. Candidates: "
            f"{candidates}"
        )
