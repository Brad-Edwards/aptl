# Range Smoke Test Protocol

Validates the full APTL lab after deployment or feature changes. Three layers of validation, each building on the last:

1. **Automated tests** — pytest code that proves plumbing works (containers, pipelines, APIs, JSON-RPC)
2. **Agent MCP protocol** — an agent uses the MCP tools to do real security work, proving the presentation layer
3. **Manual fallback** — curl/ssh commands for debugging when the above aren't available

## Automated Tests

Pytest suites gated behind `APTL_SMOKE=1`:

| Suite | File | Time | What it covers |
|---|---|---|---|
| **Smoke tests** | `tests/test_smoke.py` | < 30s | Container health, SSH, Wazuh pipeline, web UIs, network, MCP builds |
| **Integration tests** | `tests/test_range_integration.py` | 2-5 min | Cross-system detection pipeline, attack-to-alert, SOC tool CRUD, full-loop pipeline, scenario harness, MCP protocol + tool calls |

```bash
# Quick liveness check
APTL_SMOKE=1 pytest tests/test_smoke.py -v

# Full cross-system integration (requires all profiles + seed scripts)
APTL_SMOKE=1 pytest tests/test_range_integration.py -v

# Everything
APTL_SMOKE=1 pytest tests/test_smoke.py tests/test_range_integration.py -v
```

### Prerequisites

The integration tests require the full lab with all profiles running, plus seeded SOC data:

```bash
aptl lab start
./scripts/seed-misp.sh
./scripts/seed-shuffle.sh
APTL_SMOKE=1 pytest tests/test_smoke.py tests/test_range_integration.py -v
```

API keys are pre-configured in `.env` and `docker-compose.yml` so no manual export is needed. The MISP key is set via `ADMIN_KEY` in docker-compose; TheHive and Shuffle keys are stable across normal restart cycles.

> **Note**: TheHive generates its API key on first admin user creation. A full volume wipe (`docker compose down -v`) will invalidate the TheHive key. After a volume wipe, retrieve the new key from TheHive and update `.env`.

### What the automated tests prove

- **Precondition gate**: All 12 expected containers are running (fail fast, no skip)
- **Detection pipeline**: Victim log -> archives, Kali red-team log -> archives, Kali SSH to victim, Wazuh agent registration
- **Attack -> Detection**: SQLi (rule 302010), XSS (rule 302020), CmdInj (rule 302030) from Kali generate real Wazuh alerts
- **SOC tools**: MISP IOC lookup, TheHive case lifecycle, Shuffle workflow execution to FINISHED
- **Full loop**: SQLi from Kali -> Wazuh alert -> MISP lookup -> Shuffle workflow -> TheHive case (6 systems)
- **Scenario harness**: detect-brute-force lifecycle (start -> SSH brute force from Kali -> evaluate -> stop -> verify report)
- **MCP protocol**: JSON-RPC initialize + tools/list for all 7 servers (4 custom Node.js + 3 published binaries)
- **MCP tool calls**: Real tool invocations against live services (kali_info, kali_run_command, indexer_query, soar_list_workflows)

---

## Agent MCP Validation Protocol

This protocol is executed by an AI agent with the APTL MCP servers connected. The agent calls real tools, inspects real responses, and verifies real system behavior. This validates the **agent experience** — that the MCP layer actually enables useful security work.

### MCP Server Architecture

APTL uses 7 MCP servers: 4 custom (Node.js, built from `mcp/`) and 3 published open-source servers (installed to `tools/`):

| Server (.mcp.json name) | Type | Source |
|---|---|---|
| `kali-ssh` | Custom Node.js | `mcp/mcp-red/` |
| `reverse-sandbox-ssh` | Custom Node.js | `mcp/mcp-reverse/` |
| `shuffle` | Custom Node.js | `mcp/mcp-soar/` |
| `indexer` | Custom Node.js | `mcp/mcp-indexer/` |
| `wazuh` | Published Rust binary | [gbrigandi/mcp-server-wazuh](https://github.com/gbrigandi/mcp-server-wazuh) |
| `misp` | Published Python | [bornpresident/MISP-MCP-SERVER](https://github.com/bornpresident/MISP-MCP-SERVER) |
| `thehive` | Published Go binary | [StrangeBeeCorp/TheHiveMCP](https://github.com/StrangeBeeCorp/TheHiveMCP) |

### Setup

The agent's MCP client must have all 7 APTL servers configured (see `.mcp.json`). Environment variables required:

| Variable | Used by | Default |
|---|---|---|
| `INDEXER_USERNAME` | indexer | `admin` |
| `INDEXER_PASSWORD` | indexer | `SecretPassword` |
| `API_USERNAME` | indexer | `wazuh-wui` |
| `API_PASSWORD` | indexer | `WazuhPass123!` |
| `WAZUH_API_HOST` | wazuh | `localhost` |
| `WAZUH_API_PORT` | wazuh | `55000` |
| `WAZUH_API_USERNAME` | wazuh | `wazuh-wui` |
| `WAZUH_API_PASSWORD` | wazuh | `WazuhPass123!` |
| `WAZUH_INDEXER_*` | wazuh | (see `.mcp.json`) |
| `MISP_URL` | misp | `https://localhost:8443` |
| `MISP_API_KEY` | misp | (set via docker-compose `ADMIN_KEY`) |
| `THEHIVE_URL` | thehive | `http://localhost:9000` |
| `THEHIVE_API_KEY` | thehive | (from TheHive admin user) |
| `SHUFFLE_API_KEY` | shuffle | (set in docker-compose) |

### Tool inventory

| Server | Tools |
|---|---|
| `kali-ssh` | `kali_info`, `kali_run_command`, `kali_interactive_session`, `kali_background_session`, `kali_session_command`, `kali_list_sessions`, `kali_close_session`, `kali_get_session_output`, `kali_close_all_sessions` |
| `reverse-sandbox-ssh` | `reverse_info`, `reverse_run_command`, `reverse_interactive_session`, `reverse_background_session`, `reverse_session_command`, `reverse_list_sessions`, `reverse_close_session`, `reverse_get_session_output`, `reverse_close_all_sessions` |
| `shuffle` | `soar_list_workflows`, `soar_get_workflow`, `soar_execute_workflow`, `soar_list_executions`, `soar_search_workflows` |
| `indexer` | `indexer_query`, `indexer_create_rule` |
| `wazuh` | `get_wazuh_cluster_health`, `get_wazuh_cluster_nodes`, `get_wazuh_agents`, `get_wazuh_alert_summary`, `get_wazuh_rules_summary`, `get_wazuh_vulnerability_summary`, `get_wazuh_critical_vulnerabilities`, `get_wazuh_manager_error_logs`, `search_wazuh_manager_logs`, `get_wazuh_weekly_stats`, `get_wazuh_log_collector_stats`, `get_wazuh_agent_processes`, `get_wazuh_remoted_stats`, `get_wazuh_agent_ports` |
| `misp` | `search_misp`, `advanced_search`, `submit_ioc`, `generate_threat_report`, `get_misp_stats`, `get_mac_malware`, `get_platform_malware` |
| `thehive` | `search-entities`, `get-resource`, `manage-entities`, `execute-automation` |

### Protocol steps

Execute each step in order. Record PASS/FAIL per step. Stop and triage on first FAIL.

#### Step 1: Red Team -- Kali recon

**Goal**: Prove the agent can operate the Kali container as a red team platform.

1. Call `kali_info`. **Verify**: response includes container name, OS info (Kali/Debian), IP address.
2. Call `kali_run_command` with `{"command": "whoami"}`. **Verify**: output contains `kali`.
3. Call `kali_run_command` with `{"command": "nmap --version"}`. **Verify**: output contains `Nmap`.
4. Call `kali_run_command` with `{"command": "ping -c 1 172.20.2.20"}`. **Verify**: output contains `1 received` (Kali can reach victim).

**Pass**: Agent can gather system info, run commands, and confirm network connectivity from Kali.

#### Step 2: SIEM -- Query Wazuh alerts

**Goal**: Prove the agent can query the Wazuh SIEM for security alerts and cluster status.

1. Call `get_wazuh_cluster_health`. **Verify**: response includes cluster enabled/running status.
2. Call `get_wazuh_agents` with `{"status": "active"}`. **Verify**: response contains at least 1 active agent with ID, name, IP, status.
3. Call `get_wazuh_alert_summary`. **Verify**: response contains alert data with rule IDs, descriptions, timestamps.
4. Call `get_wazuh_rules_summary`. **Verify**: response contains rule definitions with IDs, levels, and groups.

**Pass**: Agent can connect to the SIEM and retrieve agent status, alerts, and rule definitions.

#### Step 3: Raw Indexer -- Elasticsearch DSL queries

**Goal**: Prove the agent can run arbitrary ES queries against the Wazuh Indexer.

1. Call `indexer_query` with `{"body": {"query": {"match_all": {}}, "size": 3}}`. **Verify**: response contains `data.hits.hits` array with at least 1 document.
2. Call `indexer_query` with `{"body": {"query": {"bool": {"must": [{"match": {"rule.groups": "web_attack"}}]}}, "size": 3}}`. **Verify**: if web attacks have occurred, hits contain web attack rules (may be empty on fresh lab).
3. Call `indexer_query` with `{"params": {"index": "wazuh-archives-4.x-*"}, "body": {"query": {"match_all": {}}, "size": 1}}`. **Verify**: agent can override the index pattern.

**Pass**: Agent can run raw Elasticsearch DSL queries against any index pattern.

#### Step 4: Threat Intelligence -- MISP lookup

**Goal**: Prove the agent can query MISP for IOCs and threat context.

1. Call `search_misp` with `{"search_term": "172.20.1.30"}`. **Verify**: response contains the seeded Kali DMZ IP indicator.
2. Call `advanced_search` with `{"search_query": "type:ip-src AND value:172.20.1.30"}`. **Verify**: response contains the Kali IP attribute with event context.
3. Call `get_misp_stats`. **Verify**: response contains MISP statistics (event count, attribute count).

**Pass**: Agent can search threat intelligence for IOCs and retrieve event context.

#### Step 5: Case Management -- TheHive CRUD

**Goal**: Prove the agent can create and manage incident cases.

1. Call `search-entities` with `{"type": "Case", "query": {}}`. **Verify**: response is a list (may be empty on fresh lab).
2. Call `manage-entities` with `{"action": "create", "type": "Case", "data": {"title": "Agent Smoke Test", "description": "Automated validation", "severity": 1}}`. **Verify**: response contains the created case with an `_id` field.
3. Call `get-resource` with `{"type": "Case", "id": "<id from step 2>"}`. **Verify**: response contains the case details matching what was created.

**Pass**: Agent can create cases, retrieve case details, and search cases.

#### Step 6: SOAR -- Shuffle workflow execution

**Goal**: Prove the agent can trigger automated response playbooks.

1. Call `soar_list_workflows`. **Verify**: response (in `data` field) contains at least the seeded "APTL Alert to Case" workflow.
2. Call `soar_execute_workflow` with `{"params": {"workflow_id": "<id from step 1>"}, "body": {"execution_argument": {"alert_id": "smoke-test-001", "src_ip": "172.20.1.30", "rule_description": "Agent smoke test"}}}`. **Verify**: response contains an `execution_id`.
3. Wait 10-15 seconds, then call `soar_list_executions` with `{"params": {"workflow_id": "<id>"}}`. **Verify**: the most recent execution has status `FINISHED` (not EXECUTING, not ABORTED).

**Pass**: Agent can discover, trigger, and monitor SOAR workflows.

#### Step 7: Reverse Engineering (optional)

**Goal**: Prove the agent can operate the RE container (if enabled).

1. Call `reverse_info`. **Verify**: response includes container name and OS info.
2. Call `reverse_run_command` with `{"command": "which r2"}`. **Verify**: output contains a path to radare2.

**Pass**: Agent has access to RE tooling. Skip if reverse container is not deployed.

#### Step 8: Cross-system investigation (full loop)

**Goal**: Prove the agent can chain tools across systems to conduct a real investigation.

This step simulates what an agent would do in an actual purple team exercise:

1. **Attack**: Call `kali_run_command` with `{"command": "curl -sk 'http://172.20.1.20:8080/search?q=1%27+OR+1%3D1--'"}`. This sends a SQLi payload from Kali to the webapp.
2. **Wait 30s** for the detection pipeline to process.
3. **Detect**: Call `indexer_query` with `{"body": {"query": {"bool": {"must": [{"match": {"rule.groups": "web_attack"}}, {"range": {"@timestamp": {"gte": "now-2m"}}}]}}, "size": 5}}`. **Verify**: at least one alert appears with the SQLi attack. Note: actual ES data is in the `data` field of the response.
4. **Enrich**: Take the source IP from the alert and call `search_misp` with `{"search_term": "<src_ip>"}`. **Verify**: MISP returns context on the IP (the seeded Kali indicator).
5. **Respond**: Call `manage-entities` to create a TheHive case with details from the alert. **Verify**: case created successfully.

**Pass**: Agent executed a complete attack -> detect -> enrich -> respond workflow across 5 systems using only MCP tools.

### Pass criteria summary

| Step | System | Server | What it proves |
|---|---|---|---|
| 1 | Kali | `kali-ssh` | Agent can operate red team container |
| 2 | Wazuh SIEM | `wazuh` | Agent can query alerts, agents, rules |
| 3 | Wazuh Indexer | `indexer` | Agent can run raw ES DSL queries |
| 4 | MISP | `misp` | Agent can look up threat intelligence |
| 5 | TheHive | `thehive` | Agent can manage incident cases |
| 6 | Shuffle | `shuffle` | Agent can trigger automated playbooks |
| 7 | RE container | `reverse-sandbox-ssh` | Agent can use RE tools (optional) |
| 8 | All systems | All servers | Agent can chain tools for end-to-end investigation |

**Full pass**: Steps 1-6 and 8 all pass. Step 7 passes if reverse container is deployed.

---

## Manual Fallback Protocol

The sections below are useful for initial setup verification and debugging
when neither automated tests nor agent MCP access are available.

### Preconditions

1. Install CLI: `pip install -e .`
2. Start the lab: `aptl lab start`
3. Wait for startup to complete (5-10 min for full SOC stack).
4. Build MCP servers: `./mcp/build-all-mcps.sh`
5. Install published MCPs (see `tools/.gitignore` for details).
6. Configure your MCP client to load all APTL servers (see `.mcp.json`).

### 1. Container Health

```bash
aptl lab status
```

All enabled containers should show **healthy** or **running**. Core containers:

| Container | Profile | Expected |
|---|---|---|
| aptl-wazuh-manager | wazuh | healthy |
| aptl-wazuh-indexer | wazuh | healthy |
| aptl-wazuh-dashboard | wazuh | healthy |
| aptl-victim | victim | healthy |
| aptl-kali | kali | healthy |

If SOC stack is enabled, also check: `aptl-misp`, `aptl-thehive`,
`aptl-shuffle-backend`, `aptl-suricata`.

If enterprise stack is enabled: `aptl-webapp`, `aptl-ad`, `aptl-db`.

### 2. SSH Access

Each SSH-accessible container should accept key-based auth:

```bash
ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022 'echo OK'   # victim
ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023 'echo OK'       # kali
ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2027 'echo OK'   # reverse (if enabled)
```

Pass: each prints `OK` and exits 0.

### 3. Wazuh Pipeline

Verify the full log ingestion path: container -> rsyslog -> Wazuh Manager -> Indexer.

```bash
# Generate a test log on the victim
docker exec aptl-victim logger -t smoketest "APTL_SMOKE_TEST_$(date +%s)"

# Wait 30-60 seconds, then query the indexer
curl -ks https://localhost:9200/wazuh-alerts-4.x-*/_search \
  -u admin:SecretPassword \
  -H 'Content-Type: application/json' \
  -d '{"query":{"match_phrase":{"full_log":"APTL_SMOKE_TEST"}},"size":1}'
```

Pass: response contains at least one hit with the smoke test string.

### 4. Web Interfaces

| Service | URL | Credentials | Check |
|---|---|---|---|
| Wazuh Dashboard | https://localhost:443 | admin / SecretPassword | Login page loads |
| Wazuh Indexer API | https://localhost:9200 | admin / SecretPassword | Returns cluster JSON |

If SOC stack is enabled:

| Service | URL | Check |
|---|---|---|
| MISP | https://localhost:8443 | Login page loads |
| TheHive | http://localhost:9000 | Status API returns 200 |
| Shuffle | http://localhost:3443 | Frontend loads |

### 5. Network Connectivity

From the Kali container, verify it can reach targets across network segments:

```bash
docker exec aptl-kali ping -c 1 172.20.2.20    # victim (internal)
docker exec aptl-kali ping -c 1 172.20.1.20    # webapp (dmz, if enabled)
```

Pass: each returns `1 packets transmitted, 1 received`.
