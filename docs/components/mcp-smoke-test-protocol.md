# Range Smoke Test Protocol

Validates the full APTL lab after deployment or feature changes. Three layers of validation, each building on the last:

1. **Automated tests**—pytest code that proves plumbing works (containers, pipelines, APIs, JSON-RPC)
2. **Agent MCP protocol**—an agent uses the MCP tools to do real security work, proving the presentation layer
3. **Manual fallback**—curl/ssh commands for debugging when the above aren't available

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

This protocol is executed by an AI agent with the APTL MCP servers connected. The agent calls real tools, inspects real responses, and verifies real system behavior. This validates the **agent experience**—that the MCP layer actually enables useful security work.

### MCP Server Architecture

APTL uses 8 custom MCP servers, all Node.js, built from `mcp/`:

| Server (.mcp.json name) | Type | Source |
|---|---|---|
| `aptl-red` | Custom Node.js | `mcp/mcp-red/` |
| `aptl-reverse` | Custom Node.js | `mcp/mcp-reverse/` |
| `aptl-indexer` | Custom Node.js | `mcp/mcp-indexer/` |
| `aptl-wazuh` | Custom Node.js | `mcp/mcp-wazuh/` |
| `aptl-network` | Custom Node.js | `mcp/mcp-network/` |
| `aptl-soar` | Custom Node.js | `mcp/mcp-soar/` |
| `aptl-casemgmt` | Custom Node.js | `mcp/mcp-casemgmt/` |
| `aptl-threatintel` | Custom Node.js | `mcp/mcp-threatintel/` |

### Setup

The agent's MCP client must have all 8 APTL servers configured (see `.mcp.json`). Environment variables required:

| Variable | Used by | Source |
|---|---|---|
| `INDEXER_USERNAME` / `INDEXER_PASSWORD` | `aptl-indexer`, `aptl-wazuh`, `aptl-network` | `.env` |
| `API_USERNAME` / `API_PASSWORD` | `aptl-indexer` | `.env` |
| `MISP_API_KEY` | `aptl-threatintel` | docker-compose `ADMIN_KEY` |
| `THEHIVE_API_KEY` | `aptl-casemgmt` | TheHive admin user (`scripts/thehive-apikey.sh`) |
| `SHUFFLE_API_KEY` | `aptl-soar` | Shuffle UI |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | all servers | `.mcp.json` |

### Tool inventory

| Server | Tools |
|---|---|
| `aptl-red` | `kali_info`, `kali_run_command`, `kali_interactive_session`, `kali_background_session`, `kali_session_command`, `kali_list_sessions`, `kali_close_session`, `kali_get_session_output`, `kali_close_all_sessions` |
| `aptl-reverse` | `reverse_info`, `reverse_run_command`, `reverse_interactive_session`, `reverse_background_session`, `reverse_session_command`, `reverse_list_sessions`, `reverse_close_session`, `reverse_get_session_output`, `reverse_close_all_sessions` |
| `aptl-wazuh` | `wazuh_query_alerts`, `wazuh_query_logs`, `wazuh_create_detection_rule` |
| `aptl-indexer` | `indexer_query`, `indexer_create_rule`, `indexer_get_rule_file`, `indexer_restart_manager` |
| `aptl-network` | `network_query_ids_alerts`, `network_query_dns_events`, `network_query_network_flows`, `network_query_web_attacks` |
| `aptl-soar` | `soar_list_workflows`, `soar_get_workflow`, `soar_execute_workflow`, `soar_list_executions`, `soar_search_workflows` |
| `aptl-casemgmt` | `cases_list_cases`, `cases_create_case`, `cases_add_observable`, `cases_update_case`, `cases_create_alert` |
| `aptl-threatintel` | `threatintel_search_iocs`, `threatintel_get_events`, `threatintel_add_indicator`, `threatintel_correlate_observable` |

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

1. Call `wazuh_query_alerts` with `{"body": {"query": {"match_all": {}}, "size": 5}}`. **Verify**: response contains alert documents with rule IDs, descriptions, timestamps.
2. Call `wazuh_query_alerts` with a time-bounded query (`{"range": {"@timestamp": {"gte": "now-24h"}}}`). **Verify**: only recent alerts return.
3. Call `wazuh_query_logs` with `{"body": {"query": {"match_all": {}}, "size": 1}}`. **Verify**: raw archive documents return (requires `logall` on the manager).

**Pass**: Agent can query processed alerts and raw archives from the SIEM.

#### Step 3: Raw Indexer -- Elasticsearch DSL queries

**Goal**: Prove the agent can run arbitrary ES queries against the Wazuh Indexer.

1. Call `indexer_query` with `{"body": {"query": {"match_all": {}}, "size": 3}}`. **Verify**: response contains `data.hits.hits` array with at least 1 document.
2. Call `indexer_query` with `{"body": {"query": {"bool": {"must": [{"match": {"rule.groups": "web_attack"}}]}}, "size": 3}}`. **Verify**: if web attacks have occurred, hits contain web attack rules (may be empty on fresh lab).
3. Call `indexer_query` with `{"params": {"index": "wazuh-archives-4.x-*"}, "body": {"query": {"match_all": {}}, "size": 1}}`. **Verify**: agent can override the index pattern.

**Pass**: Agent can run raw Elasticsearch DSL queries against any index pattern.

#### Step 4: Threat Intelligence -- MISP lookup

**Goal**: Prove the agent can query MISP for IOCs and threat context.

1. Call `threatintel_search_iocs` with the value `172.20.1.30`. **Verify**: response contains the seeded Kali DMZ IP indicator.
2. Call `threatintel_correlate_observable` with the same IP. **Verify**: response returns matching IOCs with event context.
3. Call `threatintel_get_events`. **Verify**: response contains threat events with threat levels and tags.

**Pass**: Agent can search threat intelligence for IOCs and retrieve event context.

#### Step 5: Case Management -- TheHive CRUD

**Goal**: Prove the agent can create and manage incident cases.

1. Call `cases_list_cases`. **Verify**: response is a list (may be empty on fresh lab).
2. Call `cases_create_case` with `{"title": "Agent Smoke Test", "description": "Automated validation", "severity": 1}`. **Verify**: response contains the created case with an id.
3. Call `cases_add_observable` with the case id and `{"dataType": "ip", "data": "172.20.1.30"}`. **Verify**: observable attaches to the case.

**Pass**: Agent can list cases, create cases, and attach observables.

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
4. **Enrich**: Take the source IP from the alert and call `threatintel_correlate_observable` with it. **Verify**: MISP returns context on the IP (the seeded Kali indicator).
5. **Respond**: Call `cases_create_case` with details from the alert. **Verify**: case created successfully.

**Pass**: Agent executed a complete attack -> detect -> enrich -> respond workflow across 5 systems using only MCP tools.

### Pass criteria summary

| Step | System | Server | What it proves |
|---|---|---|---|
| 1 | Kali | `aptl-red` | Agent can operate red team container |
| 2 | Wazuh SIEM | `aptl-wazuh` | Agent can query alerts and raw archives |
| 3 | Wazuh Indexer | `aptl-indexer` | Agent can run raw ES DSL queries |
| 4 | MISP | `aptl-threatintel` | Agent can look up threat intelligence |
| 5 | TheHive | `aptl-casemgmt` | Agent can manage incident cases |
| 6 | Shuffle | `aptl-soar` | Agent can trigger automated playbooks |
| 7 | RE container | `aptl-reverse` | Agent can use RE tools (optional) |
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

The victim and kali containers publish no host SSH ports; reach them
through the container runtime. The reverse engineering container is the
only one with host SSH:

```bash
docker exec aptl-victim echo OK                                   # victim
docker exec aptl-kali echo OK                                     # kali
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
| TheHive | https://localhost:9000 | Status API returns 200 |
| Shuffle | http://localhost:3443 | Frontend loads |

### 5. Network Connectivity

From the Kali container, verify it can reach targets across network segments:

```bash
docker exec aptl-kali ping -c 1 172.20.2.20    # victim (internal)
docker exec aptl-kali ping -c 1 172.20.1.20    # webapp (dmz, if enabled)
```

Pass: each returns `1 packets transmitted, 1 received`.
