# APTL Minimum Viable Enterprise - Smoke Test Plan

> Historical note: sections covering `aptl scenario` and the old scenario engine apply to the pre-SDL runtime, not the current SDL-only branch.

Acceptance testing for the enterprise infrastructure, SOC stack, MCP layer, and scenario engine implemented in the SOC-in-a-Box build.

---

## Test Environment

**Prerequisites:**
- Docker Engine with Docker Compose v2
- 24GB+ RAM available (32GB recommended)
- Python 3.11+ with `pip install -e .` (APTL CLI)
- Node.js 20+ (MCP server builds)
- `vm.max_map_count >= 262144`

**Profiles to enable in `aptl.json`:**
```json
{
  "containers": {
    "wazuh": true,
    "victim": true,
    "kali": true,
    "reverse": false,
    "enterprise": true,
    "soc": true,
    "mail": false,
    "fileshare": false,
    "dns": false
  }
}
```

Phase 1 and 2 tests use the default config above. Phase 3 tests require enabling `mail`, `fileshare`, and `dns` individually.

---

## Team Structure (Claude Code Teams)

Use Claude Code agent teams with the following roles:

```
Lead: Test Coordinator
  - Orchestrates test execution
  - Tracks pass/fail per test case
  - Synthesizes results into a final report

Teammate 1: Infrastructure Tester
  - Verifies containers start, networks exist, services are healthy
  - No MCP servers needed -- uses shell commands only

Teammate 2: Red Team Tester
  - Executes attack steps against enterprise services
  - Uses: mcp-red (Kali commands)

Teammate 3: Blue Team Tester
  - Verifies detections, queries alerts, manages cases
  - Uses: mcp-wazuh, mcp-network, mcp-threatintel, mcp-casemgmt, mcp-soar

Teammate 4: Integration Tester
  - Verifies end-to-end flows across red and blue
  - Validates scenario engine CLI
  - Uses: shell, mcp-red, mcp-wazuh
```

Spawn prompt for the lead:

```
Create an agent team to smoke-test the APTL enterprise lab. Read
notes/smoketest.md for the full test plan. Assign tests by section:
Infrastructure Tester gets sections 1-2, Red Team Tester gets section 3,
Blue Team Tester gets section 4, Integration Tester gets sections 5-6.
Track every test case as pass/fail. When all teammates finish, compile
a summary report with: total tests, passed, failed, and details on
every failure.
```

---

## Test Execution Protocol

For every test case:
1. Record the test ID, description, and expected result
2. Execute the test step
3. Record actual result (output, alert ID, error message)
4. Mark PASS or FAIL
5. If FAIL, note the failure reason and whether it's a blocker

---

## 1. Infrastructure: Network Segmentation

Verify the 4 Docker networks exist with correct subnets.

| ID | Test | Expected | How |
|----|------|----------|-----|
| NET-01 | Security network exists | `aptl-security` with 172.20.0.0/24 | `docker network inspect aptl_aptl-security` |
| NET-02 | DMZ network exists | `aptl-dmz` with 172.20.1.0/24 | `docker network inspect aptl_aptl-dmz` |
| NET-03 | Internal network exists | `aptl-internal` with 172.20.2.0/24 | `docker network inspect aptl_aptl-internal` |
| NET-04 | Red team network exists | `aptl-redteam` with 172.20.4.0/24 | `docker network inspect aptl_aptl-redteam` |
| NET-05 | Wazuh manager on 3 networks | Connected to security + dmz + internal | `docker inspect aptl-wazuh-manager --format '{{json .NetworkSettings.Networks}}' \| jq 'keys'` |
| NET-06 | Kali on dmz + redteam + internal | Connected to all three attack networks | `docker inspect aptl-kali --format '{{json .NetworkSettings.Networks}}' \| jq 'keys'` |
| NET-07 | Webapp on dmz + internal | Connected to both (for DB access) | `docker inspect aptl-webapp --format '{{json .NetworkSettings.Networks}}' \| jq 'keys'` |
| NET-08 | DB only on internal | Only on aptl-internal | `docker inspect aptl-db --format '{{json .NetworkSettings.Networks}}' \| jq 'keys'` |
| NET-09 | AD only on internal | Only on aptl-internal | `docker inspect aptl-ad --format '{{json .NetworkSettings.Networks}}' \| jq 'keys'` |

---

## 2. Infrastructure: Service Health

Verify every container starts and passes its health check.

### 2a. Wazuh Stack (existing)

| ID | Test | Expected | How |
|----|------|----------|-----|
| SVC-01 | Wazuh Manager healthy | Status: healthy | `docker inspect aptl-wazuh-manager --format '{{.State.Health.Status}}'` |
| SVC-02 | Wazuh Indexer healthy | Status: healthy | `docker inspect aptl-wazuh-indexer --format '{{.State.Health.Status}}'` |
| SVC-03 | Wazuh Dashboard healthy | Status: healthy, HTTPS on port 443 | `curl -ks https://localhost:443 \| head -1` |
| SVC-04 | Wazuh API responds | 200 on port 55000 | `curl -ks https://localhost:55000 -u $API_USERNAME:$API_PASSWORD` |
| SVC-05 | Indexer API responds | 200 on port 9200 | `curl -ks https://localhost:9200 -u $INDEXER_USERNAME:$INDEXER_PASSWORD` |

### 2b. Enterprise Services (new)

| ID | Test | Expected | How |
|----|------|----------|-----|
| SVC-10 | AD container healthy | Status: healthy | `docker inspect aptl-ad --format '{{.State.Health.Status}}'` |
| SVC-11 | AD domain info works | Returns TECHVAULT.LOCAL domain info | `docker exec aptl-ad samba-tool domain info 127.0.0.1` |
| SVC-12 | AD users exist | Lists sarah.mitchell, jessica.williams, svc-sql, etc. | `docker exec aptl-ad samba-tool user list` |
| SVC-13 | AD SPNs set | svc-sql has MSSQLSvc SPN | `docker exec aptl-ad samba-tool spn list svc-sql` |
| SVC-14 | PostgreSQL healthy | Status: healthy | `docker inspect aptl-db --format '{{.State.Health.Status}}'` |
| SVC-15 | PostgreSQL schema loaded | Tables exist: users, customers, files, etc. | `docker exec aptl-db psql -U techvault -d techvault -c '\dt'` |
| SVC-16 | PostgreSQL seed data loaded | 10 users, 8 customers | `docker exec aptl-db psql -U techvault -d techvault -c 'SELECT count(*) FROM users; SELECT count(*) FROM customers;'` |
| SVC-17 | Web app healthy | Status: healthy, responds on 8080 | `curl -s http://localhost:8080/ \| grep -i techvault` |
| SVC-18 | Web app login page renders | Returns HTML with login form | `curl -s http://localhost:8080/login` |
| SVC-19 | Victim container healthy | SSH on port 2022 | `ssh -o ConnectTimeout=5 -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022 'hostname'` |
| SVC-20 | Kali container healthy | SSH on port 2023 | `ssh -o ConnectTimeout=5 -i ~/.ssh/aptl_lab_key kali@localhost -p 2023 'hostname'` |

### 2c. SOC Stack (new)

| ID | Test | Expected | How |
|----|------|----------|-----|
| SVC-30 | MISP container running | Status: running, HTTPS on 8443 | `curl -ks https://localhost:8443/users/login \| head -5` |
| SVC-31 | MISP DB healthy | MariaDB running | `docker inspect aptl-misp-db --format '{{.State.Health.Status}}'` |
| SVC-32 | TheHive running | API responds on port 9000 | `curl -sf http://localhost:9000/api/v1/status` |
| SVC-33 | TheHive Cassandra healthy | Status: healthy | `docker inspect aptl-thehive-cassandra --format '{{.State.Health.Status}}'` |
| SVC-34 | TheHive ES healthy | Status: healthy | `docker inspect aptl-thehive-es --format '{{.State.Health.Status}}'` |
| SVC-35 | Shuffle backend running | API responds on 5001 | `curl -sf http://localhost:5001/api/v1/health` |
| SVC-36 | Shuffle frontend running | UI on port 3443 | `curl -ks https://localhost:3443/ \| head -5` |
| SVC-37 | Cortex running | API responds on 9001 | `curl -sf http://localhost:9001/api/status` |
| SVC-38 | Suricata running | Container exists and running | `docker ps --filter name=aptl-suricata --format '{{.Status}}'` |

---

## 3. Red Team: Attack Surface Validation

Execute from Kali container via `mcp-red`. Each test verifies a specific attack surface exists and is exploitable.

### 3a. Web Application Vulnerabilities

| ID | Test | Expected | How (from Kali) |
|----|------|----------|-----------------|
| RED-01 | Web app reachable from Kali | HTTP 200 | `curl -s http://172.20.1.20:8080/` |
| RED-02 | SQL injection in login | Bypasses auth or returns SQL error | `curl -s -X POST http://172.20.1.20:8080/login -d "username=admin'--&password=x"` |
| RED-03 | SQL injection in search | Returns data from injected query | `curl -s 'http://172.20.1.20:8080/api/v1/customers?search=x%27%20OR%201=1--'` (requires session cookie) |
| RED-04 | Command injection in ping | Returns command output | `curl -s -X POST http://172.20.1.20:8080/tools/ping -d 'host=127.0.0.1;id'` (requires session cookie) |
| RED-05 | .env file exposed | Returns DB credentials | `curl -s http://172.20.1.20:8080/.env` |
| RED-06 | Debug endpoint exposed | Returns app version, DB config | `curl -s http://172.20.1.20:8080/debug` |
| RED-07 | robots.txt reveals paths | Lists /admin, /debug, /backup | `curl -s http://172.20.1.20:8080/robots.txt` |
| RED-08 | Admin panel accessible | No role check, any user can access | Login as any user, then `curl http://172.20.1.20:8080/admin` with session cookie |
| RED-09 | IDOR on user API | Returns other users' data | `curl -s http://172.20.1.20:8080/api/v1/users/1` (with any auth) |
| RED-10 | Weak admin credentials | admin/admin123 works | `curl -s -X POST http://172.20.1.20:8080/login -d 'username=admin&password=admin123' -c /tmp/cookies.txt` |
| RED-11 | JWT with weak secret | Token is forgeable | `curl -s -X POST http://172.20.1.20:8080/api/v1/token -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}'` then decode the JWT |
| RED-12 | Backup config exposes AWS creds | Admin page shows AKIA keys | After login, check /admin for backup_config table |

### 3b. Active Directory

| ID | Test | Expected | How (from Kali) |
|----|------|----------|-----------------|
| RED-20 | LDAP reachable from Kali | Port 389 open on 172.20.2.10 | `nmap -p 389 172.20.2.10` |
| RED-21 | LDAP anonymous bind | Returns base DN info | `ldapsearch -x -H ldap://172.20.2.10 -b 'DC=techvault,DC=local' -s base` |
| RED-22 | Weak password login | jessica.williams:password123 works | `ldapsearch -x -H ldap://172.20.2.10 -D 'jessica.williams@techvault.local' -w 'password123' -b 'DC=techvault,DC=local' '(objectClass=user)' sAMAccountName` |
| RED-23 | SPN enumeration | Finds svc-sql and svc-web SPNs | `ldapsearch -x -H ldap://172.20.2.10 -D 'jessica.williams@techvault.local' -w 'password123' -b 'DC=techvault,DC=local' '(servicePrincipalName=*)' sAMAccountName servicePrincipalName` |
| RED-24 | Contractor account active | contractor.temp:Welcome1! works | `ldapsearch -x -H ldap://172.20.2.10 -D 'contractor.temp@techvault.local' -w 'Welcome1!' -b 'DC=techvault,DC=local' -s base` |
| RED-25 | Over-privileged service account | svc-backup is in Domain Admins | `ldapsearch -x -H ldap://172.20.2.10 -D 'jessica.williams@techvault.local' -w 'password123' -b 'DC=techvault,DC=local' '(sAMAccountName=svc-backup)' memberOf` |

### 3c. Database

| ID | Test | Expected | How (from Kali) |
|----|------|----------|-----------------|
| RED-30 | PostgreSQL reachable from Kali | Port 5432 open on 172.20.2.11 | `nmap -p 5432 172.20.2.11` |
| RED-31 | DB login with leaked creds | Connects with techvault/techvault_db_pass | `psql -h 172.20.2.11 -U techvault -d techvault -c 'SELECT 1'` (password from .env leak) |
| RED-32 | Customer data accessible | Returns customer records | `psql -h 172.20.2.11 -U techvault -d techvault -c 'SELECT * FROM customers'` |
| RED-33 | AWS creds in backup_config | Returns AKIA keys | `psql -h 172.20.2.11 -U techvault -d techvault -c 'SELECT * FROM backup_config'` |
| RED-34 | Password hashes extractable | Returns MD5 hashes | `psql -h 172.20.2.11 -U techvault -d techvault -c 'SELECT username, password_hash FROM users'` |

### 3d. Victim / App Server

| ID | Test | Expected | How (from Kali) |
|----|------|----------|-----------------|
| RED-40 | Victim reachable from Kali | SSH works on 172.20.2.20 | `ssh -o ConnectTimeout=5 labadmin@172.20.2.20 'hostname'` (from Kali, using internal IP) |
| RED-41 | Kali can reach internal network | Ping 172.20.2.10 (AD) succeeds | `ping -c 1 172.20.2.10` |
| RED-42 | Kali can reach DMZ | Ping 172.20.1.20 (webapp) succeeds | `ping -c 1 172.20.1.20` |

---

## 4. Blue Team: Detection & SOC Validation

### 4a. Wazuh Detection Rules

Run each attack from section 3, then verify the corresponding Wazuh alert fires.

| ID | Test | Prerequisite | Expected | How |
|----|------|-------------|----------|-----|
| BLUE-01 | SQLi detected by Wazuh | RED-02 or RED-03 | Alert with rule.groups containing "sqli" or "web_attack" | Query `mcp-wazuh` for alerts in last 5 min matching `rule.groups: sqli` |
| BLUE-02 | Command injection detected | RED-04 | Alert with rule group "command_injection" | Query alerts matching `rule.id: 302030` |
| BLUE-03 | Sensitive file access detected | RED-05 or RED-06 | Alert for .env or /debug access | Query alerts matching `rule.id: 302040` |
| BLUE-04 | AD brute force detected | Run 5+ failed LDAP logins from Kali | Alert with rule group "brute_force" | Query alerts matching `rule.id: 301002` |
| BLUE-05 | AD enumeration detected | RED-22/RED-23 (multiple LDAP queries) | Alert with rule group "enumeration" | Query alerts matching `rule.id: 301021` |
| BLUE-06 | DB auth failure detected | Attempt psql with wrong password | Alert for PostgreSQL auth failure | Query alerts matching `rule.id: 304000` |
| BLUE-07 | New Wazuh rules loaded | Check rule files mounted | ad_rules, webapp_rules, suricata_rules, database_rules all present | `docker exec aptl-wazuh-manager ls /var/ossec/etc/rules/` |

### 4b. Suricata IDS (via mcp-network)

| ID | Test | Prerequisite | Expected | How |
|----|------|-------------|----------|-----|
| BLUE-10 | Suricata eve.json generated | Suricata running | Eve log file exists with events | `docker exec aptl-suricata ls -la /var/log/suricata/eve.json` |
| BLUE-11 | Port scan alert | Run nmap from Kali to DMZ | Suricata alert for scan | Query `mcp-network` query_ids_alerts for scan signatures |
| BLUE-12 | SQLi detected at network level | RED-02 | Suricata alert for SQL injection | Query `mcp-network` query_web_attacks |
| BLUE-13 | Local rules loaded | Custom rules file mounted | Local rules file present | `docker exec aptl-suricata cat /etc/suricata/rules/local.rules \| head -5` |

### 4c. MCP Server Connectivity

Verify each new MCP server connects and responds.

| ID | Test | Expected | How |
|----|------|----------|-----|
| MCP-01 | mcp-threatintel responds | Returns API info or connection status | Call `threatintel_api_info` tool |
| MCP-02 | mcp-threatintel search IOCs | Returns results (empty is OK if no IOCs loaded) | Call `threatintel_search_iocs` with `{"body": {"type": "ip-dst", "limit": 5}}` |
| MCP-03 | mcp-casemgmt responds | Returns API info | Call `cases_api_info` tool |
| MCP-04 | mcp-casemgmt list cases | Returns empty list or cases | Call `cases_list_cases` |
| MCP-05 | mcp-casemgmt create case | Creates case, returns ID | Call `cases_create_case` with `{"body": {"title": "Smoke Test Case", "description": "Testing case creation", "severity": 1}}` |
| MCP-06 | mcp-soar responds | Returns API info | Call `soar_api_info` tool |
| MCP-07 | mcp-soar list workflows | Returns workflow list (may be empty) | Call `soar_list_workflows` |
| MCP-08 | mcp-network responds | Returns API info | Call `network_api_info` tool |
| MCP-09 | mcp-network query IDS alerts | Returns Suricata alerts from Wazuh | Call `network_query_ids_alerts` |
| MCP-10 | mcp-network query DNS events | Returns DNS events or empty | Call `network_query_dns_events` |
| MCP-11 | mcp-network query web attacks | Returns web attack alerts | Call `network_query_web_attacks` |
| MCP-12 | mcp-red still works | Kali command execution works | Call `kali_run_command` with `id` |
| MCP-13 | mcp-wazuh still works | Alert query returns results | Call `wazuh_query_alerts` |

### 4d. SOC Workflow (end-to-end)

| ID | Test | Expected | How |
|----|------|----------|-----|
| SOC-01 | Create TheHive case from Wazuh alert | Case created with alert details | 1. Query Wazuh for recent alert via `mcp-wazuh` 2. Create case in TheHive via `mcp-casemgmt` with alert info |
| SOC-02 | Add observable to case | Observable attached | Call `cases_add_observable` with attacker IP |
| SOC-03 | Query MISP for IOC | Returns result (match or no match) | Call `threatintel_search_iocs` with the attacker IP |
| SOC-04 | Correlate network and host alerts | Both Suricata and Wazuh alerts for same attack | Query `mcp-network` for scan alerts, then `mcp-wazuh` for same timeframe |

---

## 5. Phase 3: Extended Enterprise Services

Enable each profile individually, then test.

### 5a. DNS Server

Set `"dns": true` in `aptl.json`, restart.

| ID | Test | Expected | How |
|----|------|----------|-----|
| DNS-01 | DNS container healthy | Status: healthy | `docker inspect aptl-dns --format '{{.State.Health.Status}}'` |
| DNS-02 | Forward lookup works | webapp.techvault.local -> 172.20.1.20 | `dig @localhost -p 5353 webapp.techvault.local A +short` |
| DNS-03 | AD SRV records resolve | _ldap._tcp returns dc.techvault.local | `dig @localhost -p 5353 _ldap._tcp.techvault.local SRV +short` |
| DNS-04 | Reverse lookup works | 172.20.1.20 -> webapp.techvault.local | `dig @localhost -p 5353 -x 172.20.1.20 +short` |
| DNS-05 | MX record resolves | techvault.local MX -> mail.techvault.local | `dig @localhost -p 5353 techvault.local MX +short` |
| DNS-06 | Query logging enabled | Queries appear in log | `docker exec aptl-dns cat /var/log/named/query.log \| tail -5` |

### 5b. File Server

Set `"fileshare": true` in `aptl.json`, restart.

| ID | Test | Expected | How |
|----|------|----------|-----|
| FS-01 | File server container healthy | Status: healthy | `docker inspect aptl-fileshare --format '{{.State.Health.Status}}'` |
| FS-02 | Share listing works | Lists Public, Engineering, Shared, etc. | `docker exec aptl-kali smbclient -L //172.20.2.12/ -N` |
| FS-03 | Public share accessible anonymously | Can list files | `docker exec aptl-kali smbclient //172.20.2.12/Public -N -c 'ls'` |
| FS-04 | Shared drive has planted data | wifi-passwords.txt exists | `docker exec aptl-kali smbclient //172.20.2.12/Shared -N -c 'get wifi-passwords.txt /tmp/wifi.txt' && cat /tmp/wifi.txt` |
| FS-05 | Engineering share has creds | deploy.sh with hardcoded passwords | Access Engineering share and read deploy.sh |
| FS-06 | IT-Backups has SSH key | deploy_key file exists | Access IT-Backups share (requires auth) |
| FS-07 | HR share has employee PII | directory.csv with SSN/salary data | Access HR share (requires auth) |

### 5c. Mail Server

Set `"mail": true` in `aptl.json`, restart.

| ID | Test | Expected | How |
|----|------|----------|-----|
| MAIL-01 | Mail container running | Status: running | `docker ps --filter name=aptl-mailserver` |
| MAIL-02 | SMTP port open | Port 25 listening | `docker exec aptl-kali nmap -p 25 172.20.1.21` |
| MAIL-03 | Send test email | Delivery succeeds | `docker exec aptl-kali bash -c 'echo "Test" \| mail -S smtp=172.20.1.21:25 -s "Smoke Test" jessica.williams@techvault.local'` (or use swaks/sendmail) |

---

## 6. Scenario Engine & Python CLI

### 6a. CLI Commands

| ID | Test | Expected | How |
|----|------|----------|-----|
| CLI-01 | `aptl scenario list` works | Lists scenarios in table format | `cd /home/atomik/src/aptl && aptl scenario list` |
| CLI-02 | `aptl scenario show webapp-compromise` | Shows 6 steps with MITRE mappings | `aptl scenario show webapp-compromise` |
| CLI-03 | `aptl scenario show ad-domain-compromise` | Shows 5 steps, advanced difficulty | `aptl scenario show ad-domain-compromise` |
| CLI-04 | `aptl scenario show lateral-movement-data-theft` | Shows 5 steps, fileshare prerequisite | `aptl scenario show lateral-movement-data-theft` |
| CLI-05 | `aptl scenario show prime-enterprise` | Shows 13 steps with vulnerability descriptions | `aptl scenario show prime-enterprise` |
| CLI-06 | `aptl lab status` works | Shows running containers | `aptl lab status` |
| CLI-07 | `aptl scenario start/stop` lifecycle | Start creates session, stop assembles run | `aptl scenario start prime-enterprise` then `aptl scenario stop` |
| CLI-08 | `aptl runs list` works | Shows assembled runs | `aptl runs list` |
| CLI-09 | `aptl runs show <prefix>` works | Shows run manifest details | `aptl runs show <run-id-prefix>` |

### 6b. Config Model

| ID | Test | Expected | How |
|----|------|----------|-----|
| CFG-01 | Config loads with new profiles | No validation errors | `python -c "from aptl.core.config import load_config; from pathlib import Path; c = load_config(Path('aptl.json')); print(c.containers.enabled_profiles())"` |
| CFG-02 | All new profiles listed | enterprise, soc in list | Check output includes `enterprise`, `soc` |
| CFG-03 | Unknown profile rejected | Validation error | `python -c "from aptl.core.config import ContainerSettings; ContainerSettings(bogus=True)"` should raise |

### 6c. Scenario Definitions

| ID | Test | Expected | How |
|----|------|----------|-----|
| SCEN-01 | All scenarios parse cleanly | No validation errors | `python -c "from aptl.core.scenarios import find_scenarios, load_scenario; from pathlib import Path; paths = find_scenarios(Path('scenarios')); [load_scenario(p) for p in paths]; print(f'{len(paths)} scenarios loaded')"` |
| SCEN-02 | webapp-compromise has 6 steps | 6 AttackStep objects | `python -c "from aptl.core.scenarios import load_scenario; from pathlib import Path; s = load_scenario(Path('scenarios/webapp-compromise.yaml')); print(f'{len(s.steps)} steps')"` |
| SCEN-03 | prime-enterprise has 13 steps | 13 AttackStep objects with vulnerability descriptions | `python -c "from aptl.core.scenarios import load_scenario; from pathlib import Path; s = load_scenario(Path('scenarios/prime-enterprise.yaml')); print(f'{len(s.steps)} steps'); assert all(st.vulnerability for st in s.steps)"` |

---

## 7. Wazuh Rule File Verification

Verify the new rule files are syntactically valid and loaded by the manager.

| ID | Test | Expected | How |
|----|------|----------|-----|
| RULE-01 | ad_rules.xml mounted | File exists in manager | `docker exec aptl-wazuh-manager cat /var/ossec/etc/rules/ad_rules.xml \| head -3` |
| RULE-02 | webapp_rules.xml mounted | File exists | `docker exec aptl-wazuh-manager cat /var/ossec/etc/rules/webapp_rules.xml \| head -3` |
| RULE-03 | suricata_rules.xml mounted | File exists | `docker exec aptl-wazuh-manager cat /var/ossec/etc/rules/suricata_rules.xml \| head -3` |
| RULE-04 | database_rules.xml mounted | File exists | `docker exec aptl-wazuh-manager cat /var/ossec/etc/rules/database_rules.xml \| head -3` |
| RULE-05 | Manager config includes new rules | All 4 rule_include lines present | `docker exec aptl-wazuh-manager grep rule_include /var/ossec/etc/ossec.conf` |
| RULE-06 | No rule loading errors | Manager starts without rule parse errors | `docker exec aptl-wazuh-manager grep -i 'error.*rule' /var/ossec/logs/ossec.log \| tail -5` (should be empty or unrelated) |

---

## 8. MCP Server Build Verification

| ID | Test | Expected | How |
|----|------|----------|-----|
| BUILD-01 | mcp-threatintel builds | Exit 0, build/ directory created | `cd mcp/mcp-threatintel && npm install && npm run build` |
| BUILD-02 | mcp-casemgmt builds | Exit 0 | `cd mcp/mcp-casemgmt && npm install && npm run build` |
| BUILD-03 | mcp-soar builds | Exit 0 | `cd mcp/mcp-soar && npm install && npm run build` |
| BUILD-04 | mcp-network builds | Exit 0 | `cd mcp/mcp-network && npm install && npm run build` |
| BUILD-05 | build-all-mcps.sh includes new servers | Script references all 8 servers | `grep -c 'mcp-' mcp/build-all-mcps.sh` (should be 8) |
| BUILD-06 | .mcp.json references all servers | 7 entries | `cat .mcp.json \| python3 -c 'import json,sys; print(len(json.load(sys.stdin)["mcpServers"]))'` (should be 7) |

---

## 9. Regression: Existing Features

Verify nothing broke in the existing infrastructure.

| ID | Test | Expected | How |
|----|------|----------|-----|
| REG-01 | Kali SSH still works | Login via port 2023 | `ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023 'id'` |
| REG-02 | Victim SSH still works | Login via port 2022 | `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022 'id'` |
| REG-03 | Kali red team tools present | nmap, metasploit available | `kali_run_command` with `which nmap && msfconsole --version` |
| REG-04 | Wazuh agent on victim | Agent running | `docker exec aptl-victim systemctl status wazuh-agent 2>/dev/null \|\| echo "check /var/ossec"` |
| REG-05 | Kali logs forwarded to Wazuh | Bash history logging active | `kali_run_command` with `ls -la /var/log/bash_history.log` |
| REG-06 | `aptl lab start` still works | Completes 12-step orchestration | Run `aptl lab start` from project root (full integration test) |
| REG-07 | `aptl lab stop` still works | All containers stop | Run `aptl lab stop` then `docker ps` shows no aptl containers |
| REG-08 | `aptl lab stop -v` removes volumes | Volumes cleaned | Run `aptl lab stop -v` then `docker volume ls \| grep aptl` shows nothing |

---

## Test Summary Template

Use this format for the final report:

```
APTL Smoke Test Report
Date: ____
Tested by: [Claude Code Teams]
Profiles: wazuh, victim, kali, enterprise, soc [, dns, fileshare, mail]

Section                    | Total | Pass | Fail | Skip
---------------------------|-------|------|------|-----
1. Network Segmentation    |   9   |      |      |
2. Service Health           |  24   |      |      |
3. Red Team: Attack Surface |  21   |      |      |
4. Blue Team: Detection     |  24   |      |      |
5. Phase 3 Services         |  13   |      |      |
6. Scenario Engine & CLI    |  15   |      |      |
7. Wazuh Rules              |   6   |      |      |
8. MCP Build                |   6   |      |      |
9. Regression               |   8   |      |      |
---------------------------|-------|------|------|-----
TOTAL                       | 126   |      |      |

Blockers:
  [list any FAIL results that prevent further testing]

Failures:
  [ID] [description] [actual result] [notes]

Notes:
  [any environmental issues, timing dependencies, etc.]
```

---

## Execution Notes

- **Startup time**: The full stack (wazuh + enterprise + soc) takes 10-15 minutes for all services to become healthy. TheHive and MISP are the slowest. Don't start testing section 4 until SVC-30 through SVC-38 all pass.
- **Order matters**: Section 3 (red team) should run before section 4 (blue team) because the blue team tests verify that attacks were detected. The Infrastructure Tester and Red Team Tester should work sequentially, not in parallel, for sections 2-3. Blue Team Tester can start section 4a/4c while red team finishes.
- **MISP first-run**: MISP takes a long time on first boot (database migration). MCP-01 and MCP-02 may need to be retried after 5-10 minutes.
- **TheHive first-run**: TheHive requires initial admin setup (create org + user + API key) before the MCP server can authenticate. The tester should create the admin account via the UI at `http://localhost:9000` first, then set `THEHIVE_API_KEY` in the environment.
- **Shuffle first-run**: Shuffle needs initial login and API key creation at `https://localhost:3443`. Set `SHUFFLE_API_KEY` after initial setup.
- **Section 5 tests**: These require stopping the lab, changing `aptl.json`, and restarting. Run them last to avoid disrupting other tests.
- **Kali tool availability**: Some Kali tools (ldapsearch, psql, smbclient) may need to be installed if not in the base image. The Red Team Tester should check and install as needed: `apt-get install -y ldap-utils postgresql-client smbclient`.
