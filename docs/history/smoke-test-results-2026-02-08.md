# APTL Smoke Test Results

**Date:** 2026-02-08
**Tested by:** Claude Code (Opus 4.6)
**Branch:** sock-in-a-box
**Profiles:** wazuh, victim, kali, enterprise, soc
**Lab state at start:** No containers running

---

## Blockers Found

Three critical issues prevent full test execution:

1. **BLOCKER: Wazuh Manager analysisd crashes on startup**
   - `ad_rules.xml` references decoder `samba` which does not exist in Wazuh's default decoders
   - Error: `wazuh-analysisd: ERROR: Invalid decoder name: 'samba'. CRITICAL: (1220): Error loading the rules: 'etc/rules/ad_rules.xml'`
   - Impact: No alerts generated, Wazuh API unreachable, Dashboard blank. Blocks ALL blue team detection tests (BLUE-01 through BLUE-06, MCP-13, SOC-01 through SOC-04)
   - Fix: Create a custom `samba` decoder or change `ad_rules.xml` to use a valid decoder

2. **BLOCKER: PostgreSQL container crash-loops**
   - `postgres:16-alpine` does not have `/var/log/postgresql/` directory
   - `logging_collector=on` with `log_directory=/var/log/postgresql` causes immediate FATAL on startup
   - Error: `FATAL: could not open log file "/var/log/postgresql/postgresql.log": No such file or directory`
   - Impact: DB down, webapp auth broken (all login/API endpoints return 500). Blocks 12 web app tests (RED-02 through RED-04, RED-08 through RED-12, RED-31 through RED-34)
   - Fix: Either create the dir via volume mount/entrypoint, or use `/var/lib/postgresql/data/log`

3. **BLOCKER: Suricata container crash-loops**
   - Config files mounted as `:ro` but Suricata entrypoint tries to `chown` them
   - Error: `chown: changing ownership of '/etc/suricata/rules/local.rules': Read-only file system`
   - Impact: No IDS alerts. Blocks BLUE-10 through BLUE-13
   - Fix: Remove `:ro` flags, or use a custom entrypoint that skips chown

---

## Additional Issues

4. **jessica.williams user not created in AD** - Password `password123` likely rejected by Samba password complexity policy. Provisioning script suppresses errors with `2>/dev/null || true`. Affects RED-22.

5. **AD requires LDAPS for simple bind** - Plain LDAP bind returns "Transport encryption required". Tests must use `LDAPTLS_REQCERT=never ldapsearch -H ldaps://...` instead of `ldap://`. Affects RED-21 through RED-25 test commands (but tests work via LDAPS).

6. **Shuffle backend cannot connect to OpenSearch** - TLS certificate for shuffle-opensearch is only valid for `node-0.example.com, localhost`, not `shuffle-opensearch`. Shuffle backend loops retrying forever. Affects SVC-35, SVC-36, MCP-06, MCP-07.

7. **TheHive very slow to start** - Still in "starting" state after 10+ minutes. May eventually come up but blocks SOC workflow tests during this test window.

8. **`aptl lab start` exits with failure** - Because DB container fails its health check, the orchestration reports failure. However, most other containers DO start successfully. Containers must be started manually with `docker start` for those with unmet dependencies.

---

## 1. Infrastructure: Network Segmentation

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| NET-01 | Security network exists | aptl-security 172.20.0.0/24 | **PASS** | Subnet: 172.20.0.0/24 |
| NET-02 | DMZ network exists | aptl-dmz 172.20.1.0/24 | **PASS** | Subnet: 172.20.1.0/24 |
| NET-03 | Internal network exists | aptl-internal 172.20.2.0/24 | **PASS** | Subnet: 172.20.2.0/24 |
| NET-04 | Red team network exists | aptl-redteam 172.20.4.0/24 | **PASS** | Subnet: 172.20.4.0/24 |
| NET-05 | Wazuh manager on 3 networks | security + dmz + internal | **PASS** | ['aptl_aptl-dmz', 'aptl_aptl-internal', 'aptl_aptl-security'] |
| NET-06 | Kali on dmz + redteam + internal | 3 attack networks | **PASS** | ['aptl_aptl-dmz', 'aptl_aptl-internal', 'aptl_aptl-redteam'] |
| NET-07 | Webapp on dmz + internal | Both networks | **PASS** | ['aptl_aptl-dmz', 'aptl_aptl-internal'] |
| NET-08 | DB only on internal | Only aptl-internal | **PASS** | ['aptl_aptl-internal'] |
| NET-09 | AD only on internal | Only aptl-internal | **PASS** | ['aptl_aptl-internal'] |

---

## 2. Infrastructure: Service Health

### 2a. Wazuh Stack

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| SVC-01 | Wazuh Manager healthy | healthy | **FAIL** | unhealthy - analysisd crashes on ad_rules.xml (invalid 'samba' decoder) |
| SVC-02 | Wazuh Indexer healthy | healthy | **PASS** | |
| SVC-03 | Wazuh Dashboard healthy | HTTPS on 443 | **FAIL** | Returns empty response (depends on working manager) |
| SVC-04 | Wazuh API responds | 200 on 55000 | **FAIL** | Returns empty (analysisd down) |
| SVC-05 | Indexer API responds | 200 on 9200 | **PASS** | Returns OpenSearch version JSON |

### 2b. Enterprise Services

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| SVC-10 | AD container healthy | healthy | **PASS** | |
| SVC-11 | AD domain info | TECHVAULT.LOCAL | **PASS** | Domain: techvault.local, DC: dc.techvault.local |
| SVC-12 | AD users exist | sarah.mitchell, jessica.williams, svc-sql | **FAIL** | jessica.williams missing (password complexity rejection). 15 other users present. |
| SVC-13 | AD SPNs set | svc-sql has MSSQLSvc | **PASS** | MSSQLSvc/db.techvault.local:1433 and MSSQLSvc/db.techvault.local |
| SVC-14 | PostgreSQL healthy | healthy | **FAIL** | Crash-looping: /var/log/postgresql/ doesn't exist in postgres:16-alpine |
| SVC-15 | PostgreSQL schema loaded | Tables exist | **FAIL** | Cannot exec - container restarting |
| SVC-16 | PostgreSQL seed data | 10 users, 8 customers | **FAIL** | Cannot exec - container restarting |
| SVC-17 | Web app healthy | Responds on 8080 | **PASS** | Returns HTML (static pages work, DB-dependent endpoints return 500) |
| SVC-18 | Web app login page | HTML with login form | **PASS** | `<title>Login - TechVault Solutions</title>` |
| SVC-19 | Victim container healthy | SSH on 2022 | **PASS** | hostname: app.techvault.local |
| SVC-20 | Kali container healthy | SSH on 2023 | **PASS** | hostname: kali-redteam (host key changed warning - cosmetic) |

### 2c. SOC Stack

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| SVC-30 | MISP running | HTTPS on 8443 | **PASS** | Returns HTML login page |
| SVC-31 | MISP DB healthy | MariaDB running | **PASS** | healthy |
| SVC-32 | TheHive running | API on 9000 | **FAIL** | Still "starting" after 10+ min. Waiting on Cassandra migrations. |
| SVC-33 | TheHive Cassandra healthy | healthy | **PASS** | |
| SVC-34 | TheHive ES healthy | healthy | **PASS** | |
| SVC-35 | Shuffle backend running | API on 5001 | **FAIL** | TLS cert mismatch: cert valid for node-0.example.com,localhost not shuffle-opensearch |
| SVC-36 | Shuffle frontend running | UI on 3443 | **FAIL** | No response (depends on backend) |
| SVC-37 | Cortex running | API on 9001 | **PASS** | Returns version JSON: Cortex 3.1.8-1 |
| SVC-38 | Suricata running | Container running | **FAIL** | Crash-looping: chown fails on :ro mounted config files |

---

## 3. Red Team: Attack Surface Validation

### 3a. Web Application

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| RED-01 | Web app reachable from Kali | HTTP 200 | **PASS** | 200 from 172.20.1.20:8080 |
| RED-02 | SQL injection in login | Bypasses auth/SQL error | **BLOCKED** | Returns 500 (DB down, not SQLi-related) |
| RED-03 | SQL injection in search | Returns injected data | **BLOCKED** | Requires session cookie; login broken (DB down) |
| RED-04 | Command injection in ping | Returns cmd output | **BLOCKED** | Endpoint requires auth; redirects to /login |
| RED-05 | .env file exposed | DB credentials | **PASS** | Leaks DB_PASSWORD=techvault_db_pass, JWT_SECRET=techvault-jwt-weak |
| RED-06 | Debug endpoint exposed | App version, DB config | **PASS** | Exposes DB host/user/port, Flask 3.1.0, Python 3.11 |
| RED-07 | robots.txt reveals paths | /admin, /debug, /backup | **PASS** | Disallow: /admin, /api/internal, /debug, /backup |
| RED-08 | Admin panel accessible | No role check | **BLOCKED** | Requires auth session (DB down) |
| RED-09 | IDOR on user API | Other users' data | **BLOCKED** | Returns 500 (DB down) |
| RED-10 | Weak admin credentials | admin/admin123 | **BLOCKED** | Login returns 500 (DB down) |
| RED-11 | JWT with weak secret | Forgeable token | **BLOCKED** | Token endpoint returns 500 (DB down) |
| RED-12 | Backup config exposes AWS creds | AKIA keys | **BLOCKED** | Requires admin access + DB |

### 3b. Active Directory

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| RED-20 | LDAP reachable from Kali | Port 389 open | **PASS** | Port 389/tcp open, MAC visible |
| RED-21 | LDAP anonymous bind | Base DN info | **FAIL** | Samba AD rejects anonymous: "Operation unavailable without authentication" |
| RED-22 | Weak password login | jessica.williams:password123 | **FAIL** | User doesn't exist in AD (provisioning failed silently). Also requires LDAPS. |
| RED-23 | SPN enumeration | svc-sql, svc-web SPNs | **PASS** | Found via LDAPS with contractor.temp creds: svc-sql (MSSQLSvc), svc-web (HTTP) |
| RED-24 | Contractor account active | contractor.temp:Welcome1! | **PASS** | Works via LDAPS. Full domain base DN returned. |
| RED-25 | Over-privileged svc account | svc-backup in Domain Admins | **PASS** | memberOf: CN=Domain Admins confirmed |

### 3c. Database

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| RED-30 | PostgreSQL reachable from Kali | Port 5432 open | **FAIL** | Host down (container crash-looping) |
| RED-31 | DB login with leaked creds | Connects | **BLOCKED** | DB container down |
| RED-32 | Customer data accessible | Customer records | **BLOCKED** | DB container down |
| RED-33 | AWS creds in backup_config | AKIA keys | **BLOCKED** | DB container down |
| RED-34 | Password hashes extractable | MD5 hashes | **BLOCKED** | DB container down |

### 3d. Victim / App Server

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| RED-40 | Victim reachable from Kali | SSH works | **FAIL** | Permission denied (publickey) - Kali doesn't have the lab SSH key |
| RED-41 | Kali can reach internal | Ping AD succeeds | **PASS** | 1 packet, 0% loss, rtt=1.36ms |
| RED-42 | Kali can reach DMZ | Ping webapp succeeds | **PASS** | 1 packet, 0% loss, rtt=0.59ms |

---

## 4. Blue Team: Detection & SOC Validation

### 4a. Wazuh Detection Rules

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| BLUE-01 | SQLi detected by Wazuh | sqli/web_attack alert | **BLOCKED** | Wazuh analysisd down (ad_rules.xml blocker) |
| BLUE-02 | Command injection detected | rule.id 302030 | **BLOCKED** | Wazuh analysisd down |
| BLUE-03 | Sensitive file access detected | rule.id 302040 | **BLOCKED** | Wazuh analysisd down |
| BLUE-04 | AD brute force detected | rule.id 301002 | **BLOCKED** | Wazuh analysisd down |
| BLUE-05 | AD enumeration detected | rule.id 301021 | **BLOCKED** | Wazuh analysisd down |
| BLUE-06 | DB auth failure detected | rule.id 304000 | **BLOCKED** | Wazuh analysisd down |
| BLUE-07 | New Wazuh rules loaded | All rule files present | **FAIL** | Files present on disk but ad_rules.xml fails to load (invalid decoder) |

### 4b. Suricata IDS

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| BLUE-10 | Suricata eve.json generated | File exists | **BLOCKED** | Suricata container crash-looping |
| BLUE-11 | Port scan alert | Suricata alert | **BLOCKED** | Suricata down |
| BLUE-12 | SQLi detected at network level | Suricata alert | **BLOCKED** | Suricata down |
| BLUE-13 | Local rules loaded | File present | **BLOCKED** | Suricata down |

### 4c. MCP Server Connectivity

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| MCP-01 | mcp-threatintel responds | API info | **BLOCKED** | MCP server not loaded in this session (MISP running but MCP not wired) |
| MCP-02 | mcp-threatintel search IOCs | Results | **BLOCKED** | MCP server not loaded |
| MCP-03 | mcp-casemgmt responds | API info | **BLOCKED** | MCP server not loaded; TheHive still starting |
| MCP-04 | mcp-casemgmt list cases | List | **BLOCKED** | MCP server not loaded |
| MCP-05 | mcp-casemgmt create case | Case ID | **BLOCKED** | MCP server not loaded |
| MCP-06 | mcp-soar responds | API info | **BLOCKED** | MCP server not loaded; Shuffle backend broken |
| MCP-07 | mcp-soar list workflows | Workflow list | **BLOCKED** | MCP server not loaded |
| MCP-08 | mcp-network responds | API info | **BLOCKED** | MCP server not loaded; Suricata down |
| MCP-09 | mcp-network query IDS alerts | Suricata alerts | **BLOCKED** | MCP server not loaded |
| MCP-10 | mcp-network query DNS events | DNS events | **BLOCKED** | MCP server not loaded |
| MCP-11 | mcp-network query web attacks | Web attacks | **BLOCKED** | MCP server not loaded |
| MCP-12 | mcp-red still works | Command execution | **PASS** | `id` returns uid=1000(kali) |
| MCP-13 | mcp-wazuh still works | Alert results | **PASS** | Query succeeds but returns 0 hits (analysisd down, no alerts) |

### 4d. SOC Workflow

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| SOC-01 | Create TheHive case from alert | Case created | **BLOCKED** | TheHive not ready; Wazuh has no alerts |
| SOC-02 | Add observable to case | Observable attached | **BLOCKED** | TheHive not ready |
| SOC-03 | Query MISP for IOC | Returns result | **BLOCKED** | mcp-threatintel not loaded |
| SOC-04 | Correlate network + host alerts | Both alerts found | **BLOCKED** | Both Suricata and Wazuh non-functional |

---

## 5. Phase 3: Extended Enterprise Services

### 5a. DNS Server

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| DNS-01 | DNS container healthy | healthy | **SKIP** | Requires dns=true in aptl.json |
| DNS-02 | Forward lookup works | 172.20.1.20 | **SKIP** | |
| DNS-03 | AD SRV records resolve | dc.techvault.local | **SKIP** | |
| DNS-04 | Reverse lookup works | webapp.techvault.local | **SKIP** | |
| DNS-05 | MX record resolves | mail.techvault.local | **SKIP** | |
| DNS-06 | Query logging enabled | Queries in log | **SKIP** | |

### 5b. File Server

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| FS-01 | File server healthy | healthy | **SKIP** | Requires fileshare=true |
| FS-02 | Share listing works | Lists shares | **SKIP** | |
| FS-03 | Public share anonymous | Can list files | **SKIP** | |
| FS-04 | Shared drive planted data | wifi-passwords.txt | **SKIP** | |
| FS-05 | Engineering share creds | deploy.sh | **SKIP** | |
| FS-06 | IT-Backups SSH key | deploy_key | **SKIP** | |
| FS-07 | HR share PII | directory.csv | **SKIP** | |

### 5c. Mail Server

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| MAIL-01 | Mail container running | running | **SKIP** | Requires mail=true |
| MAIL-02 | SMTP port open | Port 25 | **SKIP** | |
| MAIL-03 | Send test email | Delivery succeeds | **SKIP** | |

---

## 6. Scenario Engine & Python CLI

### 6a. CLI Commands

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| CLI-01 | `aptl scenario list` | Lists 3 scenarios | **PASS** | Rich table with 3 rows. Must run from project root (CWD-relative `scenarios/` dir) |
| CLI-02 | `aptl scenario show webapp-compromise` | 6 steps with MITRE | **PASS** | 6 steps, 6 MITRE techniques, full attack chain displayed |
| CLI-03 | `aptl scenario show ad-domain-compromise` | 5 steps, advanced | **PASS** | 5 steps, advanced difficulty, 45min time estimate |
| CLI-04 | `aptl scenario show lateral-movement-data-theft` | 5 steps, fileshare prereq | **PASS** | 5 steps, fileshare in prerequisites |
| CLI-05 | Show by file path | Same output as by ID | **PASS** | `scenarios/01-webapp-compromise.json` produces identical output |
| CLI-06 | `aptl lab status` | Shows containers | **PASS** | Reports "Lab is not running" (correct for pre-start state) |

### 6b. Config Model

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| CFG-01 | Config loads with new profiles | No errors | **PASS** | Returns ['wazuh', 'victim', 'kali', 'enterprise', 'soc'] |
| CFG-02 | All new profiles listed | enterprise, soc | **PASS** | Both enterprise and soc present in enabled_profiles() |
| CFG-03 | Unknown profile rejected | Validation error | **PASS** | `pydantic_core.ValidationError: Extra inputs are not permitted` |

### 6c. Scenario Definitions

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| SCEN-01 | All scenarios parse | No errors | **PASS** | "3 scenarios loaded" |
| SCEN-02 | Scenario 01 has 6 steps | 6 steps | **PASS** | 6 steps, techniques: T1595.002, T1190, T1059.004, T1548.003, T1005, T1048.003 |
| SCEN-03 | Scoring math works | 50% coverage | **PASS** | Coverage: 50%, Gaps: [T1548.003, T1005, T1048.003] |

---

## 7. Wazuh Rule File Verification

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| RULE-01 | ad_rules.xml mounted | File exists | **PASS** | Present in /var/ossec/etc/rules/ |
| RULE-02 | webapp_rules.xml mounted | File exists | **PASS** | Present |
| RULE-03 | suricata_rules.xml mounted | File exists | **PASS** | Present |
| RULE-04 | database_rules.xml mounted | File exists | **PASS** | Present |
| RULE-05 | Manager config includes rules | 4 rule_include lines | **PASS** | All 4 new + 2 existing (falco, kali_redteam) = 6 total |
| RULE-06 | No rule loading errors | Clean start | **FAIL** | CRITICAL: Invalid decoder name 'samba' in ad_rules.xml |

---

## 8. MCP Server Build Verification

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| BUILD-01 | mcp-threatintel builds | Exit 0 | **PASS** | tsc clean, 162 deps |
| BUILD-02 | mcp-casemgmt builds | Exit 0 | **PASS** | tsc clean, 162 deps |
| BUILD-03 | mcp-soar builds | Exit 0 | **PASS** | tsc clean, 162 deps |
| BUILD-04 | mcp-network builds | Exit 0 | **PASS** | tsc clean, 162 deps |
| BUILD-05 | build-all-mcps.sh includes new servers | 8 references | **PASS** | 8 servers in for loop + aptl-mcp-common |
| BUILD-06 | .mcp.json references all servers | 7 entries | **PASS** | 7 server entries (no windows-re in .mcp.json) |

---

## 9. Regression: Existing Features

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| REG-01 | Kali SSH works | Login on 2023 | **PASS** | uid=1000(kali), host key changed warning (cosmetic) |
| REG-02 | Victim SSH works | Login on 2022 | **PASS** | uid=1000(labadmin) |
| REG-03 | Kali red team tools | nmap, metasploit | **PASS** | nmap at /usr/bin/nmap, Metasploit 6.4.99-dev |
| REG-04 | Wazuh agent on victim | Agent running | **PASS** | /var/ossec/bin/wazuh-agentd present |
| REG-05 | Kali logs forwarded | bash_history.log | **PASS** | /var/log/bash_history.log exists (0 bytes at test time) |
| REG-06 | `aptl lab start` works | 12-step orchestration | **FAIL** | Exits with failure due to DB health check failure. Most containers start successfully but some need manual `docker start`. |
| REG-07 | `aptl lab stop` works | All containers stop | **SKIP** | Not tested (lab needed for other tests) |
| REG-08 | `aptl lab stop -v` removes volumes | Volumes cleaned | **SKIP** | Not tested |

---

## Summary

| Section | Total | Pass | Fail | Blocked | Skip |
|---------|-------|------|------|---------|------|
| 1. Network Segmentation | 9 | 9 | 0 | 0 | 0 |
| 2. Service Health | 24 | 14 | 10 | 0 | 0 |
| 3. Red Team: Attack Surface | 21 | 9 | 4 | 8 | 0 |
| 4. Blue Team: Detection | 24 | 2 | 1 | 21 | 0 |
| 5. Phase 3 Services | 16 | 0 | 0 | 0 | 16 |
| 6. Scenario Engine & CLI | 9 | 9 | 0 | 0 | 0 |
| 7. Wazuh Rules | 6 | 5 | 1 | 0 | 0 |
| 8. MCP Build | 6 | 6 | 0 | 0 | 0 |
| 9. Regression | 8 | 5 | 1 | 0 | 2 |
| **TOTAL** | **123** | **59** | **17** | **29** | **18** |

**Pass rate (excluding skips and blocked): 59/76 = 78%**
**Pass rate (excluding skips only): 59/105 = 56%**

---

## Root Cause Analysis

The 17 failures and 29 blocked tests trace back to **3 root causes**:

### Root Cause 1: ad_rules.xml invalid decoder (37 tests affected)
- **Direct failures:** SVC-01, SVC-03, SVC-04, BLUE-07, RULE-06 (5)
- **Blocked:** BLUE-01 through BLUE-06, MCP-13 (partial), SOC-01 through SOC-04 (10+)
- **Fix:** Add a custom Samba decoder XML file, or rewrite ad_rules.xml to use `decoded_as` values that exist in default Wazuh decoders (e.g., parse syslog format instead)

### Root Cause 2: PostgreSQL missing log directory (14 tests affected)
- **Direct failures:** SVC-14, SVC-15, SVC-16, RED-30, REG-06 (5)
- **Blocked:** RED-02 through RED-04, RED-08 through RED-12, RED-31 through RED-34 (12)
- **Fix:** Add to docker-compose.yml command: `mkdir -p /var/log/postgresql &&` before `postgres`, OR add a volume mount for that path, OR change log_directory to `/var/lib/postgresql/data/log`

### Root Cause 3: Suricata read-only config mount (5 tests affected)
- **Direct failures:** SVC-38 (1)
- **Blocked:** BLUE-10 through BLUE-13 (4)
- **Fix:** Remove `:ro` from the suricata volume mounts in docker-compose.yml, OR use a custom entrypoint that copies configs to a writable location before starting

### Independent failures:
- **SVC-12:** jessica.williams not provisioned (password complexity). Fix: use a complexity-compliant password like `P@ssword123!`
- **SVC-32:** TheHive slow startup (may resolve with more time)
- **SVC-35/SVC-36:** Shuffle OpenSearch TLS cert mismatch. Fix: generate cert with SAN including `shuffle-opensearch`, or set `SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY=true`
- **RED-21:** Samba anonymous bind disabled (may be intentional for security)
- **RED-22:** Cascading from SVC-12 (user doesn't exist) + requires LDAPS
- **RED-40:** Kali doesn't have SSH key for victim (key not distributed to Kali container)

---

## Recommended Fix Priority

1. **PostgreSQL log directory** - simplest fix, unblocks DB + webapp + 12 red team tests
2. **ad_rules.xml decoder** - create samba decoder or rewrite rules, unblocks entire blue team
3. **Suricata :ro mounts** - remove :ro flags, unblocks IDS tests
4. **jessica.williams password** - change to complexity-compliant password in provision script
5. **Shuffle TLS cert** - add shuffle-opensearch to cert SAN or skip SSL verify
6. **Kali SSH key for victim** - distribute aptl_lab_key to Kali container

After fixing items 1-3, re-running the smoke test should bring pass rate from 56% to ~85%+.
