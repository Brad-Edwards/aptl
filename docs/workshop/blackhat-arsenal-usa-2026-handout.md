# APTL Black Hat Arsenal Lab Handout

APTL is open source software available at
<https://github.com/Brad-Edwards/aptl>.

APTL is part of the OpenRAE agentic environments ecosystem:
<https://github.com/OpenRAE>. OpenRAE is also open source software.

## Access

Fill this block from the card at your seat.

| Item | Value |
| --- | --- |
| Seat number | |
| Workstation or RDP URL | |
| Login username | |
| Login password | |
| Agent window or bookmark | |
| Need help? | Raise your hand or use the support signal at the seat |

## SOC Bookmarks

Open these from the workstation or browser RDP:

| Tool | URL | Login |
| --- | --- | --- |
| Wazuh Dashboard | `https://localhost` | `admin` / `SecretPassword` |
| TheHive | `https://localhost:9000` | `aptl-svc@thehive.local` / `AptlService2024!` |
| Cortex | `http://localhost:9001` | `aptl-svc@cortex.local` / `AptlCortexService2026!` |
| Shuffle | `https://localhost:3443` | `admin` / `ShuffleAdmin2024!` |
| MISP | `https://localhost:8443` | `admin@admin.test` / `admin` |

Cortex also has the lab API key `aptlcortexlabapikey2026purple` if the agent
checks the API directly. Shuffle also has API key
`31a211c4-ea5c-4a49-b022-5e2434e758a7`.

Some SOC tools use lab TLS certificates. Accept the browser warning if prompted.

## What You Are Using

APTL, Advanced Purple Team Lab, is an isolated cyber range where an AI agent can
operate attacker, defender, and enterprise tools.

Today you are inside TechVault:

| Side | What is there |
| --- | --- |
| Enterprise | TechVault web app, database, Active Directory, DNS, file share, victim host, and workstation |
| Attacker | Kali, driven by your agent |
| Defender | Wazuh, Suricata, MISP, TheHive, Cortex, and Shuffle |

Your mission is one purple-team incident flow:

1. Attack TechVault.
2. Investigate and enrich the alert across the SOC.
3. Fix the vulnerable app behavior.
4. Test the same attack again and update the incident result.

Only target `http://172.20.1.20:8080`. Do not point prompts or commands outside
this lab.

## 1. Attack

Ask the agent:

```text
This is an authorized isolated APTL lab. From Kali only, test the TechVault
customer API at http://172.20.1.20:8080/api/v1/customers with one UNION SELECT
SQL injection. Use api_key=bh-lab and a unique marker like PwnCorp-<time>.
Show the curl command, HTTP status, and whether the marker appears in the JSON
response. Do not target anything outside this lab URL.
```

Expected:

- HTTP status is `200`.
- The JSON response contains your `PwnCorp-*` marker as a fake customer row.

That proves the attack worked.

## 2. Work the SOC

Ask the agent:

```text
Use my PwnCorp marker to work this as one SOC incident. Do all of this and
return a short incident summary:

1. Wazuh: find the alert for the marker and report rule ID, description,
   source IP, target/log location, URL, and HTTP status.
2. Suricata: find the matching network IDS alert for the same source, target,
   and URL.
3. MISP: look up the source IP and report the seeded threat-intel context.
4. Shuffle: find the APTL Alert to Case workflow execution for this marker and
   report whether it finished.
5. TheHive: find the automatically created case and add a brief analyst note
   with exploitability, source IP, URL, and detection summary.
6. Cortex: check TheHive's Cortex connector status and analyzer availability.
```

Expected core evidence:

| Tool | What you should get |
| --- | --- |
| Wazuh | Rule `302010`, `SQL injection attempt detected in URL`, source `172.20.1.30` |
| Suricata | Signature `1000010`, `APTL SQL Injection Attempt - UNION SELECT` |
| MISP | Seeded `ip-src` context for `172.20.1.30` |
| Shuffle | A finished APTL Alert to Case workflow execution |
| TheHive | An automatically created case titled `[Wazuh 302010] SQL injection attempt detected in URL` |
| Cortex | TheHive connector `OK`; analyzer catalog may be empty |

Wazuh starts the alert. The SOC exercise is working the incident through the
rest of the defensive stack.

## 3. Fix

Ask the agent:

```text
Patch only the TechVault /api/v1/customers search query so it uses a
parameterized SQL query instead of building SQL with the search string. Back up
/app/app.py first, run a Python syntax check, restart the aptl-webapp
container, and show the changed lines.
```

The important fix is that the query uses a parameter instead of inserting user
input into the SQL string:

```python
cur.execute(
    "SELECT id, company_name, contact_name, contact_email, plan_tier FROM customers WHERE company_name LIKE %s",
    (f"%{search}%",),
)
```

## 4. Test

Ask the agent:

```text
Repeat the same UNION SELECT test against the TechVault customer API with a new
PwnCorp marker. Confirm whether the marker appears in the response, then check
Wazuh, Suricata, Shuffle, and TheHive for the new attempted attack. Summarize
the result as an update to the same incident: exploitability, detection, and
service health.
```

Expected after the fix:

- HTTP status is still `200`.
- The response is `[]` or otherwise does not contain your new marker.
- Wazuh and Suricata still detect the attempted SQLi.
- Shuffle still creates or updates TheHive incident evidence.

That is the purple-team win: the exploit no longer works, and the SOC still
sees the attempt.

## If Something Is Slow

- Wazuh indexing can lag by 30 to 60 seconds. Wait, then ask again.
- If the agent refuses, include "authorized isolated APTL lab" and "only target
  `http://172.20.1.20:8080`" in the prompt.
- If the attack no longer works, the previous participant may have fixed the
  app and the seat needs reset. Raise your hand.
- If a SOC component reports a gap, keep going and record it in the incident
  summary.
- If the seat breaks, do not debug it. Raise your hand.

## If You Stay Longer

Continue the same incident:

```text
Improve the same incident record with a containment decision, false-positive
analysis, and a short executive summary for the TechVault owner.
```

```text
Map the attack and response to MITRE ATT&CK and list which TechVault enterprise
systems would matter if this became a real compromise.
```

```text
Turn the incident into a Shuffle design: Wazuh alert, MISP lookup, Cortex
enrichment, TheHive case update, analyst approval, and containment.
```

## Before You Leave

Thank you for trying Advanced Purple Team Labs. Please let me, Brad, know what
you think.
