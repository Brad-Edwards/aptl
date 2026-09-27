# Black Hat Arsenal USA 2026 Facilitator Guide

This is the facilitator version of the short Arsenal lab. It assumes the full
TechVault stack is running, not a reduced scenario.

There is one attendee flow:

1. Attack TechVault from Kali.
2. Work the alert as one SOC incident across Wazuh, Suricata, MISP, Shuffle,
   TheHive, Cortex, and observability.
3. Fix the vulnerable TechVault app behavior.
4. Retest the same attack and summarize exploitability plus detection.

Validated on `aptl-arsenal-seat` (`3.148.112.89`) on August 5, 2026:

- Attack marker `PwnCorp-seat-final3-082239`: SQLi returned `http=200`,
  `marker_present=1`.
- Suricata generated signature `1000010`, `APTL SQL Injection Attempt - UNION
  SELECT`.
- Wazuh generated rule `302010`, level 10, `SQL injection attempt detected in
  URL`; Wazuh also ingested Suricata rule `86601`.
- Shuffle workflow `APTL Alert to Case` created a finished execution
  `8eec7454-4755-4617-adf7-eb1df5eb4c3d`.
- TheHive created cases `#10` and `#11`, `[Wazuh 302010] SQL injection attempt
  detected in URL`.
- Temporary app fix changed `/api/v1/customers` to a parameterized query.
- Fix marker `PwnCorp-seat-final3fix-082255`: returned `http=200`,
  `marker_present=0`, response `[]`, while Wazuh/Suricata/Shuffle/TheHive still
  saw the attempted attack.
- Retest Shuffle execution `96d7e3b9-6741-4c05-84f2-0bb2537e7716` finished;
  TheHive created cases `#12` and `#13`.
- Reset marker `PwnCorp-seat-final3reset-082309`: after restoring the backup,
  SQLi again returned `marker_present=1`.

Known note for facilitator language: TheHive reports Cortex connector `OK`, but
Cortex `/api/analyzer` currently returns an empty analyzer catalog. Treat that
as an enrichment coverage finding, not a reason to skip Cortex.

## The Frame

Use this sentence repeatedly:

> TechVault is the thing being attacked. The SOC is how we see it. The agent is
> how you drive the whole loop.

APTL has three sides:

| Side | What to say |
| --- | --- |
| Enterprise | TechVault: web app, database, Active Directory, DNS, file share, victim host, and workstation |
| Attacker | Kali, driven by the participant's agent through MCP |
| Defender | Wazuh, Suricata, MISP, TheHive, Cortex, Shuffle, Grafana, Tempo, and OpenTelemetry |

## Five-Minute Intro

**0:00 to 0:45 - what this is**

> APTL is Advanced Purple Team Lab. It stands up a fictional enterprise called
> TechVault, a Kali attacker environment, and a SOC stack. Agents can operate
> across those systems through MCP.

**0:45 to 1:45 - what is being attacked**

> TechVault is not one target box. It has a web app, database, Active
> Directory, DNS, file sharing, victim hosts, and a workstation. That is the
> enterprise side of the range.

**1:45 to 2:45 - what defends it**

> The SOC side includes Wazuh for SIEM and host alerts, Suricata for network
> IDS, MISP for threat intel, TheHive and Cortex for case management and
> enrichment, Shuffle for SOAR, and Grafana, Tempo, and OpenTelemetry for
> runtime observability.

**2:45 to 3:45 - what attendees do**

> Your mission is one incident flow: exploit a TechVault customer-search SQL
> injection from Kali, investigate Wazuh and Suricata alerts, enrich the source
> IP in MISP, confirm Shuffle created a TheHive case, check Cortex and
> observability, patch the vulnerable query, then rerun the exact attack and
> prove it no longer injects a row.

**3:45 to 5:00 - safety and start**

> Only target the lab URL and IPs on the handout. Do not point prompts or
> commands outside this seat. Start at the agent window and let it drive both
> the attacker and SOC sides.

## Preflight

Run this before attendees use a seat:

```bash
docker ps --filter name=aptl --format '{{.Names}}' \
  | grep -E 'aptl-kali|aptl-webapp|aptl-db|aptl-wazuh-manager|aptl-wazuh-indexer|aptl-misp|aptl-thehive|aptl-cortex|aptl-shuffle-backend|aptl-shuffle-frontend|aptl-shuffle-orborus|aptl-suricata|aptl-grafana-otel|aptl-tempo|aptl-otel-collector'
```

Confirm the app is reachable from Kali:

```bash
docker exec aptl-kali curl -sS -o /dev/null -w '%{http_code}\n' \
  http://172.20.1.20:8080/api/v1/customers?api_key=bh-lab
```

Expected: `200`.

Confirm the seat starts vulnerable:

```bash
docker exec aptl-webapp sh -lc \
  "grep -n \"query = f\\|cur.execute(query)\" /app/app.py | sed -n '1,20p'"
```

Expected: the customer search f-string and `cur.execute(query)` are present.

Confirm agent readiness:

- Agent session is logged in.
- `/home/ubuntu/aptl3` is trusted.
- APTL MCP servers are approved.
- The first prompt does not show login, trust, or MCP approval dialogs.

## Presenter Demo Track

Use this when demonstrating the loop before handing the seat to an attendee.
Keep it fast and narrate the system roles rather than every command.

**1. Show the enterprise target.**

Say:

> I am attacking TechVault, not a toy endpoint. The specific first foothold is
> the customer API, but the enterprise around it includes the app, database,
> AD, DNS, file share, victim host, and workstation.

Run the SQLi through the agent or fallback command. Point out the marker row in
the JSON response.

**2. Show the SOC taking over.**

Say:

> Wazuh is the first alert, but it is not the whole SOC. The agent is going to
> turn that alert into an incident: IDS confirmation, threat-intel lookup, SOAR
> execution, case review, enrichment readiness, and telemetry health.

Expected demo beats:

- Wazuh: rule `302010`, source `172.20.1.30`, HTTP `200`, URL contains marker.
- Suricata: signature `1000010`, same source/target URL.
- MISP: `172.20.1.30` has seeded APTL threat-intel context.
- Shuffle: the `APTL Alert to Case` workflow execution is `FINISHED`.
- TheHive: automatic case exists with the marker in the description.
- Cortex: TheHive connector is `OK`; analyzer catalog may be empty.
- Observability: Grafana, Tempo, and OTel health are checked.

**3. Show purple-team closure.**

Say:

> Now we change the system and rerun the same attack. The fix should change
> exploitability, while detection still sees the attempt.

Patch the customer search query, restart `aptl-webapp`, rerun SQLi, and show
`marker_present=0` plus fresh Wazuh/Suricata/Shuffle/TheHive evidence.

**4. Reset before the next attendee.**

Restore the app backup and rerun one quick SQLi check. The next attendee should
start with `marker_present=1`.

## Attendee Prompts

### 1. Orient

Ask the attendee to paste:

```text
Briefly identify the three sides of this APTL lab: the TechVault enterprise
target, the Kali attacker, and the SOC/defensive stack.
```

Expected: the agent names TechVault as the target, Kali as the attacker, and
the SOC stack as Wazuh, Suricata, MISP, TheHive, Cortex, Shuffle, Grafana,
Tempo, and OpenTelemetry.

### 2. Attack

Ask the attendee to paste:

```text
This is an authorized isolated APTL lab. From Kali only, test the TechVault
customer API at http://172.20.1.20:8080/api/v1/customers with one UNION SELECT
SQL injection. Use api_key=bh-lab and a unique marker like PwnCorp-<time>.
Show the curl command, HTTP status, and whether the marker appears in the JSON
response. Do not target anything outside this lab URL.
```

Expected: `http=200`, `marker_present=1`, and a fake customer row containing
the marker.

### 3. Work the SOC

Ask the attendee to paste:

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
7. Observability: check Grafana, Tempo, and OpenTelemetry health.
```

Expected tested behavior:

| Tool | Expected result |
| --- | --- |
| Wazuh | Rule `302010`, level `10`, source `172.20.1.30`, HTTP `200`, SQLi URL |
| Suricata | SID `1000010`, `APTL SQL Injection Attempt - UNION SELECT` |
| Wazuh Suricata ingestion | Rule `86601`, `Suricata: Alert - APTL SQL Injection Attempt - UNION SELECT` |
| MISP | Seeded `ip-src` match for `172.20.1.30` |
| Shuffle | Finished execution on workflow `APTL Alert to Case` |
| TheHive | Automatic case titled `[Wazuh 302010] SQL injection attempt detected in URL` |
| Cortex | TheHive connector `OK`; analyzer catalog may be empty |
| Observability | Grafana/Tempo/OTel health recorded |

### 4. Fix

Ask the attendee to paste:

```text
Patch only the TechVault /api/v1/customers search query so it uses a
parameterized SQL query instead of building SQL with the search string. Back up
/app/app.py first, run a Python syntax check, restart the aptl-webapp
container, and show the changed lines.
```

Expected code shape:

```python
cur.execute(
    "SELECT id, company_name, contact_name, contact_email, plan_tier FROM customers WHERE company_name LIKE %s",
    (f"%{search}%",),
)
```

### 5. Retest

Ask the attendee to paste:

```text
Repeat the same UNION SELECT test against the TechVault customer API with a new
PwnCorp marker. Confirm whether the marker appears in the response, then check
Wazuh, Suricata, Shuffle, and TheHive for the new attempted attack. Summarize
the result as an update to the same incident: exploitability, detection, and
service health.
```

Expected:

- `http=200`.
- `marker_present=0`.
- Response body is `[]` or otherwise does not include the marker.
- Wazuh and Suricata still alert on the attempted attack.
- Shuffle/TheHive still create or update incident evidence.

The talking point: the app fix changed exploitability; the SOC still saw the
attempt.

## Reset A Seat

If the participant completed the app patch, reset only the webapp for the next
person:

```bash
backup=$(docker exec aptl-webapp sh -lc \
  "ls -1t /app/app.py.pre-workshop-sqli-hotfix-* 2>/dev/null | head -1")
docker exec -e BACKUP="$backup" aptl-webapp sh -lc \
  'cp "$BACKUP" /app/app.py && python3 -m py_compile /app/app.py'
docker restart aptl-webapp >/dev/null
sleep 8
```

Rerun the attack prompt or fallback command. Expected: `marker_present=1`.

## If They Stay Longer

Keep the same incident open:

- Add a containment decision and false-positive analysis.
- Turn the incident into a Shuffle design with analyst approval before
  containment.
- Map the attack and fix to MITRE ATT&CK plus the TechVault enterprise systems
  at risk: web app, database, AD, DNS, file share, workstation.

## Facilitator Watch-Fors

- If the agent refuses, include "authorized isolated APTL lab" and "only target
  `http://172.20.1.20:8080`" in the prompt.
- If Wazuh indexer is empty, wait 30 to 60 seconds and query again.
- If the attack does not return a marker, the webapp may already be fixed; run
  the reset step.
- If attendees focus only on Wazuh, point back to the SOC step. Wazuh starts
  the incident; Suricata, MISP, Shuffle, TheHive, Cortex, and observability
  make it a SOC-in-a-box exercise.
- Duplicate TheHive cases can appear if Wazuh emits duplicate web access log
  alerts. Treat that as a SOAR tuning observation, not a participant blocker.
- Do not expose lab services publicly. Use the seat workstation, browser RDP,
  SSH, SSM, or tunnels only.

## Range Hotfix Notes

Coordination issue: `https://github.com/Brad-Edwards/aptl/issues/914`.

Seat-specific range hotfixes used during QA included Wazuh cert generation,
enterprise network attachment, Wazuh rule/decoder copy, Shuffle hook correction,
Suricata host bridge capture, MISP/Shuffle runtime fixups, Cortex socket/index
fixes, TheHive Cortex key, and Tempo OTLP endpoint. Do not present these to
attendees as part of the exercise.
