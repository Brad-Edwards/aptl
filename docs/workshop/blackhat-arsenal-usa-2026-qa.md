# Black Hat Arsenal USA 2026 QA Checklist

Use this to validate each seat before attendees use it. This file intentionally
uses direct commands so a tester can prove the participant flow without relying
on an agent.

## Scope

There is one required attendee flow:

1. Attack the TechVault customer API from Kali with one SQL injection.
2. Work the alert as one SOC incident across Wazuh, Suricata, MISP, Shuffle,
   TheHive, Cortex, and observability.
3. Patch the vulnerable customer-search query.
4. Repeat the attack and confirm the exploit fails while detection still fires.
5. Reset the webapp to the vulnerable starting state.

## Seat Preflight

Required containers:

```bash
docker ps --filter name=aptl --format '{{.Names}}' \
  | grep -E 'aptl-kali|aptl-webapp|aptl-db|aptl-wazuh-manager|aptl-wazuh-indexer|aptl-wazuh-dashboard|aptl-misp|aptl-thehive|aptl-cortex|aptl-shuffle-backend|aptl-shuffle-frontend|aptl-shuffle-orborus|aptl-suricata|aptl-grafana-otel|aptl-tempo|aptl-otel-collector'
```

Network attachments required for the tested participant path:

```bash
docker inspect aptl-webapp aptl-db aptl-kali --format '{{.Name}} {{json .NetworkSettings.Networks}}'
```

Expected key IPs:

- `aptl-webapp`: `172.20.1.20` on `aptl_aptl-dmz`, `172.20.2.25` on
  `aptl_aptl-internal`
- `aptl-db`: `172.20.2.11` on `aptl_aptl-internal`
- `aptl-kali`: `172.20.1.30` on `aptl_aptl-dmz`, `172.20.2.35` on
  `aptl_aptl-internal`, `172.20.4.30` on `aptl_aptl-redteam`

If those are missing on the seat AMI, attach them range-locally:

```bash
docker network connect --ip 172.20.1.20 --alias webapp --alias aptl-webapp aptl_aptl-dmz aptl-webapp
docker network connect --ip 172.20.2.25 --alias webapp --alias aptl-webapp aptl_aptl-internal aptl-webapp
docker network connect --ip 172.20.2.11 --alias db --alias aptl-db aptl_aptl-internal aptl-db
docker network connect --ip 172.20.1.30 --alias kali --alias aptl-kali aptl_aptl-dmz aptl-kali
docker network connect --ip 172.20.2.35 --alias kali --alias aptl-kali aptl_aptl-internal aptl-kali
docker network connect --ip 172.20.4.30 --alias kali --alias aptl-kali aptl_aptl-redteam aptl-kali
```

Verify Kali can reach TechVault:

```bash
docker exec aptl-kali curl -sS -o /dev/null -w '%{http_code}\n' \
  'http://172.20.1.20:8080/api/v1/customers?api_key=bh-lab'
```

Expected: `200`.

Confirm the seat starts vulnerable:

```bash
docker exec aptl-webapp sh -lc \
  "grep -n \"query = f\\|cur.execute(query)\" /app/app.py | sed -n '1,20p'"
```

Expected: the customer search f-string and `cur.execute(query)` are present.

## SOC Preflight

Wazuh:

```bash
docker exec aptl-wazuh-indexer curl -sk -u admin:SecretPassword \
  https://localhost:9200/_cluster/health

docker exec aptl-wazuh-manager sh -lc '
ls -l /var/ossec/integrations/custom-shuffle \
      /var/ossec/etc/rules/webapp_rules.xml \
      /var/ossec/etc/rules/suricata_rules.xml \
      /var/ossec/etc/shuffle_webhook_url
grep -n "<name>custom-shuffle\\|<level>" /var/ossec/etc/ossec.conf | sed -n "1,80p"
/var/ossec/bin/wazuh-control status 2>&1 | sed -n "1,80p"
' || true
```

Expected:

- Indexer health is `green` or `yellow`.
- `custom-shuffle`, `webapp_rules.xml`, `suricata_rules.xml`, and
  `shuffle_webhook_url` exist.
- `custom-shuffle` threshold is level `6`.
- `wazuh-analysisd`, `wazuh-integratord`, `wazuh-logcollector`, and Filebeat
  are running or clearly starting.

Suricata:

```bash
docker logs --tail 80 aptl-suricata
docker exec aptl-suricata sh -lc \
  'grep -n "APTL SQL Injection Attempt - UNION SELECT" /etc/suricata/rules/local.rules'
```

Expected: one SQLi rule loads and Suricata is capturing the DMZ bridge.

MISP, Shuffle, TheHive, Cortex, observability:

```bash
source scripts/aptl-env.sh
aptl_load_env_key .env MISP_API_KEY
aptl_load_env_key .env SHUFFLE_API_KEY

docker exec -e MISP_API_KEY="$MISP_API_KEY" aptl-misp sh -lc \
  'curl -ks -o /dev/null -w "misp_http=%{http_code}\n" --max-time 8 \
    -H "Authorization: $MISP_API_KEY" -H "Accept: application/json" \
    https://localhost:443/servers/getVersion'

docker exec -e SHUFFLE_API_KEY="$SHUFFLE_API_KEY" aptl-shuffle-frontend sh -lc \
  'curl -sk -w "\nshuffle_http=%{http_code}\n" \
    -H "Authorization: Bearer $SHUFFLE_API_KEY" https://localhost:443/api/v1/workflows' \
  | python3 -c '
import json, sys
raw=sys.stdin.read()
body, status = raw.rsplit("\nshuffle_http=", 1)
print("shuffle_http=" + status.strip())
for w in json.loads(body):
    print(w.get("name"), w.get("id"))
'

THEHIVE_API_KEY=$(./scripts/thehive-apikey.sh 2>/dev/null)
docker exec -e THEHIVE_API_KEY="$THEHIVE_API_KEY" aptl-thehive sh -lc \
  'curl -sS -H "Authorization: Bearer $THEHIVE_API_KEY" http://localhost:9000/api/v1/status' \
  | python3 -c 'import json,sys; s=json.load(sys.stdin); print(s["connectors"]["cortex"]["status"])'

docker exec aptl-cortex sh -lc \
  'curl -sf -H "Authorization: Bearer aptlcortexlabapikey2026purple" http://localhost:9001/api/user/current >/dev/null && echo cortex_key_ok; curl -sf -H "Authorization: Bearer aptlcortexlabapikey2026purple" http://localhost:9001/api/analyzer | wc -c'

docker exec aptl-grafana-otel sh -lc \
  'curl -sS --max-time 10 http://127.0.0.1:3000/api/health'
docker exec aptl-tempo sh -lc \
  'wget -qO- http://127.0.0.1:3200/ready 2>/dev/null || true'
```

Expected:

- MISP returns `200`.
- Shuffle returns `200` and workflow `APTL Alert to Case` exists.
- TheHive Cortex connector is `OK`.
- Cortex key works; analyzer catalog may be empty.
- Grafana/Tempo respond.

## Attack Proof

Run this from the host:

```bash
marker="PwnCorp-$(date -u +%H%M%S)"
payload="' UNION SELECT 9001,'${marker}','Mallory','mallory@example.com','enterprise'--"
docker exec -e MARKER="$marker" -e PAYLOAD="$payload" aptl-kali sh -lc '
curl -sS --max-time 10 --get \
  --data-urlencode api_key=bh-lab \
  --data-urlencode "search=$PAYLOAD" \
  http://172.20.1.20:8080/api/v1/customers \
  -o /tmp/aptl-sqli.json \
  -w "http=%{http_code}\n"
if grep -q "$MARKER" /tmp/aptl-sqli.json; then
  echo marker_present=1
else
  echo marker_present=0
fi
head -c 500 /tmp/aptl-sqli.json
printf "\n"
'
echo "$marker"
```

Expected:

- `http=200`
- `marker_present=1`
- JSON includes a fake customer row with the marker

Seat proof on August 5, 2026:

```text
PwnCorp-seat-final3-082239: http=200, marker_present=1
```

## SOC Evidence Proof

Wait up to 60 seconds, then query for the marker.

Suricata:

```bash
marker="<replace-with-your-marker>"
docker exec -e MARKER="$marker" aptl-suricata sh -lc \
  'grep "$MARKER" /var/log/suricata/eve.json | grep "event_type.*alert" | tail -1 || true'
```

Expected: SID `1000010`, source `172.20.1.30`, destination
`172.20.1.20:8080`.

Wazuh local and indexer:

```bash
marker="<replace-with-your-marker>"
docker exec -e MARKER="$marker" aptl-wazuh-manager sh -lc \
  'grep "$MARKER" /var/ossec/logs/alerts/alerts.json | tail -4 || true'

docker exec -e MARKER="$marker" aptl-wazuh-indexer sh -lc 'curl -sk -u admin:SecretPassword -H "Content-Type: application/json" https://localhost:9200/wazuh-alerts-*/_search -d @- <<EOF
{"size":10,"query":{"wildcard":{"data.url":{"value":"*$MARKER*","case_insensitive":true}}},"sort":[{"timestamp":{"order":"desc"}}],"_source":["timestamp","rule.id","rule.level","rule.description","agent.name","data.srcip","data.id","data.url"]}
EOF' | python3 -c '
import json, sys
d=json.load(sys.stdin)
hits=d.get("hits",{}).get("hits",[])
print("hits", len(hits))
for h in hits:
    s=h.get("_source",{})
    data=s.get("data",{})
    print(s.get("timestamp"), s.get("rule",{}).get("id"), s.get("rule",{}).get("level"), s.get("rule",{}).get("description"), s.get("agent",{}).get("name"), data.get("srcip"), data.get("id"), data.get("url"))
'
```

Expected:

- Wazuh rule `302010`, level 10, `SQL injection attempt detected in URL`.
- Wazuh indexer search returns only the exact marker when using the
  `data.url` wildcard query above.
- Wazuh Suricata rule `86601` may appear in local alerts before it appears in
  indexer search.

MISP:

```bash
source scripts/aptl-env.sh
aptl_load_env_key .env MISP_API_KEY
docker exec -e MISP_API_KEY="$MISP_API_KEY" aptl-misp sh -lc \
  'curl -ks --max-time 10 -X POST \
    -H "Authorization: $MISP_API_KEY" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "{\"value\":\"172.20.1.30\",\"type\":\"ip-src\",\"includeCorrelations\":true,\"returnFormat\":\"json\"}" \
    https://localhost:443/attributes/restSearch' \
  | python3 -c '
import json, sys
d=json.load(sys.stdin)
attrs=d.get("response",{}).get("Attribute",[])
print("attrs", len(attrs))
for a in attrs[:3]:
    print(a.get("event_id"), a.get("type"), a.get("value"), a.get("category"), a.get("comment","")[:80])
'
```

Expected: seeded `ip-src` context for `172.20.1.30`.

Shuffle and TheHive:

```bash
marker="<replace-with-your-marker>"
source scripts/aptl-env.sh
aptl_load_env_key .env SHUFFLE_API_KEY

docker exec -e SHUFFLE_API_KEY="$SHUFFLE_API_KEY" aptl-shuffle-frontend sh -lc \
  'curl -sk -H "Authorization: Bearer $SHUFFLE_API_KEY" \
    "https://localhost:443/api/v1/workflows/e8677710-1289-4b39-aa79-9d048a7837ee/executions?amount=8"' \
  | jq -r '.[] | [.execution_id,.status,.started_at,.completed_at] | @tsv' 2>/dev/null || true

THEHIVE_API_KEY=$(./scripts/thehive-apikey.sh 2>/dev/null)
docker exec -e THEHIVE_API_KEY="$THEHIVE_API_KEY" -e MARKER="$marker" aptl-thehive sh -lc \
  'curl -sS -H "Authorization: Bearer $THEHIVE_API_KEY" -H "Content-Type: application/json" \
    http://localhost:9000/api/v1/query \
    -d "{\"query\":[{\"_name\":\"listCase\"},{\"_name\":\"page\",\"from\":0,\"to\":100}]}"' \
  | python3 -c '
import json, os, sys
marker=os.environ.get("MARKER","")
data=json.load(sys.stdin)
matches=[c for c in data if marker in (c.get("description") or "") or marker in (c.get("title") or "")]
print("matches", len(matches))
for c in matches:
    print(c.get("number"), c.get("title"), c.get("severity"), c.get("status"))
'
```

Expected:

- At least one Shuffle execution is `FINISHED`.
- At least one TheHive case matches the marker.

Seat proof on August 5, 2026:

```text
Shuffle execution 8eec7454-4755-4617-adf7-eb1df5eb4c3d FINISHED
TheHive cases #10 and #11 [Wazuh 302010] SQL injection attempt detected in URL
```

## App Fix Proof

Apply the same temporary fix a participant should ask the agent to make:

```bash
docker exec -i aptl-webapp python3 - <<'PY'
from datetime import datetime, timezone
from pathlib import Path

p = Path('/app/app.py')
text = p.read_text()
stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
backup = Path(f'/app/app.py.pre-workshop-sqli-hotfix-{stamp}')
old = '''        query = f"SELECT id, company_name, contact_name, contact_email, plan_tier FROM customers WHERE company_name LIKE '%{search}%'"
        cur.execute(query)'''
new = '''        cur.execute(
            "SELECT id, company_name, contact_name, contact_email, plan_tier FROM customers WHERE company_name LIKE %s",
            (f"%{search}%",),
        )'''
if old not in text:
    raise SystemExit('expected vulnerable customer-search block not found')
backup.write_text(text)
p.write_text(text.replace(old, new, 1))
print(f'backup_path={backup}')
PY
docker exec aptl-webapp python3 -m py_compile /app/app.py
docker restart aptl-webapp >/dev/null
sleep 8
docker exec aptl-webapp sh -lc 'sed -n "247,258p" /app/app.py'
```

Expected:

- backup path is printed
- syntax check passes
- changed lines show parameterized `cur.execute(...)`

## Retest Proof

Run the attack proof again with a new marker.

Expected after the fix:

- `http=200`
- `marker_present=0`
- response body is `[]` or otherwise does not include the marker
- Wazuh and Suricata still log the attempted attack
- Shuffle and TheHive still record incident evidence

Seat proof on August 5, 2026:

```text
PwnCorp-seat-final3fix-082255: http=200, marker_present=0, response []
Shuffle execution 96d7e3b9-6741-4c05-84f2-0bb2537e7716 FINISHED
TheHive cases #12 and #13 matched the fixed marker
```

## Reset Proof

Reset the app to the vulnerable starting state after a participant completes the
fix:

```bash
backup=$(docker exec aptl-webapp sh -lc \
  "ls -1t /app/app.py.pre-workshop-sqli-hotfix-* 2>/dev/null | head -1")
docker exec -e BACKUP="$backup" aptl-webapp sh -lc \
  'cp "$BACKUP" /app/app.py && python3 -m py_compile /app/app.py'
docker restart aptl-webapp >/dev/null
sleep 8
```

Run the attack proof once more.

Expected after reset:

- `http=200`
- `marker_present=1`
- vulnerable f-string appears in `/app/app.py`

Seat proof on August 5, 2026:

```text
PwnCorp-seat-final3reset-082309: http=200, marker_present=1
```

## Known QA Notes

- Coordination issue: `https://github.com/Brad-Edwards/aptl/issues/914`.
- `aptl lab start` on the seat failed strict RAES handoff after rendering; the
  full profile set was started directly with Compose for QA.
- The seat needed range-only repairs for Wazuh cert files, enterprise network
  attachment, live Wazuh rule/decoder files, Shuffle webhook URL, Suricata
  bridge capture/local SQLi rule, MISP/Shuffle runtime config, Cortex socket
  and index mapping, TheHive Cortex key, and Tempo OTLP.
- Cortex analyzer catalog is empty even though the TheHive Cortex connector is
  `OK`.
- Duplicate TheHive cases can appear because duplicate Wazuh web alerts can
  fire for one request.
- Do not expose lab services publicly during QA. Use the seat workstation,
  browser RDP, SSH, SSM, or tunnels only.
