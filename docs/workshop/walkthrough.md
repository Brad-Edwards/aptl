# Lab Walkthrough

The runnable companion to the [Workshop Playbook](playbook.md). Every command
appears in order, with the result observed on a fresh box (a PyPI `aptl-labs`
install running the full TechVault range). Bracketed numbers point back to the
matching playbook section.

Two ways drive the attack and investigate steps:

- Path A, the agent, is the point of the workshop. A student's AI agent calls
  the MCP tools (`kali_run_command` and `indexer_query`). Each step gives a
  prompt.
- Path B, direct, is a facilitator fallback. It shows the raw `docker exec` or
  `curl` that the agent runs underneath. Use it if an agent gets stuck.

## 0. Prerequisites, once, at home

You need Docker running, Python 3.11 or newer, `pipx`, Node.js 18 or newer for
the MCP servers, and an AI agent of your choice such as Cursor or Claude Code.
The full TechVault workshop stack needs more than 20GB of Docker memory.

On native Linux Docker Engine only, raise the memory-map limit that OpenSearch
needs:

```bash
sudo sysctl -w vm.max_map_count=262144
```

Docker Desktop on macOS, Windows, WSL2, or Linux manages that setting inside
the Docker VM; configure memory in Docker Desktop instead. The commands in this
walkthrough use POSIX shell syntax. On Windows, run them from WSL2 or Git Bash,
or use equivalent PowerShell commands for simple file reads.

If you use Homebrew Docker with Colima on macOS instead of Docker Desktop,
install the Docker Buildx CLI plugin before starting the lab:

```bash
brew install docker-buildx
mkdir -p ~/.docker/cli-plugins
ln -sf "$(brew --prefix docker-buildx)/bin/docker-buildx" \
  ~/.docker/cli-plugins/docker-buildx
docker buildx version
```

[Playbook: Before you start]

## 1. Install and stand up the range [2]

```bash
pipx install aptl-labs
aptl --version
aptl lab init workshop && cd workshop
```

Select the full TechVault profile by writing `aptl.json` in the `workshop`
directory:

```json
{"deployment":{"provider":"docker-compose"},
 "containers":{"wazuh":true,"victim":true,"kali":true,"reverse":false,
   "enterprise":true,"soc":true,"mail":false,"fileshare":true,"dns":true},
 "run_storage":{"backend":"local","local_path":"./runs"}}
```

Then start the lab and wait for the "Lab is ready." message. The first boot
takes roughly 10 to 15 minutes while images build and the SOC images pull.

```bash
aptl lab start --yes
```

## 2. Verify the range is up [2]

```bash
aptl lab status
docker exec aptl-wazuh-manager /var/ossec/bin/agent_control -l | grep -c Active
```

Expect "Lab is running" with about 30 healthy containers. Active Wazuh agent
counts can vary by platform and startup timing; 7 to 9 active agents is normal
for a fresh workshop run. Name the parts out loud: `aptl-kali` is the attacker,
the victim and enterprise hosts are targets, and the `aptl-wazuh-*`, Suricata,
MISP, TheHive, Cortex, and Shuffle containers form the SOC.

## 3. Wire your agent [3]

In the `workshop` directory, create `.mcp.json` (copy it from
`.mcp.json.example`). The minimum set for the workshop is the red tool, which
drives Kali, and the indexer tool, which queries the SOC. The red MCP reaches
Kali through the loopback-only SSH proxy on `localhost:2023`, so the same
configuration works on Linux Docker, Docker Desktop, Colima, and WSL2 without
host routing to Compose bridge IPs:

```jsonc
{ "mcpServers": {
  "kali-ssh": { "command": "node", "args": ["./mcp/mcp-red/build/index.js"],
    "env": { "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318" } },
  "indexer": { "command": "node", "args": ["./mcp/mcp-indexer/build/index.js"],
    "env": { "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318",
             "INDEXER_USERNAME": "admin",
             "INDEXER_PASSWORD": "<from grep '^INDEXER_PASSWORD=' .env>" } } } }
```

Point the agent at this directory and confirm it lists `kali_run_command` and
`indexer_query`.

## 4. Confirm the agent can reach Kali [3, 5]

Path A (agent):

> Run `id` and `hostname` on the Kali box and show me its IP addresses.

Expect `uid=1000(kali)`, the host `kali-redteam`, and three addresses:
`172.20.1.30` on the DMZ, `172.20.2.35` on the internal network, and
`172.20.4.30` on the red-team network. Kali is multi-homed, which is why it can
reach everything.

Path B (direct):

```bash
docker exec aptl-kali bash -lc 'id; hostname; hostname -I'
```

## 5. See the attacker's toolbox [5]

```bash
for t in nmap smbclient curl msfconsole hydra; do docker exec aptl-kali which $t; done
```

All of the tools resolve. No agent step is needed here, since this only shows
what Kali carries.

## 6. Attack, hands-on [6]

### Reconnaissance

Path A (agent):

> Use the Kali tools to scan the TechVault internal (172.20.2.0/24) and DMZ
> (172.20.1.0/24) networks and list the hosts and open services.

Expect the domain controller `172.20.2.10` (ports 53 and 445), the database
`172.20.2.11` (port 5432), the file server `172.20.2.12` (port 445), the victim
`172.20.2.20` (port 22), and the web application (port 8080).

Path B (direct):

```bash
docker exec aptl-kali nmap -Pn -T4 --open -p22,53,80,445,3389,5432,8080 172.20.2.0/24 172.20.1.0/24
```

### Enumerate the file server over anonymous SMB

Path A (agent):

> Connect to `files.techvault.local` anonymously and list its shares.

Expect the shares Public, Engineering, Finance, HR, Shared, and IPC$.

Path B (direct):

```bash
docker exec aptl-kali smbclient -N -L //files.techvault.local
```

### Noisy attack one: SSH brute-force, which triggers rule 5710

Path A (agent):

> Attempt an SSH brute-force against the victim `172.20.2.20` with several
> made-up usernames, then report what happened.

Path B (direct):

```bash
docker exec aptl-kali bash -lc 'for u in admin root oracle test hacker1 hacker2 backup; do \
  ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 $u@172.20.2.20 true 2>/dev/null; done; echo done'
```

### Noisy attack two: web SQL injection, which triggers rule 302011

Path A (agent):

> Probe the TechVault web application (`172.20.1.20:8080`) for SQL injection.

Path B (direct):

```bash
docker exec aptl-kali bash -lc 'curl -s -o /dev/null -w "%{http_code}\n" \
  "http://172.20.1.20:8080/?id=1%27+OR+%271%27=%271"'
```

Narrate as students go. Ask which kill-chain step each maps to and which is
loud. Steps three and four are deliberately loud.

## 7. The blue side [7]

No commands here. Explain the loop: monitor, detect, investigate, respond,
inside the SOC. Everything in section 6 left evidence, which the students find
next.

## 8. Meet the SOC dashboards [8]

The dashboards bind to loopback, so open them on the lab host or over an SSH
tunnel:

| Tool     | URL                       | Expected code |
| -------- | ------------------------- | ------------- |
| Wazuh    | `https://localhost:443`   | 302 to login  |
| Grafana  | `http://localhost:3100`   | 302           |
| TheHive  | `https://localhost:9000`  | 200           |
| MISP     | `https://localhost:8443`  | 302           |
| Cortex   | `http://localhost:9001`   | 303           |
| Shuffle  | `http://localhost:3001`   | 200           |

The Wazuh login is `admin` with the `INDEXER_PASSWORD` value from `.env`.
TheHive serves HTTPS with a self-signed certificate.

## 9. Investigate, hands-on [9]

Ingestion lag is about 15 seconds. If the first query comes back empty, wait
and run it again.

### Find the alerts your own attacks caused

Path A (agent):

> Query the SOC (Wazuh) for alerts from our activity in the last few minutes,
> specifically rule IDs 5710 and 302011. What fired, and from which source IP?

Expect rule 5710 (sshd non-existent user) about 6 times and rule 302011 (SQL
injection special characters in URL) about 4 times. The source addresses are
Kali's `172.20.2.35` for the SSH path and `172.20.1.30` for the web path.

Path B (direct):

```bash
IP=$(grep -m1 '^INDEXER_PASSWORD=' .env | cut -d= -f2-)
docker exec aptl-wazuh-indexer curl -sk -u "admin:$IP" \
  "https://localhost:9200/wazuh-alerts-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":20,"query":{"query_string":{"query":"rule.id:5710 OR rule.id:302011"}}}' \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print("alerts:",d["hits"]["total"]["value"]);[print(" ",x["_source"]["rule"]["id"],x["_source"]["rule"]["description"]) for x in d["hits"]["hits"][:6]]'
```

### Explain the top alert

Path A (agent):

> Pull the details of the top SSH alert and explain in plain English what it
> detected.

### Human view

Open the Wazuh dashboard, go to Security events, and search `rule.id:5710`. The
same events appear in the human view.

### Stretch

Path A (agent):

> Check MISP for known-bad indicators, and open a case in TheHive for this
> incident.

Debrief: you attacked, the SOC saw it, and your agent investigated. That is the
loop.

## 10. Name it: agentic purple [10]

Red plus blue in one loop is purple. Driving both sides with an agent makes it
agentic purple.

## 11. Play [11]

- Ask your agent for a different attack, then check whether the SOC catches it.
- Try to do something the SOC misses, then discuss why coverage has gaps.
- Ask your agent to summarize every alert it caused, ranked by severity.
- Two-person purple: one student drives red, one drives blue, and they race the
  loop.

## Teardown

```bash
aptl lab stop -v
```

## Facilitator notes

Each of these held true on the last fresh-box run:

- If an agent refuses an attack, remind it that this is an authorized isolated
  lab and rephrase the request as a security exercise, or use the path B
  command.
- If an agent cannot see the tools, check that `.mcp.json` is in the working
  directory and that the indexer password is filled in.
- If no alert appears yet, wait for the roughly 15-second ingestion lag and run
  the query again. Rule 5710 (SSH) and rule 302011 (SQL injection) are the
  reliable pair, so lead with them.
- If the active Wazuh agent count is below 9 on Docker Desktop, Colima, or WSL2,
  continue with the attack and alert checks. The required proof is that the
  5710 and 302011 alerts appear from the Kali source addresses.
- The attacker address shows as `172.20.2.35` or `172.20.1.30`, not a single
  value, because Kali is multi-homed across the internal and DMZ paths. That is
  a good teaching moment.
- The dashboards bind to loopback, so reach them from the host rather than a
  remote laptop.
