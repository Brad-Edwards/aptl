# Lab Walkthrough

The runnable companion to the [Workshop Playbook](playbook.md). It describes
the `guided-purple` version 1 participant path. Bracketed numbers point back
to the matching playbook section.

The shell commands below are a developer and facilitator preview of the inner
APTL profile. Issue #823 embeds this same profile in the signed participant
appliance; these commands are not outer-appliance qualification evidence.

Two ways drive the attack and investigate steps:

- Path A, the participant agent, is the workshop path. It calls
  `kali_run_command`, `indexer_query`, and `wazuh_query_alerts`.
- Path B is a developer/facilitator diagnostic. It uses management-owned
  Docker access and does not satisfy participant workflow qualification.

## 0. Prerequisites, once, at home

The released appliance owns its guest Docker engine, APTL runtime, MCP builds,
and staged dependencies. It requires the hardware fixture named in the
[participant profile](../reference/participant-profile.md): x86-64, 8 vCPUs,
16 GiB of memory, and 100 GiB of disk.

For the developer preview only, you need Docker, Python 3.11 or newer, `pipx`,
Node.js 18 or newer for the MCP servers, and an MCP-capable agent.

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

For a source-tree preview, copy the profile config into the initialized
project and select its referenced catalog scenario:

```bash
cp participant-profiles/guided-purple-v1/aptl.json aptl.json
aptl lab start --scenario techvault-attacker-target --yes
```

A developer start may build or pull missing assets. The participant appliance
instead starts from its digest-locked staged payload with egress denied; a
download, image pull, image build, or package resolution is a qualification
failure.

## 2. Verify the range is up [2]

```bash
aptl lab status
docker exec aptl-wazuh-manager /var/ossec/bin/agent_control -l | grep -c Active
```

Expect "Lab is running" with the derived ten-service steady-state surface:
Kali, Kali capture, the Kali SSH proxy, victim, the three Wazuh services, and
the three OpenTelemetry services. Missing or additional steady-state services
fail profile qualification.

## 3. Wire your agent [3]

The participant management layer creates owner-only MCP client state after
the backing services and real semantic smoke operations pass. Start in the
`red` workbench, which contains only `aptl-red`. For a developer preview, use:

```jsonc
{ "mcpServers": {
  "aptl-red": { "command": "node", "args": ["./mcp/mcp-red/build/index.js"],
    "env": { "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318" } } } }
```

Point the agent at that config and confirm the exact red tool inventory. After
the SSH attack, close that agent and all MCP processes, remove its generated
configuration, and switch to the `guided-blue` workbench:

```jsonc
{ "mcpServers": {
  "aptl-indexer": { "command": "node",
    "args": ["./mcp/mcp-indexer/build/index.js"],
    "env": { "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318" } },
  "aptl-wazuh": { "command": "node",
    "args": ["./mcp/mcp-wazuh/build/index.js"],
    "env": { "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318" } } } }
```

Confirm the exact indexer and Wazuh tool inventories. Network IDS, threat
intelligence, case management, SOAR, and reverse-engineering MCPs must be
absent. Never keep red and guided-blue MCPs in one process environment or
client config.

## 4. Confirm the agent can reach Kali [3, 5]

Path A (agent):

> Run `id` and `hostname` on the Kali box and show me its IP addresses.

Expect `uid=1000(kali)` and the host `kali-redteam`.

Path B (direct):

```bash
docker exec aptl-kali bash -lc 'id; hostname; hostname -I'
```

## 5. See the required attack tool [5]

The required path uses the standard SSH client. A facilitator can verify the
developer preview with:

```bash
docker exec aptl-kali which ssh
```

## 6. Attack, hands-on [6]

### Bounded SSH authentication attack

Path A (agent):

> Attempt an SSH brute-force against the victim `172.20.2.20` with several
> made-up usernames, then report what happened.

Path B (direct):

```bash
docker exec aptl-kali bash -lc 'for u in admin root oracle test hacker1 hacker2 backup; do \
  ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 $u@172.20.2.20 true 2>/dev/null; done; echo done'
```

Narrate as students go. Ask which kill-chain step the action maps to and why it
is deliberately loud.

## 7. The blue side [7]

No commands here. Explain the loop: monitor, detect, investigate, respond,
inside the SOC. Everything in section 6 left evidence, which the students find
next.

## 8. Meet the SOC dashboard [8]

The required human capability is the Wazuh dashboard. The supported appliance
projects it through the participant gateway. `https://localhost:443` is only
the developer-host diagnostic endpoint; it is not the appliance participant
route.

## 9. Investigate, hands-on [9]

Ingestion lag is about 15 seconds. If the first query comes back empty, wait
and run it again.

### Find the alerts your own attacks caused

Path A (agent):

> Query the SOC (Wazuh) for alerts from our activity in the last few minutes,
> specifically rule ID 5710. What fired, and from which source IP?

Expect rule 5710 (`sshd`: non-existent user) from Kali's internal address.

Path B (direct):

```bash
IP=$(grep -m1 '^INDEXER_PASSWORD=' .env | cut -d= -f2-)
docker exec aptl-wazuh-indexer curl -sk -u "admin:$IP" \
  "https://localhost:9200/wazuh-alerts-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":20,"query":{"query_string":{"query":"rule.id:5710"}}}' \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print("alerts:",d["hits"]["total"]["value"]);[print(" ",x["_source"]["rule"]["id"],x["_source"]["rule"]["description"]) for x in d["hits"]["hits"][:6]]'
```

### Explain the top alert

Path A (agent):

> Pull the details of the top SSH alert and explain in plain English what it
> detected.

### Human view

Open the Wazuh dashboard, go to Security events, and search `rule.id:5710`. The
same events appear in the human view.

Debrief: you attacked, the SOC saw it, and your agent investigated. That is the
loop.

## 10. Name it: agentic purple [10]

Red plus blue in one loop is purple. Driving both sides with an agent makes it
agentic purple.

## 11. Play [11]

- Vary the SSH usernames or timing and compare the resulting alerts.
- Try another action against the victim and discuss whether Wazuh detects it.
- Ask your agent to summarize every alert it caused, ranked by severity.
- Two-person purple: one student drives red, one drives blue, and they race the
  loop.

The full `techvault-operational` research stack is a separate follow-on. Its
enterprise, web, MISP, TheHive, Cortex, Shuffle, and Suricata exercises are not
required participant-profile operations.

## Developer-preview clean reset

```bash
aptl lab stop -v
```

This is the clean inner reset measured by the participant profile. Disposable
appliance replacement is a separate #823 lifecycle measurement.

## Developer-preview troubleshooting

- If an agent refuses an attack, remind it that this is an authorized isolated
  lab and rephrase the request as a security exercise, or use the path B
  command.
- If an agent cannot see the tools, check that `.mcp.json` is in the working
  directory and that the indexer password is filled in.
- If no alert appears yet, wait for the roughly 15-second ingestion lag and run
  the rule 5710 query again.
- The developer dashboard binds to loopback. The supported appliance uses the
  separate participant projection defined by its release.
