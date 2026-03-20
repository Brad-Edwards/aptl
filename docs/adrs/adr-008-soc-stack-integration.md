# ADR-008: Integrated SOC Stack (MISP, TheHive, Cortex, Shuffle, Suricata)

## Status

accepted

## Date

2026-02-22

## Context

APTL's original blue team capability was Wazuh alone ([ADR-002](adr-002-wazuh-siem.md)): log collection, rule-based alerting, and a web dashboard. While sufficient for basic alert triage, this left critical gaps in the SOC workflow:

### Gaps in Wazuh-Only SOC

1. **No threat intelligence**: Wazuh alerts contain raw event data but no context about whether an IP, domain, or file hash is a known threat. Analysts (human or AI agent) must manually research each indicator.

2. **No case management**: Alerts fire and scroll. There's no way to group related alerts into an investigation, track progress, assign ownership, document findings, or close a case. For an agentic SOC where AI agents investigate incidents, case management provides the structured workflow they need.

3. **No automated response**: Wazuh has active response (block IPs, run scripts) but no orchestration layer. Complex response workflows — "if critical alert AND known IOC AND business hours, then isolate host AND create case AND notify Slack" — require a SOAR platform.

4. **No network detection**: Wazuh sees host-level logs but is blind to network traffic. Command-and-control channels, lateral movement over the wire, data exfiltration, and DNS tunneling are invisible without network IDS.

The design question from `notes/team-review-synthesis.md` captures the gap: Wazuh alone provides alerting, but an agentic SOC needs structured workflows, enrichment, and automated response to give AI agents real investigative work.

### Tool Selection Criteria

- Must run in Docker containers (per [ADR-001](adr-001-docker-compose-deployment.md))
- Open-source with active community
- REST API for MCP server integration ([ADR-003](adr-003-mcp-common-library.md))
- Reasonable resource footprint (entire SOC stack must fit within ~8GB alongside Wazuh)
- Established integration patterns between tools

## Decision

Add five SOC tools under the `soc` Docker Compose profile ([ADR-005](adr-005-docker-compose-profiles.md)), each with a dedicated MCP server for AI agent integration.

### Tool Selection and Rationale

#### 1. Suricata IDS (`aptl-suricata`, 172.20.0.50)

**Chosen over Zeek**. Suricata provides signature-based network IDS with the ET Open ruleset, JSON output (Eve JSON) that integrates cleanly with Wazuh, and simpler deployment. Zeek offers richer metadata extraction and scripting but has a steeper learning curve and less direct Wazuh integration. For a training lab focused on detection rule writing and alert investigation, Suricata's approach is more accessible.

- Deployed in IDS mode with pcap capture on Docker networks (dmz, internal, security)
- Initially configured in `network_mode: host` but switched to Docker networks with pcap capture after the host interface (`eth0`) wasn't available in container mode
- Custom local rules for lab-specific detection (e.g., detecting attack patterns in the TechVault scenario)
- Requires `NET_ADMIN`, `NET_RAW`, `SYS_NICE` capabilities for packet capture
- MCP server: `mcp-network` — query alerts, manage rules, search flow data

#### 2. MISP Threat Intel (`aptl-misp`, 172.20.0.16)

**Chosen over OpenCTI**. MISP is the more mature threat intelligence platform with better Wazuh integration (CDB lists, IOC matching), a simpler deployment model (single container + MySQL), and a well-documented REST API via PyMISP. OpenCTI offers a modern GraphQL API and STIX-native data model but requires more infrastructure (Elasticsearch, Redis, MinIO, multiple workers) and ~4GB RAM minimum.

- Pre-loaded with IOCs relevant to lab scenarios via `scripts/seed-misp.sh`
- Feed integration for abuse.ch, OTX, CIRCL threat data
- PyMISP client for API access (installed in a virtualenv within the MCP server container)
- MCP server: `mcp-threatintel` — query IOCs by type, submit indicators, correlate with SIEM alerts, pull ATT&CK technique mappings
- Known issue: MISP healthcheck passes on 503 "loading" response — fixed with `-f` flag and nginx reload (v4.6.1)

#### 3. TheHive Case Management (`aptl-thehive`, 172.20.0.18)

TheHive 5 provides case management with alert escalation, observable tracking, and timeline documentation. Selected as the only mature open-source security case management platform with a usable API.

- Uses Elasticsearch backend (separate `aptl-thehive-es` container)
- Case templates for common incident types
- Alert escalation from Wazuh → TheHive via Shuffle workflows
- API key provisioning via `scripts/thehive-apikey.sh` (takes ~24s on first run; timeout was initially set to 10s, causing failures)
- MCP server: `mcp-casemgmt` — create cases, add observables, run Cortex analyzers, update case status, generate reports
- Known issue: TheHive-ES JVM memory starvation — 256MB heap in 512MB container caused Cassandra query timeouts. Fixed by doubling heap to 512MB and container limit to 1GB (v4.1.0).

#### 4. Cortex Enrichment (`aptl-cortex`, 172.20.0.22)

Cortex provides automated observable enrichment — analyzing IPs, domains, hashes, and emails against external sources (VirusTotal, abuse.ch, WHOIS). Tightly integrated with TheHive; analyzers are triggered from case observables.

- Shares TheHive's Elasticsearch backend
- Accessible via TheHive's MCP server (no separate MCP server)

#### 5. Shuffle SOAR (`aptl-shuffle-backend` 172.20.0.20, `aptl-shuffle-frontend` 172.20.0.21)

**Chosen over n8n**. Shuffle is purpose-built for security orchestration with pre-built security app integrations (Wazuh, TheHive, MISP, email, HTTP). n8n is a more general workflow automation tool with a better UI but lacks security-specific integrations. For a SOC stack, Shuffle's domain focus outweighs n8n's polish.

- Pre-built playbooks seeded via `scripts/seed-shuffle.sh`:
  - Alert-to-Case: Wazuh alert → TheHive case creation
  - IOC enrichment: Extract observables → MISP lookup → annotate case
- Webhook triggers from Wazuh alerts
- MCP server: `mcp-shuffle` (initially `mcp-soar`) — trigger playbooks, check execution status, manage response actions
- Known issue: Initial MCP implementation built against a non-existent single-execution API endpoint — rewritten in v4.0.1

### Network Placement

All SOC tools are on the `aptl-security` network (172.20.0.0/24) per [ADR-006](adr-006-four-network-segmentation.md). Suricata is additionally multi-homed on `aptl-dmz` and `aptl-internal` to tap traffic on all zones.

### MCP Integration Pattern

Each SOC tool gets a dedicated MCP server using the config-driven architecture from [ADR-003](adr-003-mcp-common-library.md). The API-based MCP servers (MISP, TheHive, Shuffle, Suricata) use the common library's `HTTPClient` and `generateAPIToolHandlers()` for consistent error handling and response formatting.

## Consequences

### Positive

- **Full SOC workflow**: Alert → Triage → Enrich → Investigate → Contain → Report — all steps have tooling and MCP integration
- **Agentic SOC capability**: AI agents can now run complete investigation workflows through MCP tool calls, not just query logs
- **Network visibility**: Suricata fills the critical gap — C2 detection, lateral movement, exfiltration are now detectable
- **Structured threat intel**: MISP provides context for every indicator, turning raw alerts into enriched investigations
- **Automated response**: Shuffle playbooks enable programmatic containment actions without manual intervention

### Negative

- **Resource cost**: The full SOC stack adds ~6-8GB RAM (MISP ~2GB, TheHive+ES ~2GB, Shuffle ~1GB, Suricata ~1GB, Cortex ~0.5GB). Combined with Wazuh (~4GB), the security stack alone needs ~10-12GB.
- **Complexity**: 5 additional tools means 5 more configuration surfaces, version pinning concerns, inter-tool integration debugging, and health check tuning
- **Cold start time**: SOC tools have slow first-start initialization (MISP database migrations, TheHive schema creation, Shuffle app loading). Full SOC profile adds 3-5 minutes to lab startup.
- **Fragile integrations**: Each tool-to-tool integration (Wazuh → Shuffle → TheHive, TheHive → Cortex, MISP ↔ Wazuh CDB) is a potential failure point with version-specific API contracts

### Risks

- SOC tool versions are not pinned as strictly as Wazuh (which pins to 4.12.0 exactly). Major version upgrades to TheHive, MISP, or Shuffle could break API contracts with MCP servers.
- The MISP `restSearch` API only supports a lower-bound `timestamp` parameter, requiring client-side post-filtering for upper bounds (fixed in v4.6.3). Similar API limitations in other tools may surface.
- Shuffle playbook execution is eventually consistent — workflow completion status may not reflect in TheHive immediately, causing race conditions in automated investigation workflows.
