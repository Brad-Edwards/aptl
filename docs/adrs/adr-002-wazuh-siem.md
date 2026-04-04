# ADR-002: Wazuh SIEM over Splunk and qRadar

## Status

accepted

## Date

2025-08-06

## Context

The migration from AWS to Docker ([ADR-001](adr-001-docker-compose-deployment.md)) required replacing the SIEM. APTL v1.x used IBM qRadar Community Edition, and Splunk Enterprise was briefly supported as an alternative (v1.1.0).

### qRadar Community Edition

- 5,000 EPS (events per second) hard limit
- 30-day trial license requiring renewal
- 5GB ISO requiring manual transfer to the instance
- 1-2 hour installation process
- Not available as a Docker image — requires a full VM
- Excellent detection capabilities but operationally heavy for a personal lab

### Splunk Enterprise

- Supported via Terraform in v1.1.0 on a c5.4xlarge instance
- Commercial licensing: free tier limited to 500MB/day ingestion
- Excellent UI and search capabilities (SPL)
- Docker images available but licensing is complex for lab use
- SIEM selection was via `siem_type` variable in `terraform.tfvars`

### Requirements for v2.0

- Must run as Docker containers (not a VM)
- Open-source with no licensing limits for lab use
- Agent-based monitoring (for host-level visibility on victim containers)
- Syslog collection (for network-level log forwarding from all containers)
- OpenSearch/Elasticsearch-based indexing (for rich query capabilities)
- Web dashboard for investigation
- Active community and rule ecosystem
- Reasonable resource footprint (target: <4GB RAM for full SIEM stack)

## Decision

Adopt **Wazuh** (Manager + Indexer + Dashboard) as the SIEM platform for APTL.

### Wazuh Architecture

- **Wazuh Manager** (`aptl-wazuh-manager`, 172.20.0.10): Log processing, rule evaluation, alert generation, API server (port 55000). Multi-homed across security, DMZ, and internal networks to collect logs from all zones.
- **Wazuh Indexer** (`aptl-wazuh-indexer`, 172.20.0.12): OpenSearch-based data storage. Stores alerts, archives, and FIM data. Exposed on port 9200 for direct queries.
- **Wazuh Dashboard** (`aptl-wazuh-dashboard`, 172.20.0.11): OpenSearch Dashboards with Wazuh plugin. Web UI on port 443 (mapped from 5601).

### Dual Log Collection

Wazuh supports both collection methods APTL needs:

1. **Agent-based** (port 1514/tcp): Wazuh agents installed on victim and reverse engineering containers provide host-level visibility — file integrity monitoring, rootkit detection, system call auditing, process monitoring.
2. **Syslog forwarding** (port 514/udp): All containers forward application logs via rsyslog. This captures web server logs, database queries, authentication events, and SOC tool outputs without requiring an agent on every container.

### Version Pinning

All Wazuh components are pinned to version 4.12.0 to prevent agent/manager version mismatches that caused failures in earlier versions (see CHANGELOG v3.0.13).

## Consequences

### Positive

- **Zero licensing cost**: Fully open-source (GPLv2). No EPS limits, no trial periods.
- **Docker-native**: Official images (`wazuh/wazuh-manager:4.12.0`, etc.) with Docker Compose support
- **Dual collection**: Agent + syslog covers both host and network telemetry
- **OpenSearch backend**: Rich query language, compatible with MCP indexer server for AI agent queries
- **Active rules ecosystem**: Community rules, Sigma rule conversion, custom rule support. APTL adds custom rules for Falco, Kali red team activity, AD, web app, Suricata, and database events.
- **API server**: REST API on port 55000 enables programmatic rule creation and management via MCP

### Negative

- **Three containers for SIEM alone**: Manager + Indexer + Dashboard consume ~4GB RAM combined. The Indexer alone needs 2GB for its OpenSearch JVM heap.
- **Complex SSL certificate management**: All inter-component communication is TLS-encrypted, requiring certificate generation and distribution at startup
- **Wazuh-specific rule syntax**: Not the industry standard. Sigma rules must be converted. Detection engineers familiar with Splunk SPL or qRadar AQL face a learning curve.
- **Dashboard limitations**: The Wazuh Dashboard (OpenSearch Dashboards fork) is less polished than Splunk's UI or qRadar's offense management

### Risks

- Wazuh version upgrades can break agent compatibility — strict version pinning mitigates this but requires manual upgrades
- OpenSearch/Elasticsearch fork divergence may cause compatibility issues with third-party tools expecting standard Elasticsearch APIs
- The SOC stack integration ([ADR-008](adr-008-soc-stack-integration.md)) adds significant load to the Wazuh Manager for alert forwarding to MISP, TheHive, and Shuffle
