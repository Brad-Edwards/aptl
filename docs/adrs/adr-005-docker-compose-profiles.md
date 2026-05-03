# ADR-005: Docker Compose Profiles for Selective Deployment

## Status

accepted

## Date

2025-09-01

## Context

As APTL grew from 5 containers (v2.0) to 13+ containers (v3.x and beyond), the lab's resource requirements became prohibitive for many development machines:

- **Full stack**: 19 containers requiring ~20GB RAM
- **Individual containers**: Wazuh Indexer alone needs 2GB (OpenSearch JVM heap); TheHive needs 1GB; MISP needs 1-2GB
- **Not all containers are needed for every task**: A user practicing Kali reconnaissance doesn't need the SOC stack. A user testing Wazuh rules doesn't need the enterprise infrastructure.

Additionally, different use cases required different lab configurations:

- **Red team practice**: Kali + victim + basic SIEM monitoring
- **Blue team practice**: Full Wazuh stack + SOC tools + victim generating events
- **Full purple team**: Everything running
- **Development/testing**: Minimal set for MCP server development

Without selective deployment, users had to either run everything (slow startup, resource pressure) or manually comment out services in `docker-compose.yml` (error-prone, hard to share configurations).

## Decision

Use **Docker Compose profiles** to group containers into deployable subsets, controlled by `aptl.json` configuration.

### Profile Definitions

Each service in `docker-compose.yml` declares which profile(s) it belongs to:

| Profile | Containers | Purpose |
|---------|-----------|---------|
| `wazuh` | Manager, Indexer, Dashboard | Core SIEM stack |
| `victim` | Victim (Rocky Linux) | Primary attack target |
| `kali` | Kali Linux | Attack platform |
| `reverse` | Reverse engineering | Binary analysis |
| `soc` | Suricata, MISP, TheHive, Cortex, Shuffle (frontend + backend), MISP DB, Elasticsearch | SOC tool stack |
| `enterprise` | Samba AD, PostgreSQL, Web app, File server, Mail server, DNS, Workstation | Enterprise infrastructure |

### Configuration

`aptl.json` defines which containers are enabled:

```json
{
  "containers": {
    "wazuh": { "enabled": true },
    "kali": { "enabled": true },
    "victim": { "enabled": true },
    "reverse": { "enabled": false },
    "soc": { "enabled": true },
    "enterprise": { "enabled": true }
  }
}
```

The Python CLI (`aptl lab start`) reads this config and passes corresponding `--profile` flags to `docker compose up`.

### Health Checks and Resource Limits

As part of this standardization, all services received:

**Health checks** with generous timeouts for cold starts:
- `start_period: 120s-300s` — SOC tools (MISP, TheHive, Shuffle) need up to 5 minutes for first-time initialization
- `retries: 5-15` — enough attempts to survive slow disk I/O
- `interval: 30s` — balanced between responsiveness and overhead

**Memory limits** per container:
- Wazuh Indexer: 2GB (OpenSearch JVM)
- Wazuh Manager, Dashboard: 1GB each
- TheHive + Elasticsearch: 1GB each (TheHive-ES JVM heap set to 512MB within 1GB container)
- Suricata: 1GB (rule loading and packet processing)
- Most other containers: 256MB-512MB

These limits prevent any single container from starving the others and provide predictable resource planning.

## Consequences

### Positive

- **Flexible deployment**: Users run only what they need. A red team practice session uses ~6GB instead of ~20GB.
- **Faster startup**: Fewer containers = faster `docker compose up`. Core lab (Wazuh + Kali + victim) starts in ~2 minutes vs. ~8 minutes for full stack.
- **Shared configurations**: `aptl.json` can be checked in or shared to reproduce specific lab setups
- **Predictable resources**: Memory limits prevent OOM kills and resource starvation. Health check standardization ensures services are ready before dependent operations begin.

### Negative

- **Profile complexity**: Users must understand which profiles provide which capabilities. Enabling `soc` without `wazuh` is meaningless (SOC tools need SIEM data).
- **Inter-profile dependencies**: Some containers in one profile depend on containers in another. Docker Compose handles this via `depends_on` but only within the active profile set.
- **Start order constraints**: The Python CLI enforces a 12-step orchestration sequence because `depends_on` alone doesn't handle cross-profile readiness (see [ADR-007](adr-007-python-cli-control-plane.md)).

### Risks

- Health check `start_period` values were set based on observed cold-start times on a development machine. Slower machines or disk-constrained environments may need longer periods.
- Memory limits may need tuning as data volumes grow — the Wazuh Indexer's 2GB limit is tight for large alert volumes during extended scenarios
