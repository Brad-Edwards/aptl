# ADR-009: Scenario Engine with YAML Specs and Run Archive Collectors

## Status

accepted

## Date

2026-03-02

## Context

Before the scenario engine, APTL exercises were ad-hoc: a user read documentation, manually started the lab, ran commands, and inspected results. There was no structured way to:

1. **Define exercises**: What containers are needed? What's the attack chain? What MITRE ATT&CK techniques are involved? What does success look like?
2. **Reproduce runs**: Two runs of the "same" exercise could produce completely different data depending on which commands the operator ran, in what order, and what state the lab was in.
3. **Collect data**: After an exercise, SOC telemetry (Wazuh alerts, Suricata events, TheHive cases, MISP correlations, Shuffle execution logs) existed only in the running containers. Stopping the lab could lose ephemeral data.

The research goal — comparing AI agent performance across different models, prompts, and configurations on identical scenarios — requires **repeatable runs** with **comparable data collection**. Without structured scenarios, every run is a unique snowflake.

### Requirements

- Declarative scenario definitions (not code)
- MITRE ATT&CK technique mapping for each scenario
- Prerequisite validation (required containers, profiles)
- Run lifecycle management (start, stop, with timing)
- Automated data collection from all SOC tools after a run
- Range state snapshots for reproducibility
- Archive storage for historical comparison

## Decision

Implement a scenario engine with YAML-based scenario specifications, run lifecycle management via the Python CLI ([ADR-007](adr-007-python-cli-control-plane.md)), and automated data collectors for each SOC tool ([ADR-008](adr-008-soc-stack-integration.md)).

### Scenario Specification Format

Scenarios are defined in `scenarios/*.yaml` using Pydantic-validated YAML:

```yaml
metadata:
  id: prime-enterprise
  name: "TechVault Enterprise Compromise"
  description: >
    Multi-host enterprise environment designed for repeatable research.
    Three independent attack paths traverse a realistic enterprise topology.
  version: "1.0.0"
  author: "APTL Research"
  difficulty: expert
  estimated_minutes: 60
  tags: [research, enterprise, multi-path, sqli, lateral-movement]
  mitre_attack:
    tactics: [Reconnaissance, Initial Access, Credential Access, ...]
    techniques: [T1595.002, T1190, T1059.004, T1552.001, ...]

mode: purple  # red, blue, or purple

requirements:
  profiles: [wazuh, victim, kali, soc, enterprise]

objectives:
  - id: recon-nmap
    name: "Network Reconnaissance"
    description: "Discover services on the DMZ"
    techniques: [T1595.002]
    # ...

steps:
  - id: step-1
    name: "External Reconnaissance"
    # ...
```

Six scenarios are currently defined: reconnaissance (nmap scan), detection (brute force), lateral movement, web app compromise, AD domain compromise, and the full prime enterprise scenario.

### Run Lifecycle

```
aptl scenario start <scenario-id>
  → Validate prerequisites (required profiles enabled and running)
  → Record start timestamp
  → Create run directory
  → Begin scenario session

aptl scenario stop
  → Record end timestamp
  → Execute data collectors
  → Capture range snapshot
  → Assemble run archive
```

### Data Collectors

Each SOC tool has a collector module that queries its API for data generated during the run's time window (`start_iso` to `end_iso`):

| Collector | Source | Data Collected |
|-----------|--------|---------------|
| Wazuh | Indexer API (9200) | Alerts matching time window |
| Suricata | Eve JSON via Wazuh | Network IDS alerts |
| TheHive | TheHive API | Cases created during run (with `_gte` and `_lte` filters on `_createdAt`) |
| MISP | MISP API via PyMISP | Events matching time window (with client-side post-filter for upper bound) |
| Shuffle | Shuffle API | Workflow executions during run |

Collector outputs are JSON files stored in the run directory alongside a range snapshot (`snapshot.json`) containing software versions, container state, Wazuh rules inventory, network configuration, and config file hashes.

### Run Archives

Completed runs can be exported:

```
aptl runs export --s3-bucket <bucket>
  → Package run directory as tar.gz
  → Generate SHA-256 checksum
  → Optional S3 upload with metadata tags
```

### Prerequisite Validation

`aptl scenario start` validates that all required lab profiles are enabled and their containers are running before starting a session. This prevents starting scenarios with disabled containers that would lead to impossible objectives (added in v4.6.2 after a bug where scenarios could start without required containers).

### Environment and Credentials

Collectors load API credentials from the project `.env` file into `os.environ` before executing. This was a critical fix in v4.6.6 — without it, collectors got empty-string fallbacks for API keys and silently skipped data collection.

## Consequences

### Positive

- **Reproducible research**: Identical scenario definitions + automated data collection = comparable runs across different AI agents, models, and configurations
- **MITRE ATT&CK mapping**: Every scenario documents which techniques are exercised, enabling ATT&CK coverage analysis
- **Automated data collection**: No manual post-exercise data gathering. Collectors run automatically on scenario stop.
- **Range snapshots**: Complete lab state captured with each run — versions, configs, network topology — enabling root cause analysis of behavioral differences between runs
- **Extensible**: Adding a new collector (for a new SOC tool) is a new module implementing the collector interface

### Negative

- **API dependency**: Collectors depend on each SOC tool's API being available and responsive at scenario stop time. If TheHive is overloaded, its collector may timeout.
- **Time-window filtering limitations**: Each SOC tool's API has different time filtering capabilities. MISP's `restSearch` only supports a lower bound, requiring client-side post-filtering (v4.6.3). TheHive required adding both `_gte` and `_lte` filters (v4.6.3).
- **Collector timeout sensitivity**: The initial 20-second HTTP timeout was too short for MISP and TheHive cold queries, causing silent data loss. Raised to 120 seconds in v4.6.6.

### Risks

- Scenario YAML schema evolution: Adding new fields (scoring criteria, automated validation, red team instructions) requires updating the Pydantic models and potentially migrating existing scenario files
- S3 export creates a dependency on AWS credentials and boto3 — isolated behind the optional `aptl[s3]` dependency group to avoid requiring it for local-only use
- Run data volumes can grow large over hundreds of research runs. No automatic cleanup or retention policy is currently implemented.
