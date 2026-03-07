# Experiment Runs

The experiment run system captures data from each scenario execution for reproducibility and post-run analysis.

## Run Directory Structure

Each run is stored under `<project_dir>/runs/<run_id>/` with:

```
<run_id>/
  manifest.json          # Run metadata (scenario, timing, flags)
  snapshot.json          # Range snapshot (software, containers, rules, networks, config hashes)
  flags.json             # Captured flags
  scenario/
    definition.yaml      # Scenario YAML copy
    events.jsonl         # Scenario events timeline
  wazuh/
    alerts.jsonl         # Wazuh alerts from the run window
  suricata/
    eve.jsonl            # Suricata IDS events (if available)
  soc/
    thehive-cases.json   # TheHive cases (if available)
    misp-correlations.json  # MISP events (if available)
    shuffle-executions.json # Shuffle SOAR executions (if available)
  containers/
    <name>.log           # Container logs for each aptl- container
  agents/
    traces.jsonl         # MCP agent traces (if available)
```

## Range Snapshot (`snapshot.json`)

Captured at the start of each run for reproducibility. Contains:

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 capture time |
| `software.python_version` | Python interpreter version |
| `software.docker_version` | Docker Engine version |
| `software.compose_version` | Docker Compose version |
| `software.wazuh_manager_version` | Wazuh manager version (from `/var/ossec/bin/wazuh-control`) |
| `software.wazuh_indexer_version` | OpenSearch version on the Wazuh indexer |
| `software.aptl_version` | APTL package version |
| `containers[]` | Name, image, image ID, status, health, labels for each `aptl-*` container |
| `wazuh_rules.total_rules` | Total Wazuh rules loaded |
| `wazuh_rules.custom_rules` | Custom rules in `/var/ossec/etc/rules/` |
| `wazuh_rules.custom_rule_files` | List of custom rule XML filenames |
| `wazuh_rules.total_decoders` | Total decoders loaded |
| `wazuh_rules.custom_decoders` | Custom decoders count |
| `networks[]` | Docker network name, subnet, gateway, connected containers |
| `config_hashes` | SHA-256 of `aptl.json`, `docker-compose.yml`, `.env` |

## CLI Commands

```bash
# List recent runs
aptl runs list

# Show run details
aptl runs show <run-id>

# Print run directory path
aptl runs path <run-id>

# Export run as tar.gz archive
aptl runs export <run-id>

# Export to S3 (requires pip install aptl[s3])
aptl runs export <run-id> --s3-bucket my-bucket --s3-prefix runs/
```

## Key Source Files

- `src/aptl/core/runstore.py` — Storage backend protocol and local filesystem implementation
- `src/aptl/core/run_assembler.py` — Orchestrates data collection after scenario stop
- `src/aptl/core/snapshot.py` — Range snapshot dataclasses and capture logic
- `src/aptl/core/exporter.py` — Local tar.gz and S3 export
- `src/aptl/core/collectors.py` — Individual data collectors (Wazuh, Suricata, TheHive, etc.)
- `src/aptl/cli/runs.py` — CLI commands (`aptl runs list|show|path|export`)
