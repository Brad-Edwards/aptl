# Experiment Runs

The experiment run system captures data from each scenario execution for reproducibility and post-run analysis.

## Clean State Between Runs

Persistent containers accumulate state across runs: service databases, indexes, logs, generated in-container credentials, and files written during a prior exercise. That state contaminates the next run and undermines reliable batch execution and benchmarking.

The clean-boot lifecycle mode guarantees a fresh environment. It tears down the project-scoped deployment, removes the Compose-managed volumes, and then boots the lab again through the standard start path, so certificates, seeds, and the SOC stack come up fresh:

```bash
# Ephemeral clean boot: destroy lab state, then start fresh.
aptl lab start --clean

# Skip the confirmation prompt (for scripted batch runs).
aptl lab start --clean --yes
```

A clean boot removes only Docker Compose state for the configured project. It does not delete `.env`, the `keys/` directory, `.mcp.json`, checked-in configuration, or archived run directories. A failed cleanup is fatal: the lab does not start, because a contaminated environment must never be reused as clean.

The same capability backs `aptl lab validate-live`, which clean-boots the lab before snapshotting it (pass `--skip-clean-boot` to validate the running lab without destroying it).

## Run Directory Structure

Each run is stored under `<project_dir>/runs/<run_id>/` with:

```
<run_id>/
  manifest.json          # Terminal attempts: the sealed RAES experiment-run/v1 record
  seal.json              # Atomic seal marker (digest, inventory, completeness statement)
  snapshot.json          # Range snapshot (software, containers, rules, networks, config hashes)
  flags.json             # Captured flags
  provenance/
    startup-provenance.json  # Provisional apparatus provenance, written at lab start
    run-provenance.json      # Canonical ready-to-seal provenance, written at the seal boundary
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

## Run Provenance (`provenance/`)

Records which apparatus the run was actually realized on, so a later reader can
tell exactly which scenario, backend, participant implementation, images,
detector rules, collectors, and configuration produced the results.

There are two records, written at different lifecycle boundaries:

- `startup-provenance.json` is **provisional**. Lab start knows the effective
  configuration, detection content, dependency locks, and realized images, but
  not the admitted trial plan, the realized participants, or any execution
  outcome.
- `run-provenance.json` is the canonical **ready-to-seal** record, written by
  the collector that owns the admitted and executed run context. Publishing it
  without that context is refused rather than written with the experiment and
  participant sources reported missing.

Both are written **create-once**: republishing identical content is a no-op,
and republishing different content for the same run fails rather than
overwriting. Separate paths are what keep the provisional startup artifact from
foreclosing the later canonical write. Neither record is a seal; they carry no
signature or attestation claim.

| Field | Description |
|-------|-------------|
| `schema_version` | Version of the record shape |
| `run_id` | The run this provenance describes |
| `seal_state` | `ready-to-seal` for the canonical record, `provisional` for the startup record |
| `aggregate_identity` | Canonical identity over every section |
| `registry_declaration_digest` | Pins which provider declarations collected this run |
| `sections[]` | One entry per provenance source: status, declaration digest, content identity, and a bounded payload |
| `limitations[]` | Every source that did not fully collect, with a stable reason code |

Each source is collected by a code-owned provider under declared byte, entry,
and time limits. A source that is unavailable, denied, unsupported, truncated,
timed out, or failed appears in `limitations[]` with a stable reason code. Such
a source is never silently omitted and never given a fabricated digest. A plain
`aptl lab start` has no admitted experiment plan and no installed participants,
so its provisional record reports those two sources `unavailable` rather than
leaving them out.

Content identity is framed per artifact: every detector rule, decoder,
allowlist, image, and configuration is a leaf bound to its logical role, and
family identities fold the sorted leaves. Changing one rule therefore moves
that rule's leaf and the aggregate, and nothing else. Secret sources are
excluded by allowlist before collection: `.env`, rendered secret-bearing
config, credentials, and private keys are never read or hashed.

## Sealed Terminal-Attempt Records (`manifest.json`, `seal.json`)

Every terminal execution attempt produces one conformant, sealed ACES run
record (ADR-050). The execution controller (`src/aptl/core/execution/`) drives
each admitted trial: it runs the trial workload under the evidence coordinator,
normalizes the terminal cause, and hands the archival coordinator an immutable
terminal-attempt context exactly once. The archival coordinator consumes the
admitted plan, the observed apparatus and participant provenance, the evidence
acquisition result, the evaluator-supplied result summaries, the clock context,
and the normalized terminal cause, and it composes the public RAES
`ExperimentRunModel` (`schema_version = experiment-run/v1`). It never recomputes
metrics, reconstructs captures, or infers a run from mutable state.

Each attempt always records its own terminal attestation as lifecycle evidence,
so the run record's mandatory evidence, traceability, and result fields are
satisfied even when a trial ends before any authored capture starts.

- `manifest.json` is the canonical serialized RAES run record for a terminal
  attempt. It replaces the legacy `aptl.run-record/v2` shape as the single
  permanent run model; existing archives stay readable through one
  version-dispatching adapter.
- `seal.json` is the atomic seal marker. A run is discoverable as sealed only
  after this marker is durably committed. Before it exists the attempt is an
  unsealed recovery candidate even if `manifest.json` is present. The marker
  binds the canonical run-record digest, a bounded inventory (path, media type,
  size, and checksum for every sealed artifact), the applicable contract
  versions, and an explicit completeness and limitation statement.

Each execution attempt receives a distinct `attempt_id`, which is also its
portable `run_id` and its run-directory name. A retry reuses the same admitted
plan and `planned_trial_id` but gets a new `attempt_id`; retry and repair
lineage travel as RAES run references (`used_refs`, `derived_from_refs`,
`generated_refs`, and, where applicable, `invalidation.superseded_by`). The
terminal cause maps to the record's real status and is never overwritten by the
seal: completed execution records `completed` with the evaluator's outcome;
scenario or evaluator failure records `failed`; cancellation, policy stop, or
infrastructure interruption records `aborted`; capture loss or another validity
failure records `invalidated` with an invalidation reason; and a replaced record
version records `superseded`.

Sealing is atomic and immutable. The record and every referenced artifact are
verified and checksummed through the run store's descriptor-relative, no-follow
boundary before the marker is published create-once with durable, no-replace
semantics. Once sealed, every overwrite-capable writer refuses; a correction is
a new run version or attestation with explicit lineage, never an in-place edit.
Export packages the already-sealed bytes and never writes back into the archive.

A small, append-safe discovery index under the run store records bounded routing
facts (attempt identity, run version, manifest digest, seal state, terminal
timestamp, and safe relative location) using a prepared and committed journal.
Discovery replays that journal and verifies each entry against the on-disk seal
marker, so restart discovery works without scanning or trusting arbitrary
filesystem paths. The index is derived and rebuildable from sealed archives; its
loss never changes the portable record or the seal.

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
| `config_hashes` | SHA-256 of `aptl.json` and `docker-compose.yml`. `.env` is deliberately excluded: it holds control-plane secrets whose values have a small guessable domain, so a digest of it would be a confirmation oracle rather than an opaque identity. |

Snapshots and trace exports must not contain live credentials, API keys, bearer
tokens, cookies, JWTs, private key material, or default lab passwords. Redact at
the common serialization/tracing boundary before writing JSON or OTel span
attributes; do not rely on archive location, file permissions, or export
controls as the primary protection.

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

# Export to S3 (requires pip install aptl-labs[s3])
aptl runs export <run-id> --s3-bucket my-bucket --s3-prefix runs/
```

## Key Source Files

- `src/aptl/core/runstore.py`: Storage backend protocol and local filesystem implementation, seal-marker commit, and sealed-state immutability
- `src/aptl/core/archival/`: Terminal-attempt archival, covering RAES run-record composition, terminal-cause status mapping, atomic seal marker, discovery index, and the legacy-manifest read adapter
- `src/aptl/core/execution/`: The execution controller that drives admitted trials to sealed terminal records, plus the owner-native RAES sub-model bridges (clock, apparatus context, parameters, stochastic controls, evidence artifacts, result summaries)
- `src/aptl/core/run_assembler.py`: Orchestrates data collection after scenario stop
- `src/aptl/core/snapshot.py`: Range snapshot dataclasses and capture logic
- `src/aptl/core/exporter.py`: Local tar.gz and S3 export
- `src/aptl/core/collectors.py`: Individual data collectors (Wazuh, Suricata, TheHive, etc.)
- `src/aptl/cli/runs.py`: CLI commands (`aptl runs list|show|path|export`)
