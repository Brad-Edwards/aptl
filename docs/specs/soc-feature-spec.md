# Scenario & Observability Core — Architecture Spec

## 1. Overview

### 1.1 Purpose

The Scenario & Observability Core (SOC) adds structured experiment execution to
APTL. It provides the ability to define attack scenarios as YAML, execute them
against the lab, and capture **all** telemetry into a self-contained run archive
for post-hoc analysis.

### 1.2 Use Cases

| Use Case | How SOC Enables It |
|---|---|
| **Agentic experimentation** | Define a scenario, point an AI agent at it via MCP, get a complete run archive. Compare agents, models, and prompts by diffing their event logs, Wazuh alerts, and MCP traces. |
| **Hybrid purple teaming** | Scenarios with red + blue steps create coordination structure. Human analyst on blue side, AI agent on red (or vice versa). Run archive captures both perspectives. |
| **Reproducible research** | Every run produces a UUID-identified directory with frozen config, full telemetry, and timing data. Results can be shared and replayed. |

### 1.3 Design Principles

1. **Match existing patterns** — Pydantic v2 for validation, dataclasses for
   results, `get_logger()` per module, subprocess for external tools, thin CLI
   over core logic.
2. **Minimal new dependencies** — Only `PyYAML` and `requests` are added.
3. **Scenarios are data, not code** — YAML files authored, shared, and
   version-controlled independently of the engine.
4. **Analysis is separate** — The system captures raw data. Scoring, grading,
   and comparative analysis are research steps performed after data collection.
5. **Fault-tolerant collection** — Every collector returns empty on failure.
   Partial data is better than no data.

### 1.4 Non-Goals (v1)

- Automated scoring or grading (deferred to research phase)
- Multi-tenancy / concurrent scenario execution
- Web UI or real-time dashboards
- Pre-built scenario library beyond the shipped examples
- S3 storage backend (protocol exists, implementation deferred)

---

## 2. Architecture

### 2.1 Module Map

```
src/aptl/
  core/
    scenarios.py    # Scenario YAML schema (Pydantic models) + loading
    session.py      # Active session state management (JSON on disk)
    events.py       # Append-only JSONL event timeline
    flags.py        # CTF flag collection from containers
    collectors.py   # Fault-tolerant data collectors (Wazuh, Suricata, etc.)
    run_assembler.py  # Orchestrates run directory assembly
    runstore.py     # Storage protocol + local filesystem backend
    config.py       # AptlConfig with RunStorageConfig
  cli/
    scenario.py     # aptl scenario {list,show,validate,start,status,stop}
    runs.py         # aptl runs {list,show,path}
    main.py         # CLI entrypoint, registers subcommands

mcp/aptl-mcp-common/
  src/
    tracing.ts      # ToolTracer — wraps every MCP tool call with JSONL logging
    server.ts       # createMCPServer — integrates tracer into all MCP servers
```

### 2.2 Data Flow

```
                    +----------------+
aptl scenario start |  ScenarioSession |  -> .aptl/session.json
                    |  EventLog        |  -> .aptl/events/<run>.jsonl
                    |  collect_flags() |  -> session.flags
                    +-------+----------+
                            |
         +------------------+------------------+
         |                  |                  |
    MCP Servers        Wazuh SIEM        Container logs
    (OTel spans)       (alerts)          (docker logs)
         |                  |                  |
         +------------------+------------------+
                            |
                    +-------+----------+
aptl scenario stop  |  assemble_run()  |  -> runs/<uuid>/
                    |  LocalRunStore   |     manifest.json
                    |  collectors.*    |     flags.json
                    +------------------+     scenario/, wazuh/, agents/, ...
```

### 2.3 Run Directory Layout

```
runs/<uuid>/
  manifest.json             # Run metadata (UUID, scenario, timing, config)
  flags.json                # Captured CTF flags from containers
  scenario/
    definition.yaml         # Copy of the scenario YAML used
  traces/
    spans.json              # All OTel spans (scenario + MCP tool calls) from Tempo
  wazuh/
    alerts.jsonl            # All Wazuh alerts from run time window
  suricata/
    eve.jsonl               # Suricata EVE log entries
  soc/
    thehive-cases.json      # TheHive cases/alerts created during run
    misp-correlations.json  # MISP event correlations
    shuffle-executions.json # Shuffle workflow executions
  containers/
    <name>.log              # Per-container docker logs (stdout+stderr)
```

---

## 3. Scenario Schema

### 3.1 ScenarioDefinition

Top-level Pydantic model for scenario YAML files.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `metadata` | `ScenarioMetadata` | Yes | ID, name, description, difficulty, tags |
| `mode` | `ScenarioMode` | Yes | `red`, `blue`, or `purple` |
| `containers` | `ContainerRequirements` | Yes | Required container list |
| `preconditions` | `list[Precondition]` | No | Setup commands/file checks |
| `objectives` | `ObjectiveSet` | No | Red/blue objectives (informational) |
| `scoring` | `ScoringConfig` | No | Legacy field (not used at runtime) |
| `attack_chain` | `str` | No | Human-readable attack path summary |
| `steps` | `list[AttackStep]` | No | Ordered attack steps with MITRE ATT&CK mapping |
| `defenses` | `dict` | No | Defense configuration metadata |

### 3.2 AttackStep

Each step maps to a MITRE ATT&CK technique:

| Field | Type | Description |
|-------|------|-------------|
| `step_number` | `int` | Execution order |
| `technique_id` | `str` | ATT&CK ID (e.g., `T1595.002`) |
| `technique_name` | `str` | Human-readable technique name |
| `tactic` | `str` | ATT&CK tactic (e.g., `Reconnaissance`) |
| `description` | `str` | What this step does |
| `target` | `str` | Target container |
| `vulnerability` | `str` | Exploitable condition (optional) |
| `commands` | `list[str]` | Example commands (optional) |
| `expected_detections` | `list` | Expected SIEM detections (optional) |
| `investigation_hints` | `list[str]` | Blue team guidance (optional) |
| `remediation` | `list[str]` | Fix suggestions (optional) |

### 3.3 Loading and Discovery

```python
# Load and validate a specific file
scenario = load_scenario(Path("scenarios/prime-enterprise.yaml"))

# Discover all scenarios in a directory
paths = find_scenarios(Path("scenarios/"))  # Returns list[Path]
```

---

## 4. Session Lifecycle

### 4.1 States

```
IDLE -> ACTIVE -> COMPLETED -> (cleared)
```

- `IDLE` — No active scenario (session.json absent)
- `ACTIVE` — Scenario running, events being recorded
- `COMPLETED` — Scenario stopped, ready for assembly

### 4.2 CLI Commands

| Command | Action |
|---------|--------|
| `aptl scenario start <name>` | Generate run_id, collect flags, create session, log `scenario_started` |
| `aptl scenario status` | Show active session (scenario, run_id, elapsed time) |
| `aptl scenario stop` | Log `scenario_stopped`, assemble run archive, clear session |
| `aptl scenario list` | List available scenario files with metadata |
| `aptl scenario show <name>` | Display scenario details (steps, objectives, containers) |
| `aptl scenario validate <path>` | Validate a scenario YAML file |

### 4.3 Run Management

| Command | Action |
|---------|--------|
| `aptl runs list` | List recent runs with metadata |
| `aptl runs show <id>` | Show run details and file listing (prefix matching) |
| `aptl runs path <id>` | Print filesystem path (for scripting) |

---

## 5. Data Collection

### 5.1 Collectors

All collectors accept `(start_iso, end_iso)` time window parameters and return
empty results on failure.

| Collector | Source | Output Format | Auth |
|-----------|--------|---------------|------|
| `collect_wazuh_alerts` | Wazuh Indexer (OpenSearch) | `list[dict]` -> JSONL | Basic auth |
| `collect_suricata_eve` | Suricata container | `list[dict]` -> JSONL | Docker exec |
| `collect_thehive_cases` | TheHive API | `list[dict]` -> JSON | API key |
| `collect_misp_events` | MISP API | `list[dict]` -> JSON | API key |
| `collect_shuffle_executions` | Shuffle API | `list[dict]` -> JSON | API key |
| `collect_container_logs` | Docker daemon | `dict[str, str]` -> per-container files | Docker socket |
| `collect_mcp_traces` | `.aptl/traces/*.jsonl` | `list[dict]` -> merged JSONL | Filesystem |

### 5.2 MCP Tracing

The `ToolTracer` class in `mcp/aptl-mcp-common/src/tracing.ts` wraps every MCP
tool invocation:

```typescript
interface ToolTrace {
  timestamp: string;        // ISO 8601
  server_name: string;      // e.g. "kali-ssh", "wazuh"
  tool_name: string;        // e.g. "kali_run_command"
  arguments: Record<string, unknown>;
  response: unknown;        // Truncated at 50KB
  duration_ms: number;
  success: boolean;
  error?: string;
}
```

MCP tool calls are instrumented as OpenTelemetry spans and exported to the OTel
Collector via OTLP HTTP. At run assembly, spans are fetched from Tempo by trace ID.

### 5.3 CTF Flags

Flags are generated dynamically on container startup (entrypoint scripts) and
collected at scenario start via `docker exec`. Each flag is a signed token:

```
APTL{<hex>}                          # Display flag
aptl:v1:<host>:<level>:<nonce>:<sig> # Verifiable token
```

Flag locations are defined in `FLAG_LOCATIONS` in `flags.py` per container
(user/root levels).

---

## 6. Storage

### 6.1 RunStorageBackend Protocol

```python
class RunStorageBackend(Protocol):
    def create_run(self, run_id: str) -> Path: ...
    def write_file(self, run_id: str, relative_path: str, data: bytes) -> None: ...
    def write_json(self, run_id: str, relative_path: str, obj: Any) -> None: ...
    def write_jsonl(self, run_id: str, relative_path: str, records: list[dict]) -> None: ...
    def copy_file(self, run_id: str, relative_path: str, source: Path) -> None: ...
    def list_runs(self) -> list[str]: ...
    def get_run_manifest(self, run_id: str) -> dict: ...
    def get_run_path(self, run_id: str) -> Path: ...
```

### 6.2 LocalRunStore

Stores under `<base_dir>/<run_id>/`. Default base directory is `./runs`
(configurable via `run_storage.local_path` in `aptl.json`).

### 6.3 RunManifest

```python
class RunManifest(TypedDict):
    run_id: str
    scenario_id: str
    scenario_name: str
    started_at: str          # ISO 8601
    finished_at: str         # ISO 8601
    duration_seconds: float
    config_snapshot: dict    # Frozen lab config at start
    containers: list[str]    # Active containers during run
    flags_captured: int
```

---

## 7. Configuration

### 7.1 aptl.json

```json
{
  "lab": {
    "name": "aptl",
    "network_subnet": "172.20.0.0/24"
  },
  "containers": {
    "wazuh": true,
    "victim": true,
    "kali": true,
    "enterprise": true,
    "soc": true
  },
  "run_storage": {
    "backend": "local",
    "local_path": "./runs"
  }
}
```

### 7.2 Environment Variables

| Variable | Used By | Purpose |
|----------|---------|---------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | MCP servers, CLI | OTLP endpoint for OTel Collector |
| `TEMPO_URL` | CLI (collectors) | Grafana Tempo HTTP API for trace queries |
| `THEHIVE_API_KEY` | collectors.py | TheHive authentication |
| `MISP_API_KEY` | collectors.py | MISP authentication |
| `SHUFFLE_API_KEY` | collectors.py | Shuffle authentication |

---

## 8. Testing

### 8.1 Test Modules

| Test File | Covers |
|-----------|--------|
| `tests/test_runstore.py` | LocalRunStore CRUD operations |
| `tests/test_collectors.py` | Collector mocking, fault tolerance |
| `tests/test_run_assembler.py` | End-to-end assembly with mocked collectors |
| `tests/test_cli_scenario.py` | CLI scenario commands |
| `tests/test_integration.py` | Full lifecycle (start -> status -> stop) |
| `tests/test_smoke.py` | Basic import and schema validation |

### 8.2 Running Tests

```bash
# All tests
pytest tests/ -v

# Just the run storage/assembly tests
pytest tests/test_runstore.py tests/test_collectors.py tests/test_run_assembler.py -v

# Integration tests (require scenario files on disk)
pytest tests/test_integration.py -v

# Range integration tests (require running lab)
pytest tests/test_range_integration.py -v
```
