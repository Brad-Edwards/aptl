# DEP-003 Ephemeral Lifecycle Policy Preflight

This note is the architecture preflight for DEP-003 / issue #467. It is
guidance, not an implementation plan. It extends
[`RNG-001 Ephemeral Environments`](rng-001-ephemeral-environments-preflight.md):
RNG-001 owns the destructive clean-boot seam; DEP-003 adds lifecycle policy
decisions around when provisioning and teardown happen.

Existing ADRs remain binding: ADR-013 and ADR-023 own deployment backends,
ADR-025 owns first-party config shape, ADR-028 owns runtime-rendered config,
ADR-029 owns secret handling, ADR-030 owns lab-result envelopes, ADR-031 owns
orchestration contract guards, ADR-037 owns Docker Compose backend cohesion,
ADR-039 owns web API auth, and ADR-044 owns ACES/run reproducibility records.

## Architecture Decisions

- Treat lifecycle policy as a control-plane decision layer above lab lifecycle.
  TTL expiry, idle detection, and schedules decide when to invoke existing
  lifecycle operations; they do not become new Docker, Compose, ACES, or web
  lifecycle implementations.
- Provisioning must reuse the public lab start path:
  `orchestrate_lab_start()` for normal starts and `clean_boot_lab()` when the
  policy requires clean state. Teardown must reuse `stop_lab()` through
  `DeploymentBackend`; complete teardown means `remove_volumes=True` unless a
  typed policy explicitly says otherwise.
- A "range instance" is the configured deployment project, not an individual
  container, scenario file, folder name, `lab.name`, GitHub issue, or run
  archive. The current concrete identity is `DeploymentConfig.project_name`
  plus the project directory/backend. Any future concurrent instances must
  parameterize that identity and state root explicitly instead of relying on
  Docker name prefixes.
- Lifecycle policy state is data: `started_at`, `expires_at`,
  `last_activity_at`, `next_provision_at`, policy name, action, result, and
  narrow error labels. It must not carry `.env` values, bearer tokens, raw
  Docker stderr, terminal content, generated config, or command lines.
- Automated policy execution must have one owner per project/backend. Do not
  hide timers in FastAPI request handlers, SSE loops, or web clients where
  process restarts, multiple workers, or disconnected browsers can double-run
  or miss destructive actions.
- Lifecycle actions must be serialized per project/backend. A scheduled start,
  TTL teardown, idle teardown, manual `aptl lab start --clean`, and API
  start/stop must not overlap against the same Compose project.

## Cross-Cutting Concerns To Reuse

- Lab lifecycle: `clean_boot_lab()`, `orchestrate_lab_start()`,
  `stop_lab(remove_volumes=True)`, `_LabStartContext`, `_LAB_START_STEPS`,
  `LabResult`, `StartupOutcome`, and `StartupDiagnostic`.
- Deployment boundary: `DeploymentBackend`, `DockerComposeBackend`,
  `SSHComposeBackend`, `DeploymentConfig.project_name`, compose-project label
  filters, SSH transport semantics, backend timeouts, `BackendTimeoutError`,
  and `BackendSeedError`.
- Config and env: `AptlConfig`, `DeploymentConfig`,
  `ContainerSettings.enabled_profiles()`, `RunStorageConfig`, `load_config()`,
  `load_dotenv()`, `EnvVars`, `env_vars_from_dict()`, and
  `find_placeholder_env_values()`.
- Scenario selection and ACES handoff: `resolve_scenario_selection()`,
  `start_aces_scenario()`, `selected_profiles_for_scenario()`, ACES parser /
  runtime manager gates, and the REP-001 run-record threading already in
  lab start.
- API and web surfaces: `verify_token`, `WebAuthSettings`,
  `LabActionResponse`, `StartupDiagnosticModel`, `StartupOutcomeLiteral`,
  `web/src/lib/types.ts`, and existing API projection style.
- Observability and persistence: `get_logger()`, `redact()`,
  `RangeSnapshot.to_dict()`, `LocalRunStore.write_json()`,
  `write_jsonl()`, `append_jsonl()`, and the run archive/reference pattern
  from ADR-044.
- Live proof point: `src/aptl/validation/_live_gate_probes.py` already consumes
  `clean_boot_lab()` instead of open-coding destructive stop/start.

## Security And Validation Layers

- **Auth surface:** any API trigger for provisioning, teardown, policy updates,
  or policy status must remain behind ADR-039 bearer-token auth. Do not pass
  API tokens, destructive intent, or policy payloads in query strings,
  EventSource URLs, WebSocket subprotocol data beyond the existing terminal
  token shape, logs, or redirects.
- **Policy input shape:** durable lifecycle knobs belong in strict Pydantic
  config models under `AptlConfig` only when they have a runtime consumer.
  Transient CLI/API options may use boundary DTOs, but they must be typed,
  range-checked, and `extra="forbid"` in the same style. Avoid unchecked dicts,
  free-form shell commands, stringly typed cleanup modes, and duplicated
  profile/scenario schemas.
- **Time and schedule parsing:** use timezone-aware UTC instants for persisted
  timestamps and simple bounded integer seconds for TTL/idle intervals. If a
  cron-like schedule is required later, add one validated parser boundary; do
  not interpret arbitrary schedule strings in multiple call sites.
- **Environment binding:** lifecycle policy must not parse `.env` or service
  config itself. Lab start continues through `load_dotenv()`,
  `env_vars_from_dict()`, placeholder checks, generated config renderers, SOC
  cert generation, Suricata seeding, and bind-mount validation.
- **Deployment boundary:** policy actions call lifecycle functions that call
  `DeploymentBackend`. Do not call `docker compose`, `docker ps`,
  `docker volume rm`, `ssh`, or backend-private `_run()` methods directly from
  policy, API, web, validation, or tests.
- **Idle detection:** track narrow activity metadata only. Acceptable signals
  are control-plane lifecycle actions, terminal/session activity timestamps,
  scenario/orchestrator actions, runstore appends, or explicit heartbeat-style
  markers routed through one activity boundary. Do not record terminal bytes,
  command text, SOC payloads, packet contents, raw Docker logs, CPU load, or
  network counters as the canonical idle signal.
- **OS/process exposure:** schedulers and API workers must not put bearer
  tokens, passwords, API keys, private keys, raw `.env`, rendered config, or
  credential-bearing curl commands in argv or shell strings. Preserve argv-list
  subprocess construction and existing `curl_safe` handling for SOC HTTP.
- **Error envelopes:** lifecycle policy failures use existing `LabResult` /
  `LabActionResponse` shapes. A failed TTL/idle teardown is not a new exception
  hierarchy or readiness category. Redact backend stderr and unexpected
  exception text before it reaches CLI, API, logs, telemetry, web, run
  archives, or policy state.
- **Persistence boundary:** policy events and action receipts that are part of
  a run must use `LocalRunStore` redacting JSON/JSONL writes. Scheduler
  checkpoint state, if needed, belongs under ignored `.aptl/` state with the
  same ID/path validation and redaction discipline, not in checked-in config or
  as mutable run-archive truth.

## Extensibility Seam

The seam belongs at a small lifecycle-policy boundary that evaluates typed
policy data and emits one of the existing lifecycle actions: start, clean boot,
or teardown. The first policy variants should be parameterized by:

- instance identity: project directory, deployment backend, and
  `deployment.project_name`;
- lifecycle action: normal start, clean boot, or teardown;
- cleanup policy: remove Compose-managed volumes or preserve them;
- selected scenario: catalog id or explicit scenario path resolved by the
  existing scenario-selection helper;
- timing policy: TTL seconds, idle-timeout seconds, and scheduled UTC windows
  or intervals;
- activity source: a single last-activity marker that future terminal,
  orchestrator, API, or MCP activity producers can update without re-editing
  every policy evaluator.

Future cloud, Kubernetes, classroom pool, quota, or queue semantics should
extend this policy boundary and `DeploymentBackend` implementations. They
should not duplicate lab-start ordering, Docker Compose command construction,
config parsing, API schemas, or run-record assembly.

## Whole-Repo Surface

- `aptl.json`, `.env`, `.env.example`, `AptlConfig`,
  `DeploymentConfig.project_name`, and `RunStorageConfig`.
- `docker-compose.yml`, Compose profiles, top-level volumes, networks,
  generated bind mounts, and compose-project labels.
- `.aptl/` state, `.aptl/config/...`, `.aptl/runs/...`,
  `config/soc_certs/...`, `config/suricata/...`, `keys/`, `.mcp.json`, and
  run archives.
- `src/aptl/core/lab.py`, `src/aptl/core/lab_types.py`,
  `src/aptl/core/deployment/`, `src/aptl/core/config.py`,
  `src/aptl/core/env.py`, `src/aptl/core/runstore.py`,
  `src/aptl/core/snapshot.py`, and `src/aptl/backends/aces*.py`.
- `src/aptl/cli/lab.py`, `src/aptl/api/routers/lab.py`,
  `src/aptl/api/schemas.py`, `src/aptl/api/deps.py`,
  `web/src/lib/api.ts`, and `web/src/lib/types.ts`.
- Host/runtime layers: Docker daemon, SSH Docker transport, local process argv,
  local filesystem permissions, API worker lifetime, scheduler lifetime, and
  browser/web client disconnects.
- Repo gates: `.gc/plan-rules.md`, `pytest`, and
  `pre-commit run --all-files`.

## Gotchas And Anti-Patterns

- Adding a second `EphemeralInstance`, `RangeController`, Docker script, API
  schema, exception hierarchy, or validation stack when existing lifecycle
  results and deployment backends already own the behavior.
- Treating TTL/idle/schedule policy as deployment-backend behavior. Backends
  perform typed lifecycle operations; policy decides when to call them.
- Treating clean state as a container restart while preserving service
  volumes, SOC databases, generated rule volumes, stale API-key sync state, or
  in-container credentials.
- Inferring instance identity from container names, `aptl-*` prefixes,
  scenario names, folder names, `lab.name`, GitHub issue ids, or ACES metadata.
- Deleting `.env`, `.mcp.json`, `keys/`, checked-in `config/`, run archives,
  or ACES inventory evidence as part of the default teardown guarantee.
- Running timers in web clients, SSE loops, or request-local `asyncio` tasks and
  calling that reliable automated teardown.
- Scraping logs, terminal transcripts, Docker stats, packet captures, or SOC
  payloads to decide idle state.
- Returning raw Docker stderr, raw `icontract` messages, rendered config,
  `.env` values, terminal content, or command lines in policy errors.
- Weakening SSH-remote safety by assuming locally generated artifacts are
  visible to a remote Docker daemon.

## Non-Goals

- Do not implement DEP-003 in this preflight.
- Do not redesign Docker Compose, ACES SDL, deployment backends, run archive
  layout, SOC seeding, Suricata rule semantics, terminal capture, web auth, or
  startup readiness classification.
- Do not add Kubernetes, Podman, Nomad, cloud account provisioning, quota
  management, classroom pool scheduling, or multi-tenant billing semantics as
  part of the first lifecycle policy boundary.
- Do not guarantee byte-identical regenerated credentials, logs, timestamps,
  Docker object IDs, network IDs, endpoint IDs, or image cache contents across
  provisioned instances.
- Do not make destructive TTL/idle teardown part of default fast CI or
  pre-commit.
