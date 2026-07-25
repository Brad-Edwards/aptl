# OBS-002 Correlation Identity And Clock Context Preflight

This note is the architecture preflight for OBS-002 / issue #447. It is
guidance, not an implementation plan. No new ADR is needed: ADR-012 owns
OpenTelemetry integration, ADR-027 owns red-team structured logging, ADR-029
owns secret handling and redaction, ADR-033 owns the reasoning trace boundary,
ADR-041 and ADR-042 own Kali capture and PTY ownership, ADR-044 owns the
ACES-aligned run record, ADR-046 owns dynamic ACES realization, and ADR-047
owns experiment admission and trial-plan determinism.

OBS-002 adds one cross-cutting rule: action-to-observation linkage must be
auditable without treating timestamp proximity as causality. Stable identity,
clock context, evidence source limits, and observer effects must travel through
the existing ACES, control-plane, capture, and archive contracts rather than a
new local tracing vocabulary.

## Architecture Decisions

- Reuse ACES experiment and runtime identities as the portable identities:
  `ExperimentSpecModel.spec_id/spec_version`, task refs and task
  `task_id/task_version`, run-plan condition/allocation identifiers,
  `TrialPlan.plan_id`, `TrialPlan.plan_digest`,
  `TrialPlan.source_set_digest`, `PlannedTrial.planned_trial_id`,
  ACES participant addresses and episode IDs, participant runtime event/action
  refs, capture spec/requirement/window refs, evidence record refs, derived
  measure/evaluation refs, and `ExperimentRunModel.run_id`.
- Treat APTL `trace_id`, MCP `session_id`, and sidecar capture session IDs as
  local correlation and routing facts, not replacements for experiment, planned
  trial, attempt/run, participant episode, action, capture, evidence, or
  evaluator identities. They may appear as related metadata only when validated
  and redacted according to the existing runstore/MCP policies.
- Preserve the deterministic admission boundary. Planned identities must be
  derived from ACES inputs through `TrialPlan` and canonical JSON hashing, not
  from wall clock, filesystem order, UUIDs, process-global randomness, or
  runtime ingestion order. Per-attempt identities are allowed only where the
  surface is explicitly a run/attempt/episode result, and they must not be
  mistaken for planned identity.
- Represent correlation as a graph of typed associations over existing refs.
  The minimum association methods are `explicit_identifier`, `declared_rule`,
  `time_window_candidate`, and `gap_or_unknown`. Timestamp proximity alone is
  never a causal link. `SourcePipelineModel.correlation_uid` is a source fact;
  it is not automatically an APTL causal edge.
- Record clock context per evidence source and timestamp domain. ACES already
  provides `ExperimentClockContextModel`, run-plan `clock_intent`,
  participant runtime `occurred_at`/`recorded_at`/`ingested_at` plus
  `clock_authority`, source pipeline timestamp fields, participant
  time-management contexts, capture windows, evidence `captured_at`, and
  derived-measure `generated_at`. APTL may add archive-local projections only
  to connect these contracts to local run files and collector outputs.
- Disclose observer effects with the existing realized-form and augmentation
  disclosure contracts. Injecting metadata into a range component, blue
  telemetry source, command stream, environment, capture channel, or runtime
  binding is an experiment augmentation unless the channel is already
  documented as a non-secret control-plane channel.
- Keep capture capability declarations honest. APTL may admit capture
  requirements only when `create_aptl_manifest().observation` and
  `SUPPORTED_CAPTURE_CAPABILITIES` describe the supported non-secret channel.
  A collector function or sidecar path by itself is not a portable capture
  capability claim.

## Cross-Cutting Concerns To Reuse

| Layer | Canonical incumbent and required behavior |
|---|---|
| ACES experiment contracts | Use `aces_contracts.contracts` models for experiment specs, tasks, run plans, clock contexts, capture specs, evidence records, derived measures, run traceability, realized-form disclosures, augmentation disclosures, and participant runtime envelopes. Do not mirror these schemas in APTL DTOs. |
| Admission and planning | `src/aptl/core/experiment/spec_loading.py`, `resolver.py`, `admission.py`, `admission_steps.py`, `trial_plan.py`, `capture_mapping.py`, `apparatus.py`, and `errors.py` own bounded loading, project-contained resolution, ACES validation, deterministic planned-trial IDs, fail-closed capture support, and safe diagnostics. |
| Runtime adapters | `src/aptl/backends/aces.py`, `aces_orchestrator.py`, `aces_evaluator.py`, `aces_participant_runtime.py`, `aces_participant_actions.py`, `aces_participant_support.py`, `aces_participant_bindings.py`, `aces_observation.py`, and `aces_repro.py` are the owners of ACES workflow, evaluation, participant, observation, and run-record projections. |
| Run archive and persistence | `src/aptl/core/runstore.py` owns run/session ID validation, active trace lookup, `.aptl/runs/<run_id>` layout, `create_json_once`, JSON/JSONL persistence, and redacted structured writes. `src/aptl/core/exporter.py` packages archives; it is not a sanitizer or correlation builder. |
| Telemetry and red logs | `src/aptl/core/telemetry.py`, `mcp/aptl-mcp-common/src/telemetry.ts`, `mcp/mcp-red/src/capture.ts`, and `mcp/mcp-red/src/logger.ts` own trace context, OTel attributes, MCP tool-call capture, OCSF-shaped red activity logs, and best-effort local sinks. Extend those envelopes through existing redaction/truncation paths. |
| Capture sidecar | `containers/kali-capture/writer.py`, `mcp/aptl-mcp-common/src/runs.ts`, `captures.ts`, and `tools/handlers.ts` own ID checks, run-path resolution, PTY tee files, bounded sidecar RPC, Docker-copy harvest, and MCP result envelopes. Do not add path, command, chmod, truncate, delete, or shell execution to the sidecar for correlation. |
| Config and environment | `src/aptl/config.py`, `src/aptl/core/config_models.py`, `src/aptl/core/env.py`, `mcp/aptl-mcp-common/src/config.ts`, `aptlShellEnv`, and ADR-025 own first-party config and explicit runtime environment binding. Add no free-form `correlation` dict or parallel env parser. |
| Secret handling and errors | `src/aptl/core/redaction.py`, `mcp/aptl-mcp-common/src/redaction.ts`, `curl_safe`, `AdmissionRejection`, `Diagnostic`, `LabResult`, `StartupDiagnostic`, `SSHError`, and MCP `harvest_warning` own redaction and error envelopes. Correlation metadata must pass through these instead of adding a new exception hierarchy. |
| API and web auth | `src/aptl/api/deps.py` and `src/aptl/api/middleware/bff.py` own bearer-token verification, WebSocket token handling, host/CSRF gates, and BFF session injection. OBS-002 should not add a bypass or alternate auth path. |
| Verification workflow | `.gc/plan-rules.md`, `pytest`, `pre-commit run --all-files`, MCP package tests/builds, and existing deterministic clock seams such as timestamp factories and injected command runners are the verification and test-style incumbents. |

## Security And Validation Layers

- **Auth surface:** the design should add no new public endpoint, listener, or
  remotely supplied identity authority. Any future API exposure must remain
  behind `verify_token` and BFF host/CSRF/session gates. MCP remains local
  stdio; the Kali sidecar remains a local Unix-socket helper.
- **Secret-handling surface:** IDs are non-secret but replayable local
  session/run/trace values are sensitive in analysis surfaces under ADR-029.
  Do not log, export, or return raw tokens, credentials, private keys,
  secret-bearing config, full commands, transcripts, or captured payload bytes
  as correlation metadata. Use existing Python and TypeScript `redact()`
  policies and `curl_safe`.
- **Schema and shape validation:** ACES Pydantic models remain the portable
  schema authority. APTL archive projections must validate incoming and
  outgoing IDs with `LocalRunStore`/MCP/sidecar ID rules and must preserve
  pydantic diagnostics without leaking `input`. TypeScript MCP arguments must
  keep using JSON Schema definitions plus handler assertions.
- **Environment binding:** correlation metadata may enter range components
  only through existing explicit channels such as SSH environment propagation
  and sidecar metadata frames. Any new variable must be centralized in the
  shared MCP SSH environment construction and documented as non-secret. Do not
  smuggle IDs through `.env`, scenario parameters, arbitrary command strings,
  URLs, target content, or durable service config.
- **OS/process exposure:** launch commands through argument arrays and existing
  backend runners. Do not put secrets or unnecessary correlation IDs in process
  argv where `ps`, shell history, audit logs, or target telemetry can observe
  them. Do not add local shell interpolation to collectors or sidecar paths.
- **Error envelopes:** admission, lab startup, API, MCP, and sidecar failures
  must continue through existing diagnostic/result envelopes. Errors may name a
  missing ref, unsupported capture capability, unknown clock context, duplicate
  event, or unresolved evidence rule, but must not include raw ACES payloads,
  pydantic `input`, backend stderr, command bodies, evidence bytes, or tokens.
- **Persistence and export:** `LocalRunStore` is the archive owner. Use
  create-once writes for identity-bearing canonical records and append-only
  JSONL only for event streams. `exporter.py` must preserve the resulting
  graph and disclosures but must not be relied on to redact or infer them.
- **Observability:** OTel and red-team logs may carry bounded, redacted IDs and
  association refs. They must not capture LLM reasoning, secrets, raw evidence,
  or blue-detection conclusions as unqualified causal claims.
- **Backend/runtime validation:** deployment and ACES adapters must continue to
  use `DeploymentBackend`, ACES runtime snapshot contracts, manifest
  capability checks, and stateful observation helpers. OBS-002 must not call
  Docker directly or infer support from container names.

## Extensibility Seam

The seam is a small versioned correlation projection in the run archive whose
nodes are existing ACES references or `LocalRunStore` evidence refs, and whose
edges carry only:

`source_ref`, `target_ref`, `association_method`, `rule_id`, `clock_context_ref`,
`confidence_or_status`, and `disclosure_refs`.

A future source should add a source adapter that emits this projection plus its
clock metadata and capture capability row. It should not edit every controller,
collector, exporter, and evaluator to learn a new identity concept.

Clock collection needs one source-owned provider seam:

`(source_kind, source_id, timestamp_domain, clock_source, synchronization_status,
measured_offset, uncertainty, measurement_time, observer_effect_ref)`.

Collectors and MCP sinks can implement that seam differently, but they should
not scatter `datetime.now(UTC)`, `Date.now()`, UUIDs, or wall-clock parsing
through business logic as identity or causality sources.

## Whole-Repository Surface

- ACES contract consumption: `aces_contracts`, `aces_sdl`, and
  `src/aptl/backends/aces_manifest.py`.
- Experiment admission and planning: `src/aptl/core/experiment/**`.
- Runtime realization, participant histories, observation, evaluation, and run
  record projection: `src/aptl/backends/aces*.py`.
- Local control-plane state and archives: `src/aptl/core/session.py`,
  `telemetry.py`, `runstore.py`, `lab.py`, `collectors.py`, `snapshot.py`, and
  `exporter.py`.
- API/web control surfaces: `src/aptl/api/**` and web BFF auth middleware when
  correlation data is exposed to the UI.
- MCP common and red sinks: `mcp/aptl-mcp-common/src/**`,
  `mcp/mcp-red/src/capture.ts`, and `mcp/mcp-red/src/logger.ts`.
- Kali capture sidecar and host/runtime layer:
  `containers/kali-capture/writer.py`, Docker copy/exec paths, SSH
  environment propagation, process argv, local filesystem permissions, and
  ignored `.aptl` state.
- Published architecture docs and workflow gates: this note,
  `docs/architecture/index.md`, `.ground-control.yaml`, `.gc/plan-rules.md`,
  `.pre-commit-config.yaml`, and CI.

## Gotchas And Anti-Patterns

- Do not conflate `trace_id`, `run_id`, `session_id`, `episode_id`,
  `action_instance_id`, `evaluator run_id`, planned trial ID, capture ID, and
  evidence record ID. They answer different questions and have different
  stability promises.
- Do not use timestamp proximity, ingest order, sorted filenames, or sidecar
  copy order as causal proof. At most they create `time_window_candidate`
  associations with clock uncertainty attached.
- Do not fabricate causal IDs for sources that cannot propagate identifiers.
  Preserve their source timestamps, collection timestamps, offset/uncertainty,
  and association method instead.
- Do not collapse duplicate events, restarts, missing source timestamps, or
  reordered ingestion into one "best" event by timestamp. Preserve the source
  sequence/status, gap disclosure, and association method.
- Do not create an APTL-local replacement for ACES capture, evidence,
  derived-measure, clock, run traceability, participant runtime, or apparatus
  context schemas.
- Do not duplicate ID validation separately in Python, TypeScript, and the
  sidecar. Reuse the existing run/session ID rules and add any new shared rule
  at the boundary that owns the ID.
- Do not silently inject identifiers into attacker-visible command text, target
  files, blue telemetry, SIEM log fields, HTTP parameters, shell history, or
  service config. If an experiment permits that augmentation, record the
  observer effect and the non-secret channel used.
- Do not treat `mcp-red` OCSF logs, OTel spans, pcap timestamps, Wazuh alert
  times, container wall clocks, and Python/Node collection times as one clock
  domain. Record domains and uncertainty before comparing them.
- Do not make exporter, dashboard, or evaluator code infer missing links from
  filenames or timestamps. Correlation belongs in the run archive projection
  and ACES traceability/disclosure records.
- Do not bypass capture capability admission by accepting every capture spec
  and later writing loss notes. Unsupported capabilities must fail or be
  explicitly disclosed at the admission/capture boundary required by ACES.
- Do not broaden OBS-002 into a global tracing backend, database migration,
  remote telemetry service, generic event bus, or new workflow engine.

## Non-Goals And Boundaries

- Do not implement OBS-002 in this preflight.
- Do not change ACES contract models, invent portable APTL identity schemas, or
  redesign experiment admission.
- Do not redesign lab lifecycle, Docker topology, MCP transport, web/API auth,
  sidecar RPC ownership, OTel deployment, exporter packaging, or runstore
  layout except through a separately reviewed implementation.
- Do not capture LLM reasoning traces or unredacted transcripts as evidence.
- Do not require an always-on global tracing backend; the local single-user
  offline run archive remains the default.
- Do not make timestamp correlation a causal inference engine. OBS-002 records
  explicit identifiers, declared rules, candidate windows, gaps, and clock
  disclosures so later evaluators can reason over evidence honestly.
