# EXP-001 Durable Experiment Execution Preflight

This note is the architecture preflight for EXP-001 / issue #437. It is
guidance, not an implementation plan. It does not define another experiment,
task, trial, workflow, capture, or archival schema. EXP-001 is blocked on the
typed contracts delivered by EXP-002 (#438), EXP-010 (#752), and EXP-011
(#753); implementations must consume those contracts rather than anticipating
them with local substitutes.

Existing decisions remain binding: ADR-012 owns telemetry, ADR-013 and ADR-023
own deployment backends, ADR-025 owns first-party config, ADR-029 owns secret
handling, ADR-030 owns lab-start readiness envelopes, ADR-031 owns pure
orchestration contract guards, ADR-035 and ADR-046 own the ACES/runtime
boundary, ADR-039 owns web authentication, ADR-044 owns run reproducibility
records, and ADR-045 plus the DEP-003 and RNG-001 preflights own range lifecycle
and destructive clean boot.

## Architecture Decisions

- Add one durable **campaign controller** above existing admission, readiness,
  deployment, capture, archive, and cleanup services. It owns journaled control
  transitions and retry decisions. It does not parse ACES documents, schedule
  batch capacity, execute workflow graphs, operate Docker directly, collect
  evidence, or define the archival run schema.
- Keep the control journal and the archival run distinct. The journal is
  mutable, internal control-plane recovery state. Each attempt's ACES
  `experiment-run/v1` archive is portable scientific evidence and becomes
  immutable when sealed. The journal references admitted plans and archives by
  stable identifier and digest; it does not copy their schemas.
- Use three identities only: `campaign_id`, the stable `planned_trial_id` from
  EXP-002, and one globally unique `run_id` for each attempt. The `run_id` is
  also the attempt's archival identity. Do not add a second public attempt UUID.
  Store the attempt ordinal and prior attempt's `run_id`; #444 owns the single
  mapping of that lineage into public ACES reference semantics. Trace, span,
  workflow, and interactive session IDs remain correlation identifiers; none
  may substitute for an archival `run_id`.
- Journal campaign admission/readiness independently from trial attempts. An
  attempt-scoped readiness check receives its `run_id` before it can fail, so a
  readiness failure can still produce one terminal attempt. A campaign-level
  admission failure does not fabricate an archival trial attempt.
- Model admission, readiness, provisioning, running, capture finalization,
  sealing, cleanup, and terminal disposition as a closed, versioned transition
  graph. The names describe controller phases, not ACES run statuses,
  `StartupOutcome`, `DiagnosticImpact`, scenario-session states, or workflow
  step states. Map between domain results once at adapters; do not merge the
  enums.
- Treat capture finalization, archive sealing, and cleanup as independent
  receipts. Preserve primary failure classification if cleanup also fails.
  Cleanup produces a separate `clean`, `dirty`, or `unknown` range disposition;
  `dirty` or `unknown` always blocks automatic retry. Seal only after all
  evidence that the archival contract requires is available. If the final
  order chosen with #444 places cleanup after sealing, cleanup remains a
  controller receipt and must not mutate the sealed archive.
- Persist a transition intent before an external side effect and a receipt
  after observing its result. No filesystem transaction can atomically include
  Docker, an SSH daemon, a collector, or an archive writer, so restart must
  reconcile an unacknowledged intent with the actual range/capture/archive
  state before either advancing or retrying it.
- A completed planned trial is a durable fact. Recovery never calls the
  executor merely because a process-local future, callback, or response was
  lost. Explicit re-execution, when added by #499, creates a new attempt/run and
  lineage; it is not recovery of completed work.
- One owner may advance a range at a time. Ownership is keyed by the resolved
  project directory, deployment provider, `DeploymentConfig.project_name`, and
  state root. A durable owner generation/fencing value protects against stale
  processes after lease takeover; an advisory file lock alone is not a host-
  failure or multiple-worker guarantee.

## Durable Journal Contract

The existing `LocalRunStore` remains the run-archive boundary and its ID/path
validation and structured redaction rules must be reused. Its current
`write_json()`, `write_jsonl()`, and `append_jsonl()` operations are not a
campaign journal: they do not provide transactional transition-plus-receipt
writes, uniqueness, durable flush, corruption detection, or cross-process
serialization. `SessionState` and ADR-045 lifecycle checkpoint files are also
not suitable: they are convenience state whose recovery semantics permit reset
or clearing.

- Add a narrow campaign-journal repository contract rooted beside, but never
  inside, sealed per-run directories under the one resolved
  `RunStorageConfig.local_path`. The default local implementation should use a
  transactional durable store such as SQLite, with durability enabled and the
  storage/filesystem assumptions documented. Do not introduce a generic event
  bus, ORM domain model, or repository framework.
- Commit an event and its current projection in one transaction. Enforce at the
  persistence boundary: unique `run_id`; unique attempt ordinal per planned
  trial; at most one active attempt per planned trial; monotonic event sequence;
  valid predecessor/state transition; and exactly one immutable terminal event
  per attempt. Controller checks may improve errors but do not replace these
  constraints.
- Version the journal envelope/schema independently from ACES versions. Parse
  every read through one strict shape/version boundary. An unknown newer
  version, failed integrity check, invalid transition history, missing admitted
  plan/digest, or broken archive reference fails closed in a read-only
  `recovery_required` posture with bounded operator guidance. Never rename,
  truncate, delete, or silently start fresh from corrupt state.
- Protect the journal root with the same containment, identifier, symlink, and
  local permission discipline used by `LocalRunStore` and credential writers.
  A local journal must not be opened on a filesystem whose locking/durability
  guarantees are unknown. Future non-local run archives require an explicitly
  parameterized journal repository; they must not turn an S3 object append into
  a pretend transaction log.
- Resolve the existing split between configured `./runs` storage and direct
  `.aptl/runs` capture paths before treating either as canonical archival
  discovery. The controller must receive one resolved run-store/root object and
  pass it to capture and archive adapters; it must not infer or hard-code a
  second path.
- Record UTC timestamps for audit and restart, but calculate live deadlines and
  sleeps with an injectable monotonic clock. Persist absolute budget deadlines
  or consumed duration so a process restart cannot reset elapsed-time budgets.
  Record the realized delay when jitter is enabled.

## Failure Classification And Retry

- Use one closed failure class set at the controller boundary:
  `infrastructure`, `apparatus_readiness`, `participant`, `scenario`, `capture`,
  `operator_cancelled`, `policy_budget`, and `internal_defect`.
- Classify typed dependency results and stable diagnostic/error codes at their
  adapters. Never classify by exception message, exception class name, raw
  stderr, HTTP text, log scraping, or substring matching. Unexpected exceptions
  become a bounded `internal_defect` record and are non-retryable by default.
- Keep facts separate from policy. A failure record contains class, safe stable
  code, phase, time, and affected component. A retry decision separately
  records the versioned policy, attempt and elapsed budgets, clean-range
  disposition, archive/capture disposition, and chosen delay. A boolean
  `retryable` on a backend result is not sufficient campaign policy.
- Keep the primary cause, evidence completeness, archival disposition, and
  range cleanliness as separate axes. For example, a participant failure
  followed by cleanup failure remains a participant failure with an
  `unknown`/`dirty` range; do not overwrite it with a synthetic cleanup class.
- Defaults are conservative: deterministic scenario and participant failures,
  operator cancellation, budget/policy denial, internal defects, unknown
  codes, corrupt state, uncertain cleanup, and uncertain archive identity are
  not retried. Only explicitly configured classes/codes may retry, and only
  while attempt-count, per-attempt, backoff, and total elapsed-time budgets all
  permit it.
- A retry allocates a fresh `run_id`, records prior-run lineage, and starts only
  after existing safe stop/kill and readiness/clean-state checks prove the
  range clean. It never overwrites an archive, reuses a workflow execution ID,
  resumes a participant process by assumption, or invokes the current
  single-run ACES backend retry with the same archival run target.

## Required Cross-Cutting Concerns To Reuse

- **Admission and ACES:** public `aces_contracts` loaders/validators,
  `experiment-authoring-input/v1`, the immutable planned-trial contract from
  EXP-002, ACES diagnostic rendering, and #444's `ExperimentRunModel` assembly,
  validation, lineage, sealing, and discovery index. Do not add Pydantic mirrors
  of ACES models.
- **Range lifecycle:** `clean_boot_lab()`, `orchestrate_lab_start()`,
  `stop_lab(remove_volumes=True)`, the existing safe kill boundary,
  `DeploymentBackend.status()`, `LabResult`, and typed readiness checks from
  EXP-011. Reconciliation queries these owners; it does not shell out to Docker
  or SSH.
- **Execution:** the ACES parser/planner/runtime manager and
  `DeploymentBackend.realize()` remain owners of scenario realization.
  `WorkflowEngine` remains an in-memory workflow helper; its run ID, history,
  and step attempt counts are not campaign or archival attempt state.
- **Capture:** EXP-010 owns capture-plan validation, collector registry,
  media/path/budget gates, bounded collector execution, evidence references,
  and loss/finalization results. The controller consumes typed receipts and
  never passes itself, credentials, or unrestricted filesystem/process access
  to a collector.
- **Config:** `AptlConfig` and nested Pydantic models with `extra="forbid"`,
  `load_config()`, and existing CLI config display/projection. Runtime retry,
  classifier override, timeout, backoff, attempt/elapsed budget, and
  fail-fast/continue policy belong in one strict nested execution config with
  conservative defaults, finite upper bounds, and explicit units.
- **Environment and validation:** `load_dotenv()`, `EnvVars`,
  `env_vars_from_dict()`, placeholder validation, generated-config renderers,
  bind-mount checks, and ACES/readiness/capture validators remain the only
  owners of their shapes. Campaign policy cannot name env keys, compose
  objects, shell commands, host paths, or arbitrary Python classifiers.
- **Persistence and security:** `LocalRunStore` ID/path containment,
  `redact()`, `_safe_default`, credential-writer symlink/permission patterns,
  and `curl_safe` token handling. Structured journal/run writes are redacted at
  the boundary; opaque capture bytes remain EXP-010's validated responsibility.
- **Errors and observability:** existing typed domain results and stable codes,
  `get_logger()`, ADR-012 telemetry helpers, and established CLI/API envelopes.
  Do not add a parallel exception hierarchy. The logger and telemetry helpers
  are not automatic secret filters, so callers pass only already-bounded safe
  fields such as IDs, phase, class/code, counts, and durations.
- **API and web:** authenticated FastAPI router registration through
  `verify_token`, `WebAuthSettings`, loopback/Host validation, BFF same-origin
  and CSRF controls, Pydantic response projections, and `web/src/lib/api.ts`
  fetch streaming. CLI/API/web read a core status DTO; they do not replay the
  journal or reimplement transition and retry policy.

## Security And Validation Layers

- **Experiment input:** EXP-002 parses untrusted YAML/JSON through ACES safe
  loaders and strict public models, resolves only admitted references, and
  emits an immutable plan plus digest. The controller accepts that typed plan,
  never a raw document or a second permissive dict schema.
- **Capture input:** EXP-010 validates collector names/options, path
  containment, media type, size/duration/count budgets, and secret-handling
  rules before any collector starts. Journal records contain only typed
  receipts/references, never evidence payloads or collector exception text.
- **Config shape:** the nested execution policy is part of `AptlConfig` only,
  with unknown fields rejected, enumerated failure classes/codes, finite
  positive limits, bounded backoff, and cross-field budget validation. `.env`
  remains service-secret/runtime binding, not a second retry-policy surface.
- **Deployment/readiness:** EXP-011 readiness gates and existing lifecycle
  entry points validate apparatus, resources, archive writability, range
  identity, clean state, isolation, and safe stop/kill. The controller cannot
  translate `LabStatus.running` alone into “clean” or “ready.”
- **Filesystem/persistence:** validate every external ID and relative path,
  reject traversal/symlinks, contain resolved paths under the configured root,
  use owner-only permissions, transactional durable commits, and integrity/
  version checks before side effects. Opaque evidence never passes through a
  structured serializer that pretends it can sanitize bytes.
- **Auth surface:** all status and control routes remain behind ADR-039 auth and
  the BFF's Host/same-origin/CSRF controls. Tokens, idempotency keys, policy
  bodies, and diagnostics do not go in URLs, redirects, browser storage,
  WebSocket subprotocols, or SSE `EventSource` query strings.
- **OS/process exposure:** use existing argv-list subprocess construction,
  deployment backends, and `curl_safe`; never place secrets, rendered config,
  raw experiment documents, capture options, or journal payloads in process
  argv, shell text, environment dumps, Docker labels, or container names.
- **Error envelope:** persist and return only stable safe code, failure class,
  phase, redacted component label, timestamp, retry/budget summary, and bounded
  operator action. Do not copy existing raw `str(exc)`/stderr response patterns.
  Frontend truncation is not a security boundary.
- **Logging/telemetry:** emit identifiers and low-cardinality phase/outcome/
  class/code fields only. Do not attach plan bodies, commands, env/config,
  evidence, exception strings, backend stderr, participant output, or file
  paths. `APTL_EXPERIMENT_NO_REDACT` is a local capture-sink exception and must
  never disable journal, logs, telemetry, CLI, or API redaction.

## Extensibility Seam

The seam belongs at the campaign controller's typed ports: journal repository,
clock/sleeper and ID generator, admitted-plan reader, readiness/reconciliation,
attempt executor, capture finalizer, archive sealer, and range cleanup. The
controller receives an explicit range identity and a versioned retry policy.
This supports the next expected variations (#459 parallel ranges, #499
pause/resume/re-execution, SSH or future deployment backends, new collector
plugins, and a future non-local journal) without editing the transition graph or
duplicating dependency schemas. New failure-producing components extend one
stable code-to-class adapter table; they do not add classifier conditionals to
CLI, API, collectors, or backend implementations.

Do not generalize this seam into another workflow language. New states require
a journal-version migration and explicit recovery semantics. New retry knobs
require strict config fields and must be recorded with each decision. A future
parallel scheduler must pass a distinct range identity/lease; it cannot weaken
single-owner fencing or share contaminated state.

## Whole-Repo Surface

- Contracts and decisions: installed `aces_contracts`, `docs/sdl/`, ADR-012,
  ADR-025, ADR-029 through ADR-031, ADR-035, ADR-039, ADR-044 through ADR-046,
  this preflight, and the RNG-001/DEP-003 preflights.
- Config and state: `aptl.json`, `.env` binding, `AptlConfig`,
  `RunStorageConfig`, `DeploymentConfig`, the resolved project directory,
  configured run root, `.aptl/` operational state, per-run archives, and the
  new journal root.
- Core/runtime: `core/config.py`, `runstore.py`, `lab.py`, `lab_types.py`,
  `kill.py`, `session.py`, `lifecycle_policy.py`, `lifecycle_enforce.py`,
  `runtime/workflow_engine.py`, `services.py`, `telemetry.py`, deployment
  backends, ACES adapters, capture adapters, and redaction/logging utilities.
- Control surfaces: CLI run/lab/kill/status commands; FastAPI deps, middleware,
  routers and Pydantic schemas; BFF proxy controls; web API/types/status views;
  and any MCP operation that can start, stop, or mutate the same range.
- Host/runtime: local filesystem durability and permissions, process crash and
  host reboot, multiple API/controller workers, Docker daemon and Compose
  project labels/volumes/networks, SSH transport/remote daemon state, process
  argv/environment, clocks, signals, OOM/container loss, disk exhaustion, and
  browser/client disconnects.
- Verification: `.gc/plan-rules.md`, fault injection at every transition and
  every intent/side-effect/receipt gap, state-model transition tests, journal
  corruption/newer-version tests, double-controller/fencing tests, restart
  tests, redaction/API tests, ACES lineage validation, and the repository
  `pytest` and `pre-commit run --all-files` gates. Clock, sleeper, ID, backend,
  collector, and archive seams must be injectable so tests never wait real
  backoff intervals.

## Current Incompatibilities Not To Inherit

- Lab start currently chooses timestamp-to-the-second run IDs and can reuse one
  `AcesRunTarget` during its backend retry. Neither behavior is a valid archival
  attempt identity for EXP-001. Its active trace ID must not become the new
  campaign run ID merely because current capture code uses it as a directory.
- The current lab path writes a success-only `aptl.run-record/v1` record as a
  non-fatal late startup step. It neither produces one terminal record for every
  attempt nor replaces #444's ACES archive/seal contract.
- Some collectors write beneath `.aptl/runs` while CLI and validation resolve
  `RunStorageConfig.local_path` (default `./runs`). Recovery and discovery
  cannot be correct until one run root is threaded through all owners.
- `LocalRunStore` overwrite/append operations, scenario-session persistence,
  lifecycle-policy JSON checkpoints, and continuity JSONL events are not
  atomic campaign state and must not be promoted by renaming them.
- `WorkflowEngine` is process-local, and its step attempt counter is not a
  scientific attempt. The current ACES apply retry is an operational retry,
  not bounded campaign recovery.
- Existing API paths that surface raw `str(exc)` or launch work in request-local
  threads are precedents to correct at the new boundary, not patterns to copy.
  Campaign ownership cannot depend on an HTTP request, SSE connection, browser,
  or one FastAPI worker staying alive.

## Gotchas And Anti-Patterns

- Building a second experiment DSL, trial/task/run model, ACES validator,
  capture-plan schema, readiness engine, archive manifest, or evidence index.
- Reusing `StartupOutcome`, `DiagnosticImpact`, ACES workflow outcomes,
  `SessionState`, HTTP statuses, exception types, or a generic `retryable` bool
  as the campaign failure taxonomy.
- Retrying from exception handlers, backend callbacks, API handlers, or
  collectors instead of making one durable controller decision.
- Reusing or overwriting a run directory, manifest, workflow ID, or evidence
  file for a retry; “attempt 2” must be a new archival run with lineage.
- Assuming an absent container means clean state, or treating cleanup failure,
  timeout, missing telemetry, corrupt journal, unavailable archive, or unknown
  state as success. Uncertainty blocks automatic action.
- Replaying external side effects from last-known journal phase without first
  observing the deployment, collector, archive, and cleanup owners.
- Holding a database transaction across Docker/SSH/capture calls, or claiming a
  file rename makes those remote side effects exactly once.
- Storing exception text, command lines, env dumps, config snapshots with
  secrets, participant output, collector payloads, raw stderr, bearer tokens,
  filesystem paths, or arbitrary metadata in journal/log/API error fields.
- Hard-coding `./runs`, `.aptl/runs`, Compose names, localhost Docker, one API
  worker, POSIX `flock`, wall-clock sleeps, or a clean shutdown assumption.
- Letting pause/cancel kill first and journal later. Record command intent and
  fence new work before invoking the existing safe stop/kill boundary, then
  preserve/finalize evidence as far as safely possible.

## Non-Goals And Boundaries

- Do not implement EXP-001 in this preflight.
- Do not implement the blocked EXP-002 admission/planning, EXP-010 capture, or
  EXP-011 readiness contracts, and do not guess their DTOs. EXP-001 begins at
  their typed boundaries.
- Do not redesign ACES schemas or validation, author a local experiment DSL,
  or own #444's archival model, evidence index, checksum seal, and migration.
- Do not absorb #459 batch ordering/capacity/fairness, #469 resource accounting,
  or #499 pause/resume/re-execution semantics. The controller exposes durable
  attempt/status seams for those owners.
- Do not promise mid-trial scientific checkpoint/resume, exactly once external
  side effects, automatic repair of corrupt/newer journals, or recovery of
  unflushed external evidence. Recovery is reconciliation plus safe monotonic
  progress.
- Do not add Kubernetes/cloud orchestration, distributed consensus, a generic
  saga framework, a message broker, arbitrary retry plugins, or S3 journal
  emulation to the first local implementation.
- Do not change Docker Compose, container Dockerfiles, or service config merely
  to host controller state. If later implementation does, the clean-lab
  validation rule in `.gc/plan-rules.md` applies.
