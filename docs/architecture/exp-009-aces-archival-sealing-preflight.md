# EXP-009 ACES Archival Run And Evidence Sealing Preflight

This note is the architecture preflight for EXP-009 / issue #444. It is
guidance, not an implementation plan. [ADR-050](../adrs/adr-050-terminal-attempt-archival-and-atomic-seal.md)
owns attempt identity, the canonical portable record, the atomic seal commit,
the discovery index, and legacy-manifest migration. ADR-044 remains the
composition boundary; EXP-010 owns evidence acquisition; REP-003 owns
ready-to-seal provenance; OBS-002 owns correlation and clock disclosures; and
the execution lifecycle in #437/#459 owns when an attempt becomes terminal.

The requirement uses ACES terminology. In this repository the installed
`raes==2.0.0` public contract package is the schema authority and publishes
`ExperimentRunModel` with `schema_version="experiment-run/v1"` and
`ExperimentEvidenceRecordModel` with
`schema_version="experiment-evidence-record/v1"`. Do not recreate an ACES
package, DTO namespace, or schema mirror.

## Architecture Decisions And Guardrails

### One terminal authority, one record per attempt

The execution controller must expose one terminal-attempt handoff covering
success, scenario/evaluator failure, infrastructure interruption, policy stop,
cancellation, invalidation, and retry. That handoff is the only authority that
may finalize the portable run.

The handoff carries immutable owner-native facts, not a bag of dictionaries to
rediscover later:

- admitted plan/source-set identity, planned trial, task and sealed scenario
  snapshot references, realized bindings, parameters, stochastic controls, and
  any random-stream draw records;
- distinct `attempt_id`/portable `run_id`, predecessor run reference, attempt
  ordinal or execution-owned lineage coordinate, and terminal cause;
- final RAES runtime snapshot, observed range/apparatus facts, selected
  processor/backend/participant manifests, and participant implementation
  provenance;
- evidence `AcquisitionResult` plus the exact content/artifact metadata
  captured by its owners;
- evaluator-supplied result summaries and their concrete evidence references;
- terminal timestamps and source-owned clock contexts; and
- deviations, invalidation reason, cleanup/reset disclosure, and any
  recovery-origin fact.

`planned_trial_id`, `attempt_id`/run ID, `trace_id`, `session_id`,
participant-episode ID, action ID, workflow execution ID, evidence-record ID,
and result ID stay distinct. A retry reuses admitted plan bytes but gets a new
attempt/run ID. Do not derive an attempt ID from time alone, reuse the planned
trial ID, or use a workflow engine's internal UUID as the experiment run ID.

The execution controller owns terminal-cause normalization. The archive
coordinator consumes that typed cause and the ADR-050 mapping; it does not add
another `PENDING/RUNNING/FAILED` workflow or infer cancellation from a missing
file. A normal `finally` boundary covers exceptions and cooperative
cancellation. A durable attempt journal must make SIGKILL, host restart, or
power-loss recovery explicit without rebuilding the past from current
control-plane state.

### Compose public RAES records; do not mirror them

Construct the canonical terminal `manifest.json` through the public
`ExperimentRunModel`. Reuse its nested public models for:

- `ExperimentTaskReferenceModel` and
  `ExperimentScenarioSnapshotReferenceModel`;
- `ExperimentApparatusContextModel`, apparatus components, manifest refs,
  compatibility declarations, configuration parameters, stochastic controls,
  clocks, measurement channels, observed setup evidence, and known
  limitations;
- `ParticipantImplementationProvenanceModel`;
- `ExperimentParameterModel`, `RealizedBindingProvenanceModel`,
  `ExperimentStochasticControlModel`, random-stream draw records, and realized
  time-model provenance;
- `ExperimentRunTraceabilityModel`, evidence/artifact refs, realized-form and
  augmentation disclosures;
- `ExperimentResultSummaryModel`; and
- `ExperimentInvalidationModel` plus RAES `ExperimentReferenceModel` lineage.

Validate the model and then run every applicable public cross-artifact
validator, especially:

- `validate_experiment_run_against_task`;
- `validate_experiment_run_archival_datetimes`;
- `validate_experiment_apparatus_context_against_manifests`; and
- `validate_experiment_run_time_model` when the admitted scenario is governed
  by a time-model declaration.

The task/run validator is load-bearing. It checks task and scenario identity,
apparatus constraints, declared metric IDs, observation requirements, concrete
metric evidence, and stochastic draw/control binding. Local validation may
check archive bounds, containment, digest agreement, terminal policy, and
cross-owner joins that RAES cannot see. It must not restate RAES field or
semantic validation.

The current `RunRecordInputs` / `build_reproducibility_record()` output is a
legacy APTL composition, not an input shortcut to the RAES model. Do not grow
it into a mirror of `ExperimentRunModel`. New internal holders, if any, are
narrow immutable value transport at the terminal coordinator boundary, never
serializable contracts.

### Evidence identity and result grounding stay owner-native

EXP-010 already owns collector registration, acquisition limits, terminal
capture status, structured redaction, content addressing, and public evidence
record construction. EXP-009 consumes those outputs; it does not rescan
`mcp-side/`, `kali-side/`, orchestration directories, or arbitrary run paths to
guess evidence.

Every raw capture retained by a run is represented by an
`ExperimentEvidenceRecordModel`. Prefer its
`ExperimentRawEvidenceContentModel.artifact_ref` as the full portable
`ExperimentArtifactRefModel` for the content-addressed blob. That keeps media
type, size, checksum, creation time, source, sensitivity, and satisfied
evidence refs together and lets the run reuse the exact same artifact object in
`evidence_artifacts`. A bare `content_uri`/checksum pair is insufficient when
the run later needs concrete artifact metadata.

Current `EvidenceRef` lacks media type, size, source, and creation time.
Preserve these owner-observed facts at acquisition time or in an immutable
acquisition receipt; do not fill them at seal time with `stat()`, file
extension guesses, or the seal clock.

Capture failure must not disappear because no raw bytes were produced.
Unavailable source, startup failure, mid-run loss, truncation, clock skew,
timeout, and finalization failure retain their existing typed status and stable
diagnostic code. The terminal lifecycle dependency must supply concrete
lifecycle/attempt evidence sufficient for the RAES run's mandatory
traceability, artifact, and result-summary fields even when an authored
collector never starts. Do not fabricate an evidence-record ref or use an empty
file as proof.

Result summaries are supplied by the evaluator and retain its metric IDs,
value/value-status, uncertainty, notes, and evidence refs. The archival layer
may validate and copy them; it must not derive scores, compute statistics,
translate workflow success into a metric value, compare conditions, or attach
evidence merely by timestamp. Even `missing`, `withheld`, and
`not-applicable` summaries require the concrete evidence references demanded
by the installed model.

### Apparatus, provenance, correlation, and clock contexts remain distinct

Do not flatten these incumbent concepts:

- RAES `RuntimeSnapshot` is portable runtime state.
- APTL `RangeSnapshot` is backend-owned observed inventory.
- `ExperimentApparatusContextModel` is the portable apparatus projection.
- REP-003 `run-provenance.json` is a ready-to-seal, create-once backend
  provenance input.
- OBS-002 `correlation.json` is an APTL-local graph over existing refs with
  explicit association methods and clock uncertainty.
- The trial plan is an internal immutable execution journal.
- Evidence records describe captured evidence.
- The seal marker commits the validated byte graph.

Use the existing provenance provider registry and `SealProfile`. A complete
terminal context publishes canonical `run-provenance.json`; startup continues
to publish only `startup-provenance.json`. Missing/denied/truncated provenance
is an explicit limitation whose fatality is decided by the readiness/seal
policy, not by a second archive-specific provider vocabulary.

Use `ClockProvider` and RAES `ExperimentClockContextModel`. Preserve each
source's timestamp domain, authority, synchronization status, offset, and
uncertainty. Do not claim NTP synchronization from a host UTC timestamp, merge
container/MCP/SOC clocks into one domain, or treat time proximity as causal
traceability.

Correlation must be finalized before the seal commit or explicitly disclosed
as limited. Reuse the pure OBS-002 builder and association rules, but do not use
the current post-manifest, overwrite-capable
`persist_run_correlation_best_effort()` path after an archive is sealed.

### Seal visibility is a store transaction, not a filename convention

The final archive has one commit point: the ADR-050 seal marker. Before that
marker, the attempt is an unsealed recovery candidate even if a complete
`manifest.json` happens to exist. After it, all referenced bytes are immutable.

The seal inventory is closed and bounded. Each entry carries a safe
run-relative POSIX path, media type, exact byte size, checksum algorithm/value,
and logical role. It includes the canonical run record, evidence records and
blobs, final provenance, correlation/clock disclosures, evaluator artifacts,
and required lifecycle evidence. The completeness statement identifies every
required producer/capture/provenance outcome and every accepted limitation.
Directory enumeration is not the authority for membership.

The store verifies bytes and digests through descriptor-relative no-follow
reads before commit. Its final publication primitive must:

- reject absolute, empty, `.`, `..`, NUL, symlink, special-file, and
  user-selected paths;
- write all bytes, detect short writes, and enforce per-file and aggregate
  bounds;
- flush the file and required parent-directory metadata;
- publish create-once/no-replace so two finalizers cannot clobber each other;
- accept an identical existing commit as idempotent;
- reject a differing existing record or marker as a conflict; and
- make the marker visible only when it is complete.

`LocalRunStore.write_json`, `write_jsonl`, and `append_jsonl` remain the shared
structured-redaction boundary for mutable/pre-seal archive streams. Canonical
final records use the already established RFC 8785, secret-invariant,
create-once semantics hardened at the same store boundary. Do not add a second
filesystem repository or call the EXP-010 helper copy a third implementation.

The current primitives have gaps the implementation must not silently inherit:

- `write_json` overwrites and follows resolved path components.
- `append_jsonl` has no cross-process lock, durable flush, partial-tail
  recovery contract, or sealed-state rejection.
- `create_exclusive_nofollow()` uses one unchecked `os.write()` and does not
  fsync the parent directory.
- `content_store.create_run_json_once()` duplicates a method now present on
  `RunStorageBackend`/`LocalRunStore`.
- `export_local()` writes `checksums.sha256` into the run directory, mutating
  the source archive.

Harden and consolidate these incumbents. Do not paper over them with a second
`atomic_write()` helper in the archival module.

All capture writers must be stopped and their handles closed before sealing.
This includes Python collectors, MCP JSONL/PTY sinks, Kali-sidecar harvest, and
orchestration/evaluator streams. After commit, store methods reject writes and
direct TypeScript/sidecar writers have no open path or descriptor. Filesystem
modes are defense in depth; checksum verification detects same-user host
tampering but is not a signature.

### Discovery index and migration remain subordinate

The local append-safe index uses ADR-050's prepared/committed journal and
contains routing facts only. It never contains a second copy of the run,
apparatus, parameters, outcome, results, or evidence list. Readers:

- replay bounded canonical entries under a store-owned lock contract;
- validate the same run-ID and relative-path rules as the run store;
- verify the referenced seal/manifest digest before returning a run;
- treat duplicate identical events as idempotent and conflicting events as
  corruption; and
- recover a partial trailing append without trusting later arbitrary bytes.

The prepared event is what lets restart recovery check one known safe attempt
path if a crash occurs between seal commit and the final index append. Normal
discovery does not scan the store. An explicit repair operation may rebuild the
derived index from validated sealed directories.

`manifest.json` becomes the single portable RAES record for new terminal
attempts. `list_runs`, `get_run_manifest`, CLI display, S3 metadata, exporter,
and correlation readers migrate to that shape. Existing
`aptl.run-record/v1|v2` archives stay readable through one version-dispatching
adapter. New attempts do not persist both old and new manifests, and a
compatibility projection is never sealed as a second authority.

## Canonical Incumbents To Reuse

| Concern | Canonical incumbent and required use |
|---|---|
| RAES contracts | Locked `raes==2.0.0`, public `raes_contracts.contracts` models, serializers, corpus fixtures, and public cross-artifact validators. Never copy package schemas or import private serialization helpers. |
| Admission and planned identity | `src/aptl/core/experiment/{controller,admission,trial_plan,trial_plan_models,bindings,capture_mapping,capture_registry}.py` and persisted admitted plan bytes. Consume; do not re-resolve or replan. |
| Attempt lifecycle | The #437/#459 execution controller terminal handoff, its durable attempt journal, and existing RAES runtime/workflow/evaluation states. Archival is a consumer, not another workflow engine. |
| Runtime and evaluation | `src/aptl/backends/raes*.py`, especially runtime snapshots, participant apparatus/provenance, evaluator result/history, orchestrator history, and backend manifest helpers. Evaluator output stays authoritative for summaries. |
| Evidence | `src/aptl/core/evidence/{coordinator,protocol,outcomes,records,_persist,content_store}.py`, trusted adapters, and the code-owned collector registry/registrations. Preserve typed failure and visibility semantics. |
| Provenance | `src/aptl/core/provenance/**`, `DEFAULT_PROVENANCE_REGISTRY`, `SealProfile`, `collect_run_provenance()`, and create-once `run-provenance.json`. |
| Correlation and clocks | `src/aptl/core/correlation/**`, `ClockProvider`, explicit association rules, and canonical correlation identities. Build before commit; never infer causality from time. |
| Apparatus inventory | `RangeSnapshot.to_dict()`, snapshot/endpoints owners, processor/backend manifests, selected realization/profile closure, and participant apparatus projections. Do not parse Compose or call Docker from the sealer. |
| Persistence and containment | `RunStorageBackend`, `LocalRunStore`, `_validate_id`, shared relative-path validation, `aptl.utils.pathsafe`, RFC 8785 create-once persistence, and content-addressed blob insertion. Harden this one boundary. |
| Config and environment | Strict `AptlConfig`, `RunStorageConfig`, `load_config`, `resolve_run_store`, `EnvVars`, placeholder validation, and generated-config owners. Experiment input never selects a storage root or secret source. |
| Secrets | ADR-029, `aptl.utils.redaction`, `is_sensitive_key`, `is_secret_shaped_value`, TypeScript parity, and owner classification for opaque evidence. `APTL_EXPERIMENT_NO_REDACT` never disables canonical structured-record redaction. |
| Logging and diagnostics | `get_logger`, RAES `Diagnostic`, existing admission/capture/provenance reason-code patterns, and fixed CLI/API projections. No archive exception hierarchy or raw validation envelope. |
| API and visibility | API-wide `verify_token`/`WebAuthSettings`, BFF Host/CSRF/session controls, and evidence visibility projection if sealed records are later exposed. Archive presence is not authorization. |
| MCP and sidecar sinks | `mcp/aptl-mcp-common/src/{runs,redaction,captures}.ts`, `mcp/mcp-red/src/{capture,logger}.ts`, ADR-041/042 sidecar ownership, and the configured run-root/correlation contract. Quiesce before seal. |
| Export and CLI | `src/aptl/core/exporter.py` and `src/aptl/cli/runs.py` as read-only consumers of sealed records, with one legacy read adapter. |
| Workflow gates | `.ground-control.yaml`, `.gc/plan-rules.md`, pytest, pre-commit, RAES contract fixtures, MCP dependent builds/tests when common changes, and clean-lab validation for Compose/config changes. |

## Security And Validation Passage

The intended design must pass every applicable layer below. Passing the
archival builder's local type check is not sufficient.

| Layer | Required passage |
|---|---|
| Authority/authentication | Core finalization has no network auth surface and is called only by the trusted execution controller with its attempt authority. Any future API route inherits bearer verification, BFF Host/CSRF/session gates, body-size limits, and server-side evidence visibility before reading paths or content. |
| RAES shape validation | Validate task, run, evidence, apparatus, participant, artifact, stochastic, time, disclosure, and reference objects through the installed public models with `extra="forbid"`. Reject unknown versions/fields; do not coerce into local DTOs. |
| RAES cross-artifact validation | Run task/run, apparatus/manifest, archival-datetime, time-model, evidence/ref, result/evidence, realized-binding, and stochastic draw/control checks. Seal only the exact validated serialization. |
| Admission and execution binding | Verify the persisted admitted-plan digest and bind the exact planned trial. Never reopen source paths, resolve current manifests, rematch collectors, reread mutable config, or accept a runtime object that names a different plan/run. |
| Terminal policy | One code-owned mapping covers every terminal cause and requires invalidation/deviation/limitation data where applicable. Unknown causes fail closed into an explicit archival failure, not success or omission. |
| Capture/evidence policy | Verify pinned collector registration/config digest, typed acquisition disposition, media/count/size/time limits, sensitivity, redaction/loss disclosure, visibility, content digest, and concrete file bytes. Unsupported or unavailable evidence is explicit. |
| Config shape | Durable non-secret settings remain strict `AptlConfig` fields. Storage backend/path comes from `resolve_run_store`; authored experiments, env vars, result data, and index entries cannot override it. A future remote backend extends `RunStorageBackend`, not `backend="s3"` branches in the sealer. |
| Environment/secret binding | Runtime secrets remain behind `.env`/`EnvVars`, credential owners, placeholder checks, generated config, and `curl_safe`. The archival context carries approved non-secret projections or opaque owner refs, never raw env/config/credentials. |
| Secret serialization | Structured payloads pass shared redaction as an invariant: canonical identity-bearing data changed by redaction is rejected, not silently rewritten. Opaque evidence follows its capture registration's sensitivity/visibility policy and declares loss/redaction; exporter never sanitizes it. |
| Filesystem containment | Every run ID, version, relative path, index entry, and content-derived path is validated. Use descriptor-relative no-follow opens for every component, reject special files, and hash/read the same handle. Do not use `resolve()`/`rglob()` as authorization. |
| Atomicity/durability | Full writes, file and required directory `fsync`, no-replace publication, per-attempt finalization exclusion, and index append locking are store invariants. A seal marker is never observable partially; a crash leaves a typed recovery state. |
| OS/process exposure | Sealing needs no subprocess. Never put tokens, cookies, raw parameters, evidence, private keys, auth headers, secret hashes, or user-selected paths in argv, URLs, environment, process titles, tar flags, or shell strings. Owner adapters continue to use typed backend calls and `curl_safe`. |
| Resource bounds | Bound record/evidence count, artifact count, per-file/aggregate bytes, nesting, strings, index line size, finalization time, and recovery work before buffering or sorting. A malicious evaluator/source cannot create unbounded canonicalization or logging work. |
| Concurrency/immutability | Duplicate identical finalization is idempotent; conflicting finalization fails. Stop all writers before commit, reject all post-seal writes, and never repair bytes in place. Index and export code do not weaken the seal. |
| Logging/observability | Log safe attempt/run IDs, stage, stable diagnostic/reason code, counts, durations, versions, and digests only. Do not log raw Pydantic `input`/`ctx`, evaluator values, evidence bytes, source paths, exception text, backend stderr, locator queries, or completeness prose from untrusted sources. |
| Error envelope | Normalize contract, owner, persistence, containment, and recovery failures into bounded RAES diagnostics or existing typed limitation/status results at their owner boundary. Public messages use stable codes and safe addresses. Do not return `str(exc)`, validation excerpts, host paths, or partial record content. |
| Export/API projection | Verify the seal and requested visibility before packaging or projecting. Export is read-only and does not add checksums or fix records. API/CLI summaries adapt from the canonical model and never become a second schema. |

## Extensibility Seams

The storage seam remains `RunStorageBackend`. A future local layout or remote
object store supplies the same create-once content, canonical record, atomic
commit, verified read, append-safe discovery, and immutability semantics. The
archive coordinator receives the backend; it does not branch on local/S3 or
hardcode `./runs`/`.aptl/runs`.

The policy seam is the existing `SealProfile` pattern: seal point, required
provider/collector roles, accepted limitation codes, contract versions, and
digest policy. Adding the next trusted provenance or capture source extends
its existing registration plus the profile; it does not edit the RAES run
schema or aggregate finalizer.

The terminal seam is a typed immutable attempt snapshot from the execution
controller. A future distributed worker or new cancellation cause supplies the
same snapshot and code-owned terminal cause; it does not add a second
finalization path.

## Gotchas And Anti-Patterns

- Do not reuse `planned_trial_id` as `run_id`; retries then collide.
- Do not use `trace_id`, session ID, workflow UUID, timestamp, or archive
  directory name as a substitute for an execution-owned attempt identity.
- Do not write the canonical record from lab startup, `atexit`, exporter,
  signal-only cleanup, or a best-effort telemetry hook.
- Do not claim every final record has `run_status="sealed"` and thereby erase
  whether execution completed, failed, aborted, or invalidated. The seal marker
  is the archive commit state.
- Do not always label outcome success as `_write_run_record()` currently does.
- Do not turn `RunRecordInputs` or a new `AttemptManifest` into a mirror of the
  RAES run model.
- Do not emit both `aptl.run-record/v2` and `experiment-run/v1` as permanent
  records for a new attempt.
- Do not infer task/scenario/participant/parameter/evidence identity from
  current config, display names, source paths, mutable runtime state, or file
  presence.
- Do not scan `mcp-side/`, `kali-side/`, SOC, container logs, or arbitrary
  paths to fabricate evidence references. Consume collector outcomes and exact
  content insertions.
- Do not treat a checksum, image tag, `.gitignore`, `0600`, archive location,
  tarball, or S3 ACL as a seal or authenticity proof.
- Do not allow `export_local()` or S3 export to mutate sealed bytes.
- Do not use overwrite-capable JSON writes for the manifest, record ledger,
  provenance, correlation, seal, or committed index state.
- Do not assume one `os.write()` writes the complete buffer or that file
  `fsync` alone makes a newly created directory entry durable.
- Do not let JSONL writers append after seal or rely on checksum detection as
  permission for post-seal mutation.
- Do not let the local index carry a second result/apparatus/evidence schema,
  trust absolute paths, or define seal truth.
- Do not silently skip a corrupt index line in the middle; quarantine/report
  corruption. Only a partial trailing append has the narrow recovery rule.
- Do not create a new archive exception tree, diagnostic formatter, redactor,
  path helper, content store, retry state machine, metric engine, or plugin
  registry.
- Do not log raw validator errors. Pydantic messages can include rejected
  values; evaluator notes and source exceptions can include secrets or host
  paths.
- Do not expose evaluator-only/apparatus-only evidence through a run API or
  participant response merely because its ref appears in the portable record.
- Do not seal when task/run cross-artifact validation fails or when mandatory
  result evidence is only a dangling ref.
- Do not represent a crashed finalizer as a completed attempt. Recovery must
  distinguish execution terminality, archival incompleteness, and index
  incompleteness.

## Non-Goals And Implementation Boundaries

- No metric definition, scoring, derived measures, statistics, condition
  comparison, stopping-rule interpretation, or scientific conclusion.
- No experiment admission, scenario planning, parameter binding, participant
  selection, capture-capability matching, or collector implementation.
- No lazy reconstruction of a run from current Compose, Docker, config,
  environment, scenario files, participant provider, or evaluator state.
- No replacement of RAES task/run/evidence/apparatus/provenance contracts.
- No new database, global event bus, generic repository/service/DTO hierarchy,
  remote archive service, signing PKI, transparency log, or third-party
  attestation scheme.
- No redesign of lab startup, deployment backends, MCP transport, sidecar RPC,
  OTel deployment, web authentication, or participant visibility policy.
- No in-place mutation, deletion, or repair of sealed records. A correction is
  a new version or attestation with explicit lineage.
- No promise that a digest-only seal proves who produced the archive. It proves
  byte identity and completeness under the local trust boundary.

## Whole-Repository Surface

- Contract authority and dependency pin: `pyproject.toml`, `uv.lock`, installed
  `raes_contracts`, and RAES corpus fixtures.
- Admission/planning: `src/aptl/core/experiment/**`.
- Execution/runtime/evaluator/participant owners:
  `src/aptl/backends/raes*.py` and `src/aptl/core/runtime/**`.
- Evidence, provenance, correlation, snapshots, sessions, and telemetry:
  `src/aptl/core/{evidence,provenance,correlation}/**`,
  `snapshot.py`, `session.py`, and `telemetry.py`.
- Persistence, path safety, redaction, config, CLI, and export:
  `src/aptl/core/runstore.py`, `src/aptl/utils/{pathsafe,redaction,logging}.py`,
  `src/aptl/core/config.py`, `src/aptl/cli/{_common,runs}.py`, and
  `src/aptl/core/exporter.py`.
- API/web projection and auth: `src/aptl/api/**`, `web/**`, and ADR-039 BFF
  controls if a sealed-run surface is added.
- MCP/sidecar capture and cross-language redaction:
  `mcp/aptl-mcp-common/src/**`, `mcp/mcp-red/src/**`,
  `containers/kali-capture/**`, and the host `.aptl`/configured run-root
  boundary.
- Architecture and workflow gates: ADR-029/033/041/042/044/047/050, EXP-005,
  EXP-010, REP-003, OBS-002, `docs/reference/experiment-runs.md`,
  `.ground-control.yaml`, `.gc/plan-rules.md`, `.pre-commit-config.yaml`, and
  CI.
