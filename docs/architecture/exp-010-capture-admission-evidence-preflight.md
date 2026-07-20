# EXP-010 Capture Admission And Evidence Acquisition Preflight

This note is the architecture preflight for EXP-010 / issue #752. It is
guidance, not an implementation plan. No new ADR is needed: ADR-047 owns ACES
experiment admission and deterministic trial planning, OBS-002 owns correlation
identity and clock context, ADR-029 owns secret handling, ADR-041 and ADR-042
own Kali capture and PTY boundaries, and ADR-044 owns the ACES-aligned run
record. This note fixes how EXP-010 crosses those boundaries without creating a
parallel workflow, evidence schema, persistence system, or plugin loader.

## Architecture Decisions And Guardrails

### One declaration, one admitted binding

- Evolve the empty, code-owned `SUPPORTED_CAPTURE_CAPABILITIES` table and its
  `CaptureCapability` in `src/aptl/core/experiment/capture_mapping.py` into one
  versioned collector registry. A registration has a stable non-executable ID,
  implementation version, static capability declaration, trusted factory
  wiring, and a conformance fixture. The ID is not an import path, class name,
  command, URL, host path, credential selector, or arbitrary configuration key.
- The registry is the sole detailed source of truth for capture support. Its
  declarations cover the ACES contract version, channel identity and version,
  capture kind, scope, window semantics, media types, required artifact roles,
  sensitivity and redaction support, integrity and sealing support, retention
  policy IDs, loss disclosure, visibility class, and size/count/time limits.
  The backend `ObservationCapabilities` manifest is an aggregate projection of
  the same declarations, not a second hand-maintained capability matrix.
- Admission must match every authored requirement field deterministically and
  return an immutable binding, not the current owner string. Unknown contract
  versions, channel versions, policy vocabulary, or requirement values fail
  closed. Function existence, container presence, or a sidecar path does not
  constitute declared support.
- Persist each binding in the canonical, immutable trial-plan bytes before
  mutation. It pins the capture/requirement/window refs, collector registration
  and implementation version, public effective-config digest, expected
  artifact and media contract, limits, clock policy, visibility, and accepted
  failure/limitation policy. Runtime verifies the pinned registration and
  digest and never re-matches against a changed registry.
- The capture plan is an internal execution projection within or referenced by
  `TrialPlan`; it is not a local replacement for
  `ExperimentCaptureSpecModel`, `ExperimentEvidenceRecordModel`, or
  `ExperimentRunModel`. Capture-plan IDs, planned-trial IDs, attempt/run IDs,
  trace IDs, sidecar session IDs, evidence-record IDs, and run-record IDs remain
  distinct concepts.

ACES capture-spec v1 has no general `required` flag. Treat authored capture
requirements as required by default. A trusted admission policy may explicitly
accept a stable limitation code and comparability disclosure for a supported
degradation; the acceptance must be persisted in the plan and default to
empty. Never infer optionality from notes, validity text, an empty result, or a
collector's historical best-effort behavior.

### Narrow collector boundary

- A collector receives only an immutable admitted context: planned-trial and
  run/attempt IDs, its pinned binding and window, a deadline and limits, a
  `ClockProvider`, and the narrow source adapter it needs. It does not receive
  `ExperimentController`, the full ACES runtime target, `LocalRunStore`, raw
  filesystem paths, `EnvVars`, the complete application config, or generic
  command/HTTP clients.
- Built-ins remain behind their existing authority boundaries:
  `DeploymentBackend` for container operations, established SOC clients and
  `curl_safe` for authenticated services, the MCP result envelope for MCP
  activity, and the ADR-041/ADR-042 sidecar for Kali PTY/packet sources. Trusted
  composition code injects those narrow adapters; experiment input never
  chooses their executable implementation or secret-bearing configuration.
- The coordinator owns deadlines, cancellation, quotas, clock observations,
  path allocation, hashing, redaction, media checks, persistence, diagnostics,
  and ACES record construction. A collector can report source bytes/chunks and
  typed counters or failures; it cannot choose archive paths or directly
  create portable evidence records.
- `src/aptl/core/collectors.py`, red MCP logs, and sidecar harvesters are useful
  source adapters but currently have best-effort/empty-on-error semantics. Do
  not reinterpret an empty list or a successful harvest call as successful
  required capture. A conformant adapter must preserve startup failure,
  mid-run loss/drop, truncation, timeout, source disappearance, and finalization
  failure as distinct outcomes.

The extension seam is the registry registration plus this narrow lifecycle
protocol. Adding a reasonable next built-in source should require one adapter,
one static declaration, and its conformance fixture; it must not require edits
to the experiment controller, manifest logic, persistence layout, or evidence
schema. Untrusted or out-of-process third-party collectors require a separate
authorization and sandboxing design and are outside this boundary.

### Lifecycle and terminal semantics

The ordering is a correctness contract:

1. Load ACES artifacts, validate all cross-artifact refs, match every capture
   requirement, compile the immutable plan, and persist it before any range
   mutation.
2. Provision through the existing ACES/deployment lifecycle. Start admitted
   collectors after their sources are ready but before participant actions or
   orchestrator workflows can begin.
3. Stop collectors in reverse order from a `finally` boundary, even when the
   trial or another collector fails.
4. Bound, classify, redact where required, media-check, hash, and persist the
   captured bytes; then construct ACES evidence records and explicit evidence
   references.
5. Only a successfully finalized result is ready for the sealing work owned by
   issue #444. Capture authorization and artifact presence are not proof of a
   successful seal.

`RuntimeManager.apply` in `src/aptl/backends/aces.py` currently drives
orchestrator workflows before returning. The execution design therefore needs
a narrow seam between successful provisioning/registration and
`_drive_orchestrator_workflows`; wrapping capture around the return from
`apply` starts too late. Reuse the existing provisioning and workflow owners
rather than cloning either lifecycle.

Unsupported or missing declared capability is an admission rejection and must
cause zero range mutation. A declared source that becomes unavailable at
runtime or a collector startup failure aborts the attempt before participant
action and still runs cleanup. Required mid-run loss, unacceptable truncation
or clock uncertainty, and required finalization failure produce an unsealed,
invalidated/inconclusive result. An explicitly accepted optional degradation
may produce a completed/partial result only with loss, limitation, and
comparability disclosures. Stable diagnostic/reason codes must distinguish
missing source, startup failure, loss, truncation, clock skew, timeout, and
finalization failure even where ACES terminal statuses coincide.

Use `ExperimentRunModel` status/outcome, its deviations and disclosures, and
safe ACES diagnostics for experiment outcomes. Do not create a second
controller state machine or overload `LabResult` startup readiness to describe
capture success. Collector failures are typed outcome data projected into those
diagnostics; normalize internal exceptions instead of exposing a second public
exception hierarchy.

### Evidence ownership and persistence

- Use public models from `aces_contracts.contracts` as the portable schema:
  `ExperimentEvidenceRecordModel`, `ExperimentArtifactRefModel`,
  `ParticipantObservationEnvelopeModel`, `SourcePipelineModel`,
  `RawDataIntegrityModel`, experiment clock context, and run
  augmentation/realized-form disclosures. An internal collector receipt may be
  an adapter result, but it is not another portable evidence record.
- Extend the existing `RunStorageBackend` boundary narrowly for streamed,
  content-addressed blob insertion and run-scoped create-once canonical JSON.
  Do not add an evidence repository beside `LocalRunStore`. The coordinator
  derives fixed locations from validated IDs and the computed digest; plugins
  never supply a relative or absolute destination.
- Content insertion must be descriptor-relative/no-follow and create-exclusive,
  reuse `src/aptl/utils/pathsafe.py`, use restrictive permissions, enforce
  byte/count/time limits while streaming, and recompute size, digest, and media
  type from the stored object. A repeated digest is idempotent only when the
  existing bytes agree; a conflict fails closed.
- Checksums in ACES artifact/evidence references identify the bytes actually
  retained. When policy permits redaction or truncation, retain safe original
  digest/size observations separately where available and record the stored
  digest/size, redaction state, and mandatory loss disclosure. Never fabricate
  evidence content for a failed collection.
- Structured material must pass the shared Python/TypeScript redactors before
  persistence. Opaque control-plane secrets are rejected or excluded. Designed
  target secrets may be captured only through an explicit source/path and
  sensitivity policy under ADR-029. `APTL_EXPERIMENT_NO_REDACT`, direct
  `write_file`/`copy_file`, a harvested file, or an exporter pass is not a
  final-evidence sanitation decision.
- Build an explicit verified evidence ledger. The current run-directory scan
  for orchestration, MCP-side, and Kali-side files is useful legacy inventory,
  but path presence without digest, source outcome, and record validation is
  not evidence truth and cannot satisfy the seal gate.
- `src/aptl/core/lab.py` writes the existing reproducibility run record during
  lab startup. That record is not a final `ExperimentRunModel` and must not be
  stretched into the experiment evidence ledger or issue #444 seal. Feed
  verified references into the later experiment result through the existing
  run/correlation projection boundaries.
- Evidence-record identity must derive from stable run/planned-trial,
  capture-spec, requirement, window, collector-config, and retained-content
  identity. `captured_at`, filesystem order, or ingestion order must not define
  identity. Preserve each source's clock domain, offset/uncertainty, and
  observer-effect disclosure using the OBS-002 clock/correlation seams.

Participant visibility is a separate projection from capture authorization.
Reuse the participant-visible/disclosed/evaluator-only partition in
`src/aptl/backends/aces_participant_actions.py` and ACES participant observation
envelopes. Hidden or evaluator-only evidence remains absent from participant
responses, logs, and future API projections even when the collector is
authorized to retain it.

## Cross-Cutting Incumbents To Reuse

| Concern | Canonical incumbent and required use |
|---|---|
| ACES schema and conformance | Public `aces_contracts.contracts` loaders/models, the installed fixture corpus, and `aces_conformance` observability diagnostics. Do not copy schemas or fixture payloads into APTL. |
| Admission and planning | `src/aptl/core/experiment/{resolver,spec_loading,admission,admission_artifacts,capture_mapping,trial_plan,policy,errors}.py` for bounded loading, public contract parsing, deterministic projection, policy, canonical hashing, persistence-before-mutation, and safe `AdmissionRejection`. |
| Backend capability manifest | `src/aptl/backends/aces_manifest.py` and ACES `ObservationCapabilities`. Generate observation claims from conformant registry declarations. |
| Runtime seams | `src/aptl/backends/aces.py`, `aces_orchestrator.py`, `aces_participant_runtime.py`, `aces_participant_actions.py`, `aces_observation.py`, and `aces_repro.py` for provisioning, workflow/action boundaries, visibility, and run projection. |
| Source ownership | `DeploymentBackend`, `src/aptl/core/collectors.py`, established SOC clients/`curl_safe`, `mcp/aptl-mcp-common`, `mcp/mcp-red`, and `containers/kali-capture/writer.py`. Adapt; do not bypass their safety boundaries with Docker/shell/HTTP duplicates. |
| Persistence and path safety | `RunStorageBackend`/`LocalRunStore`, RFC 8785 canonical JSON, `src/aptl/utils/pathsafe.py`, run/session ID validators, restrictive creation, and `src/aptl/core/exporter.py`. Export remains packaging, not validation or sanitation. |
| Secrets and logs | ADR-029, `src/aptl/utils/redaction.py`, TypeScript redaction parity, `src/aptl/utils/logging.py`, bounded ACES diagnostics, `LabResult` diagnostics, and MCP `harvest_warning`. Log stable IDs, stages, codes, counts, and durations only. |
| Identity and clocks | `src/aptl/core/correlation`, its `ClockProvider`, `TrialPlan` identities, ACES run/participant/source identities, and OBS-002 association and clock rules. |
| Configuration | Strict `src/aptl/core/config.py`, `src/aptl/core/env.py`, ADR-025 first-party config, and shared MCP config/environment binding. Durable operator knobs require a typed field and a real consumer; experiment documents do not become config. |
| Auth and projection | `src/aptl/api/deps.py`, BFF host/CSRF/session middleware, existing local MCP stdio authority, sidecar peer checks, and participant visibility filtering. EXP-010 adds no auth bypass or endpoint. |
| Workflow and tests | `.ground-control.yaml`, `.gc/plan-rules.md`, pytest, pre-commit, MCP package tests/builds, injected clocks/runners, and ACES corpus/conformance fixtures. Compose/container/config changes retain the clean-lab validation gate. |

## Security And Validation Passage

The intended design must pass every applicable layer below; passing only the
collector's local input checks is insufficient.

| Layer | Required passage |
|---|---|
| Authentication/authority | No new network endpoint. Future API access inherits bearer verification plus BFF host/CSRF/session gates. MCP remains local stdio; the sidecar remains a peer-checked local socket. A capture grant identifies allowed sources and visibility, not general controller authority. |
| ACES shape validation | Parse capture specs and emit evidence/run artifacts only through public ACES models. Preserve bounded diagnostics without pydantic `input`, arbitrary metadata, or source payloads. |
| Cross-artifact admission | Existing resolver/spec-loading and ADR-047 validate project containment, artifact kinds/versions, references, task joins, and apparatus compatibility before mutation. Capture matching then checks every requirement axis and policy vocabulary. |
| Registry/policy validation | Enforce unique stable registration IDs, supported contract/channel versions, deterministic selection, public-config digest, explicit limits, visibility, and accepted limitation codes. No dynamic import, fallback collector, or notes-driven policy. |
| Config/environment binding | `AptlConfig` remains strict and `EnvVars` remains the environment authority. Secret-bearing clients are injected after admission; their values are excluded from config digests, plans, manifests, logs, and evidence metadata. No experiment-provided env keys. |
| OS/process/URL exposure | Use backend argument arrays and existing runners/timeouts. No shell command construction, executable name, host path, arbitrary URL, credential, or token from experiment input. Secrets must not appear in argv, query strings, process listings, diagnostic text, or child environment except through an incumbent explicitly designed for that secret. |
| Source boundary | Built-ins use only their narrow deployment/SOC/MCP/sidecar adapters. Enforce start/stop deadlines and cancellation outside plugin code; distinguish source failure from legitimate zero events. |
| Filesystem and persistence | Validate IDs; derive destinations internally; reject traversal, absolute paths, symlinks, special files, and replacement races; enforce quotas during streaming; verify digest/size/media after storage; create records once. |
| Secret/media boundary | Classify before structured persistence, redact with shared helpers, reject prohibited secrets and media mismatches, and disclose every allowed redaction/truncation/loss. Never make global redaction weaker for a fixture. |
| Visibility boundary | Project participant-visible, disclosed, hidden, and evaluator-only observations server-side using existing partitioning. Storage or evaluator authorization never implies participant visibility. |
| Error/log envelope | Convert untrusted/backend exceptions to stage-specific safe diagnostics. Do not return or log raw exception strings, backend stderr, host paths, URLs, headers, queries, hostile metadata, captured bytes, credentials, or full commands. |
| Seal/export boundary | Validate ACES records and conformance, explicit references, retained digests, required capture outcomes, clock/observer disclosures, and finalization state before declaring ready to seal. Export does not repair or sanitize an invalid archive. |

An important manifest guardrail follows from the ACES contract: declaring
`ObservationCapabilities` requires the backend's top-level supported contract
versions to cover the capture spec, evidence record, derived measure, and
experiment run contracts. Do not turn on `create_aptl_manifest().observation`
until that whole claim is true and conformance-tested. Claim only implemented
sealing modes; a content digest or immutable local object is not a signed
attestation or complete chain of custody.

## Verification Guardrails

- Pin deterministic, contract-version-aware matching across all requirement
  axes, registry order, and equivalent input ordering. Assert unsupported
  capture causes no backend, environment, sidecar, collector, session, or
  run-directory mutation.
- Give every registration a shared conformance fixture for start, stop,
  deadlines, empty success, source unavailable, startup failure, mid-run
  drop/loss, truncation, clock uncertainty, and finalization failure. Validate
  the emitted record with the installed ACES corpus/conformance APIs.
- Exercise traversal, absolute paths, symlinks and replacement races, hostile
  filenames/metadata/media types, oversized streams and artifact counts,
  stuck collectors, partial writes, digest collisions/conflicts, and concurrent
  finalization. Quotas must be enforced during reads, not after buffering.
- Use target-secret and control-plane-secret fixtures to prove intended target
  evidence is classified/disclosed while credentials and operator secrets do
  not enter plan bytes, argv, logs, records, CAS objects, or exports.
- The representative integration must bind red action, container, network, and
  defensive sources to one planned trial/run with explicit clock context and
  ACES-valid evidence references. Tests must prove participant-hidden and
  evaluator-only material never enters the participant projection.
- Follow `.gc/plan-rules.md`: Python behavior gets pytest coverage; MCP common
  changes rebuild and test every dependent MCP; web changes get web tests; and
  compose, container-Dockerfile, or `config/` changes require a clean
  `aptl lab stop -v && aptl lab start` validation on a fresh machine.

## Gotchas And Anti-Patterns

- Do not turn `capture_owner` into `importlib`, `getattr`, a command dispatcher,
  or a plugin-supplied factory locator.
- Do not duplicate ACES capture/evidence/run DTOs, validators, diagnostics,
  retention/redaction vocabularies, or terminal-state workflows.
- Do not discard admitted mapping output, re-select collectors at runtime, or
  let a mutable registry/config silently change a persisted plan.
- Do not conflate plan, collector receipt, raw blob, artifact reference,
  evidence record, run record, correlation edge, trace, or sealed archive.
- Do not treat best-effort empty results, file presence, successful `docker cp`,
  telemetry spans, or a path scan as proof of evidence fidelity.
- Do not let collectors write archive paths, follow symlinks, buffer unbounded
  streams, decide redaction, construct ACES records, or receive the full
  controller/backend/runtime target.
- Do not use free-text notes as executable failure, retention, redaction, or
  comparability policy; do not silently downgrade an authored requirement.
- Do not infer causality or record identity from timestamp proximity, and do
  not collapse source/host/container clocks into one synchronized clock.
- Do not log raw exception text or preserve secrets through argv, URLs, env,
  metadata, diagnostic contexts, opaque writes, or the no-redact test switch.
- Do not seal before required collectors finalize, or translate a capture
  failure into a harmless lab-start warning.

## Non-Goals And Boundaries

- This preflight does not implement EXP-010 or prescribe task sequencing.
- It does not change ACES schemas, add a local capture DSL, or make APTL the
  authority for portable experiment/evidence contracts.
- It does not design arbitrary third-party discovery, dynamic plugin loading,
  untrusted code sandboxing, remote collector installation, or arbitrary URI
  acquisition. The first boundary is trusted, code-owned registrations.
- It does not redesign `DeploymentBackend`, lab provisioning, SOC services,
  MCP transport, the Kali PTY/packet ownership model, OpenTelemetry, or the
  existing red-action logs; those are source boundaries to adapt.
- It does not implement derived measures, statistical evaluation, participant
  UI/API access, or issue #444 sealing. It produces validated, explicit,
  ready-to-seal evidence inputs and prevents sealing when required capture is
  incomplete.
- It does not broaden participant visibility or convert evaluator-only data
  into participant-observable state.

## Whole-Repository Surface

The design crosses the experiment modules and tests under
`src/aptl/core/experiment/` and `tests/test_experiment_*`; ACES manifest/runtime
adapters under `src/aptl/backends/`; `src/aptl/core/{lab,lab_types,runstore,
collectors,config,env}.py`; `src/aptl/core/correlation/`; path, logging, and
redaction utilities under `src/aptl/utils/`; MCP common and red-team packages;
the Kali capture sidecar; SOC client boundaries; API/BFF auth if evidence is
later exposed; exporter/run archives; ACES fixture/conformance packages; and
the repo workflow gates in `.ground-control.yaml` and `.gc/plan-rules.md`.

At runtime, the affected host/OS surfaces are container engines reached only
through `DeploymentBackend`, process argv/environment, local Unix sockets,
container filesystems and evidence mounts, SOC HTTPS/TLS clients, host run
storage permissions and symlink behavior, clocks across host/container/source
domains, and archive/export readers. None may receive authority merely because
an experiment document requested a capture.
