# ADR-047: ACES Experiment Admission and Trial-Plan Boundary

## Status

accepted

## Date

2026-07-19

## Context

EXP-002 makes APTL the execution apparatus for experiments authored through
ACES `experiment-authoring-input-v1`. The authoring input references an ACES
`experiment-task-v1`, capture specifications, and scenario material, then asks
the apparatus to turn a bounded allocation into stable executable trials.

The architectural risk is not the allocation loop. It is creating a second
experiment language, resolving untrusted references after the lab has already
changed, or letting an admission-only code path bypass the controls already
used by scenario startup and run capture.

The repository already owns the relevant boundaries:

- `aces_contracts.experiment_spec.parse_experiment_spec` and the exported ACES
  contract models own experiment structure and model-level semantic invariants.
- `aces_sdl.parse_sdl_file`, `RuntimeManager.plan()`, and planner diagnostics
  own scenario semantics, parameter binding, realization requirements, and the
  backend capability gate.
- `create_aptl_manifest()` owns APTL backend identity and runtime capability
  claims. The ACES reference processor manifest is the corresponding processor
  identity surface.
- `start_aces_scenario()`, `AcesRunTarget`, `AcesStartOutcome`, and
  `_LAB_START_STEPS` own the existing ACES-to-lab handoff.
- `DeploymentBackend` owns Docker, Compose, host, and container operations.
- Strict `AptlConfig` owns durable non-secret configuration. `EnvVars`, `.env`
  hydration, placeholder checks, and generated config own runtime secrets.
- `LocalRunStore`, `RangeSnapshot.to_dict()`, ADR-044's reproducibility record,
  and the exporter own persistence, redaction, inventory, and packaging.
- ACES `Diagnostic`, `render_aces_diagnostics()`, `StartupDiagnostic`,
  `LabResult`, and the existing CLI/API projections own failure reporting.

Current startup ordering is important. `_LAB_START_STEPS` hydrates `.env`,
generates keys and certificates, renders service configuration, seeds volumes,
and pulls images before `_step_start_containers` plans and applies the ACES
scenario. Experiment admission cannot simply be added inside
`start_aces_scenario()`: by then APTL has already mutated local apparatus state.

## Decision

### Experiment-controller boundary

Add one experiment-controller composition boundary above lab lifecycle. It has
two distinct phases:

1. **Admission** reads bounded inputs, resolves and pins every referenced
   artifact, invokes ACES validation and planning APIs, checks APTL apparatus
   policy, and produces canonical immutable trial-plan bytes. Admission may use
   bounded temporary staging and persist its final journal, but it must not
   hydrate `.env`, generate credentials or certificates, render service config,
   pull images, invoke collectors, call `DeploymentBackend`, start a session, or
   otherwise mutate the range.
2. **Execution** is downstream work. It receives an admitted plan and delegates
   each trial's scenario to the existing `RuntimeManager` and lab lifecycle. It
   must not re-resolve references, reinterpret the allocation, or mint a new run
   identity.

Admission is all-or-nothing across the complete allocation. No trial may start
when any source, condition, capture requirement, stochastic control, apparatus
constraint, or planned scenario fails admission. A retry after an operational
backend failure may reuse the exact admitted bytes; it must not parse or plan a
new input, matching the existing admitted-plan retry rule in `aces.py`.

The controller is a coordinator, not another runtime manager. Do not split it
into speculative repository, service, provider, DTO, and policy hierarchies.
Its dependencies should be explicit inputs: ACES public loaders/models, the
canonical processor and backend manifests, an authorized artifact resolver,
an admission policy with resource limits, and the existing
`RunStorageBackend`. Deployment is not an admission dependency.

### ACES contracts remain authoritative

The admitted graph retains ACES objects and identities directly:

- The root enters through `parse_experiment_spec`; APTL does not define a local
  authoring-input model.
- Task and capture payloads validate through the exported
  `ExperimentTaskModel` and `ExperimentCaptureSpecModel` public surfaces. The
  installed ACES fixture corpus is the contract test source; fixtures are not
  copied into an APTL-owned schema corpus.
- Scenario material enters through `parse_sdl_file`; canonical scenario or
  instantiated-snapshot identity uses the ACES canonical digest API.
- Associated-artifact manifests enter through
  `load_associated_artifact_manifest_json` and
  `validate_associated_artifact_manifest`, with caller-supplied bounded readers
  and `AssociatedArtifactValidationLimits`.
- Each unique condition binding is submitted to `RuntimeManager.plan()` against
  `create_aptl_manifest()` before admission succeeds. ACES planner diagnostics,
  realization support, variable typing, and semantic validation are not
  duplicated locally.

APTL performs only joins and apparatus policy that require multiple already
validated artifacts: reference identity/version equality, unique resolution,
task/scenario agreement, capture-scope compatibility, condition parameter
target resolution, supported allocation/control policy, and conjunction of the
task's apparatus constraints with the authoring input's apparatus intent.
These checks must operate on ACES fields; they must not restate those fields in
local Pydantic or dataclass mirrors.

Contract schema versions and artifact versions are different concepts.
`schema_version="experiment-task/v1"` selects the ACES contract, while a
task reference's `ref_version` identifies the authored task revision. Admission
must validate and record both and must not compare one namespace to the other.
Likewise, the hyphenated identifiers in manifest
`supported_contract_versions` are not interchangeable with slash-form schema
version values.

The backend manifest remains a runtime capability declaration. Do not add
experiment authoring/task/capture contract identifiers to
`create_aptl_manifest()` merely to advertise this controller unless ACES's
backend manifest authority explicitly allows and requires them.

### Authorized artifact resolution

Experiment references are capabilities, not paths or commands. The default
resolver is offline and project-contained. It accepts only explicitly
supported locator forms and returns one bounded byte stream plus normalized
locator metadata; it never returns an executable object or a path to reopen.

For project files, build on the containment rule in
`scenario_catalog._resolve_project_file`, strengthened for untrusted experiment
inputs:

- Reject absolute paths, `..` components, NULs, non-files, and every symlinked
  path component. Resolving a path and checking its prefix is not enough because
  a symlink can change between check and open.
- Open once using descriptor-relative, no-follow semantics where the platform
  provides them. Hash and parse the exact bytes from that open handle so a
  time-of-check/time-of-use swap cannot change the admitted payload.
- Enforce per-document, per-artifact, aggregate-byte, reference-count,
  allocation-size, and nesting/depth limits before expensive parsing or trial
  expansion. ACES's associated-artifact limits remain the authority where that
  contract applies.
- Verify declared size and checksum before parsing or using a payload. Digest
  mismatch, unsupported digest algorithm, ambiguous/missing resolution, or an
  undeclared extra binding is fatal.
- Reject credential userinfo and secret-bearing query fields in every locator,
  not only associated-artifact manifests. Persist portable references and
  digests, not host-absolute paths.

Network, OCI, or registry fetching is disabled by default. A future remote
resolver is a separately authorized implementation of the same narrow
resolver contract, parameterized by allowed scheme/authority, offline mode,
timeouts, redirect policy, maximum bytes, authentication source, and digest
requirement. It must reject redirects to unauthorized authorities and must not
take credentials from the experiment document. Do not fall back from a failed
remote resolution to an ambient filesystem search, current working directory,
`PATH`, environment variable, or package import.

### Apparatus and capture capability admission

Task apparatus constraints and authoring-input apparatus intent are conjunctive;
the latter cannot weaken the former. Evaluate processor/backend identities,
manifest references and digests, compatibility declarations, required
capabilities, and contract versions against the canonical ACES processor
manifest and `create_aptl_manifest()` payload.

Scenario-specific feasibility remains with `RuntimeManager.plan()`. Docker or
Compose must not be probed directly during admission, and config flags must not
be treated as proof of a capability the manifest or planner rejects.

Capture admission needs one code-owned mapping from ACES capture requirement
terms to existing APTL capture owners (`collectors.py`, MCP/Kali capture,
runtime snapshots, orchestration/evaluation history). Admission and later
execution must share that mapping. Unknown capture kinds, channels, media types,
sealing/redaction requirements, or retention/integrity guarantees fail closed;
they never become arbitrary collector names, imports, backend method names, or
shell commands. The mapping describes support only. It does not replace the
ACES capture-spec model.

Participant implementation/provider selection remains behind the ACES
participant-runtime boundary and issue #557. Admission may retain and validate
an ACES red-variant selection, but it cannot resolve `agent_ref` to a Python
entry point, executable, image, environment variable, or provider method.

### Deterministic immutable trial plan

The trial plan is an APTL internal execution journal, not a portable ACES
experiment, task, study, run, apparatus, capture, or analysis contract. It may
carry only the data needed to bind execution back to the admitted ACES graph:
source identities and digests, canonical condition/factor assignments,
resolved non-secret scenario parameter bindings, stochastic controls, episode
controls, capture-spec references, ordering coordinates, and stable planned
trial IDs. Eventual portable run and apparatus records use ACES contracts; they
must not serialize this journal as if it were `experiment-run-v1`.

Expansion obeys these rules:

- A flat allocation uses ordinal `0..target_run_count-1`.
- A condition allocation follows the authored `compared_conditions` order,
  then an explicit zero-based replication ordinal. Map insertion order,
  filesystem enumeration, locale, wall clock, and process-global randomness
  have no effect.
- An `allocation_method`, stochastic-control role, or ordering behavior is
  executable only when it maps to a supported, versioned controller policy.
  Free-form text is never evaluated or silently approximated. Unknown or
  under-specified controls fail admission.
- Condition and red-variant parameters may bind only to uniquely declared ACES
  scenario variables. The ACES planner validates the assembled binding.
  Missing targets, multiple candidate targets, conflicting values, and unused
  parameters are fatal.
- A seed or randomized order is derived with a documented, domain-separated
  cryptographic hash from canonical source-set identity plus logical trial
  coordinates and control ID. Do not use Python `hash()`, UUIDs, timestamps,
  ambient RNG state, or a library PRNG whose algorithm is not part of the
  policy version.
- The plan and source-set identities are digests of RFC 8785 canonical JSON
  projections. Canonical projections exclude admission time, host-absolute
  paths, temporary paths, log text, and mutable runtime state. They normalize
  digest case and sort semantically unordered maps/sets. Authored lists whose
  order is meaningful remain ordered.
- Planned-trial IDs are a filesystem-safe prefix plus a full or collision-safe
  cryptographic digest of the versioned identity domain, source-set digest,
  condition ID (or flat sentinel), and replication ordinal. The same admitted
  inputs and policy version produce the same IDs on every supported host.

The in-memory plan is immutable after construction. No downstream caller may
mutate a shared list/dict or replace a referenced artifact. Before execution,
the persisted plan digest must still match the canonical bytes and every
trial's plan reference must match it.

The extensibility parameter for allocation is a small versioned ordering and
stochastic-control policy passed into the pure expander. A future supported
blocked or seeded-random allocation adds a policy mapping and conformance tests;
it does not add scenario-name branches or reinterpret old plan bytes.

### Persistence and state model

`RunStorageBackend` remains the only persistence dependency. The controller
must receive the configured store; it must not hardcode `./runs`,
`.aptl/runs`, or a third root. Trace-correlated run capture and configured run
storage currently use both roots in different paths, so EXP-002 must not deepen
that inconsistency. Callers resolve and inject one store/target, as they already
do with `AcesRunTarget`.

The existing `LocalRunStore.write_json()` is contained and redacting, but it is
overwrite-capable and emits presentation JSON rather than canonical bytes.
Immutability therefore requires a narrow create-once canonical JSON operation
on the existing run-store protocol, not a second experiment repository. That
operation redacts first, canonicalizes once, writes atomically with
create-exclusive semantics, and treats an identical existing payload as an
idempotent success while rejecting different bytes. `write_file()` and
`copy_file()` are not acceptable for structured plans because they bypass
structural redaction.

Persist the full admitted plan once under a controller-owned plan namespace.
Each planned trial archive stores only the plan identity/digest and its own
trial projection, then reuses the planned-trial ID as the execution `run_id`.
Do not call `_resolve_run_target()` to mint a timestamp run ID for an admitted
trial. The controller journal is explicitly APTL-internal and names the ACES
source artifacts it derives from; it is not an ACES study or run.

Admission has a one-shot result, not a parallel workflow engine:

- rejected: structured diagnostics and no plan;
- admitted: immutable canonical plan bytes, plan identity, and trial tuple.

Execution state continues through ACES operation receipt/status, runtime
snapshot, workflow/evaluation history, `ScenarioSession`, and `LabResult`.
Do not create `PENDING/RUNNING/FAILED` experiment-controller states that
duplicate those incumbents.

## Security layers

| Layer | Required behavior |
| --- | --- |
| Auth surface | Core admission performs no authentication. A local CLI caller is the current trusted operator boundary. Any future `/api` admission route must inherit the API-wide `verify_token` dependency before resolving paths or reading bodies, use a bounded Pydantic request projection, and never accept credentials in a URL. |
| Input shape | Bound the root bytes before `parse_experiment_spec`; use ACES closed-world models and validators for all ACES payloads. Reject unknown versions and malformed/duplicate or ambiguous bindings rather than coercing them into a local shape. |
| Semantic validation | Use ACES model validators, canonical digest APIs, associated-artifact validation, and `RuntimeManager.plan()` diagnostics. Local checks are cross-artifact identity joins and explicit apparatus policy only. |
| Artifact resolution | Use the injected authorized resolver, no-follow contained opens, one-handle hash/parse, digest and size verification, aggregate limits, offline default, and no ambient lookup. No input controls imports, commands, collectors, backend methods, environment names, or filesystem roots. |
| Secret handling | Treat the whole experiment graph as untrusted. Reject secret-shaped scalar content and parameter name/value pairs using the canonical `redact()` taxonomy before plan construction; never rely on later redaction to make an executable secret safe. Keep control-plane secrets out of source artifacts and locators. |
| Config shape | Non-secret admission limits or resolver policy that become durable settings must be strict `AptlConfig` fields with real consumers. The experiment document cannot add config keys or override deployment provider/project identity. |
| Environment binding | Admission must not call `.env` hydration or construct `EnvVars`. Experiment parameters cannot name or read environment variables. Runtime secrets remain in `EnvVars`, placeholder validation, and generated config after admission succeeds. |
| Apparatus capability | Compare both task and spec constraints with canonical manifest payloads and ACES planner diagnostics. Unknown contract/capability/capture terms fail closed before `_LAB_START_STEPS`. |
| OS/process exposure | Default admission uses no subprocess. Do not put parameter values, digests used as credentials, auth headers, or artifact contents in argv, process titles, URLs, or environment. A future resolver uses in-process transport or the existing `curl_safe` boundary without credential-bearing argv. |
| Range-mutation gate | The complete plan must be admitted and persisted before `.env` hydration, key/cert generation, rendered config, volume seeding, image pulls, session creation, or any `DeploymentBackend` call. Clean boot/teardown is execution and cannot precede admission. |
| Persistence | Inject `RunStorageBackend`; reuse ID/path containment and shared redaction. Add only create-once canonical structured writes. Exporter packages already-safe records and is never the first sanitizer. |
| Logs and telemetry | Use `get_logger`; log contract/diagnostic codes, safe identities, counts, and digests only. Raw documents, parameter values, artifact bytes, locators with queries, exception strings, and validation `input` fields never enter logs or OTel attributes. Admission spans may carry plan/trial counts and digests after `redact()`. |
| Error envelope | Normalize failures into redacted ACES `Diagnostic` values in an experiment-admission domain, then reuse `render_aces_diagnostics`, `StartupDiagnostic`, `LabResult`, Typer exits, and existing API response conventions. Do not expose raw Pydantic errors with `input_value`, YAML excerpts, absolute paths, resolver exceptions, or backend stderr. |

## Canonical incumbents

| Concern | Reuse |
| --- | --- |
| Experiment contracts and examples | `aces_contracts.experiment_spec`, exported `aces_contracts.contracts` models, associated-artifact APIs, and the installed ACES fixture corpus |
| Scenario parsing and parameter semantics | `aces_sdl.parse_sdl_file`, ACES canonical scenario digests, and `RuntimeManager.plan()` |
| Backend identity and feasibility | `create_aptl_manifest()`, ACES manifest payload/model APIs, planner diagnostics, and existing conformance tests |
| Runtime handoff | `start_aces_scenario()`, `AcesRunTarget`, `AcesStartOutcome`, and the admitted-plan retry behavior in `aces.py` |
| Lab lifecycle | `_LAB_START_STEPS`, orchestration contract predicates, `LabResult`, `StartupOutcome`, and `StartupDiagnostic` |
| Deployment | `DeploymentBackend` and its typed local/SSH Compose implementations |
| Scenario containment precedent | `scenario_catalog._resolve_project_file`, strengthened to no-follow one-open semantics rather than copied into a second path checker |
| Config and secrets | `load_config`/`AptlConfig`, `EnvVars`, placeholder checks, ADR-028/029 generated-state rules, and `redact()` |
| Capture | `collectors.py`, MCP/Kali capture owners, `RuntimeSnapshot`, workflow/evaluation history, and the ADR-033/044 evidence layout |
| Persistence and export | `RunStorageBackend`/`LocalRunStore`, `RangeSnapshot.to_dict()`, ADR-044 run records, and `exporter.py` |
| Diagnostics and observability | ACES `Diagnostic`, `render_aces_diagnostics()`, `_emit_diagnostic()`, `get_logger`, and ADR-012 telemetry rules |
| API exposure if added | API-wide `verify_token`, `WebAuthSettings`, existing router assembly, and narrow Pydantic response projections |

## Extensibility

The primary external extension seam is the authorized artifact resolver. It is
parameterized by trust roots/authorities, offline mode, limits, redirects,
timeouts, and digest policy while always returning the same bounded immutable
byte binding. This permits a future digest-verified OCI or registry resolver
without changing admission semantics or allowing the experiment to select a
transport implementation.

The execution-side seam is the versioned allocation/control policy and the
shared capture-capability mapping. Future ordering methods, stochastic
controls, or capture owners extend those bounded mappings. They do not edit
ACES source models, dispatch by scenario name, or add arbitrary plugin loading.

If ACES publishes a portable trial-plan or admission-diagnostic contract later,
the controller should replace the corresponding internal projection at the
ACES namespace while keeping APTL-only resolver and persistence evidence under
the backend journal namespace.

## Testing contract

Implementation must prove the boundary without creating a new test harness:

- ACES package fixtures cover valid and invalid authoring input, task, capture,
  associated-artifact, manifest, and scenario contracts through public APIs.
- Unit tests cover cross-artifact identity joins, apparatus/capture capability
  decisions, exact mutation ordering, redacted diagnostics, canonical bytes,
  create-once persistence, and stable IDs.
- Property-based tests under the existing `fuzz` marker cover traversal and
  symlink inputs, resource limits, secret-shaped values, map/list order,
  condition/replication counts, digest changes, ID uniqueness, and repeated
  admission determinism.
- Contract tests assert that every planned trial resolves to exactly one task,
  one scenario snapshot, one condition or flat sentinel, one stochastic-control
  set, one episode-control set, and the admitted capture-spec references.
- Mutation-spy tests prove that rejected admission makes no
  `DeploymentBackend`, hydration, credential, certificate, Compose, session,
  collector, or run-execution call.

Do not weaken these tests by snapshotting APTL-local copies of ACES schemas.
The project dependency range (`aces-sdl>=0.23.1,<0.24.0`) and `uv.lock` are the
version authority used by the fixtures and public APIs.

## Gotchas

- Pydantic validation strings can contain the rejected `input_value`; wrapping
  `str(exc)` in a diagnostic can leak an injected secret. Render only stable
  error type/location metadata and omit input values and documentation URLs.
- `parse_experiment_spec` is the public schema loader, but callers still need a
  byte limit before passing text to it. Do not use `load_experiment_spec` on an
  unbounded attacker-controlled file.
- ACES task and capture references deliberately do not carry digest/path fields
  in their typed reference models. Pin resolved byte digests in the internal
  admission journal or an ACES associated-artifact binding; do not add forbidden
  fields or subclass the contracts.
- A generic scenario reference is not a sealed scenario snapshot. It must
  resolve to one concrete parsed/instantiated snapshot and canonical digest
  before planning trials.
- `target_runs_per_condition` and `target_run_count` have no useful apparatus
  upper bound in the portable contract. The caller policy must reject expansion
  beyond configured count/byte limits before allocating a large list.
- `allocation_method`, `replication_policy`, `stopping_rule`,
  `termination_rule`, and stochastic descriptions are data, not code. Never
  evaluate or parse them as shell, Python, templates, expressions, or import
  names.
- Current trace capture favors `.aptl/runs`, while configured CLI run storage
  can point elsewhere. Injection of one resolved `RunStorageBackend` is
  mandatory; hardcoding either root would split evidence again.
- `LocalRunStore.write_json` overwrites and is not canonical. Calling it twice
  is not an immutability guarantee, and bypassing it with `write_file` loses
  structural redaction.
- A plan generated with timestamps, absolute paths, Python set/dict traversal,
  `random`, or UUIDs can look stable in one test process and still drift across
  hosts or retries.
- Admission-time Docker probes would make results host-state-dependent and
  would bypass both the manifest truth surface and the no-mutation boundary.

## Non-goals

- Do not define an APTL experiment DSL or mirror ACES authoring input, task,
  capture, run, study, apparatus, evidence, protocol, or analysis schemas.
- Do not execute a trial batch, schedule workers, select participant providers,
  implement stopping rules, or perform statistical analysis as part of the
  admission slice.
- Do not redesign ACES scenario compilation, participant runtime, lab startup,
  clean boot, collectors, snapshots, run archive layout, exporter, telemetry,
  web authentication, or deployment backends.
- Do not add remote fetching by default, a plugin loader, arbitrary URI scheme
  support, or ambient package/filesystem discovery.
- Do not make the internal journal a portable ACES artifact or claim that it is
  an archival `experiment-run-v1` record.
- Do not weaken redaction so experiment parameters can preserve
  control-plane/operator secrets. Designed-vulnerable evidence remains governed
  by ADR-029 at capture time, not by the experiment input.

## Anti-patterns

- Local `ExperimentSpec`, `Task`, `CaptureSpec`, `Study`, `Run`, or protocol
  models that copy ACES fields.
- A second YAML/JSON schema validator, semantic-invariant registry, exception
  hierarchy, diagnostic DTO, readiness taxonomy, or workflow state machine.
- Resolving references after the first trial starts or reopening a path after
  hashing it.
- Treating a digest as optional when bytes can affect execution, or treating an
  image tag/path/URI as immutable identity.
- Passing input strings to `getattr`, `importlib`, `subprocess`, shell, Docker,
  collector dispatch, environment lookup, or backend method selection.
- Letting condition names or scenario IDs select behavior in `if`/`match`
  branches instead of using typed ACES fields and bounded policy mappings.
- Logging raw validation/resolver exceptions or returning them through CLI/API
  error envelopes.
- Replanning a trial at execution time and accepting a plan that differs from
  the persisted digest.
- Using exporter filtering, file permissions, `.gitignore`, or an offline flag
  as a substitute for admission-time containment, authorization, and redaction.

## References

- EXP-002 / GitHub issue #438.
- [ADR-025](adr-025-strict-first-party-config-schema.md): strict APTL config.
- [ADR-029](adr-029-control-plane-secret-handling.md): secret classification
  and serialization-boundary redaction.
- [ADR-031](adr-031-lab-orchestration-contract-guards.md): lifecycle guards and
  existing error envelopes.
- [ADR-035](adr-035-aces-sdl-adoption.md): ACES contract authority and adapter
  boundary.
- [ADR-039](adr-039-web-control-plane-authentication.md): API auth and error
  exposure.
- [ADR-044](adr-044-aces-aligned-run-reproducibility-record.md): portable ACES
  identity versus APTL backend evidence.
- [ADR-046](adr-046-dynamic-aces-scenario-realization.md): compiled-plan
  authority, manifest capability gates, and `DeploymentBackend` realization.
