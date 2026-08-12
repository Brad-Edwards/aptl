# EXP-005 Safe Parameter Binding And Provenance Preflight

This note is the architecture preflight for EXP-005 / issue #441. It is
guidance, not an implementation plan. No new ADR is needed: ADR-025 owns the
strict first-party configuration schema, ADR-029 owns secret handling, ADR-033
owns the prompt/reasoning-capture boundary, ADR-044 owns RAES-aligned run
records, ADR-046 owns scenario realization, ADR-047 owns experiment admission
and deterministic trial plans, and the EXP-010 preflight owns capture
capability admission and evidence acquisition.

EXP-005 specializes ADR-047's admission boundary. Parameter binding must be a
closed, typed join between an RAES-authored condition and an already-owned
configuration surface. It is not a generic overlay engine, template system,
environment injector, participant provider, or prompt runtime.

## Contract Readiness Gate

RAES 2.0.0 resolves the contract-readiness gap identified when this preflight
was first run against ACES 0.23.1. RAES issue #903 and release commit
`957155f13cc5eecc06481483bf89604a08e6173a` publish the authoritative
`experiment-binding-descriptors-v1` and
`participant-configuration-result-v1` surfaces, plane-specific target
identities, strict literal/secret-reference values, configuration target
registries, target-resolution admission, participant configuration
realization, and portable realized-binding provenance.

The superseded ACES 0.23.1 limitation was:

- `ExperimentConditionAssignmentParameterModel` carries only `name`, scalar
  `value`, `value_kind`, and `redaction="none"`. It does not identify a binding
  plane, canonical target address, declared target type, source factor,
  sensitivity, or secret-reference identity.
- `value_kind` is archival classification, not a dispatch authority.
  `configuration` does not distinguish scenario variables from participant
  implementation configuration, and `apparatus` does not name an allowlisted
  `AptlConfig` field.
- `factor_levels` and `required_parameters` are separate collections. The
  contract does not identify which factor produced a parameter. Name equality
  is not a valid join.
- `ParticipantImplementationManifestModel` declares compatibility,
  capabilities, concept bindings, and string constraints.
  `ParticipantImplementationSelectionModel` can pin a `configuration_ref` and
  `configuration_digest`, but the current contracts expose no typed,
  addressable participant-configuration parameter surface.
- Condition parameters are required to carry concrete, non-redacted values.
  They cannot represent a secret reference as a distinct, non-value binding.

The gate is now satisfied by RAES 2.0.0. APTL must consume those public models
and validators directly; it must not fill the remaining adapter work with a
private authoring DTO, encoded parameter names, `required_refs`, free-text
descriptions, manifest `constraints`, or an `x-aptl` extension.

The legacy scenario-only behavior must not be generalized or advertised as
EXP-005. In particular,
`admission_steps._plan_conditions()` currently sends every
`required_parameter` to RAES scenario instantiation regardless of
`value_kind`; a same-named scenario variable could therefore absorb a value
that an author intended for another plane. Full EXP-005 admission must require
an explicit plane and target and fail closed on older ambiguous inputs.

## Binding Boundary

Admission resolves the complete binding set for every condition before any
range mutation. Each admitted binding has exactly one authoritative plane,
one canonical target, one strict scalar type, one source factor and condition,
one value disposition (concrete non-secret value or non-sensitive reference
identity), and one owning validator. Unqualified targets, cross-plane fallback,
and target aliases are invalid.

### RAES scenario instantiation

Scenario parameters remain wholly RAES-owned:

- Resolve targets only against `Scenario.variables`. Use the RAES qualified
  parameter identity, declared `VariableType`, `allowed_values`, and required
  semantics.
- Use `raes.instantiate_scenario()` and reference-processor planning.
  Never substitute strings locally or write directly into the parsed scenario.
- Reuse `InstantiatedScenario.instantiation_provenance.bindings` and
  `BindingOrigin.PROVIDED` / `BindingOrigin.DEFAULT` for realized values and
  default/override provenance. Do not reconstruct defaults from the authoring
  model.
- Use `canonical_instantiated_sdl_digest()` as the scenario-plane
  configuration identity.

### RAES participant implementation configuration

Participant implementation configuration stays behind the RAES participant
runtime and implementation-manifest boundary:

- The participant implementation owns its configuration contract, strict
  validation, defaults, and compatibility with its manifest. APTL may resolve,
  pin, and pass an admitted configuration artifact or receipt; it must not
  interpret prompt templates, provider options, Python entry points,
  executables, images, environment variable names, or arbitrary manifest
  strings.
- Reuse `ParticipantImplementationManifestModel`,
  `ParticipantImplementationSelectionModel.configuration_ref` /
  `configuration_digest`, `ParticipantImplementationProvenanceModel`, and the
  participant runtime admission/history contracts. Use RAES
  `realize_participant_configuration()` for the complete atomic configuration;
  do not add a local participant manifest or configuration schema.
- A participant plane is bindable only when the selected RAES 2.0.0
  implementation manifest publishes a `configuration_registry` and the
  required configuration contracts. Manifests without that surface still fail
  closed.
- Production admission resolves participant-manifest bytes only from
  `role="manifest"` entries in the same checksum-validated RAES associated
  artifact set as the experiment. It matches the parsed manifest's exact
  implementation name, version, and schema to the descriptor target, retains
  the artifact identity and digest, and rejects duplicate owners. No package,
  environment, or ambient filesystem lookup supplies a manifest.
- Provider and participant construction remain owned by #557 /
  `OpenRAE/rae#251`, not EXP-005.

### APTL apparatus configuration

`AptlConfig` is the only first-party configuration authority. Apparatus binding
uses a small code-owned, versioned allowlist of stable target IDs that point to
existing strict `AptlConfig` fields and name their runtime owner. EXP-005
approves exactly one target,
`participant-runtime.action-timeout-seconds`, backed by the strict
`experiment.participant_action_timeout_seconds` field and its participant
action consumer. Every other `AptlConfig` field remains unbindable.

An allowlist entry must define the canonical target ID, exact JSON scalar type,
normalization policy, and public effective-configuration projection. It must
not accept a dotted path supplied by the experiment or traverse Pydantic fields
with `getattr`. Apply an admitted overlay to a JSON projection and validate the
whole result again with `AptlConfig.model_validate`; `model_copy(update=...)`
and Pydantic coercion are not strict type checks.

Deployment provider/host/user/key/remote directory, project identity,
run-storage paths, lifecycle policy, environment variables, credential
settings, arbitrary container names, network subnets, filesystem paths, and
command fragments are not apparatus experiment targets merely because they
exist in `AptlConfig`. Topology-changing container flags also remain excluded
unless a later architecture decision defines their clean-reset, capability,
and comparability semantics.

Follow the established one-declaration/one-trusted-wiring pattern used by the
collector registry, but do not generalize `CollectorRegistry` into a
meta-registry. An apparatus target registry and a capture registry describe
different concepts.

### Execution controls

Allocation, ordering, stochastic controls, and episode controls continue
through `ExperimentRunPlanModel`, `AdmissionPolicy`, and the pure trial-plan
expander. A `protocol` or `analysis` parameter is not a back door into these
controls. Unsupported controls fail admission; no free-text value is evaluated
as code, a template, or a policy expression.

## Deterministic Realized Provenance

The immutable trial plan uses the
`aptl-experiment-trial-plan/v3` internal realized-binding projection. It is an
APTL execution journal shape, not a portable RAES parameter, run, apparatus,
participant, or provenance contract. It retains the legacy scenario
`parameter_bindings` projection for execution compatibility while pinning the
authoritative RAES realized-binding, participant-configuration, and approved
apparatus projections alongside it.

For each binding, the projection records only:

- RAES factor identity and level plus condition identity;
- authoritative plane and canonical target identity;
- declared scalar type and value source;
- normalized non-secret realized value, or a separately typed non-sensitive
  reference identity with no resolved secret value;
- the owning configuration/manifest/policy version; and
- the authoritative plane digest.

Canonical target identity, not input spelling or registry insertion order,
drives sorting and collision detection. Two authored entries resolving to the
same target are an error even when their values match. Aliases must be resolved
by the owning authority before comparison; ambiguous or deprecated aliases
fail rather than pick a winner.

The `aptl-experiment-source-set/v2` identity includes the resolved
experiment-authoring-input digest, RAES binding-descriptor digest, and selected
participant-manifest identities and digests.
RAES owner validation rejects canonical-target collisions before planning,
and the admitted descriptor set is sorted by stable binding identity before
realization. Planned-trial IDs therefore change with authored binding values
without depending on map insertion order.

The authoring-input digest and the complete secret-safe binding-set identity
must affect planned-trial identity. Never derive identity from raw secret
values. Use RFC 8785 canonical JSON, a versioned domain separator, and SHA-256,
matching `trial_plan.py` and `LocalRunStore.create_json_once()`. Reject
non-finite numbers and distinguish booleans from integers before
canonicalization.

Plane digests retain their native authority:

- scenario: RAES canonical instantiated-scenario digest;
- participant: the RAES participant configuration result's validated digest;
- apparatus: a digest of the versioned allowlist identity and canonical public
  effective values for allowed targets, not the whole host-specific
  `AptlConfig`;
- trial binding set: a domain-separated digest over the sorted, non-secret
  realized-binding projections and their plane digests.

## Run Record And Secret Semantics

The persisted plan is the create-once admission receipt. Execution must verify
its digest and use the pinned bindings without re-resolving targets or
re-matching a changed allowlist.

Portable run output continues through RAES:

- `ExperimentRunModel.parameter_set` and
  `ExperimentApparatusContextModel.configuration_parameters` carry RAES
  parameter values/classification where those contracts apply.
- `ParticipantImplementationProvenanceModel` carries participant selection and
  configuration identity.
- scenario snapshot references and realized-form disclosures carry the
  realized RAES scenario identity.

Use RAES `RealizedBindingProvenanceModel` for the portable realized-binding
surface. The exact APTL plan remains the create-once admission receipt and must
not be turned into a second `ExperimentRunModel` or flattened into
`RangeSnapshot`.

Secret handling is fail-closed:

- Concrete parameter names and values pass
  `is_sensitive_key()` / `is_secret_shaped_value()` before plan construction.
  A value that the shared redactor would change is not executable experiment
  data.
- A secret reference is a distinct upstream binding form, never a string value
  that happens to contain a vault path, environment name, token, or URI.
- Record only a validated, non-sensitive reference identity and its provider
  or manifest identity. Do not record, log, hash, compare, or canonicalize the
  resolved secret value.
- Resolve the secret only at the existing owning runtime boundary after
  admission, through its existing environment/file/credential channel. Never
  put it in process argv, a URL/query, a command, the trial plan, a config
  digest, or an RAES diagnostic.
- `LocalRunStore.create_json_once()` remains the invariant check: if shared
  redaction would change the canonical projection, persistence and execution
  fail instead of silently redacting identity-bearing bytes.

`APTL_EXPERIMENT_NO_REDACT` is not parameter-binding authority and is not
permission to persist secrets in plans or run records.

## Capture Boundary

Varying a prompt or interaction does not authorize its capture. Prompt,
completion, or interaction content may be retained only when all of the
following are true:

- an admitted RAES `ExperimentCaptureSpecModel` explicitly requires that
  evidence kind and scope;
- the requirement's sensitivity, redaction, visibility, retention, integrity,
  window, and loss policy matches a conformant registration in
  `DEFAULT_COLLECTOR_REGISTRY`;
- trusted composition supplies an implementation-owned source adapter; and
- the evidence coordinator applies its quotas, redaction, visibility,
  content-addressing, record validation, and terminal-outcome rules.

No current registration declares prompt/completion content. The workbench's
one-shot agent adapter sends the prompt on stdin with
`--no-session-persistence` and records hashes/counts rather than content; that
remains the safe default. MCP tool-call, terminal, OTel, and provider logs are
not implicit substitutes for an RAES prompt-capture specification.

## Cross-Cutting Incumbents To Reuse

| Concern | Canonical incumbent and required use |
|---|---|
| RAES authoring and archival schemas | Public `raes_contracts.contracts` / `experiment_spec` models and installed contract fixtures. Do not copy or extend their fields locally. |
| Bounded admission | `src/aptl/core/experiment/{resolver,spec_loading,admission,admission_steps,apparatus,policy,errors}.py` for limits, contained resolution, joins, all-or-nothing admission, and safe diagnostics. |
| Scenario binding | `Scenario.variables`, `raes.instantiate_scenario`, `InstantiationProvenance`, `canonical_instantiated_sdl_digest`, and the RAES reference processor. |
| Deterministic planning | `trial_plan.py` RFC 8785 projection, versioned hash domains, immutable tuples, policy versioning, and create-once plan persistence. |
| Participant boundary | RAES participant manifest/configuration/provenance models and validators plus `raes_participant_runtime.py`, `raes_participant_actions.py`, and `raes_participant_support.py`. `experiment/bindings.py` performs owner validation and atomic configuration realization; `raes_participant_bindings.py` consumes the approved action-timeout apparatus setting without becoming a generic configuration overlay. |
| First-party config | Strict `AptlConfig`, `load_config`, its actual runtime consumers, ADR-025, and a closed code-owned apparatus allowlist. |
| Secrets and generated config | `env.py`, `EnvVars`, placeholder validation, `credentials.py`, ADR-028/029, `redact`, `is_sensitive_key`, `is_secret_shaped_value`, TypeScript redaction parity, and `curl_safe`. |
| Runtime mutation | `_LAB_START_STEPS`, `RuntimeManager`, `AcesRunTarget`, the admitted-plan apply/retry seam, and typed `DeploymentBackend` methods. |
| Persistence and run records | `RunStorageBackend` / `LocalRunStore`, `RangeSnapshot.to_dict()`, RAES `ExperimentRunModel` and apparatus/participant provenance, ADR-044, and `raes_repro.py` only within its existing backend-record role. |
| Capture and visibility | The EXP-010 collector registry/bindings, evidence coordinator, RAES evidence records, content store, and participant visibility projection. |
| Errors and observability | RAES `Diagnostic`, `AdmissionRejection`, `render_raes_diagnostics`, `LabResult`/startup diagnostics at lifecycle boundaries, and `get_logger`. |
| Auth if exposed | API-wide `verify_token`, BFF Host/CSRF/session middleware, request-size limits, and narrow Pydantic projections. EXP-005 adds no endpoint. |
| Workflow and verification | `.ground-control.yaml`, `.gc/plan-rules.md`, pytest/property tests, RAES fixtures, pre-commit, and the existing clean-lab gate for Compose/container/config changes. |

## Security And Validation Passage

The intended design must pass every applicable layer:

| Layer | Required passage |
|---|---|
| Authentication/authority | No new network surface. A future API route authenticates and passes BFF Host/CSRF/session gates before resolving artifacts or configuration identities. Local CLI authority does not authorize arbitrary host paths or environment lookup. |
| Document shape | Bound bytes and reject ambiguous/duplicate documents in `spec_loading`; validate through closed RAES models. Reject contract versions that lack explicit plane/target/source semantics. |
| Cross-artifact semantics | Resolve factor, condition, task, scenario, participant manifest/configuration, capture, and apparatus identities before mutation. Every reference and digest must resolve uniquely. |
| Binding policy | Dispatch only by an RAES-governed plane term and exact canonical target. Scenario, participant, apparatus, and execution-control validators remain separate owners; no fallback between them. |
| Strict types | Validate exact JSON scalar types before owner validation; boolean is not integer, strings are not coerced, and non-finite numbers are rejected. Then run the owning RAES/Pydantic validator over the complete realized shape. |
| Secret handling | Reject secret-shaped concrete values before hashing or planning. Accept only a distinct validated reference form, retain non-sensitive identity only, and resolve actual secret material at the owning runtime boundary. |
| Config/environment | Apparatus targets come only from the code allowlist and strict `AptlConfig`. Participant config comes only from its manifest-owned schema. No experiment-provided env keys, `.env` reads, file paths, provider settings, or rendered config. |
| OS/process/URL | Use in-process validators and typed backend argument arrays. No target/value controls subprocess names, argv, shell text, import paths, Docker methods, environment names, URLs, queries, or filesystem destinations. |
| Range mutation | Resolve, validate, canonicalize, persist, and re-read the entire plan before `.env` hydration, credentials/certificates, config rendering, clean boot, image pulls, session creation, collectors, or any `DeploymentBackend` call. |
| Persistence/export | Use `create_json_once` for the plan and create-once run/evidence records. Structured run writes use shared redaction; opaque stores are never used for config values. Export packages already-safe records. |
| Prompt/evidence capture | Capture requires an admitted RAES spec plus a matching registry binding and sensitivity policy. Parameter variation, workbench use, MCP capture, or an environment redaction toggle is not consent. |
| Logs/telemetry | Log only stable codes, safe IDs, plane/target counts, policy versions, and digests. Never log realized values, references with secret-bearing metadata, raw validation input, config documents, prompts, backend stderr, or exception strings. |
| Error envelope | Normalize to safe RAES diagnostics using fixed messages and stable addresses. Do not expose Pydantic `input`/`ctx`, YAML excerpts, absolute paths, participant/provider exceptions, command output, or secret-resolution distinctions. |

## Extensibility Seam

The external seam is the RAES binding descriptor and participant
implementation configuration contract. One reasonable future parameter target
should require an additive declaration by its owning authority and conformance
fixtures, not changes to every controller, run-record builder, exporter, or
participant provider.

The APTL-only seam is the versioned apparatus target allowlist. Adding one
apparatus knob requires one stable target declaration tied to an existing
strict `AptlConfig` field and runtime consumer, plus tests for type,
normalization, digest, and clean reset. It does not enable arbitrary dotted
paths or make all future `AptlConfig` fields bindable.

The binding engine itself remains a closed dispatcher over the supported
planes. A future new plane requires an RAES contract change and explicit
architecture review; it is not a plugin selected by experiment input.

## Whole-Repository Surface

- RAES contracts and canonicalization: locked `raes_contracts`, `raes`,
  the reference processor, and `src/aptl/backends/raes_manifest.py`.
- Experiment admission/planning: `src/aptl/core/experiment/**`.
- Scenario realization and execution: `src/aptl/backends/raes*.py`,
  `src/aptl/core/lab.py`, and `src/aptl/core/deployment/**`.
- Participant implementation/runtime: RAES participant contracts,
  `src/aptl/backends/raes_participant_*.py`, and downstream #557 ownership.
- Config/secrets: `src/aptl/core/config.py`, `env.py`, `credentials.py`,
  ignored generated config, `aptl.json`, and redaction helpers in Python and
  TypeScript.
- Persistence/provenance: `runstore.py`, `raes_repro.py`, `snapshot.py`,
  `exporter.py`, RAES run/apparatus/participant provenance, and #444 sealing.
- Capture/visibility: `src/aptl/core/experiment/capture_*`,
  `src/aptl/core/evidence/**`, MCP/Kali capture owners, and workbench
  hash/count-only events.
- Control surfaces: CLI experiment admission today; API/BFF authentication and
  request/error projection only if later exposed.
- Host/runtime exposure: process argv/environment, generated files, Compose
  and container lifecycle, Docker/SSH/HTTP adapters, logs, OTel, run archives,
  and exports.
- Workflow/docs/tests: this note, ADR-025/029/033/044/046/047, the EXP-010
  preflight, `.gc/plan-rules.md`, RAES fixtures, pytest/property tests,
  pre-commit, and CI.

## Gotchas And Anti-Patterns

- Do not infer plane or target from `value_kind`, parameter name prefixes,
  dots, JSON Pointer-like strings, factor names, `required_refs`, notes, or a
  matching field that happens to exist.
- Do not dispatch authored strings through `getattr`, `setattr`, `importlib`,
  environment lookup, a shell, subprocess, Docker, collector factories, or
  participant provider selection.
- Do not let duplicate names, normalized aliases, case folding, or dict
  construction create last-write-wins behavior. Detect collisions before
  building any map.
- Do not rely on Pydantic coercion. In Python, `bool` is an `int`; `"1"` is not
  an integer; NaN/Infinity are not canonical JSON experiment values.
- Do not compute planned-trial identity without the authoring input and complete
  realized binding set.
- Do not hash a raw secret as a substitute for excluding it. Low-entropy secret
  hashes are reversible by guessing and still couple identity to secret
  material.
- Do not record only overrides. Defaults are realized values and must come from
  the owning validator's provenance.
- Do not recompute participant configuration digests with an APTL-specific
  algorithm or treat a manifest reference as proof that its configuration
  validated.
- Do not expose every `AptlConfig` field, accept arbitrary JSON Merge Patch,
  mutate the loaded config in place, or persist a generated `aptl.json`.
- Do not conflate scenario binding, participant configuration, apparatus
  configuration, execution controls, capture configuration, environment
  secrets, and provider construction because all involve “parameters.”
- Do not create parallel RAES models, a generic overlay/template language, a
  second exception hierarchy, a second redaction taxonomy, a second run
  repository, or a parameter-specific workflow state machine.
- Do not re-resolve or revalidate against mutable registries at execution and
  accept a different result. Digest mismatch is terminal.
- Do not automatically capture prompt/completion content because a prompt was
  varied, because the workbench saw it, or because tool/terminal capture is
  already active.
- Do not use `APTL_EXPERIMENT_NO_REDACT`, file permissions, `.gitignore`,
  offline operation, or exporter filtering as an admission or secrecy control.

## Non-Goals And Boundaries

- This preflight does not implement EXP-005 or redefine the RAES 2.0.0
  contracts.
- EXP-005 does not create an APTL experiment DSL, participant/provider runtime,
  prompt templating system, secret manager, environment overlay engine,
  arbitrary config patcher, or plugin loader.
- It does not execute trial batches, construct participant providers, redesign
  lab startup/clean reset, change deployment backends, or implement #444
  sealing.
- It does not make prompt, completion, chain-of-thought, transcript, terminal,
  MCP, OTel, or provider-log capture implicit.
- It does not weaken ADR-029 redaction or turn experiment records into a secret
  vault.
- It does not redesign RAES scenario variables, participant contracts, capture
  specs, evidence records, apparatus context, or experiment run models.
