# DSL-003 Runtime Variable Backend Consumption Preflight

This note is the architecture preflight for issue #432. It is guidance, not an
implementation plan. The variable and substitution contract is owned by ACES
(upstream issue Brad-Edwards/aces#655). ADR-035 remains the schema/adoption
boundary, ADR-044 owns run evidence, and ADR-046 owns dynamic realization and
provider safety.

## Architecture Decisions

- ACES remains the sole authority for variable declarations, defaults, types,
  allowed values, selected profiles, substitution, provenance, unresolved
  reference detection, and post-substitution semantic validation. APTL passes
  an explicit typed binding mapping to `RuntimeManager.plan(parameters=...)`
  or consumes an ACES-admitted plan; it does not mutate YAML, interpolate
  strings, coerce values, or define a local variable DTO.
- A lab-start attempt has exactly one substitution/planning authority. The
  resulting `ExecutionPlan` and its `RuntimeModel` are the concrete scenario
  consumed by realization, participant-action projection, selected-profile
  reporting, evidence, and apply. No downstream path may reparse or recompile
  the raw `Scenario` to rediscover those facts.
- Keep the lifecycle types distinct: authored `Scenario`, ACES
  `InstantiatedScenario`, `RuntimeModel`, `ExecutionPlan`, APTL
  `AptlRealization`, provider `DeploymentRealizationSpec`, observed
  `RuntimeSnapshot`, and persisted `RangeSnapshot`. A parameter bag is input to
  admission, not a realization model, deployment configuration, or snapshot.
- Substitution failure is fatal and occurs before provider side effects.
  Missing required values, undeclared names, type mismatches, allowed-value
  failures, unresolved references, and post-substitution validation failures
  must not reach `DeploymentBackend`. They are deterministic contract failures,
  not SOC readiness failures, and must not take the current delayed retry path.
- `SDLInstantiationError` is the upstream failure owner. Project it once into
  the existing redacted `LabResult`/startup/API envelope. Do not create a local
  exception hierarchy, reproduce upstream checks, or classify failures by
  scraping English exception text.
- The selected `aces-sdl` 0.21.x surface exposes instantiation details as free
  text rather than stable value-free diagnostic records. Raw rendering is not
  safe because details may contain provided or derived values. A bounded
  generic failure is the safe fallback. Per-mode actionable projection requires
  an upstream code, variable path/name, and value-free detail contract; advance
  the ACES dependency rather than introducing duplicate APTL validation or an
  English-message parser.
- Runtime bindings are explicit per-run inputs. They do not come implicitly
  from `os.environ`, `.env`, `EnvVars`, `AptlConfig`, Compose interpolation, or
  scenario-name defaults. The same immutable input must be retained across a
  legitimate clean-boot/retry attempt and handed to ACES unchanged.
- SDL variables are not a secret transport. Do not persist the raw mapping or
  expose it in logs, traces, errors, CLI output, API responses, process argv, or
  provider environment. A future secret-capable contract needs explicit
  sensitivity and delivery semantics; existing `.env`/generated-credential
  owners remain the only secret surface.

## Required Cross-Cutting Concerns

- **ACES contract and validation:** `aces_sdl.parse_sdl_file`, source/import
  constraints, semantic validation, ACES instantiation, `RuntimeManager.plan()`,
  planner diagnostics, `ExecutionPlan`, `RuntimeModel`, instantiation
  provenance, backend manifest validation, and `RuntimeManager.apply()`.
- **APTL admission and lowering:** `start_aces_scenario()`,
  `create_aptl_runtime_target()`, `interpret_provisioning_plan()`,
  `AptlProvisioner.validate()`, typed `AptlRealization`, and
  `_apply_execution_plan()`. SEM-218 and provider support remain plan/apply
  gates after successful substitution.
- **Single-model consumers:** `participant_action_specs_from_runtime_model()`,
  the selected profiles already returned in `AcesStartOutcome`, realization
  details, manifest payload, and ACES run evidence. The best-effort
  `participant_action_specs_for_scenario()` compiler and
  `selected_profiles_for_scenario()` must not create a second model during the
  same start attempt.
- **Provider safety:** `DeploymentBackend`, `DockerComposeBackend`,
  `SSHComposeBackend`, typed argv calls, project-name/Compose-label scoping,
  timeouts, image source/digest/build-path checks, content source/destination
  containment, network/address checks, exact port conflict checks, loopback
  publishing defaults, account validation, and participant binding validation.
- **Configuration and secrets:** strict `AptlConfig`, `.env`/`EnvVars`,
  placeholder rejection, generated credential/config owners, `redact()`, and
  ADR-025/ADR-029. These are adjacent controls, not alternate variable binding
  systems.
- **Errors and observability:** ACES `Diagnostic` for plan/apply failures,
  `aces_diagnostics`, `render_aces_diagnostics()`, `LabResult`,
  `StartupDiagnostic`, `AcesStartOutcome`, `get_logger()`, existing telemetry,
  and authenticated API projections. Substitution is a pre-plan failure and
  must not be mislabeled as provisioning or degraded readiness.
- **Evidence and persistence:** `LocalRunStore` redacting JSON/JSONL methods,
  `aces_repro`, `RuntimeSnapshot`, and `RangeSnapshot.to_dict()`. Preserve an
  upstream instantiated artifact identity and value-free binding metadata when
  available; do not create an APTL parameter record or persist raw provenance
  values by default.
- **Workflow conventions:** `orchestrate_lab_start()`, `_LabStartContext`,
  `_step_start_containers()`, clean boot, static/live ACES gates, `pytest`, and
  `pre-commit run --all-files` under `.gc/plan-rules.md`.

## Cross-Cutting Layers The Design Must Pass

| Layer | Required behavior |
| --- | --- |
| Scenario selection | Continue through `resolve_scenario_selection()` and project-file containment. A runtime binding must never become a path or import bypass. |
| ACES parse and semantic admission | Let the selected ACES package parse, shape-check, resolve imports, and validate authored SDL. Do not add an APTL schema or placeholder scanner. |
| ACES instantiation | Pass one explicit mapping with ACES-supported scalar types to `RuntimeManager.plan(parameters=...)`. ACES owns required/default, undeclared, type, constraint, selected-profile, unresolved-reference, and post-substitution checks. |
| Plan and manifest | Fail planner diagnostics before side effects and preserve the planned manifest, provenance, canonical addresses, and SEM-218 requirements. Do not synthesize a plan from substituted dictionaries. |
| APTL lowering | Interpret only the admitted plan/model into `AptlRealization`. A remaining `${...}` token or malformed concrete value is a contract failure, not a value to drop, default, or substitute locally. |
| Provider policy | Re-run all existing image, content, network, port, account, participant-binding, and backend capability checks on concrete values. Successful ACES substitution does not waive provider safety policy. |
| Deployment and OS exposure | Use `DeploymentBackend` and discrete argv. Never forward the binding mapping wholesale to Compose environment, container environment, subprocess argv, or shell. Participant-action values still pass governed binding validation; bindings must not carry secrets because container argv may be inspectable. |
| Config and environment shape | Keep durable non-secret configuration in strict `AptlConfig` and control-plane secrets in `.env`/`EnvVars` and generated config. No ambient environment lookup or string-to-scalar coercion is permitted. |
| Auth and ingress | Issue #432 adds no HTTP or CLI variable-authoring surface. Existing lab start remains behind `verify_token` and BFF host/CSRF/session gates. A later ingress must use an authenticated strict Pydantic body or protected typed file that preserves scalar types, never query parameters or secret-bearing command-line flags; validation projections must omit raw input values. |
| Retry and side-effect boundary | Instantiation and planner failures are non-retryable and return immediately. If orchestration needs a signal, carry a narrow stage/retryability classification on the existing start outcome; do not infer it from message text. A legitimate provider retry reuses the same admitted inputs. |
| Error envelope | Return a fatal redacted `LabResult` before deployment. Expose stable upstream codes, variable identifiers/paths, and value-free remediation only when the upstream contract supplies them; otherwise use a bounded generic message. Do not echo the mapping, raw exception, scenario, or plan. |
| Logging and telemetry | Log only stage, stable code, safe variable identifier, and counts. Never attach values, the binding mapping, raw plan/model, exception payload, or rendered scenario to logs or span attributes. `redact()` is defense in depth, not proof that arbitrary values are safe. |
| Persistence and export | Use existing runstore paths and redaction. Raw binding values and upstream provenance containing them stay out of snapshots, run JSON, archives, CLI/API projections, and exports unless a later sensitivity-aware contract explicitly admits them. Export remains packaging-only. |

## Extensibility Seam

The required seam is the existing ACES planning call, parameterized by:

`(Scenario, explicit per-run bindings, selected ACES profile, prior
RuntimeSnapshot, RuntimeTarget) -> ExecutionPlan`.

The bindings are handed to ACES exactly once. Every later concern receives the
admitted `ExecutionPlan` or its `RuntimeModel`, never the raw mapping. This
allows the next reasonable variation -- a different authenticated binding
carrier, another backend, or an upstream-admitted instantiated artifact -- to
replace only the input/admission edge while leaving realization, participant
projection, apply, provider validation, and evidence handling unchanged.

The error-projection seam is an upstream structured instantiation diagnostic:
stable code, variable address/name, phase, and value-free remediation. APTL may
map that to its existing envelopes, but must not define the semantic taxonomy.
If orchestration needs retry control, stage/retryability belongs on the existing
start outcome, not in a second exception tree.

## Whole-Repo Surface

- Contract authority: `pyproject.toml`, `uv.lock`, the selected `aces-sdl`
  parser/instantiator/runtime APIs, ACES diagnostics, manifest, conformance
  corpus, and upstream contract tests.
- Runtime path: `src/aptl/backends/aces.py`, `aces_start_model.py`,
  `aces_participant_actions.py`, `aces_participant_bindings.py`,
  `aces_realization.py`, `aces_realization_model.py`,
  `aces_realization_values.py`, `aces_profiles.py`, `aces_provisioner.py`, and
  `aces_diagnostics.py`.
- Provider/security path: `aces_image_realization.py`,
  `aces_content_realization.py`, `aces_realization_networks.py`,
  `aces_account_realization.py`, `src/aptl/core/deployment/`, host-port checks,
  Docker/SSH Compose process boundaries, project labels, and host binding.
- Lifecycle/output path: `src/aptl/core/lab.py`, `lab_types.py`, `runstore.py`,
  `snapshot.py`, `src/aptl/backends/aces_repro.py`, CLI lab output,
  `src/aptl/api/routers/lab.py`, API schemas, BFF/auth middleware, logs, traces,
  run archives, and exports.
- Config/secret path: `src/aptl/core/config.py`, `env.py`, `.env`, generated
  config/credentials, `AptlConfig`, `EnvVars`, `redact()`, ADR-025, ADR-029,
  ADR-035, ADR-039, ADR-044, and ADR-046.
- Validation path: `src/aptl/validation/_gate_checks.py`,
  `_live_gate_probes.py`, and `curated_live_proof.py`. Required-variable
  scenarios need an explicit representative binding input; do not add
  scenario-name parameter maps to make gates pass.
- Test path: `tests/test_aces_backend.py`,
  `tests/test_aces_realization_service_ports.py`,
  `tests/test_aces_repro.py`, `tests/test_lab.py`, CLI/API tests, target
  conformance, static scenario gates, and the bounded live gate.

## Gotchas And Anti-Patterns

- `participant_action_specs_for_scenario()` currently recompiles the raw
  scenario and swallows failure. Runtime-substituted participant bindings must
  instead come from the already planned `execution_plan.model` through
  `participant_action_specs_from_runtime_model()`.
- Lab start currently calls `selected_profiles_for_scenario()` after a
  successful ACES start, causing a second raw parse/plan. Use
  `AcesStartOutcome.selected_profiles`; otherwise required bindings disappear
  or defaults may diverge from the executed plan.
- The SOC startup path currently retries any ACES failure after a delay.
  Substitution, parse, planner, and provider-policy failures are deterministic
  and must not be delayed or retried as readiness failures.
- `aces_realization_values` currently drops unsubstituted port tokens, and tests
  pin that defensive behavior. In the admitted runtime path, unresolved tokens
  are impossible by contract; if one arrives, fail closed before side effects
  rather than silently omitting a declaration. Do not add a repo-wide duplicate
  placeholder validator.
- `aces_repro` currently records `scenario_parameters: null` and a note that no
  parameter surface exists. That statement becomes stale, but replacing it
  with raw ACES binding provenance would create a secret/data leakage surface.
- Do not use local regex replacement, recursive dictionary walkers, YAML
  mutation, local Pydantic variable models, string coercion, or duplicate
  required/type/allowed-value checks.
- Do not conflate ACES `${variable}` semantics with Compose interpolation,
  `.env.example` placeholder detection, participant `{{...}}` templates,
  generated credentials, shell variables, or service environment variables.
- Do not reparse/replan for profiles, participant actions, evidence, retries, or
  validation; do not branch on scenario name or hardcode a parameter map for a
  curated scenario.
- Do not parse `SDLInstantiationError` prose, blindly render it, hash low-entropy
  values as a substitute for secrecy, or rely on `redact()` to discover
  arbitrary user-provided values.
- Do not treat a substitution failure as an ACES provisioning diagnostic,
  backend execution failure, degraded startup diagnostic, or successful lab
  with omitted fields.

## Non-Goals And Boundaries

- Do not implement issue #432 in this preflight.
- Do not define or change SDL variable syntax, scope, precedence, types,
  defaults, allowed-value semantics, profile semantics, substitution order, or
  provenance in APTL; the upstream ACES contract is authoritative.
- Do not add an API, UI, CLI flag, environment convention, config property, or
  persistence schema for authoring/storing bindings in this issue.
- Do not make SDL variables a secret manager or migrate existing service
  credentials, generated config, TLS/SSH material, tokens, or `.env` values into
  the SDL variable surface.
- Do not redesign `DeploymentBackend`, Compose topology, startup readiness,
  provider validation, participant templates, run archives, snapshots,
  exporter packaging, authentication, or observability.
- Do not accept arbitrary externally serialized plans unless the selected ACES
  contract supplies an admission/integrity path. An in-process `ExecutionPlan`
  from the canonical planner is not a general remote-plan API.
- Do not weaken downstream provider validation because substitution succeeded,
  and do not broaden live gates beyond one representative valid concrete
  binding plus fast contract/failure coverage.
