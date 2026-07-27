# Issue #557 Participant Implementation Binding Preflight

This note fixes the architecture guardrails for driving a governed RAES
participant through an installed coding-agent implementation. It is design
guidance, not an implementation plan. No new ADR is needed:
[ADR-033](../adrs/adr-033-agent-reasoning-trace-boundary.md),
[ADR-035](../adrs/adr-035-raes-sdl-adoption.md),
[ADR-044](../adrs/adr-044-raes-aligned-run-reproducibility-record.md),
[ADR-046](../adrs/adr-046-dynamic-raes-scenario-realization.md),
[ADR-049](../adrs/adr-049-sealed-disposable-lab-appliance.md), the
[DSL-010 preflight](../raes/dsl-010-participant-runtime-preflight.md), and the
[participant-workbench preflight](issue-821-participant-workbench-preflight.md)
already own the relevant decisions.

RAES 2.0.0 is the minimum participant-contract baseline for this work. Its
issue-909 exact-cut first-turn semantics supersede the earlier RAES 1.1
projection assumptions in prior issue discussion.

ADR-049 supersedes the issue's historical physical-host assumption for
supported participant delivery. The participant runtime, coding agent, MCP
processes, credentials, and evidence store run in the appliance management
zone. A trusted developer-local adapter may remain opt-in, but it is not proof
of the supported participant isolation boundary.

## Architecture Decisions

- RAES owns the participant implementation contract. Use
  `ParticipantImplementationManifestModel`,
  `ParticipantImplementationSelectionModel`,
  `ParticipantActionResultModel`, and
  `ParticipantActionAdmissionRequest` as published; do not create APTL
  mirrors, a local provenance DTO, or a second behavior-history schema. The
  actor field comes from
  `participant_implementation_actor_provenance(selection)`, never a configured
  or hard-coded `actor_provenance` string.
- RAES also owns the participant lifecycle and native-action commit algorithm.
  `AptlParticipantRuntime` must reuse/subclass
  `raes_backend_protocols.participant_runtime_base.BaseParticipantRuntime` and
  implement its `_model_action()` seam, returning
  `ParticipantNativeActionExecution`. Do not retain a parallel APTL
  initialize/reset/restart/terminate/admit implementation or manually rebuild
  the three portable behavior events.
- The bounded-agency validation begins with one admitted `ExecutionPlan.model`. Its
  participant behavior, action contract, observation boundary, exposure
  policy, and compiled addresses are the only action authority.
  `ParticipantPlanAuthority`, `validate_participant_realizations()`, and the
  closed `BPA_ACTION_REALIZATIONS` registry are the current APTL incumbents for
  the selected research freeze. `participant_action_specs_from_runtime_model()`
  lowers an older backend-private fixed-probe binding and remains a smoke-path
  incumbent; it is not the action authority for
  `bounded-participant-agency-techvault`. APTL must not reparse YAML, compile a
  second model, or recover action facts from a scenario/catalog/profile name.
  The exact admitted plan identity that realized the lab remains attached to
  the episode and proof.
- When the installed implementation chooses among actions, use RAES's
  `project_participant_decision_surface_v2()`,
  `ParticipantDecisionSurfaceV2Model`,
  `ParticipantDecisionSurfaceSelectionV2Model`,
  `bind_participant_decision_surface_selection_v2()`, exact delivery records,
  and
  `RuntimeControlPlane.admit_participant_decision_surface_selection_v2()`. A
  prompt containing an action list and a hand-parsed provider response is not
  a substitute for the time-indexed exact-cut visibility projection,
  apparatus binding, delivery re-resolution, and governed argument-shape
  validation. Provider solicitation itself runs as a failed-or-succeeded
  participant control-plane operation before any selection may reach
  admission.
- Keep four concepts separate: the compiled SDL participant address, the
  selected RAES participant implementation identity/version/digests, a
  workbench capability profile, and the APTL deployment backend. A `red`
  workbench profile is not an implementation selection; `aptl`, Docker
  Compose, a container name, and a coding-agent product name are not actor
  provenance.
- Reuse the existing provider-neutral `ManagedAgentAdapter`,
  `ClaudeCodeManagedAgentAdapter`, `CodexManagedAgentAdapter`,
  `BoundedProcessRunner`,
  `EphemeralCredentialBroker`, strict MCP profile renderer, inventory verifier,
  and workbench lifecycle/locking patterns. Issue #557 adds the RAES
  participant-binding orchestration around that boundary; it does not add a
  parallel adapter protocol, subprocess runner, credential lease, provider
  exception hierarchy, MCP launcher, or transcript store.
- The governed behavior is agent-driven only when the selected implementation
  is actually invoked inside the participant operation and the trusted APTL
  realization returns a terminal RAES `ParticipantActionResultModel` through
  `ParticipantNativeActionExecution`. Provider output alone is not effect
  truth. `BaseParticipantRuntime.admit_action()` and
  `participant_action_binding_events()` remain the single owner of the
  portable attempted, state-transition, and observation event sequence.
- Agent invocation must execute within a RAES participant control-plane
  operation so every terminal outcome becomes `operation-status-v1`.
  Invalid selection, unavailable or unsafe executable, MCP inventory mismatch,
  malformed result, timeout, output overflow, credential/config failure,
  transcript persistence failure, or an action outside the compiled
  affordance returns a redacted `Diagnostic` in a failed `ApplyResult`. It is
  not degraded lab readiness, a successful episode with a warning, or a raw
  adapter exception.
- The current `kali-victim-ssh-probe` default action remains, at most, a narrow
  smoke action. It is not a fallback for bounded-participant-agency validation,
  and its `codex-cli` provenance must not appear there. The legacy scenario
  binding's `command.argv` may describe a legacy backend smoke affordance; it
  cannot be silently executed and relabeled as a coding agent's decision.
- The checked-in bounded-participant-agency research freeze includes logical
  participant-observation and evaluator-evidence datasets. APTL realizes those
  datasets as typed append-only run-store placements; it does not seed them
  into participant containers or reinterpret them as files. Scenario planning
  and realization fail closed if either dataset, any authored file, or any of
  the 26 action targets lacks a truthful realization.

## Existing Adapter Boundary And Extensibility Seam

The installed-agent seam already exists at `ManagedAgentAdapter`. Extend its
production assembly rather than introducing another provider abstraction.
`WorkbenchRuntime` and `ProfileLaunch` remain coarse interactive-profile
lifecycle concepts; they must not be treated as the SDL action authority merely
to reuse the adapter. A participant-runtime invocation is sealed from:

`(participant_address, behavior_specification_address, decision_surface_ref or assigned-action basis, action_contract_address, argument_shape_ref, governed_arguments, observation_boundary_address, implementation_manifest, implementation_selection, compiled affordance refs, permitted visible/disclosed/evidence refs, realization details, episode_id, operation_id, request_fingerprint, timeout and output limits)`.

The adapter receives the minimal disclosure-derived task on stdin and returns a
strict result that can be validated as the applicable RAES
`ParticipantDecisionSurfaceSelectionV2Model`. The trusted realization, not the
provider, constructs the terminal `ParticipantActionResultModel`.
It does not receive an arbitrary scenario file, shell command, environment
mapping, host working directory, evidence directory, or backend handle.

Claude Code and Codex CLI use this same seam. A closed, code-owned provider
mapping selects the injected `ManagedAgentAdapter`, executable policy,
provider-specific credential alias, manifest identity, and non-secret
configuration digest. The shared credential broker leases only the selected
provider's alias. A further provider adds one adapter and mapping; it does not
add a scenario-name branch, dynamic entry-point loader, new RAES DTO,
credential broker, or changes to deployment/control-plane plumbing. Provider
CLI flags remain inside the adapter.

A workbench profile remains a coarse participant UX compartment. The SDL
driver needs an action-scoped capability set derived from the compiled
affordance. It must not launch the full `red` profile merely because the
participant role is red, and it must not expose `kali_run_command`, every
profile tool, or a provider's built-in shell/file tools when the declared
action needs a narrower surface. The coding agent may select or request a
declared action; APTL alone resolves the realized target and performs the
allowlisted typed deployment/MCP operation.

## Cross-Cutting Layers And Canonical Incumbents

| Layer | Required owner and guardrail |
| --- | --- |
| Appliance identity, placement, and egress | ADR-049, `ApplianceBoundaryPolicy`, `ApplianceBoundaryBinding`, `run_appliance_boundary_gate()`, and the exact-authority egress proxy own the supported OS/network boundary. The agent and MCPs run in guest management; model traffic reaches only signed exact authorities. The physical host is not in the agent-to-MCP-to-lab path. |
| SDL, compiled model, and realization | `parse_sdl_file`, `RuntimeManager.plan()`, the admitted `ExecutionPlan`, `ParticipantPlanAuthority`, `interpret_provisioning_plan()`, `validate_participant_realizations()`, `BPA_ACTION_REALIZATIONS`, and the RAES participant compiler and argument resolver are the only parse/compile/lowering path. `scenarios/bounded-participant-agency-techvault.sdl.yaml` is the APTL copy of the research freeze selected by the validation runbook. The privileged registry requires both its approved source identity and the SHA-256 of the complete, versioned `aptl.raes-runtime-model-artifact/v1` RFC 8785 artifact; a reused scenario name grants nothing. Unsupported compiled values fail canonicalization instead of being stringified. Blocking planner diagnostics are an admission gate, not warnings. |
| RAES participant contracts | `BaseParticipantRuntime`, `ParticipantNativeActionExecution`, `ParticipantActionApplyResult`, `ParticipantActionAdmissionRequest`, `participant_action_admission_request_violations()`, `participant_action_binding_events()`, `participant_behavior_event_payload()`, `project_participant_decision_surface_v2()`, `deliver_participant_decision_surface_v2()`, `bind_participant_decision_surface_selection_v2()`, `resolve_participant_action_arguments()`, RAES behavior/episode snapshot validators, and `RuntimeControlPlane` own portable lifecycle, exact-cut projection, delivery, request, selection, event, validation, commit, and operation shapes. |
| Runtime lifecycle | `BaseParticipantRuntime.initialize()` and `admit_action()` remain distinct; APTL supplies native realization through `_model_action()`. Episode lifecycle is not workbench profile, Compose, scenario, or appliance lifecycle. The RAES base snapshot projection supersedes APTL's duplicate lifecycle storage helpers. |
| Installed-agent execution | `ManagedAgentAdapter`, `ClaudeCodeManagedAgentAdapter`, `_admitted_executable()`, `_read_private_config()`, `_assert_config_unchanged()`, `BoundedProcessRunner`, and the applicable `WorkbenchRuntime` lifecycle/locking patterns own executable admission, strict config, exact tool inventory, no-shell execution, process-group teardown, and single-active-launch cleanup. Ownership and mode admission precedes every executable invocation, including version discovery; version discovery receives a fixed credential-free environment. `ProfileLaunch` and `ProfileId` do not grant action authority. |
| Configuration | Signed appliance settings and `ApplianceWorkbenchSettings` own trusted executable/payload paths in supported delivery. A closed implementation registry owns provider id, executable setting, required secret aliases, manifest, and limits. Durable developer-local non-secret settings, if required, pass through strict `AptlConfig` / Pydantic validation under ADR-025. None of these shapes may accept free-form command/args, environment maps, prompts, tokens, arbitrary tool lists, arbitrary URLs, or `PATH`-selected executables. |
| Environment and secrets | `EphemeralCredentialBroker`, `contains_placeholder()`, ADR-029, and appliance bootstrap own the model/service credential lease. Existing lab secrets continue through `load_dotenv()`, `env_vars_from_dict()`, and `find_placeholder_env_values()`; do not widen Wazuh-oriented `EnvVars` into agent config. The child receives a minimal explicit lease, never APTL/SOC ambient environment. |
| Host process and filesystem exposure | Reuse the workbench's absolute resolved executable checks, owner/mode checks, private `0700` work directory, no-follow bounded `0600` config reads/writes, fixed argv, stdin task input, combined output cap, and whole-process-group timeout teardown. A fixed minimal child `PATH` is acceptable; `PATH` must never select the coding-agent executable. |
| Deployment and MCP surfaces | `DeploymentBackend` remains the owner of container operations. Resolve targets only from `AptlRealization`, then verify project membership with `container_exists()` before any typed action. Approved MCP paths retain `aptl-mcp-common` JSON Schemas, handler assertions, exact `tools/list` verification, endpoint-origin/TLS checks, SSH lifecycle, telemetry, capture, and redaction. No adapter calls raw Docker, Compose, SSH, curl, or an unscoped container. |
| Visibility and evaluator separation | The compiled RAES observation boundary and implementation exposure policy are the source of visible/disclosed/evidence refs. `project_for_participant()` is the evidence-side incumbent. Wazuh records, evaluator diagnostics, internal endpoint identities, negative checks, backend commands, and implementation internals stay evaluator/control-plane-only unless the compiled boundary explicitly projects them. |
| Logging, diagnostics, and errors | Use `AgentExecutionError` / `WorkbenchStateError` only inside the existing agent boundary, then translate to `participant_action_diagnostic()`, `ApplyResult`, RAES operation status, `render_aces_diagnostics()`, and `LabResult` at their existing boundaries. Use `get_logger()` and `redact()`; do not add another readiness taxonomy or exception family. |
| Persistence and evidence | Reuse the active `ScenarioSession` trace id, `RunStorageBackend`, workbench event correlation, evidence coordinator/content store, RAES evidence records, and evidence visibility projection. After RAES commit, `LocalRunStore.create_run_json_once()` atomically publishes one immutable participant/evaluator action-evidence transaction; `append_jsonl()` publishes recoverable participant and evaluator projections. A projection failure cannot invalidate the accepted RAES transition, but it is diagnosed and fails readiness. Agent output never uses opaque `write_file()`, `copy_file()`, or direct `Path.write_text()` as its first persistence boundary. |
| API and CLI ingress | This issue adds no provider-registration, arbitrary-agent execution, or operator-terminal API. If an ingress is later required, the participant workbench remains a separate authenticated route assembly using a strict `extra="forbid"` body and a configured provider id; it never reuses the operator bearer/terminal routes, query-string secrets, or arbitrary command fields. |

The synthetic TechVault web surface is deliberately an unauthenticated
plain-HTTP service inside the isolated lab network. Its typed realization pins
the container-local origin, forbids redirects and any protocol other than
HTTP, and sends no credential material; it is not an external or management
transport. Episode working state lives under a private `/run/aptl` hierarchy
created with a restrictive umask, never in a publicly writable temporary
directory.

## Security, Reliability, And Evidence Rules

- Validate the RAES manifest, selection, exposure policy, compiled behavior,
  decision surface and selection when applicable, action/boundary assignment,
  and admission request before agent or backend side effects. Governed
  arguments must first match the compiled action address and content-hashed
  `argument_shape_ref`. Then apply APTL policy: the
  implementation mapping is allowlisted,
  executable/config identity is safe, MCP inventory is exact, numeric limits
  are positive and capped, and every realized target belongs to the active
  deployment project. RAES validation does not waive appliance, process, MCP,
  or backend policy.
- A decision surface must enumerate every finite semantic value and
  cardinality combination admitted by each compiled argument definition.
  A distinct proposal identity binds each complete argument map. Infinite or
  excessively large domains fail closed; selecting the first allowed value or
  minimum cardinality is not a valid nondeterministic surface.
- Validate signed appliance identity and boundary policy before accepting a
  supported live invocation. The management-to-egress crossing and exact model
  provider authority must be present; a proxy environment variable or a coding
  agent's own URL setting is not egress authorization.
- Keep task input minimal and disclosure-derived. It may name the selected
  participant, task brief, and declared affordance, but not Wazuh evidence,
  evaluator interpretation, withheld refs, raw configuration, credentials,
  hidden target topology, backend commands, or an unbounded script.
- Treat provider output as hostile. Apply the combined byte limit before
  parsing, require the provider's strict outer JSON envelope, then validate a
  selection through the RAES decision-surface binder or validate the semantic
  result with RAES models and compiled address/ref membership. A terminal
  `ParticipantActionResultModel` is constructed or corroborated by the trusted
  typed APTL realization and readback. Free text, self-reported provider
  identity, tool names, targets, evidence paths, or success claims are not
  authority.
- Each native handler must operate on its contract-specific synthetic
  resource and use a separate readback of the affected semantic fields.
  Generic process success, a shared opaque state carrier, or the contract's
  own declaration is not proof that a precondition or effect occurred.
  Every governed dimension must change that operation or its selected
  readback, including identity, credential-candidate, field-set, alert,
  event-limit, endpoint, method, classification, and response choices.
  Evidence is staged during native execution and published only after the
  RAES base runtime accepts the typed outcome and history transition.
- Model and service credentials use the existing ephemeral, selected lease.
  They never enter argv, stdin task content, SDL, MCP config values, proof JSON,
  logs, diagnostics, snapshots, transcripts, or evidence. Because the current
  adapter uses a child environment, the management compartment must prevent
  participant/sibling process inspection; teardown clears the in-memory lease
  and generated config. Prefer a provider-supported descriptor/file/keychain
  channel later without changing the shared adapter contract.
- The adapter transcript is a structured invocation lifecycle record, not a
  chat transcript or reasoning archive. Persist provider/selection identity,
  manifest/configuration digest, invocation/result hashes, approved affordance
  and compiled addresses, timestamps, exit/timeout/limit status, bounded
  redacted excerpts only when necessary, and the operation/evidence reference.
  Never collect hidden chain-of-thought, raw prompts/completions, raw tool
  transcripts, inherited environment, or binary output.
  `APTL_EXPERIMENT_NO_REDACT` does not weaken this control-plane artifact.
- If the transcript is cited as action/evaluator evidence, route it through the
  existing evidence coordinator/content store and RAES evidence record
  projection. Storage authorization never grants participant visibility. Only
  the compiled observation boundary may authorize its reference in
  `visible_refs` or `disclosed_refs`.
- Pre-side-effect validation failure leaves the baseline runtime snapshot
  unchanged. Once an external action has started, failures are not falsely
  rolled back. A timeout or malformed native response before RAES commit
  produces a failed operation and no admitted success event. After RAES has
  accepted the native outcome and history transition, archival failure cannot
  roll that transition back: the operation retains the accepted snapshot,
  carries an explicit publication diagnostic, and fails qualification until
  the evidence projection is complete. Do not claim atomicity across an
  irreversible external action.
- Use a deterministic request fingerprint over the sealed non-secret envelope
  and the existing control-plane idempotency key. Retrying the same submitted
  operation reuses its receipt/status; it must not launch a second agent turn or
  duplicate the backend action. A new operation after an uncertain external
  side effect must remain explicit rather than silently retrying.
- Successful results pass the RAES backend-call snapshot gates and participant
  episode/behavior/shared-state validators before they become the control-plane
  snapshot. A coding-agent exit code, prose answer, tool call, backend return
  code, or Wazuh alert alone is not proof.
- `behavior_mode: autonomous` in the authored behavior specification is not the
  RAES `autonomous_execution` scheduler policy or a backend capability claim.
  This issue does not enable the shared-clock scheduler, advertise autonomous
  limits, or synthesize time/cadence policy merely because the word
  "autonomous" appears in the behavior.

## Verification Contract

- Fake-agent tests use the existing `ManagedAgentAdapter` and `ProcessRunner`
  seams and exercise APTL through `BaseParticipantRuntime`. They prove
  implementation-selection mapping, exact argv, no shell, stdin task transfer,
  minimal provider-specific credential environment, exact action-scoped tool
  inventory, timeout/process-group cleanup, combined output bounds, config
  tamper rejection, redaction, idempotent replay, failed operation status, and
  manifest/selection/decision-surface/address/exposure mismatch cases.
- Successful fake execution produces `ParticipantNativeActionExecution` with a
  RAES `ParticipantActionResultModel`, goes through `RuntimeControlPlane` and
  `BaseParticipantRuntime.admit_action()`, and passes all participant snapshot
  validators. Failure tests prove no successful behavior event,
  participant-visible evidence, or shared-state mutation is fabricated.
- The live opt-in readiness validation runs the selected installed
  implementation against `bounded-participant-agency-techvault` through the
  public RAES control-plane path using the exact admitted plan. It records
  implementation provenance, transcript/evidence reference, compiled
  participant/behavior/action/boundary addresses, governed arguments,
  lifecycle phases, and bounded participant observation. It does not use the
  TechVault SSH smoke path or recreate a default-only runtime target after
  scenario start.
- `aptl lab participant-readiness --suite` is the canonical pre-capture gate.
  It exercises the authored-order positive paths across all nine behaviors,
  covers every compiled action, and executes boundary challenges BC-01 through
  BC-10 with structured no-effect evidence. Passing it never starts official
  capture. Adding `--provider claude` or `--provider codex` also runs bounded
  installed-provider green, red, and blue episodes; the provider-specific
  credential lease remains mandatory.
- The live proof asserts evaluator-only Wazuh and negative-boundary material is
  absent from agent input and the participant projection. Evaluator evidence
  may be checked independently, but does not prove the participant observed it.
- The APTL and second-backend validations use the same authored scenario and
  portable RAES contract assertions. Provider- or backend-specific transcript
  details remain additional evidence, not a forked success definition.

## Whole-Repository Scope

Implementation must reconcile these existing surfaces rather than work only in
the participant runtime file:

- `scenarios/bounded-participant-agency-techvault.sdl.yaml`,
  `src/aptl/backends/raes.py`, `raes_participant_apparatus.py`,
  `raes_participant_driver.py`, `raes_participant_fixture.py`,
  `raes_participant_provider.py`, `raes_participant_realizations.py`,
  `raes_participant_runtime.py`, `raes_manifest.py`, and
  `src/aptl/validation/participant_live_proof.py`;
- `src/aptl/workbench/{agent,process,runtime,profiles,credentials,bootstrap}.py`
  and, only if ingress changes, the separate participant `app.py`;
- `src/aptl/core/{appliance_boundary,appliance_boundary_gate,config,env,runstore,session}.py`,
  `src/aptl/core/deployment/`, `src/aptl/core/evidence/`,
  `src/aptl/utils/{pathsafe,redaction,logging}.py`, and the appliance egress
  proxy;
- `mcp/aptl-mcp-common/` and only the action-scoped MCP servers selected by
  the compiled affordance; changing common requires every dependent MCP to
  rebuild and test;
- the RAES/backend, bounded-participant-agency scenario (including its
  source/compiled freeze hashes and zero-blocking-diagnostics gate),
  participant live-proof, workbench, redaction, runstore/evidence,
  appliance-boundary, MCP, and opt-in live test suites, plus the repository
  completion commands in `.ground-control.yaml`.

## Gotchas And Anti-Patterns

- Do not create a second installed-agent abstraction beside
  `ManagedAgentAdapter`, a second subprocess runner beside
  `BoundedProcessRunner`, or a second credential broker beside
  `EphemeralCredentialBroker`.
- Do not keep APTL's hand-written participant lifecycle/behavior commit path
  beside `BaseParticipantRuntime`, and do not bypass its native-outcome checks
  by appending events after an agent turn.
- Do not equate `ProfileId.RED`, an SDL participant role, a RAES participant
  address, and a participant implementation selection.
- Do not expose a whole workbench profile when one compiled action is the
  authority, and do not rely on prompt instructions or a client-side tool
  filter to enforce an affordance.
- Do not paste a coding-agent name into `actor_provenance` while
  `container_exec()` still performs a fixed precursor command.
- Do not use the legacy fixed-probe runtime-binding command as the
  bounded-participant-agency action realization, and do not promote
  `participant_action_specs_from_runtime_model()` into a second registry beside
  `BPA_ACTION_REALIZATIONS`.
- Do not hand the agent a prompt-rendered action list and parse free-form text
  as authority when RAES decision-surface projection and selection binding are
  applicable.
- Do not derive provider identity from `PATH`, version banners, hostnames,
  ambient environment, free-form self-report, or a scenario name.
- Do not let a provider choose an executable, MCP config, container, command,
  timeout, network endpoint, evidence path, run id, or observation visibility.
- Do not assume `DeploymentBackend.container_exec()` performs a project
  membership check; validate the realized target and `container_exists()`
  before the typed operation.
- Do not make direct `Path.write_text()` proof output, an unredacted provider
  transcript, `0600` permissions, or a guest VM name substitute for the
  runstore/evidence/redaction/appliance gates.
- Do not call `admit_action()` after a failed invocation to make the proof look
  complete, create another action-operation protocol, or report a failed agent
  turn as successful episode initialization.
- Do not duplicate RAES schema/snapshot validation, behavior events,
  exception/readiness hierarchies, redaction helpers, evidence records, run
  archives, correlation ids, workflow loops, or Compose/Docker logic.
- Do not make Wazuh availability, evaluator evidence, internal endpoints, or a
  negative-boundary check participant-visible because it helps verification.
- Do not register `/var/ossec/etc` as a generic scenario-content destination.
  Wazuh configuration remains management-owned; the bounded scenario's
  defender node is realized independently and logical evidence datasets stay
  in the run store.
- Do not use a physical-host agent run as the supported participant-boundary
  proof after ADR-049.
- Do not ignore the bounded scenario's dataset planner diagnostics, expand the
  backend manifest from red to green/blue without implemented proof, or claim
  RAES autonomous-execution support from `behavior_mode: autonomous`.

## Non-Goals And Boundaries

This issue does not add a general agent framework, plugin marketplace, dynamic
provider discovery, host-shell API, arbitrary MCP bridge, prompt/reasoning
archive, model benchmark, multi-agent coordination, scheduler, new RAES SDL
schema, new backend capability claim, participant-profile schema, participant
UI redesign, operator API route, Wazuh participant observation, or a redesign
of deployment, evidence acquisition, run storage, authentication, appliance
delivery, or the TechVault curated live gate. It does not install coding agents
on the physical host or make workbench profile lifecycle a RAES episode
lifecycle. It leaves the legacy smoke action available only as a smoke test and
prevents it from standing in for the governed participant proof. It does not
enable RAES shared-clock autonomous execution or broaden APTL beyond the
participant roles and behavior features it truthfully implements.
