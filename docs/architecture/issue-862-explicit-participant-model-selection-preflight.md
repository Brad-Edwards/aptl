# Issue #862 Explicit Participant Model Selection Preflight

This note fixes the architecture boundaries for explicit model selection by
installed participant providers. It is design guidance, not an implementation
plan. No new ADR is needed: ADR-025 owns strict first-party configuration,
ADR-029 owns secret handling, ADR-032 and ADR-033 own participant isolation and
reasoning-capture boundaries, ADR-044 owns reproducibility records, and the
issue-557 and issue-858 preflights own installed-provider execution and choice
transport.

## Architecture decisions

- Treat the selected `(provider, model)` pair as non-secret participant
  apparatus configuration. It is not a scenario value, RAES action argument,
  credential, prompt instruction, participant response, executable identity,
  workbench profile, or deployment provider.
- The canonical durable authority is a strict nested field under
  `AptlConfig.experiment`. It has the same provider-neutral meaning for every
  installed provider: one provider key selects one bounded, canonical model
  identifier. A selected installed provider with no admitted model fails
  closed. The deterministic fixture does not have a model and remains exempt.
- Do not give model selection a CLI flag, environment override, user-config
  fallback, scenario extension, or prompt field. The CLI may select the closed
  provider id; the already validated APTL configuration selects its model.
  Checked-in or study-specific `aptl.json` can therefore freeze the non-secret
  identity while credentials remain outside study records.
- Validate in two stages. Strict Pydantic validation owns shape, length,
  character, provider-key, and explicitness checks. The provider mapping also
  rejects product defaults, empty/default/latest sentinels, and rolling aliases
  that do not name the frozen provider model required by the protocol. Only a
  bounded real provider request with the selected credential can prove that the
  leased API project may access that model. Unsupported or inaccessible models
  fail that request without fallback or a second model attempt.
- Carry the admitted model through the existing sealed `AgentLaunch` boundary.
  Every model-bearing invocation through `ManagedAgentAdapter`, including both
  decision-only and profile launches, must receive an explicit admitted model.
  `DecisionAgentLaunch` and `ProfileLaunch` must not leave an interactive
  Claude path that can still inherit a product default. Production appliance
  assembly may transport the already admitted value through
  `ApplianceWorkbenchSettings`; it must not introduce a second default or
  configuration authority.
- Provider-specific launch mechanics remain inside the existing adapters.
  Claude Code and Codex CLI both receive their explicit model through their
  native `--model` argument. Claude retains `--bare`, no session persistence,
  and no fallback model. Codex retains `--ignore-user-config`,
  `--ignore-rules`, strict config, ephemeral read-only execution, and all
  current feature disables. Model configuration supplies only the model
  argument; it cannot supply arbitrary argv, profiles, tools, feature flags,
  endpoints, environment variables, or fallback policy.
- Keep three identities distinct:
  1. the installed provider and requested model;
  2. the admitted CLI adapter implementation name and discovered CLI version;
  3. the RAES participant implementation manifest and selection.

  Do not encode the model into `implementation_name`,
  `implementation_version`, actor provenance, or the CLI version. The RAES
  `ParticipantImplementationSelectionModel.configuration_ref` and
  `configuration_digest` pin the admitted non-secret provider/model
  configuration; the existing manifest ref/digest continues to identify the
  implementation contract.
- Use one provider-neutral provenance projection: `provider`, `model`,
  configuration ref/digest, CLI implementation identity/version, and RAES
  manifest/selection refs. Extend the existing participant control and
  readiness/qualification records at their canonical builders. Do not create a
  parallel model-provenance DTO or provider-specific fields such as
  `claude_model` and `codex_model`.
- The configuration digest covers a versioned, canonical, secret-free
  projection of the selected provider and exact model, using the repository's
  existing RFC 8785/SHA-256 pattern. It never covers a token, ambient
  environment, project credential, raw config file, or provider error.
  Configuration ref/digest must be attached before the apparatus is projected
  or a selection is solicited.
- Evidence must survive turn-zero failure. A readiness report for missing,
  malformed, unsupported, or inaccessible model selection records the selected
  provider and admitted model identity when one exists, plus a stable redacted
  failure classification. Successful per-turn control evidence also records
  the same pair and the RAES configuration ref/digest. The root qualification
  report carries the pair used for all installed green/red/blue children.
- Amend or version the existing readiness, qualification, and control-evidence
  schemas once at their current serialization owners. Do not silently change a
  published `v1` meaning in one writer while leaving tests, renderers, or other
  consumers on the old contract.

## Canonical incumbents to reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| First-party apparatus configuration | `ExperimentSettings`, `AptlConfig`, `load_config()`, `resolve_config_for_cli()`, ADR-025, and `tests/test_config.py`. Keep `extra="forbid"` and strict scalar validation; do not add a pass-through provider options dictionary. |
| Closed provider selection | `build_selection_provider()`, `_launch_adapter()`, `installed_version()`, and the existing provider/credential mapping in `participant_readiness_provider.py`. Add the admitted model as a parameter at this seam rather than creating dynamic provider discovery or a plugin registry. |
| Sealed adapter handoff | `AgentLaunch`, `DecisionAgentLaunch`, `ProfileLaunch`, and `ManagedAgentAdapter` in `workbench/runtime.py`. These are the existing secret-free handoff and provider-neutral launch protocol. |
| Provider mechanics | `ClaudeCodeManagedAgentAdapter` and `CodexManagedAgentAdapter` own exact argv and result parsing. `_admitted_executable()`, `_prepare_work_dir()`, private config checks, and `BoundedProcessRunner` remain unchanged authorities for executable, filesystem, timeout, output, and process-group safety. |
| Credentials and environment | `EphemeralCredentialBroker`, `contains_placeholder()`, the adapters' minimal base environments, and ADR-029. Lease only `ANTHROPIC_API_KEY` or `CODEX_API_KEY` for the selected provider; model identity is configuration, not a credential alias. |
| RAES participant provenance | `build_participant_apparatus()`, `ParticipantApparatus`, RAES `ParticipantImplementationManifestModel`, `ParticipantImplementationSelectionModel`, `canonical_contract_digest()`, and the existing apparatus projection/binder. Use selection configuration ref/digest rather than a local RAES mirror. |
| Decision-only enforcement | `ManagedAgentSelectionProvider`, `ParticipantDecisionSolicitation`, compact-choice parsing, `AptlParticipantRuntime.solicit_selection()`, exact delivered-candidate membership, and RAES admission. Explicit model selection does not alter any of these authorities. |
| Control evidence | `ParticipantControlEvidence`, `_control_evidence_payload()`, `solicitation_fingerprint()`, and `persist_control_evidence()`. Add provider/model configuration identity here for successful and failed solicitations; retain the full delivered solicitation fingerprint. |
| Readiness and qualification evidence | `ParticipantReadinessRequest`, `ParticipantReadinessReport`, `ParticipantQualificationReport`, `validate_participant_agency_readiness()`, `validate_participant_agency_qualification()`, and their existing run-store writers/renderers. These own pre-capture failure and green/red/blue qualification evidence. |
| Persistence and redaction | `RunStorageBackend`, `LocalRunStore` JSON/JSONL methods, `redact()`, `is_sensitive_key()`, `is_secret_shaped_value()`, and ADR-044. Provider/model identity is intentionally reproducible and non-secret; credentials and raw provider diagnostics remain excluded. |
| Diagnostics and logging | `AgentExecutionError` inside the adapter boundary, existing readiness failure reports, RAES `Diagnostic`/operation status, `get_logger()`, and shared redaction. Enrich the existing translation with stable model-selection classifications; do not add another exception hierarchy or readiness taxonomy. |
| Verification workflow | `tests/test_config.py`, `tests/test_participant_workbench_adapter.py`, `tests/test_bounded_participant_runtime.py`, participant CLI tests, and `docs/raes/bounded-participant-agency-readiness.md`. Extend these existing seams and the canonical pre-capture suite. |

## Security and cross-cutting passage

| Layer | Required behavior |
| --- | --- |
| Auth and ingress | The existing CLI/config-loading boundary remains the only new operator path; this issue adds no API route. The participant cannot submit provider or model fields. If a future API exposes this setting, it must use existing authenticated config DTO conventions and the same strict `AptlConfig` validator rather than a second request-only schema. |
| Strict config shape | `load_config()` validates the complete `aptl.json` into strict nested Pydantic models. Unknown providers/options, coercible non-strings, blank or oversized ids, control characters, product-default sentinels, and prohibited rolling aliases fail before process launch. Absence is allowed only while no installed provider is selected; selection makes it fatal. |
| Provider boundary | The closed provider mapping resolves exactly one model and one credential alias. The adapter defensively verifies that `launch.provider` matches its own provider and that an admitted model is present. A model string never selects another provider, local/OSS mode, base URL, profile, or credential source. |
| RAES shape and apparatus binding | Build the existing manifest and selection only after model configuration admission. RAES model validation checks the manifest/selection shape, and selection configuration ref/digest binds the exact provider/model configuration to the same participant, exposure policy, decision surface, and run. Model choice grants no action or observation authority. |
| Secret and environment binding | Credentials continue through `EphemeralCredentialBroker` and placeholder checks into a minimal explicit child environment. Do not inherit project/user/provider environment wholesale. Do not place credentials, organization/project ids, or secret-derived digests in model configuration or evidence. |
| OS/process exposure | The exact model id is intentionally non-secret and may appear in process argv. Credentials remain absent from argv, prompt stdin, paths, and URLs. Existing absolute executable ownership/mode checks, private work directories, no-shell invocation, bounded output, timeout, and whole-process-group teardown remain mandatory. Version discovery remains credential-free and does not consult the selected model. |
| User/product configuration isolation | Codex must continue using its private `CODEX_HOME` plus `--ignore-user-config`; Claude must continue using `--bare` and explicit tool/settings restrictions. The explicit `--model` is additive to these isolation flags, not a replacement for them. Neither adapter may consult a CLI profile, user setting, project rule, or product default to fill a missing model. |
| Decision-only compartment | Model selection is orthogonal to tool authority. Keep Codex feature disables, read-only sandbox, empty tool inventory, Claude `--tools ""`, no MCP config for decision launches, compact selection parsing, exact candidate resolution, and RAES admission unchanged. For each solicitation, both adapters bind the same exact provider-native schema: one integer `candidate` bounded from zero through the final alias in that delivered candidate set, with no additional properties. Codex receives each distinct range schema from a create-once `0600` file inside its private run directory. The parser and exact-candidate resolver independently enforce the same bounds after generation. A model id cannot add tools, MCP servers, shell access, filesystem writes, browsing, subagents, or native action authority. |
| Provider output and errors | Treat stdout/stderr and JSON events as hostile and bounded. Adapters may classify known provider model-not-found/access-denied failures into stable secret-free messages, but must not persist or echo raw stderr, response bodies, request ids, account/project details, stack traces, or provider output. Unknown failures retain the existing generic failure. Apply `redact()` before any diagnostic crosses the adapter boundary. |
| Accessibility validation | Do not add a raw HTTP model-list/probe path or duplicate provider client. The first bounded, tool-disabled provider request and the live green/red/blue qualification are the accessibility proof for the exact credential lease and model. Failure is terminal for that configured pair; no implicit fallback, alias resolution, or retry with another model is allowed. |
| Persistence and evidence | Existing run-store path containment and JSON/JSONL redaction remain the only persistence boundary. Record provider, exact model, configuration ref/digest, CLI version, RAES manifest/selection refs, outcome, and `official_capture_started: false`. Never record credentials, ambient configuration, raw prompt/completion, or raw provider diagnostics. |
| Error envelope | Missing/malformed selection is a deterministic configuration failure; unsupported/inaccessible selection is an installed-provider failure. Both use the existing readiness/control failure envelopes with stable classifications and non-secret provider/model identity. They are not degraded lab readiness, successful episodes with warnings, or RAES action failures. |

## Extensibility seam

The seam remains the existing installed-provider construction and launch
boundary:

```text
(provider_id, model_id, configuration_ref, configuration_digest,
 executable, credential_alias, adapter_factory)
```

The provider-neutral fields flow through `AgentLaunch`, participant apparatus,
control evidence, and readiness evidence. The adapter factory alone translates
them to provider-native argv and provider-native safe error classification.
Adding the next installed provider should require one strict config entry, one
closed provider mapping entry, and one adapter implementation; it must not
require changes to RAES decision surfaces, action realizations, candidate
transport, credential brokerage, run-store layout, or the provider-neutral
evidence fields.

Do not generalize this seam into arbitrary command/argv/environment
configuration. Provider registration remains code-owned and closed.

## Whole-repository surface in scope

- `src/aptl/core/config.py`, `src/aptl/cli/_common.py`, and
  `src/aptl/cli/participant_readiness.py`;
- `src/aptl/validation/participant_readiness_provider.py`,
  `participant_readiness_models.py`, `participant_agency_readiness.py`,
  `participant_qualification_models.py`, and
  `participant_agency_qualification.py`;
- `src/aptl/workbench/runtime.py`, `agent.py`, `codex_agent.py`,
  `credentials.py`, `process.py`, and `bootstrap.py`;
- `src/aptl/backends/raes_participant_provider.py`,
  `raes_participant_apparatus_models.py`, `raes_participant_apparatus.py`,
  `raes_participant_control_evidence.py`, `raes_participant_driver.py`, and
  `raes_participant_runtime.py`;
- `src/aptl/core/runstore.py`, `src/aptl/utils/redaction.py`, and
  `src/aptl/utils/logging.py`;
- checked-in and participant-profile `aptl.json` examples that intentionally
  freeze an installed model, plus signed appliance workbench assembly where it
  launches an installed participant;
- the config, CLI, workbench-adapter, bounded-participant runtime,
  readiness/qualification, redaction, and run-store tests; and
- `docs/raes/bounded-participant-agency-readiness.md`, which must show
  non-secret model selection/freeze separately from credential setup and retain
  official capture disabled.

No deployment backend, Compose topology, MCP server, web frontend, scenario
SDL, or RAES action-envelope expansion is in scope.

## Live qualification obligations discovered after preflight

The explicit-model implementation made the installed Codex qualification
executable end to end. That live run exposed two incumbent defects which must
be repaired before issue 862 can truthfully satisfy its live acceptance gate:

- the projection offered actions whose declared successful-observation
  prerequisites did not yet hold at the exact episode state cut, including a
  repeat sign-out without a fresh authentication; and
- the native HTTP probe realization encoded `HEAD` as a generic custom method
  instead of the provider's dedicated head-only operation.

The subsequent immutable-model qualification also showed that a pinned model
can obey the bounded decision protocol only if its provider-native structured
output constraint is explicit and reflects the current candidate count.
Codex therefore receives the same exact compact, range-bounded selection schema
as Claude through `--output-schema`; each distinct schema is sealed as a
private create-once file and adds no participant capability. Provider-native
generation constraints do not replace APTL's independent parser, range check,
exact candidate resolution, or RAES admission. Provider access errors may
appear in nested Codex JSONL error items, so classification inspects both
top-level and nested messages but emits only the same stable secret-free
diagnostic.

These repairs do not let model selection change the RAES action envelope,
governed arguments, tools, or authority. Candidate projection filters the
already-declared actions by the same prerequisite relation enforced again at
realization admission. The HTTP repair makes the existing declared `HEAD`
choice match its native semantics. The boundary suite uses an ineligible
`TRACE` mutation to retain proof that a governed method cannot be replaced by
an out-of-surface value.

The affected incumbent owners are
`raes_participant_candidates.py`, `raes_participant_projection.py`,
`raes_participant_realizations.py`,
`raes_participant_realization_execution.py`, and
`participant_qualification_boundaries.py`. These are implementation
obligations discovered by the required live gate, not a redesign of the model
selection seam.

## Gotchas and anti-patterns

- Do not fix Codex alone. Claude Code and Codex must consume the same admitted
  provider/model provenance contract even though their flags and result
  envelopes differ.
- Do not leave `ProfileLaunch` or appliance workbench assembly as a
  default-inheriting escape hatch while fixing only `DecisionAgentLaunch`.
- Do not accept `--model` on the readiness CLI, `MODEL` in the environment,
  provider output, prompt text, a scenario extension, or user CLI
  configuration as apparatus authority.
- Do not use aliases such as `default`, `latest`, a product family nickname, or
  an omitted value when the research protocol requires a frozen model
  identity.
- Do not enable Claude fallback models, retry Codex with its product default,
  or treat a different accessible model as equivalent after failure.
- Do not encode model identity into implementation name/version, actor
  provenance, provider executable version, workbench profile, or RAES action
  address. Those concepts have different owners and lifecycles.
- Do not add provider-specific model fields to every report. Persist the one
  provider-neutral pair and its configuration identity.
- Do not add a generic provider options mapping, free-form argv, configuration
  profile, base URL, arbitrary credential alias, or tool list to
  `AptlConfig`. Explicit model selection must not become a general CLI
  pass-through.
- Do not validate access with `curl`, a new SDK client, an unbounded model-list
  request, or credentials in argv. Reuse the admitted adapter and bounded live
  qualification.
- Do not expose raw CLI stderr or JSON error events to make diagnostics useful.
  Classify known failures and otherwise preserve the existing generic,
  secret-free envelope.
- Do not hash credentials into a configuration digest or assume redaction after
  persistence repairs an unsafe record.
- Do not let model selection change prompt/candidate semantics, tool inventory,
  decision-only flags, RAES exposure policy, action envelope, native
  realization, or evidence visibility. State-qualifying an incumbent action
  against its declared prerequisite and correcting an incumbent realization
  to match its declared method are independent live-gate repairs documented
  above.
- Do not claim accessibility from config validation or a CLI version command.
  It is proved only by the exact credential/model request and the live
  qualification result.

## Non-goals and boundaries

This issue does not add model routing, fallback, benchmarking, automatic model
discovery, capability negotiation, price/budget selection, provider plugins,
local/OSS providers, arbitrary endpoints, new credential sources, or a general
participant configuration framework. It does not make model choice an EXP-005
factor, scenario variable, participant action, or participant-visible choice.

It does not redesign RAES manifests, decision surfaces, compact choice
transport, workbench tools, deployment, MCP, capture, run-store layout, API
authentication, or appliance egress policy. The limited incumbent
qualification repairs documented above align projection and realization with
the already-declared RAES semantics. It does not capture prompts, completions,
reasoning, or raw provider errors.

The live Codex green/red/blue qualification is an implementation acceptance
gate, not part of this architecture preflight. It must use an explicitly
selected accessible model and preserve `official_capture_started: false`.
