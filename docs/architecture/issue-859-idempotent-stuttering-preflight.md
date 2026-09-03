# Issue #859 Idempotent Stuttering Preflight

This note fixes the architecture guardrails for truthful idempotent
participant-action outcomes in bounded participant realizations. It is design
guidance, not an implementation plan. No new ADR is needed:
[ADR-029](../adrs/adr-029-control-plane-secret-handling.md),
[ADR-033](../adrs/adr-033-agent-reasoning-trace-boundary.md),
[ADR-044](../adrs/adr-044-raes-aligned-run-reproducibility-record.md),
[ADR-046](../adrs/adr-046-dynamic-raes-scenario-realization.md),
[ADR-049](../adrs/adr-049-sealed-disposable-lab-appliance.md), and the
existing participant preflights already own the relevant runtime, evidence,
secret, and appliance boundaries.

## Architecture Decisions

- Keep semantic truth in the verified native operation. The closed native
  handler remains the only owner of whether the requested postcondition was
  independently established. `VerifiedParticipantOperation.success`,
  `established_preconditions`, `established_effects`, `pre_state`,
  `post_state`, and `state_changed` remain the truth surface; digest inequality
  is evidence of mutation, not the success criterion.
- Keep mutation policy explicit and per realization. Extend the incumbent
  `ParticipantActionRealization` record so it separates `mutates_state` from
  `allows_idempotent_stutter`; that record is the correct seam. Do not infer
  stutter permission from provider identity, behavior name, scenario name,
  action text, or digest equality alone.
- Keep fail-closed mutation enforcement after semantic readback. A successful
  native observation may remain a terminal failure when the realization policy
  is contradicted: undeclared no-change mutations still fail closed for
  `mutates_state=True` plus `allows_idempotent_stutter=False`, and undeclared
  state changes still fail closed for `mutates_state=False`.
- Keep participant-visible authority unchanged. The participant still receives
  the same RAES-selected action surface and the same `ParticipantActionResult`
  semantics. Mutation-versus-stutter policy is evaluator/control evidence, not
  participant action authority.
- Keep truthful digests and history on permitted stutters. When a realization
  declares stuttering success and the postcondition is independently verified,
  the accepted record must preserve the real pre/post digests,
  `state_changed: false`, established preconditions/effects, and the existing
  portable attempted/transition/observation history sequence.
- Keep success/failure taxonomy incumbent. Failed postcondition verification,
  unmet prerequisites, unsupported arguments, malformed provider output, and
  backend failures continue to use the existing failure classes and RAES
  operation/evidence pathways. This issue does not add a new exception family,
  readiness state, or participant outcome category.

No ADR is needed. This change tightens the meaning of an existing realization
policy field and its evidence path; it does not change the durable product
architecture.

## Canonical Incumbents To Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| Per-action mutation policy | `src/aptl/backends/raes_participant_realizations.py` owns the closed realization registry, `ParticipantActionRealization`, and `mutates_state`. Add `allows_idempotent_stutter` there and keep policy declaration at that seam. |
| Semantic truth and readback | `src/aptl/backends/raes_participant_fixture_core.py` owns `VerifiedParticipantOperation`, canonical pre/post state digests, `state_changed`, and established precondition/effect reporting. Native handlers continue to prove effects by separate semantic readback, not by command success or declared intent. |
| Policy enforcement | `src/aptl/backends/raes_participant_realization_execution.py` owns `_enforce_mutation_claim()` and the conversion from verified native observation to accepted or rejected native execution. Keep the fail-closed contradiction check here rather than duplicating it in handlers, readiness, or qualification code. |
| RAES admission and history | `src/aptl/backends/raes_participant_runtime.py`, `src/aptl/backends/raes_participant_driver.py`, `BaseParticipantRuntime.admit_action()`, and `ParticipantNativeActionExecution` own the attempted/transition/observation commit path. Do not rebuild history logic for stutters. |
| Evidence and persistence | `src/aptl/backends/raes_participant_realization_execution.py`, `src/aptl/backends/raes_participant_evidence_publication.py`, `src/aptl/backends/raes_participant_control_evidence.py`, and `RunStorageBackend` own evaluator/participant records, immutable transaction publication, and recoverable JSONL projections. Reuse the existing evidence schemas; extend the incumbent action-evidence record only if additional mutation-policy disclosure is necessary. |
| Qualification/readiness | `src/aptl/validation/participant_agency_readiness.py`, `src/aptl/validation/participant_agency_qualification.py`, `src/aptl/validation/participant_readiness_provider.py`, and `tests/test_bounded_participant_runtime.py` own the end-to-end readiness and qualification contract. Reuse those suites instead of adding ad hoc probes or a parallel qualification harness. |
| Logging and diagnostics | Existing RAES `Diagnostic`, participant `failure_class`, `ApplyResult`, `OperationState`, `get_logger()`, and `redact()` remain the observability vocabulary. Do not create a second mutation-policy diagnostic format or exception hierarchy. |

Do not add a second mutation-policy DTO, a duplicate state-change validator, a
second evidence schema for semantic digests, another participant failure
taxonomy, or a behavior-name/provider-name branch that decides stutter policy.

## Security And Validation Passage

| Layer | Required behavior |
| --- | --- |
| RAES action admission and governed-argument validation | The action still enters through the existing exact-cut projection, delivered candidate, and RAES admission path. `resolve_participant_action_arguments()` and the existing binder remain the only governed-argument authority. This issue does not widen the action surface or add a bypass around RAES request validation. |
| Closed realization registry | Stutter permission is code-owned closed data in `BPA_ACTION_REALIZATIONS`. Keep it out of scenario names, provider config, prompt text, `.env`, CLI flags, run-store payload overrides, or participant-visible transport. |
| Native handler boundary | Handlers continue to receive only resolved governed arguments and realized targets. They may observe and mutate only the contract-specific synthetic state they already own. No new shell, Docker, SSH, network, or provider authority is introduced. |
| Semantic-state digest and readback shaping | The canonical digest remains `_mapping_digest()` over the verified pre/post state maps. Do not add a second digest algorithm, lossy projection, or synthetic “mutation token” to decide success. Exact pre/post state maps remain the source of the digest and of `state_changed`. |
| Error envelope and leakage | Contradictions between declared mutation policy and observed semantics still fail through existing `failure_class="backend_error"` and RAES operation diagnostics. Do not leak raw backend stderr, handler internals, provider output, hidden evaluator truth, or unredacted state payloads into participant-visible observations or diagnostics. |
| Persistence and evidence | Accepted stutters must persist the truthful digests, `state_changed: false`, established preconditions/effects, and the declared policy flags through the existing action transaction and evaluator projection. Rejected undeclared stutters still retain the existing failure path and must not be silently rewritten as success during publication or readiness summarization. |
| OS/process exposure | No new OS/process surface is needed. Existing private `/run/aptl` episode state, fixed argv, stdin prompt delivery, bounded child environment, and run-store write paths remain unchanged. This issue must not move semantic state, digests, or policy through argv, environment variables, or filenames. |

## Extensibility Seam

The seam belongs on the incumbent closed realization policy:

`(action_contract_address, operation, target_nodes, mutates_state, allows_idempotent_stutter, observer_kind)`

That is the next-change-friendly parameterization. If a future action needs a
stricter or richer mutation policy, extend this closed realization record and
keep `_enforce_mutation_claim()` as the single enforcement point. Do not
distribute policy across handlers, readiness heuristics, provider parsers, or
evidence post-processors.

## Whole-Repository Surface In Scope

- `src/aptl/backends/raes_participant_realizations.py`
- `src/aptl/backends/raes_participant_realization_execution.py`
- `src/aptl/backends/raes_participant_fixture_core.py`
- `src/aptl/backends/raes_participant_runtime.py`
- `src/aptl/backends/raes_participant_driver.py`
- `src/aptl/backends/raes_participant_evidence_publication.py`
- `src/aptl/backends/raes_participant_control_evidence.py`
- `src/aptl/validation/participant_agency_readiness.py`
- `src/aptl/validation/participant_agency_qualification.py`
- `src/aptl/validation/participant_readiness_provider.py`
- `docs/raes/bounded-participant-agency-readiness.md`
- `tests/test_bounded_participant_runtime.py`
- existing participant preflights and ADR-029/033/044/046/049

## Gotchas And Anti-Patterns

- Do not equate “success” with `post_state_digest != pre_state_digest`. That is
  exactly the hidden deterministic-progression assumption this issue must
  remove.
- Do not infer stutter permission from provider identity, behavior name,
  scenario name, action summary text, or whether the same arguments were
  repeated.
- Do not move mutation-policy checks into the provider boundary, readiness
  reporter, qualification summarizer, or evidence publication layer. Those
  layers may report policy, but they must not become the authority that decides
  whether the semantic result is acceptable.
- Do not fabricate a changed digest, synthetic nonce, or extra state field to
  force repeated success paths to look mutating.
- Do not accept an undeclared no-change result merely because the action is
  usually idempotent. Default remains fail closed unless the closed realization
  explicitly declares `allows_idempotent_stutter=True`.
- Do not collapse precondition failure, postcondition failure, unsupported
  arguments, and backend contradiction into one generic “stutter” bucket.
- Do not add duplicate evidence schemas, duplicate validation helpers, or a new
  exception hierarchy for mutation-policy mismatches.

## Non-Goals And Boundaries

This issue does not redesign RAES decision-surface projection, provider
solicitation, action admission, participant visibility, run-store layout,
episode lifecycle, or the closed synthetic handler model. It does not add a
new API route, CLI flag, scenario field, config schema, prompt instruction,
logger, exception type, or persistence backend. It does not make read-only
actions mutating, and it does not relax backend/postcondition/precondition
failures into successful outcomes. The scope is limited to truthful
representation of declared idempotent stuttering within the existing bounded
participant realization and evidence pipeline.
