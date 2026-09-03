# Issue #858 Bounded Participant Choice Transport Preflight

This note fixes the design boundaries for bounding installed-participant choice
transport without changing delivered RAES candidate semantics. It is
architecture guidance, not an implementation plan. No new ADR is needed:
`docs/architecture/issue-557-participant-implementation-binding-preflight.md`,
`docs/architecture/issue-821-participant-workbench-preflight.md`,
ADR-029, ADR-033, ADR-044, ADR-046, and ADR-049 already own the relevant
runtime, secret, evidence, and appliance boundaries.

[ADR-052](../adrs/adr-052-configured-participant-credential-sourcing.md)
supersedes this note's broker/lease terminology; transport remains separate
from configured credential sourcing and provider delivery.

## Architecture decisions

- Keep the authoritative decision surface unchanged. RAES remains the source of
  truth for `ParticipantDecisionSurfaceV2Model`,
  `ParticipantDecisionSurfaceSelectionV2Model`, projection/delivery,
  proposal identity, selection binding, and admission. The bounded transport is
  a provider-facing view over the already delivered candidate set, not a second
  decision-surface contract.
- Keep the compact form outside RAES admission. APTL may derive a bounded
  solicitation representation from `turn.candidates` for the installed
  provider, but the provider response must resolve back to exactly one original
  delivered candidate before `admit_participant_decision_surface_selection_v2()`
  runs. The existing delivered candidate remains the only object that reaches
  RAES binding and native realization.
- Reuse existing proposal identity. `proposal_ref` is already the canonical,
  delivered, per-candidate identity. Do not invent a second permanent action
  id, a transport-only semantic id, or an alternate admission path. If the
  bounded representation needs a shorter provider-facing token, that token is a
  transient alias for one delivered `proposal_ref`, recorded only as transport
  metadata.
- Make compaction structural, not semantic. The accepted lossiness is limited
  to repeated trusted coordinates that the participant did not choose. Do not
  drop candidates, merge semantically distinct candidates, or normalize away
  governed dimensions that determine native operation or readback.
- Keep the complete solicitation authoritative in evidence. Evaluator evidence
  must continue to retain the full delivered solicitation fingerprint, selected
  delivered candidate identity, and existing admission receipts/diagnostics.
  The compact transport may be retained as an additional bounded transport
  record or digest, but it must not replace the authoritative delivered-view
  fingerprint.
- Bound size with code-owned limits at the installed-provider seam. The limit is
  an execution-policy concern owned by the decision-provider boundary, not a
  scenario field, profile field, prompt instruction, or user input. Existing
  adapter prompt/output limits remain the incumbent shape for these ceilings.
- Fail closed before provider-side action authority can expand. Missing,
  malformed, ambiguous, out-of-range, duplicate, or out-of-set provider outputs
  are solicitation failures and never reach RAES admission, behavior history, or
  native realization.

No ADR is needed. This issue constrains how an existing installed-provider
boundary serializes an already authoritative RAES decision surface; it does not
change the durable product architecture.

## Canonical incumbents to reuse

| Concern | Canonical owner and required reuse |
|---|---|
| Exact decision surface and delivery | `project_participant_turn()`, `project_participant_decision_surface_v2()`, `deliver_surface()`, `ParticipantDecisionTurn`, and `candidate_selections()` own exact-cut projection, delivery, and full finite candidate enumeration. |
| Candidate identity and governed semantics | `ParticipantDecisionSurfaceSelectionV2Model`, existing `proposal_ref` construction in `candidate_selections()`, `argument_shape_ref`, and `resolve_participant_action_arguments()` own the exact candidate meaning. |
| Provider solicitation workflow | `ParticipantDecisionSolicitation`, `ManagedAgentSelectionProvider`, `parse_provider_selection()`, `AptlParticipantRuntime.solicit_selection()`, and `run_participant_turn()` own provider invocation, hostile-output parsing, replay/budget gates, and fail-closed solicitation status. |
| Admission and native realization | `admit_projected_participant_selection()`, `_build_admission_request()`, `_build_binding_resolvers()`, `RuntimeControlPlane.admit_participant_decision_surface_selection_v2()`, and RAES base runtime admission remain the only admission path. |
| Evidence and persistence | `ParticipantControlEvidence`, `persist_control_evidence()`, `solicitation_fingerprint()`, `selection_fingerprint()`, `_persist_admission_evidence()`, `RunStorageBackend.append_jsonl()`, and immutable action-transaction publication remain the evidence owners. |
| Installed-provider execution limits | `build_selection_provider()`, `DecisionAgentLaunch`, `ManagedAgentAdapter`, `ClaudeCodeManagedAgentAdapter`, `CodexManagedAgentAdapter`, `BoundedProcessRunner`, and their existing timeout/prompt/output caps own installed-provider execution policy. |
| Qualification and hostile-boundary tests | `validate_participant_agency_qualification()`, `validate_participant_agency_readiness()`, boundary challenges in `participant_qualification_boundaries.py`, and `tests/test_bounded_participant_runtime.py` remain the contract and regression suites. |
| Logging and diagnostics | RAES `Diagnostic`, participant operation status, `get_logger()`, and the existing redacted workbench/participant error translation remain the observability vocabulary. Do not add a second exception family or prompt-bound diagnostic format. |

Do not add a second candidate DTO, a second binder, a second selection parser,
another evidence schema for authoritative selection identity, or a provider-name
branch in scenario logic.

## Security and validation passage

| Layer | Required behavior |
|---|---|
| RAES shape and binding | The bounded transport starts from already validated delivered candidates. Before admission, provider output must resolve to one delivered `ParticipantDecisionSurfaceSelectionV2Model`, after which the existing RAES binder re-checks `delivery_ref`, `proposal_ref`, `argument_shape_ref`, apparatus refs, and governed arguments. |
| Solicitation parser / hostile-output gate | Treat provider output as hostile. Keep the current bounded outer envelope, JSON parsing, and strict closed-world membership check in `AptlParticipantRuntime.solicit_selection()`. Add bounded-transport parsing there or immediately adjacent, not in native handlers. Raw provider text never becomes action authority. |
| Config and env shape | No scenario, profile, API, or operator config field should define candidate compaction rules or provider-visible mappings. If a durable ceiling must vary by provider, keep it in the existing closed provider registry/adapter construction path, not `AptlConfig`, `.env`, or participant-visible payloads, unless a genuine repo-wide setting is later justified. |
| Secret handling | Reuse the ADR-052 workbench credential boundary, fixed argv, stdin prompt delivery, and redacted diagnostics. Compact transport must not move credentials, hidden evaluator truth, backend handles, or extra topology into provider-visible prompt content. |
| OS/process exposure | Prompt bytes still flow over stdin to the admitted executable. Do not place compacted candidate maps, fingerprints used as credentials, or prompt payloads in argv, filenames, URLs, or environment variables. Existing work-dir, timeout, and output-cap limits remain in force. |
| Error envelopes | Prompt-bound overflow, malformed alias selection, ambiguous alias mapping, and out-of-range selection are solicitation failures surfaced through the existing participant operation failure path and control evidence. Do not leak raw provider output, parser traces, or the full prompt body in diagnostics. |
| Persistence and evidence | Preserve `solicitation_fingerprint()` over the authoritative full delivered solicitation and retain the selected delivered candidate digest/ref. If compact transport metadata is persisted, record it as supplemental transport evidence tied to the same run/episode/solicitation ids, never as a replacement authority. |
| API/CLI ingress | This change adds no new ingress. Existing CLI/operator boundaries remain unchanged. Do not add an operator override to pass raw compacted candidate payloads or choose alternate transport modes at runtime. |

## Extensibility seam

The seam belongs at the installed-provider transport boundary:

`(authoritative_solicitation, compact_representation, compact_id ↔ delivered proposal_ref mapping, size_limit_bytes_or_chars, provider_parser)`

The compact mapping is derived and ephemeral. It must not contain new semantic
fields, duplicated governed argument schemas, or realization data not already
present in the delivered surface. The next reasonable variation is another
provider with a different safe prompt budget; that should require only a
different limit/parser policy at this seam, not changes to RAES projection,
candidate enumeration, evidence schema, or native action handlers.

## Whole-repository surface in scope

- `src/aptl/backends/raes_participant_provider.py`
- `src/aptl/backends/raes_participant_driver.py`
- `src/aptl/backends/raes_participant_runtime.py`
- `src/aptl/backends/raes_participant_control_evidence.py`
- `src/aptl/backends/raes_participant_candidates.py`
- `src/aptl/validation/participant_agency_readiness.py`
- `src/aptl/validation/participant_agency_qualification.py`
- `src/aptl/validation/participant_qualification_boundaries.py`
- `src/aptl/validation/participant_readiness_provider.py`
- `src/aptl/workbench/{runtime,agent,codex_agent,process}.py`
- `tests/test_bounded_participant_runtime.py` and related participant
  qualification/readiness tests
- existing issue-557 / issue-821 architecture notes and ADR-029/033/044/046/049

## Gotchas and anti-patterns

- Do not send the full authoritative candidate JSON through the provider prompt
  and separately add a compact alias layer; that keeps the original overflow and
  adds concept confusion.
- Do not admit a provider response by reconstructing a near-match from
  user-visible fields. Admission must resolve to one exact delivered candidate,
  not “best effort” semantic equivalence.
- Do not replace `proposal_ref` with a new permanent identifier or infer
  selected identity from list position alone without a fail-closed mapping.
- Do not duplicate `ParticipantDecisionSurfaceSelectionV2Model`,
  governed-argument validators, or `resolve_participant_action_arguments()` in
  APTL transport code.
- Do not move compaction into scenario authoring, RAES model compilation, native
  action handlers, or evidence publication. The change belongs at provider
  solicitation and its immediate parser/mapping boundary.
- Do not weaken out-of-set rejection merely because a compact token decodes to a
  valid action name. Membership is against the delivered candidate set for that
  exact state cut.
- Do not log or persist the full provider prompt body, raw provider response, or
  hidden evaluator context as a debugging shortcut. Keep evidence digest-based
  and redacted unless existing authoritative records already retain the allowed
  content.
- Do not tune transport size by dropping candidates from large red/blue surfaces.
  Candidate-count reduction changes the experiment and is out of scope.

## Non-goals and boundaries

This issue does not redesign RAES decision-surface projection, candidate
enumeration, participant apparatus/exposure policy, native realizations,
participant workbench routing, provider credential brokerage, or run-store
layout. It does not add a new API route, CLI option, config file schema,
scenario syntax, evidence store, logger, exception hierarchy, or admission
workflow. It does not change the authoritative delivered candidate set, only
how that set is compactly represented to an installed decision-only provider.
