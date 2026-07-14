# DSL-005 Assertion Evaluation Preflight

This note is the architecture preflight for issue #434. It is guidance, not an
implementation plan. The assertion contract is owned by ACES (upstream issue
Brad-Edwards/aces#657); APTL consumes that contract and evaluates it against a
realized environment. ADR-035 remains the ACES-adoption decision, ADR-044 owns
run records, and ADR-046 owns dynamic realization and evidence boundaries.

## Architecture Decisions

- ACES remains the sole authority for proposition, assertion, predicate,
  polarity, role, quantifier, truth-outcome, evidence, temporal-context, plan,
  and snapshot shapes. Consume the selected `aces-sdl` package's compiled
  resources and `PropositionTruthResultModel`; do not mirror them in APTL.
- Keep four concepts separate:
  - a condition is a probe realization/binding;
  - a proposition is the backend-neutral claim being decided;
  - an assertion applies role and polarity to that proposition;
  - `EvaluationExecutionState` is evaluator lifecycle state, not proposition
    truth. Portable truth belongs in
    `RuntimeSnapshot.proposition_truth_results`.
- Boundary timing is part of correctness. Provisioning first establishes an
  observed snapshot. Preconditions are evaluated immediately before their
  compiled owning boundary executes. Postconditions are evaluated from a fresh
  observation after that boundary finishes. Objective and workflow outcomes
  consume those assertion results only after the applicable checkpoint.
- Only compiled owner-reference metadata identifies which assertion gates an
  event, workflow predicate, objective, agent starting state, or other boundary.
  An assertion's `role` alone does not make it global or identify an owner. If
  the upstream plan does not carry an unambiguous owner/checkpoint binding, APTL
  must report the contract gap rather than infer one from names or SDL text.
- Preconditions fail closed at the execution boundary: only a contract-valid
  `assertion_outcome=true` admits the owning action. `false`, `unknown`, and
  `unsupported` remain distinct portable outcomes and do not execute the gated
  action. A failed postcondition is reported and propagated through the existing
  objective/workflow result path; it is not an implicit Compose rollback or a
  new lab-readiness category.
- `AptlEvaluator` owns proposition observation, predicate evaluation, polarity,
  quantification, and truth-result emission. `AptlOrchestrator` and
  `WorkflowEngine` own control flow and consume already-decided assertion or
  objective outcomes. Neither component should call back into the other. The
  single sequencing owner remains the ACES handoff in `aptl.backends.aces`.
- Observation is side-effect-free and backend-scoped. It may reuse the current
  `RuntimeSnapshot`, realization addresses, `DeploymentBackend` inventory, and
  existing captured evidence. It must not echo planned payloads and call that
  observed truth. It also must not overload the SEM-218
  `aces_observation.observe_realization()` concern map: realization-conformance
  observation and proposition evidence have different contracts.
- Capability publication is evidence-backed. `create_aptl_manifest()` may claim
  `propositions`/`assertions`, predicate families, quantifiers, evidence
  channels, time domains, binding provenance, and
  `proposition-truth-result-v1` only for the surface the same runtime target can
  actually evaluate. Unsupported inputs produce the ACES `unsupported` outcome
  or planner diagnostics; they are not coerced to `false`.

## Required Cross-Cutting Concerns

- **ACES schema and validation:** `aces_sdl.parse_sdl_file`, ACES semantic
  validation, `compile_runtime_model`, `RuntimeManager.plan()`,
  `EvaluationPlan`, `OrchestrationPlan`, canonical compiled addresses,
  `PropositionTruthResultModel`, `RuntimeSnapshot`, `ApplyResult`, and
  `proposition_truth_contract_diagnostics()`.
- **APTL adapter owners:** `create_aptl_runtime_target()`,
  `_apply_execution_plan()`, `AptlEvaluator`, `_aces_evaluator_engine`,
  `AptlOrchestrator`, `WorkflowEngine`, `create_aptl_manifest()`, and
  `render_aces_diagnostics()`.
- **Realized-state owners:** `AptlProvisioner`, `AptlRealization`, the
  backend-observed provisioning snapshot, `DeploymentBackend`,
  `ComposeQueryMixin`, project-name/Compose-label scoping, bounded
  `container_exec()`, `container_inspect()`, network inventory, and existing
  `RangeSnapshot` capture. ACES adapters do not call Docker directly.
- **Evidence and persistence:** ACES evidence requirements and truth-result
  `evidence_refs`, `LocalRunStore.write_json()` / `write_jsonl()` /
  `append_jsonl()`, the ACES snapshot embedded by `aces_repro`, and the existing
  run id resolved once by lab start. Add references to the existing run record;
  do not create an assertion-run manifest.
- **Errors and observability:** ACES `Diagnostic` with stable code/domain/address,
  `redact()`, `get_logger()`, `render_aces_diagnostics()`, `LabResult`,
  `StartupDiagnostic`, and existing API projections. Do not add an assertion
  exception hierarchy, truth logging taxonomy, or English-message parser.
- **Configuration and secrets:** strict `AptlConfig`, `.env`/`EnvVars`,
  placeholder validation, ADR-028 generated config, ADR-029 redaction, and
  ADR-034 TLS material. Evaluator capabilities and probe bindings are not an
  unchecked `aptl.json` dictionary or an SDL extension.
- **Verification conventions:** extend `tests/test_aces_evaluator.py`,
  `tests/test_aces_orchestrator.py`, `tests/test_workflow_engine.py`,
  `tests/test_aces_backend.py`, `tests/test_aces_repro.py`, and existing
  conformance/static/live gates. Python changes remain subject to `pytest` and
  `pre-commit run --all-files` per `.gc/plan-rules.md`.

## Cross-Cutting Layers The Design Must Pass

| Layer | Required behavior |
| --- | --- |
| SDL parser and semantic validator | Accept only ACES-valid propositions, assertions, role-constrained uses, finite subjects, typed predicates, and evidence requirements. APTL does not parse or structurally revalidate their YAML. |
| Plan and manifest validation | Consume only `EvaluationPlan` / `OrchestrationPlan` resources with canonical addresses. Planner diagnostics must reject capability overclaims before side effects. Manifest dimensions and supported contract ids must match the implemented probe surface. |
| Runtime target and result shape | Return ACES `ApplyResult` and `RuntimeSnapshot`. Preserve unrelated carriers and pass snapshot-address, result-contract, proposition-truth, transition, and changed-address admission checks in `aces_runtime.backend_calls`. |
| Truth-result envelope | Construct `PropositionTruthResultModel`, preserving positive/negative polarity and all four outcomes. Decided observed truth requires real evidence refs, a matching probe binding, temporal context, and admissible loss disclosures; missing evidence becomes `unknown`, not success. |
| Realized subject binding | Resolve compiled subject addresses through the current realization/snapshot and the project-scoped `DeploymentBackend`. A plan entry, Compose service name, scenario name, or successful `compose up` is not by itself observed proposition truth. |
| Probe execution and OS exposure | Prefer typed inventory reads. If a supported probe requires container execution, use bounded argv-list `DeploymentBackend.container_exec()` against a realized project member. Never use `shell=True`, raw host commands, or place tokens, passwords, cookies, hashes, private keys, or rendered config in argv. An authored condition command is not automatically an admitted shell probe. |
| Config and environment shape | Reuse strict `AptlConfig` for durable non-secret knobs and existing `.env`/`EnvVars` validation for secrets. Do not add free-form probe commands or credentials to config, snapshots, or evaluator payloads. |
| Auth surface | Issue #434 requires no new HTTP surface. Existing scenario start remains behind `verify_token` and BFF host/CSRF gates. Any later results endpoint must use the same auth and a narrow Pydantic projection, never expose raw snapshots or internal paths. |
| Error envelope and logging | Convert probe/contract failures to redacted ACES diagnostics, then existing `LabResult`/startup/API envelopes. Log addresses, codes, outcome classes, and counts; do not log raw evidence, command output, backend stderr, or exception payloads. |
| Persistence and export | Keep truth results in the ACES runtime snapshot and structured evidence under the current run through redacting `LocalRunStore` methods. Path validation remains in runstore; exporter remains packaging-only. Ensure assertion/evaluation evidence is included by the existing run-record evidence-reference enumeration. |
| Participant projection | Evaluator-only evidence, internal endpoint identities, negative-boundary details, and raw SOC data stay outside participant-visible observation boundaries and workbench/API projections, per ADR-046. |

## Extensibility Seam

The required seam is one evaluator-owned, capability-declared probe binding,
parameterized by:

`(proposition address, assertion address, owning boundary and checkpoint,
evaluation basis, predicate kind/property/semantic ref/operator/operand,
quantifier/threshold, resolved subject addresses, evidence requirements,
runtime snapshot, backend/project identity, temporal context)`.

It returns the upstream `PropositionTruthResultModel` (plus evidence references
or ACES diagnostics), not an APTL truth DTO. Bindings should be selected by the
governed semantic/predicate identity and advertised capability, never by
scenario name, file path, catalog id, Compose profile, assertion name, or
TechVault convention.

The next reasonable change is another observable property, predicate family,
evidence channel, or deployment provider. It should add one truthful probe
binding and manifest capability entry while leaving checkpoint coordination,
polarity, quantification, workflow consumption, persistence, and error handling
unchanged. Probe implementation identity/version/digest and backend-manifest
reference must remain explicit so observed decided truth satisfies ACES binding
provenance instead of relying on an unversioned Python callable.

## Whole-Repo Surface

- Dependency/contract authority: `pyproject.toml`, `uv.lock`, and the installed
  ACES parser, processor, runtime, contracts, conformance corpus, and validators.
- Runtime path: `src/aptl/backends/aces.py`, `aces_manifest.py`,
  `aces_evaluator.py`, `_aces_evaluator_engine.py`, `aces_orchestrator.py`,
  `aces_provisioner.py`, `aces_realization*.py`, `aces_observation.py`, and
  `src/aptl/core/runtime/workflow_engine.py`.
- Host/runtime path: `src/aptl/core/deployment/`, Docker/SSH Compose transport,
  Docker daemon inventory, container argv, project labels, bounded timeouts, and
  the post-provision runtime snapshot.
- Lifecycle/output path: `src/aptl/core/lab.py`, `lab_types.py`, `runstore.py`,
  `snapshot.py`, `src/aptl/backends/aces_repro.py`, CLI output, authenticated API
  projections, logs, traces, run archives, and exports.
- Security/config path: `AptlConfig`, `.env`/`EnvVars`, generated config and TLS,
  `redact()`, ADR-023, ADR-025, ADR-029, ADR-035, ADR-039, ADR-044, and ADR-046.
- Repo gates: existing evaluator/orchestrator/workflow/backend/repro tests,
  ACES target conformance, static/live scenario gates, `pytest`, and pre-commit.

## Gotchas And Anti-Patterns

- The current manifest advertises conditions/objectives only and omits
  `proposition-truth-result-v1`; widening code without widening and validating
  the manifest, or widening the manifest before live support exists, is drift.
- `OrchestratorCapabilities.supports_assertion_refs` defaults true upstream.
  Relying on that default while `WorkflowEngine` ignores compiled assertion
  predicates is an overclaim; set and test the capability deliberately.
- The current evaluator treats provisioning node readiness as condition success.
  Node readiness is not a general boolean/string/number proposition evaluator,
  and a condition command's exit code is not automatically proposition truth.
- `RuntimeManager.apply()` currently runs evaluation once before orchestration,
  while APTL drives workflows afterward. Reusing that one snapshot for
  postconditions evaluates too early. Returning the pre-drive snapshot also
  loses later truth/workflow state from the run record.
- Do not evaluate every precondition at scenario start or every postcondition at
  scenario end. Use its compiled owning boundary and take a fresh observation at
  that boundary.
- Do not collapse `unknown`/`unsupported` into `false`, invert them for negative
  assertions, or let missing/redacted/stale/probe-failure evidence become a
  decided result.
- Do not make evaluation success depend on a planned payload matching itself,
  a container merely existing, an unscoped container name, or cached evidence
  from before the action.
- Do not publish raw probe stdout/stderr as result detail or evidence. Persist a
  redacted/typed evidence artifact and reference it; bind it to the same run,
  subject, checkpoint, and time context.
- Do not hand-build truth-result dicts, duplicate ACES polarity/quantifier logic,
  add a local assertion schema, or create a second validation/exception/result
  hierarchy.
- Do not let postcondition reporting mutate participant-visible projections,
  invent scoring, or silently trigger teardown/rollback outside existing
  workflow/lifecycle policy.

## Non-Goals And Boundaries

- Do not implement issue #434 in this preflight.
- Do not define or modify assertion semantics, schemas, controlled vocabulary,
  plan metadata, or truth-result contracts in APTL; upstream ACES is authoritative.
- Do not turn authored condition commands into a general shell/query execution
  surface or expose evaluator probes through a new API.
- Do not implement unsupported event/inject/script/story execution, participant
  action admission, continuous invariant monitoring, grading/scoring, or a new
  workflow engine merely because those constructs may reference assertions.
- Do not redesign provisioning, Docker Compose topology, deployment backends,
  config/env binding, generated secrets, web auth, startup readiness, run archive
  layout, exporter packaging, or participant observation boundaries.
- Do not require every predicate/property/evidence channel in the first backend
  implementation. Unsupported surfaces must remain explicit and contract-clean,
  and the manifest must claim only what is proven.
