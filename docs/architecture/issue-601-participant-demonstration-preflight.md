# Issue #601: participant demonstration architecture preflight

## Approved scope revision

The implementation now selects a minimal TechVault copy in OpenRAE/env-packs,
`techvault-participant-study`, and reuses TechVault's exact APTL adapter through
new digest-scoped registrations. The participant uses the normal Claude CLI
login and host MCP grant. The checkout-only `aptl lab participant-readiness`
path is removed. The source and capture procedure are recorded in the
[issue 601 runbook](../raes/issue-601-participant-demonstration.md). The
preflight discussion below records the earlier boundary analysis; where it
mentions readiness or configured provider credentials, this approved revision
controls the implementation.

## Decision boundary

The deliverable is an observed run by a real installed participant against an
identified, authored scenario, with the evidence requested by #558 and a
reproducible account of what the evidence supports. The September 5 review
supersedes an APTL-versus-LilRAE independent-backend comparison: they are one
product across a rename (ADR-054). Coordinate the advanced APTL experience
with Hub #15; paired-backend research belongs to LilRAE #11. Neither external
issue changes the authority of this repository's actual run records.

Freeze the selected scenario source and digest, acquired pack identity where
applicable, published RAES contract and processor versions, backend manifest,
installed participant implementation and model, non-secret config identity,
apparatus and image identities, capture specifications, attempt/run identity,
host platform, and observed reset state. Keep scenario and provider selection as
inputs to the demonstration record; do not bake one provider or the checkout-only
`paper-agent-loop` or bounded-participant fixture into a new generic workflow.
If a checkout-only fixture is selected, disclose that dependency and do not
claim a released, independently installed pack journey. Separate observed
actions, evaluator observations, failed or missing captures, and interpretation.

## Existing boundaries to reuse

| Concern | Canonical owner and guardrail |
| --- | --- |
| Scenario meaning and validation | Published RAES SDL parser, processor, runtime and diagnostics; `src/aptl/backends/raes.py`, `raes_manifest.py`, and `src/aptl/validation/` gates. Use the compiled, admitted addresses and contracts; do not parse SDL again into APTL mirrors or infer success from declarations. |
| Experiment admission | `src/aptl/core/experiment/` and `aptl experiment admit`: bounded, project-contained artifact resolution; public RAES task, capture, experiment and cross-artifact models; apparatus and capture capability checks; immutable trial plan. Admission does not start a lab or prove a participant acted (ADR-047). |
| Installed participant | `docs/reference/host-mcp-access.md` and `src/aptl/workbench/` own authenticated host CLI transport and grants. RAES participant admission and action readback live in `src/aptl/backends/raes_participant_*` where used. Record the selected implementation/model and actual transition evidence, not just a provider process exit or a plausible transcript. |
| Capture and persistence | `src/aptl/core/experiment/capture_registry.py` binds published capture intent to closed collectors; `src/aptl/core/evidence/coordinator.py` owns capture lifecycle, quotas, redaction, content-addressed bytes, typed outcomes and RAES evidence records. `src/aptl/core/runstore.py` owns contained writes. Missing required capture invalidates or interrupts the attempt; it cannot be filled with an authored requirement or a manually assembled JSON file. |
| Terminal result and export | `src/aptl/core/execution/`, `src/aptl/core/archival/` and ADR-050 own attempt identity, status, RAES `experiment-run/v1`, cross-artifact checks and atomic seal. `src/aptl/core/archival/verify.py` and `aptl runs verify-bundle` verify artifacts. `aptl runs export-bundle` packages existing bytes and discloses an absent seal; packaging is not validation of a scientific claim. |
| Auth and participant reach | ADR-039 and `docs/components/participant-workbench.md` govern browser principal, live grant, role, deployment identity, revocation, capture admission and narrow MCP dispatch. `docs/reference/host-mcp-access.md` governs host clients. A participant cannot receive operator API, Docker socket, evaluator store or unrestricted service credentials through a convenience demonstration path. |
| Errors and observability | RAES `Diagnostic` and `render_raes_diagnostics()` cover admission failures; capture uses typed `CollectorStatus`/`AcquisitionDisposition`; archival uses `TerminalCause` and its one status mapper. `src/aptl/utils/logging.py`, `src/aptl/utils/redaction.py` and MCP common redaction own safe logs and traces. Do not add a demo-specific exception hierarchy, success flag, logging channel or error envelope. |

## Cross-cutting gates for the live path

- **Input and configuration:** resolve paths through the project-contained
  resolver and existing no-follow run-store rules. Pass scenario, experiment,
  task and capture input through the published RAES parser/models and the
  admission policy; pass durable settings through strict `AptlConfig` and
  runtime secrets through its established environment binding. Unknown fields,
  unsupported capabilities, mismatched digests and missing sources fail closed.
- **Secret and process surface:** ADR-029 and ADR-052 classify operator/provider
  credentials separately from designed target data. The configured credential
  locator is non-secret; its value never enters `aptl.json`, a command argument,
  a run record, a prompt, a trace or an error. Use the existing broker and
  minimal child environment, bounded process runner, provider-native schema,
  cleanup evidence and explicit model selection. Check the host process,
  descendants and outbound reach actually allowed; ADR-057's stronger OS
  compartment is proposed, so current tool restriction alone cannot support a
  sandbox or host-isolation claim.
- **Capture and output:** redact at the Python run-store / evidence persistence
  and MCP trace boundaries before bytes reach logs, CLI/API responses, OTel,
  archives or exports. The shared redactors and safe diagnostic projections
  handle error envelopes; raw provider errors, command output, absolute private
  paths and credential locators do not become public diagnostics. Keep the
  participant projection separate from evaluator-only Wazuh and negative
  boundary evidence, as in `docs/raes/paper-scenario-realization.md`.
- **Host and runtime:** `aptl lab start` and `DeploymentBackend` own real range
  realization, profiles, network attachment and reset. Record actual health,
  action effect/readback, capture status, seal state and residual state. A
  clean-start request, static conformance pass, container health, or mock-backed
  readiness result alone does not establish a reproduced live demonstration.

## Claim limits and non-goals

A passing qualification report is pre-capture evidence only. A sealed archive
establishes byte identity and declared completeness, not
that an evaluator's interpretation is correct. Report exact observed evidence,
unsupported claims, failures and environment limits. Do not claim comparative
backend results, detection quality, autonomous host containment, released-pack
installability, or general reproducibility beyond the tested apparatus without
separate evidence.

This preflight adds no implementation plan, alternate RAES schema, new
controller/repository, second participant workflow, new collector protocol, or
feature code. The live demonstration and research evidence remain downstream
work under #601/#558; Hub #15 and LilRAE #11 own their respective coordination
and paired research outcomes.
