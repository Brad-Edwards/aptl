# ADR-030: Startup Partial-Readiness Classification

## Status

accepted

## Date

2026-05-11

## Context

`aptl lab start` deliberately treats some late startup checks as non-fatal:
image pre-pull misses, service readiness timeouts, SSH probes, snapshot capture,
MCP build, SOC seeding, and MCP config sync are not all equivalent. Some are
cosmetic or recoverable, while others materially reduce scenario usability,
detection fidelity, telemetry, or run-data trust.

The current envelope, `LabResult(success, message, error)`, cannot express that
distinction. The result is a concept leak: the core orchestrator knows a step
degraded, but the CLI/API/web surfaces mostly see a success boolean plus log
warnings. Automation then has to scrape text or trust a startup that may be
missing important evidence-producing services.

Relevant incumbents already exist:

- `src/aptl/core/lab_types.py` owns lifecycle result/status dataclasses shared
  by the core, deployment backends, CLI, and API.
- `src/aptl/core/lab.py` owns startup ordering through `_LabStartContext` and
  `_LAB_START_STEPS`.
- `src/aptl/core/services.py` owns readiness polling and returns
  `ServiceResult`.
- `src/aptl/core/deployment/` owns Docker/Compose execution through
  `DeploymentBackend` (ADR-013 and ADR-023).
- `src/aptl/api/schemas.py`, `src/aptl/cli/lab.py`, and `web/src/lib/types.ts`
  are the current user-facing action/status envelopes.
- `src/aptl/utils/redaction.py`, ADR-012, and ADR-029 own serialization,
  observability, CLI, API, and log redaction boundaries.

## Decision

Startup partial readiness must be represented as a first-class lifecycle result
contract in the Python control plane, not as ad hoc warning text in individual
steps.

The canonical structured contract belongs in `src/aptl/core/lab_types.py` and
is then projected into API schemas, CLI output, and web types. Do not create a
parallel startup schema in the API or web layer that reclassifies core results.

The contract should keep three concepts separate:

- **Outcome:** the overall machine-readable startup state, with a closed set
  such as `ready`, `degraded_usable`, `degraded_unusable`, and `failed`.
- **Diagnostic impact:** what a warning affects, with at least `cosmetic` and
  `telemetry`, and room for capability/readiness impact without changing every
  caller.
- **Severity / operator action:** whether the issue is informational,
  warning-level, or error-level, independent of whether the already-started lab
  can still be used.

`LabResult.success` may remain for backward compatibility, but it must not be
the only semantic field. Map it from the structured outcome rather than letting
callers infer partial readiness from text. In particular, a
`degraded_unusable` startup should be distinguishable from both a hard startup
failure and a usable-but-degraded startup.

Each startup step that can degrade should emit a diagnostic through a single
core-owned path. Step bodies may still log, but logs are secondary; CLI/API/web
must render the structured diagnostics. The implementation must characterize
the current live behavior before changing classifications so existing
"non-critical" steps are not silently promoted or demoted.

### Amendment: Persisted Wazuh Credential Mismatch

Wazuh Indexer authentication readiness crosses two existing states: the current
run's intended credentials from `.env`/`EnvVars`, and the persisted OpenSearch
security state inside the Compose-managed `wazuh-indexer-data` volume. Docker
health only proves that the HTTP listener responds; it is not proof that the
current `.env` credentials match the live security database.

When the indexer auth probe fails with HTTP 401 while the indexer container is
running/healthy, lab startup should emit a specific structured diagnostic on
the existing `wait_for_services/wazuh_indexer` surface. The operator action
should point to the existing clean-state recovery path (`aptl lab stop -v` or
`aptl lab start --clean`) rather than introduce a second volume-reset workflow.
The normal start path must not mutate the persisted Wazuh security database,
rewrite `internal_users.yml`, or delete volumes to make `.env` and the old
volume agree.

Any probe that handles `.env` credentials must satisfy ADR-029: no password in
process argv, logs, exception text, API envelopes, or diagnostics. If the
existing readiness helper cannot distinguish HTTP status safely, extend the
shared readiness / curl-safe boundary instead of adding one-off raw `curl`
subprocesses. If a future credential fingerprint is stored to warn before live
startup, it must be advisory, non-reversible, versioned service metadata under
ignored state (for example `.aptl/`) and never a replacement for the live auth
probe.

## Guardrails

- Keep lab-start orchestration in `core.lab` as a flat sequence of `_step_*`
  functions and `_LAB_START_STEPS`. Add classification at the step boundary or
  shared context boundary; do not replace the orchestrator with a workflow
  engine.
- Reuse `ServiceResult` for readiness probe details and `DeploymentBackend`
  for deployment interactions. Do not shell out directly from a new
  classification helper.
- Reuse `LabResult` / `LabStatus` as the lifecycle DTO boundary. If new nested
  dataclasses or enums are needed, define them beside those types in
  `lab_types.py`.
- Keep API models in `api.schemas` as projections of the core DTO, not a
  second source of classification truth.
- Keep web TypeScript interfaces aligned with API schemas; do not infer
  degraded state from English messages in the Svelte layer.
- Preserve `AptlConfig` / `.env` validation ownership. Classification must not
  add unvalidated config flags, environment-variable bypasses, or a second
  config schema.
- Redact diagnostics before they cross CLI, API, log, telemetry, snapshot, or
  persistence boundaries. Diagnostic details may name a step, component, path,
  container, or service, but must not include `.env` values, API keys, bearer
  tokens, cookies, private keys, generated config contents, or full command
  lines containing credentials.

## Security Layers

- **Config/env binding:** startup still uses `AptlConfig`, `load_dotenv`,
  `env_vars_from_dict`, and `find_placeholder_env_values`. New classification
  fields are runtime result data, not durable config knobs.
- **Deployment boundary:** Docker and remote-Compose interactions stay behind
  `DeploymentBackend`; this preserves SSH-remote behavior and avoids leaking
  transport-specific details into result classification.
- **OS/process exposure:** readiness probes and subprocess failures can include
  sensitive argv or stderr. Structured diagnostics must store narrow labels and
  redacted summaries, not raw argv or command output.
- **Error envelopes:** `LabResult`, `LabActionResponse`, CLI output, SSE/API
  status payloads, and web action errors must preserve structure while applying
  the ADR-029 redaction invariant.
- **Observability/persistence:** if startup diagnostics are later traced,
  snapshotted, archived, or written to run storage, the existing
  `redact()`/`LocalRunStore` boundaries remain authoritative.

## Extensibility

The extensibility seam is a small, closed diagnostic taxonomy plus per-step
diagnostic emission metadata in the core startup context. A future startup step
should add a diagnostic code, impact, and outcome contribution without editing
every CLI/API/web caller. A future deployment backend should receive the same
structured result shape without emulating Docker-specific warning text.

## Non-Goals

- Do not redesign Docker Compose profiles, deployment providers, or container
  health checks.
- Do not make every warning fatal.
- Do not add a second exception hierarchy for startup classification.
- Do not add a general workflow engine or requirement/status engine to lab
  startup.
- Do not persist startup diagnostics in run archives as part of this
  classification unless a later issue explicitly owns that artifact contract.

## Anti-Patterns

- Scraping log text or CLI output to decide readiness.
- Adding `is_degraded`, `partial`, `telemetry_ok`, or similar booleans in
  multiple layers instead of one canonical outcome plus diagnostics.
- Returning raw subprocess stderr, curl output, Docker command lines, or
  generated config content in user-facing diagnostics.
- Reclassifying the same core result separately in the CLI, API, and web UI.
- Treating telemetry-impacting, SOC/detection-impacting, SSH-readiness, and
  cosmetic display warnings as the same "warning" concept.
